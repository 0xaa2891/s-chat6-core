//! Exhaustive state-machine checks.
//!
//! - Delivery lifecycle: every state × every transition operation; only
//!   legal edges occur, illegal ones are rejected (`BadTransition`) and
//!   leave the row untouched. Legal edges (see `sync::outbox`):
//!   `Queued → Transmitted`, `Queued → Acknowledged` (the peer's sync
//!   view is ground truth and may ack a write we never confirmed),
//!   `Queued → Failed`, `Transmitted → Acknowledged`,
//!   `Transmitted → Failed`, `Transmitted → Transmitted` (idempotent
//!   resync requeue). `Acknowledged` and `Failed` are terminal.
//!   `Received` (inbound) never transitions.
//! - Message lifecycle: once a row is erased (TTL sweep or
//!   `erase_history`) no operation resurrects it — late duplicate
//!   delivery, resync retransmit coverage, or tombstone application.
//!   There is no ERASED → * edge.
//! - Session lifecycle: `Active → Broken` on crypto failure; `Broken`
//!   refuses encrypt AND decrypt and fails `send_text`; there is no
//!   path back to `Active` without re-pairing.

use std::sync::Arc;
use std::time::SystemTime;

use schat_core::engine::{Engine, EngineError, EngineEvent};
use schat_core::pairing::relationship::load_relationship;
use schat_core::pairing::{accept, accept_request, ingest_frame, offer, Ingest, PairingFailure};
use schat_core::session::{self, SessionError, SessionState};
use schat_core::store::clock::FakeClock;
use schat_core::store::inbound_seqs::InboundSeqsRepository;
use schat_core::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use schat_core::store::outbox::OutboxRepository;
use schat_core::store::tombstones::TombstonesRepository;
use schat_core::store::{hex_encode, Db};
use schat_core::sync::outbox::{drain, mark_acknowledged, mark_transmitted};
use schat_core::sync::resync::{build_request, handle_request};
use schat_core::sync::{Sync, SyncError, MESSAGE_TTL_SECS};
use schat_core::transport::framing;
use schat_core::transport::Transport;
use schat_core::wire::frame as wire_frame;
use schat_wire_types::envelope::{Envelope, Payload};
use schat_wire_types::msg::Msg;

const T0: u64 = 1_700_000_000;
const REL: &str = "rel";

// ---------------------------------------------------------------------------
// Delivery state machine (pure store layer; no pairing needed)
// ---------------------------------------------------------------------------

fn fresh_db() -> (Db, FakeClock) {
    let clock = FakeClock::new(T0);
    let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
    (db, clock)
}

fn insert_row(db: &Db, direction: Direction, state: DeliveryState) -> [u8; 16] {
    let msg_id = rand::random::<[u8; 16]>();
    db.insert_message(&NewMessage {
        msg_id,
        rel_id: REL.into(),
        direction,
        app_seq: 1,
        sent_at: T0,
        received_at: (direction == Direction::In).then_some(T0),
        env_type: 1,
        ref_id: None,
        payload: b"body".to_vec(),
        state,
        expires_at: None,
    })
    .unwrap();
    msg_id
}

fn state_of(db: &Db, msg_id: &[u8; 16]) -> DeliveryState {
    db.message(msg_id).unwrap().unwrap().state
}

#[test]
fn delivery_state_machine_legal_edges_only() {
    use DeliveryState::*;
    let (db, _clock) = fresh_db();

    // (from, op target) → legal?
    let legal = |from: DeliveryState, to: DeliveryState| {
        matches!(
            (from, to),
            (Queued, Transmitted)
                | (Queued, Acknowledged) // sync-view ground-truth ack
                | (Queued, Failed)
                | (Transmitted, Transmitted) // idempotent resync requeue
                | (Transmitted, Acknowledged)
                | (Transmitted, Failed)
        )
    };

    for from in [Queued, Transmitted, Acknowledged, Failed, Received] {
        for to in [Transmitted, Acknowledged] {
            let dir = if from == Received {
                Direction::In
            } else {
                Direction::Out
            };
            let msg_id = insert_row(&db, dir, from);
            let result = match to {
                Transmitted => mark_transmitted(&db, &msg_id),
                Acknowledged => mark_acknowledged(&db, &msg_id),
                _ => unreachable!(),
            };
            if legal(from, to) {
                assert!(result.is_ok(), "{from:?} → {to:?} must be legal");
                assert_eq!(state_of(&db, &msg_id), to);
            } else {
                assert!(
                    matches!(result, Err(SyncError::BadTransition { .. })),
                    "{from:?} → {to:?} must be rejected, got {result:?}"
                );
                assert_eq!(state_of(&db, &msg_id), from, "rejected edge mutated state");
            }
        }
    }

    // Transitions on an unknown msg_id fail closed.
    assert!(mark_transmitted(&db, &[9u8; 16]).is_err());
    assert!(mark_acknowledged(&db, &[9u8; 16]).is_err());
}

#[test]
fn delivery_fail_expired_path_moves_queued_and_transmitted_to_failed() {
    let (db, clock) = fresh_db();

    // Queued → Failed via the outbox delivery horizon.
    let queued = insert_row(&db, Direction::Out, DeliveryState::Queued);
    db.enqueue(&queued, REL, b"rec-q", 100).unwrap();
    // Transmitted → Failed: write completed but the row is still queued
    // (e.g. requeued by resync) when the horizon passes.
    let transmitted = insert_row(&db, Direction::Out, DeliveryState::Queued);
    db.enqueue(&transmitted, REL, b"rec-t", 100).unwrap();
    mark_transmitted(&db, &transmitted).unwrap();

    clock.advance(101);
    let report = Sync::new(&db).sweep_expired().unwrap();
    assert_eq!(report.outbox_failed, 2);
    assert_eq!(state_of(&db, &queued), DeliveryState::Failed);
    assert_eq!(state_of(&db, &transmitted), DeliveryState::Failed);
    assert_eq!(db.queued_len().unwrap(), 0);

    // Failed is terminal.
    assert!(matches!(
        mark_transmitted(&db, &queued),
        Err(SyncError::BadTransition { .. })
    ));
    assert!(matches!(
        mark_acknowledged(&db, &transmitted),
        Err(SyncError::BadTransition { .. })
    ));
}

#[test]
fn delivery_requeue_retransmit_is_idempotent() {
    let (db, _clock) = fresh_db();
    let msg_id = insert_row(&db, Direction::Out, DeliveryState::Queued);
    db.enqueue(&msg_id, REL, b"record", MESSAGE_TTL_SECS)
        .unwrap();

    // First drain: Queued → Transmitted, dequeued.
    let outcome = drain(&db, 10, |_, _| Ok(())).unwrap();
    assert_eq!(outcome.transmitted, vec![msg_id]);
    assert_eq!(state_of(&db, &msg_id), DeliveryState::Transmitted);
    assert_eq!(db.queued_len().unwrap(), 0);

    // Resync requeue: identical bytes back in the queue (I11).
    db.requeue(&msg_id, REL, b"record", MESSAGE_TTL_SECS)
        .unwrap();
    assert_eq!(db.queued_len().unwrap(), 1);

    // Second drain: Transmitted → Transmitted, no error, no regression.
    let outcome = drain(&db, 10, |_, record| {
        assert_eq!(record, b"record", "requeue must hold identical bytes");
        Ok(())
    })
    .unwrap();
    assert_eq!(outcome.transmitted, vec![msg_id]);
    assert_eq!(state_of(&db, &msg_id), DeliveryState::Transmitted);
}

// ---------------------------------------------------------------------------
// Message lifecycle + session state machine (paired instances)
// ---------------------------------------------------------------------------

struct Instance {
    db: Db,
    transport: Arc<Transport>,
    clock: FakeClock,
    _tmp: tempfile::TempDir,
}

impl Instance {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let clock = FakeClock::new(T0);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        Self {
            db,
            transport,
            clock,
            _tmp: tmp,
        }
    }
}

fn pending_service_id(db: &Db) -> String {
    db.conn()
        .query_row(
            "SELECT service_id FROM pending_pairing WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// offer → accept → intro frame → request → accept (see
/// `src/pairing/tests.rs` for the same ceremony on crate-private API).
async fn pair_up(inviter: &Instance, accepter: &Instance) -> String {
    let now = SystemTime::now();
    let offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    let accepted = accept(
        accepter.db.conn(),
        &accepter.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .unwrap();
    let row = load_relationship(accepter.db.conn(), &accepted.rel_id)
        .unwrap()
        .unwrap();
    let frame = session::encrypt(accepter.db.conn(), &accepted.rel_id, "intro", b"hi", now)
        .await
        .unwrap();
    let record = wire_frame::build_record(&frame).unwrap();
    let packed = framing::pack(Some(&row.our_qr_bytes), &record, true).unwrap();
    let mut slice: &[u8] = &packed;
    let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
    let service_id = pending_service_id(&inviter.db);
    let outcome = ingest_frame(
        inviter.db.conn(),
        &inviter.transport,
        &service_id,
        opaque.intro.as_deref(),
        &opaque.frame,
        now,
    )
    .await
    .unwrap();
    let rel_id = match outcome {
        Ingest::RequestReceived { rel_id, .. } => rel_id,
        other => panic!("expected RequestReceived, got {other:?}"),
    };
    accept_request(inviter.db.conn(), &inviter.transport, &rel_id)
        .await
        .unwrap();
    rel_id
}

/// Encrypt + ledger + queue an outbound text on `db`; return
/// (msg_id, record, plaintext).
async fn queue_text(db: &Db, rel_id: &str, body: &str) -> ([u8; 16], Vec<u8>, Vec<u8>) {
    let now = db.clock().now_secs();
    let seq = db.next_out_seq(rel_id).unwrap();
    let msg_id = rand::random::<[u8; 16]>();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at: now,
        ref_id: None,
        payload: Payload::Msg(Msg::new(body.into()).unwrap()),
    };
    let plaintext = env.encode().unwrap();
    let frame = session::encrypt(
        db.conn(),
        rel_id,
        &hex_encode(&msg_id),
        &plaintext,
        SystemTime::now(),
    )
    .await
    .unwrap();
    let record = wire_frame::build_record(&frame).unwrap();
    db.insert_message(&NewMessage {
        msg_id,
        rel_id: rel_id.into(),
        direction: Direction::Out,
        app_seq: seq,
        sent_at: now,
        received_at: None,
        env_type: env.envelope_type().code(),
        ref_id: None,
        payload: env.payload.encode().unwrap(),
        state: DeliveryState::Queued,
        expires_at: Some(now + MESSAGE_TTL_SECS),
    })
    .unwrap();
    db.enqueue(&msg_id, rel_id, &record, MESSAGE_TTL_SECS)
        .unwrap();
    (msg_id, record, plaintext)
}

/// Deliver a record through the full inbound path (transport ingest →
/// engine dispatch). Returns the engine events of the first (accepted)
/// delivery.
async fn deliver(engine: &mut Engine, rel_id: &str, record: &[u8]) -> (Ingest, Vec<EngineEvent>) {
    let service_id = load_relationship(engine.db.conn(), rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let outcome = ingest_frame(
        engine.db.conn(),
        &engine.transport,
        &service_id,
        None,
        record,
        SystemTime::now(),
    )
    .await
    .unwrap();
    match &outcome {
        Ingest::Message { plaintext, .. } => {
            let events = engine.handle_plaintext(rel_id, plaintext).await.unwrap();
            (outcome, events)
        }
        _ => (outcome, Vec::new()),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn erased_rows_never_return() {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let rel_id = pair_up(&inviter, &accepter).await;
    let clock = inviter.clock.clone();
    let mut engine = Engine::new(inviter.db, inviter.transport);

    // m1 lands on the inviter.
    let (m1, record1, plaintext1) = queue_text(&accepter.db, &rel_id, "m1").await;
    let (outcome, events) = deliver(&mut engine, &rel_id, &record1).await;
    assert!(matches!(outcome, Ingest::Message { .. }));
    assert_eq!(events.len(), 1);
    assert!(engine.db.message(&m1).unwrap().is_some());

    // TTL passes; the sweeper erases the row.
    clock.advance(MESSAGE_TTL_SECS + 1);
    engine.sweep().await.unwrap();
    assert!(engine.db.message(&m1).unwrap().is_none(), "not swept");

    // No ERASED → * edge:
    // - late duplicate delivery of the same frame: session-layer
    //   duplicate, no plaintext, no row;
    let (outcome, events) = deliver(&mut engine, &rel_id, &record1).await;
    assert!(matches!(outcome, Ingest::Duplicate));
    assert!(events.is_empty());
    assert!(
        engine.db.message(&m1).unwrap().is_none(),
        "resurrected by redelivery"
    );
    // - a replayed plaintext (decrypt oracle): dedup by app_seq, no row;
    let events = engine.handle_plaintext(&rel_id, &plaintext1).await.unwrap();
    assert!(events.is_empty(), "replayed plaintext produced events");
    assert!(engine.db.message(&m1).unwrap().is_none());
    // - store-level operations all no-op on the gone row;
    assert!(!engine.db.mark_tombstoned(&m1).unwrap());
    assert!(!engine.db.mark_edited(&m1, b"x", 99).unwrap());
    assert!(!engine.db.set_delivery(&m1, DeliveryState::Failed).unwrap());
    assert!(!engine.db.delete_message(&m1).unwrap());
    // - a resync request covering its seq retransmits nothing: the
    //   receiver's view still covers the seq (inbound_seqs persists),
    //   and the sender's row is swept too.
    // Advance both clocks together so later messages stay skew-honest.
    accepter.clock.advance(MESSAGE_TTL_SECS + 1);
    clock.advance(MESSAGE_TTL_SECS + 1);
    Sync::new(&accepter.db).sweep_expired().unwrap();
    let req = build_request(&engine.db, &rel_id).unwrap();
    let retransmits = handle_request(&accepter.db, &rel_id, &req).unwrap();
    assert!(retransmits.is_empty(), "erased message retransmitted");

    // erase_history path: m2 lands, then the thread is wiped.
    let (m2, record2, plaintext2) = queue_text(&accepter.db, &rel_id, "m2").await;
    let (outcome, _) = deliver(&mut engine, &rel_id, &record2).await;
    assert!(matches!(outcome, Ingest::Message { .. }));
    assert!(engine.db.message(&m2).unwrap().is_some());
    let erased = engine.db.erase_history(&rel_id, &[]).unwrap();
    assert!(erased >= 1);
    assert!(engine.db.message(&m2).unwrap().is_none());
    // Late duplicate after erase_history: dedup by seq, no resurrection.
    let events = engine.handle_plaintext(&rel_id, &plaintext2).await.unwrap();
    assert!(events.is_empty());
    assert!(engine.db.message(&m2).unwrap().is_none());
    let (outcome, _) = deliver(&mut engine, &rel_id, &record2).await;
    assert!(matches!(outcome, Ingest::Duplicate));
    assert!(engine.db.message(&m2).unwrap().is_none());

    // Tombstone application: a tombstoned msg_id is dropped without a
    // ledger row, but its seq is still noted (continuity).
    let tomb_id = rand::random::<[u8; 16]>();
    engine.db.add_tombstone(&rel_id, &tomb_id).unwrap();
    let seq = accepter.db.next_out_seq(&rel_id).unwrap();
    let env = Envelope {
        msg_id: tomb_id,
        app_seq: seq,
        sent_at: accepter.db.clock().now_secs(),
        ref_id: None,
        payload: Payload::Msg(Msg::new("zombie".into()).unwrap()),
    };
    let plaintext = env.encode().unwrap();
    let frame = session::encrypt(
        accepter.db.conn(),
        &rel_id,
        &hex_encode(&tomb_id),
        &plaintext,
        SystemTime::now(),
    )
    .await
    .unwrap();
    let record = wire_frame::build_record(&frame).unwrap();
    let (outcome, events) = deliver(&mut engine, &rel_id, &record).await;
    assert!(matches!(outcome, Ingest::Message { .. }));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, EngineEvent::Message { .. })),
        "tombstoned message produced a Message event"
    );
    assert!(engine.db.message(&tomb_id).unwrap().is_none());
    assert!(engine.db.has_inbound_seq(&rel_id, seq).unwrap());
}

#[tokio::test(flavor = "current_thread")]
async fn session_state_machine_active_broken_terminal() {
    let inviter = Instance::new();
    let accepter = Instance::new();

    // None: no relationship, no session.
    assert_eq!(
        session::session_state(inviter.db.conn(), "no-such-rel").unwrap(),
        SessionState::None
    );
    let nope = session::encrypt(
        inviter.db.conn(),
        "no-such-rel",
        "m",
        b"x",
        SystemTime::now(),
    )
    .await;
    assert!(matches!(nope, Err(SessionError::NoSession)));

    let rel_id = pair_up(&inviter, &accepter).await;
    assert_eq!(
        session::session_state(inviter.db.conn(), &rel_id).unwrap(),
        SessionState::Active
    );
    assert_eq!(
        session::session_state(accepter.db.conn(), &rel_id).unwrap(),
        SessionState::Active
    );

    // Active: the accepter can send (the mock transport has no daemon,
    // so the frame stays queued — the send itself is accepted).
    let mut acc_engine = Engine::new(accepter.db, accepter.transport);
    acc_engine
        .send_text(&rel_id, "while active", None)
        .await
        .unwrap();

    // Active → Broken on crypto failure (tampered ciphertext MAC).
    let mut frame = session::encrypt(inviter.db.conn(), &rel_id, "m2", b"hi", SystemTime::now())
        .await
        .unwrap();
    let n = frame.len();
    frame[n - 2] ^= 0x01;
    let record = wire_frame::build_record(&frame).unwrap();
    let service_id = load_relationship(acc_engine.db.conn(), &rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let outcome = ingest_frame(
        acc_engine.db.conn(),
        &acc_engine.transport,
        &service_id,
        None,
        &record,
        SystemTime::now(),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, Ingest::SessionBroken { .. }));
    assert_eq!(
        session::session_state(acc_engine.db.conn(), &rel_id).unwrap(),
        SessionState::Broken
    );

    // Broken refuses decrypt AND encrypt.
    let dec = session::decrypt(acc_engine.db.conn(), &rel_id, &frame, SystemTime::now()).await;
    assert!(matches!(dec, Err(SessionError::Broken(_))));
    let enc = session::encrypt(acc_engine.db.conn(), &rel_id, "m3", b"x", SystemTime::now()).await;
    assert!(matches!(enc, Err(SessionError::Broken(_))));

    // The engine refuses to send while Broken.
    let send = acc_engine.send_text(&rel_id, "while broken", None).await;
    assert!(
        matches!(send, Err(EngineError::SessionBroken)),
        "send_text while broken: {send:?}"
    );

    // No path back to Active without re-pair: a further valid frame
    // from the peer is refused, the state stays Broken, and
    // re-accepting the (already active) relationship is rejected.
    let valid = session::encrypt(
        inviter.db.conn(),
        &rel_id,
        "m4",
        b"still there?",
        SystemTime::now(),
    )
    .await
    .unwrap();
    let record = wire_frame::build_record(&valid).unwrap();
    let outcome = ingest_frame(
        acc_engine.db.conn(),
        &acc_engine.transport,
        &service_id,
        None,
        &record,
        SystemTime::now(),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, Ingest::SessionBroken { .. }));
    assert_eq!(
        session::session_state(acc_engine.db.conn(), &rel_id).unwrap(),
        SessionState::Broken
    );
    let reaccept = accept_request(acc_engine.db.conn(), &acc_engine.transport, &rel_id).await;
    assert!(matches!(reaccept, Err(PairingFailure::NotARequest)));
}
