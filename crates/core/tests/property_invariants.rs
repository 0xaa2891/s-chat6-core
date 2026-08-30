//! Property/model-style tests for the
//! protocol invariants I4, I5, I7, I11.
//!
//! Two instances are paired fully in-memory (mock `Transport`, frames
//! handed over through the real wire codec — the same ceremony pattern
//! as `src/pairing/tests.rs` and `src/sync/tests.rs`, expressed here
//! against the public API only).
//!
//! - I4 (relationship isolation): N=4 relationships on one device share
//!   no public value, and a frame encrypted under relationship A fails
//!   closed in relationship B (no cross-talk).
//! - I5 (time): retention is receiver-local; randomized clock schedules
//!   never resurrect erased rows, never let a malicious `sent_at` move
//!   retention past `receiver_now + TTL`, and clock rollback never
//!   un-expires or extends.
//! - I7 (idempotence): k deliveries of one frame have the effect of
//!   one; unknown envelope types drop with the session unaffected.
//! - I11 (immutable retransmission): resync retransmissions are
//!   bit-identical to the first ciphertext; the peer's ledger converges
//!   to exactly the sent set.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use proptest::prelude::*;
use proptest::test_runner::{TestCaseError, TestRunner};
use schat_core::engine::{Engine, EngineEvent};
use schat_core::pairing::relationship::{list_relationships, load_relationship};
use schat_core::pairing::{accept, accept_request, ingest_frame, offer, Ingest};
use schat_core::session::{self, SessionState};
use schat_core::store::clock::{Clock, FakeClock};
use schat_core::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use schat_core::store::outbox::OutboxRepository;
use schat_core::store::{hex_encode, Db};
use schat_core::sync::ingress::{ingest_envelope, IngestOutcome};
use schat_core::sync::outbox::drain;
use schat_core::sync::resync::{build_request, handle_request, BITMAP_BITS};
use schat_core::sync::{Sync, MESSAGE_TTL_SECS};
use schat_core::transport::framing;
use schat_core::transport::Transport;
use schat_core::wire::envelope::decode_envelope;
use schat_core::wire::frame as wire_frame;
use schat_wire_types::envelope::{Envelope, Payload};
use schat_wire_types::msg::Msg;

const T0: u64 = 1_700_000_000;

// ---------------------------------------------------------------------------
// Mock pairing ceremony (public API only)
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

/// The inviter's open-offer service id (the `load_pending` helper used
/// by the in-tree tests is `cfg(test)`-private; the row is public
/// schema).
fn pending_service_id(db: &Db) -> String {
    db.conn()
        .query_row(
            "SELECT service_id FROM pending_pairing WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
}

/// offer → accept → intro frame delivered → request received → accepted.
/// Both sides end up with an active relationship and a live session.
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

fn random_msg_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Build, encrypt, ledger, and queue a text envelope with an explicit
/// `sent_at`. Returns (msg_id, frame, record).
async fn queue_text_at(
    db: &Db,
    rel_id: &str,
    body: &str,
    sent_at: u64,
) -> ([u8; 16], Vec<u8>, Vec<u8>) {
    let seq = db.next_out_seq(rel_id).unwrap();
    let msg_id = random_msg_id();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at,
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
    let now = db.clock().now_secs();
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
    (msg_id, frame, record)
}

async fn queue_text(db: &Db, rel_id: &str, body: &str) -> ([u8; 16], Vec<u8>, Vec<u8>) {
    let now = db.clock().now_secs();
    queue_text_at(db, rel_id, body, now).await
}

/// Simulate the wire: decrypt at the receiver and land the envelope in
/// its ledger (sync-layer ingress).
async fn receive_record(receiver: &Instance, rel_id: &str, record: &[u8]) -> IngestOutcome {
    let frame = wire_frame::parse_record(record).unwrap();
    let plaintext = session::decrypt(receiver.db.conn(), rel_id, frame, SystemTime::now())
        .await
        .unwrap();
    let env = decode_envelope(&plaintext).unwrap();
    ingest_envelope(&receiver.db, rel_id, &env).unwrap()
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    // enable_all: the mock transport binds real loopback listeners.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// I4 — relationship isolation
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn i4_no_shared_public_values_and_no_cross_talk() {
    let inviter = Instance::new();
    let accepters: Vec<Instance> = (0..4).map(|_| Instance::new()).collect();
    let mut rel_ids = Vec::new();
    for accepter in &accepters {
        rel_ids.push(pair_up(&inviter, accepter).await);
    }
    assert_eq!(
        rel_ids.iter().collect::<HashSet<_>>().len(),
        4,
        "relationship ids collide"
    );

    let rels: Vec<_> = rel_ids
        .iter()
        .map(|r| load_relationship(inviter.db.conn(), r).unwrap().unwrap())
        .collect();
    assert_eq!(list_relationships(inviter.db.conn()).unwrap().len(), 4);

    // Our per-relationship identity keypairs (one persona per rel).
    let our_keys: Vec<Vec<u8>> = rel_ids
        .iter()
        .map(|r| {
            inviter
                .db
                .conn()
                .query_row(
                    "SELECT identity_keypair FROM signal_locals WHERE namespace = ?1",
                    [r],
                    |row| row.get(0),
                )
                .unwrap()
        })
        .collect();

    // I4: no public value repeats across relationships on one device.
    for i in 0..4 {
        for j in (i + 1)..4 {
            assert_ne!(rels[i].service_id, rels[j].service_id, "service id repeats");
            assert_ne!(rels[i].onion, rels[j].onion, "onion repeats");
            assert_ne!(rels[i].peer_onion, rels[j].peer_onion, "peer onion repeats");
            assert_ne!(
                rels[i].peer_identity_key, rels[j].peer_identity_key,
                "peer identity key repeats"
            );
            assert_ne!(
                rels[i].our_qr_bytes, rels[j].our_qr_bytes,
                "prekey bundle blob repeats"
            );
            assert_ne!(rels[i].our_nonce, rels[j].our_nonce, "nonce repeats");
            assert_ne!(our_keys[i], our_keys[j], "identity keypair repeats");
        }
    }

    // Every accepter encrypts a frame under its own relationship.
    let now = SystemTime::now();
    let mut frames = Vec::new();
    for (i, accepter) in accepters.iter().enumerate() {
        frames.push(
            session::encrypt(
                accepter.db.conn(),
                &rel_ids[i],
                &format!("x{i}"),
                b"secret",
                now,
            )
            .await
            .unwrap(),
        );
    }
    // Sanity: correctly routed frames decrypt.
    for (i, frame) in frames.iter().enumerate() {
        let pt = session::decrypt(inviter.db.conn(), &rel_ids[i], frame, now)
            .await
            .unwrap();
        assert_eq!(pt, b"secret");
    }
    // Cross-talk: a frame encrypted under relationship A must fail
    // closed under relationship B — at the session layer AND at the
    // ingest routing layer — and must leave no ledger row behind.
    // (Fail-closed here marks the *target* session broken; that is the
    // intended behavior for unauthentic ciphertext, so these checks run
    // last.)
    for (i, frame) in frames.iter().enumerate() {
        for (j, rel) in rels.iter().enumerate() {
            if i == j {
                continue;
            }
            let res = session::decrypt(inviter.db.conn(), &rel_ids[j], frame, now).await;
            assert!(res.is_err(), "frame for rel {i} decrypted under rel {j}");
            let record = wire_frame::build_record(frame).unwrap();
            let outcome = ingest_frame(
                inviter.db.conn(),
                &inviter.transport,
                &rel.service_id,
                None,
                &record,
                now,
            )
            .await
            .unwrap();
            assert!(
                matches!(outcome, Ingest::Dropped | Ingest::SessionBroken { .. }),
                "cross-routed frame accepted: {outcome:?}"
            );
            assert!(
                inviter.db.thread(&rel_ids[j], 10, None).unwrap().is_empty(),
                "cross-talk left a ledger row in rel {j}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// I5 — receiver-local retention under randomized clock schedules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Op {
    /// Advance both clocks by 0..90000s.
    Advance(u64),
    /// Roll both clocks back to T0 + offset (device-time rollback).
    Rollback(u64),
    /// Queue an honest outbound message on the accepter.
    Send,
    /// Deliver the next undelivered frame (in send order).
    Deliver,
    /// Redeliver a random already-delivered frame (duplicate).
    Redeliver(prop::sample::Index),
    /// Run the TTL sweeper on both instances.
    Sweep,
    /// Inbound MSG with a hostile/honest-skew sent_at:
    /// 0 => sent_at 0, 1 => u64::MAX, 2 => now + 10^9, 3 => now + 60.
    Evil(u8),
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u64..=90_000).prop_map(Op::Advance),
        1 => (0u64..=200_000).prop_map(Op::Rollback),
        3 => Just(Op::Send),
        3 => Just(Op::Deliver),
        2 => any::<prop::sample::Index>().prop_map(Op::Redeliver),
        2 => Just(Op::Sweep),
        2 => (0u8..4).prop_map(Op::Evil),
    ]
}

#[test]
fn i5_retention_is_receiver_local() {
    let rt = current_thread_runtime();
    let mut runner = TestRunner::new(ProptestConfig::with_cases(16));
    runner
        .run(&prop::collection::vec(op_strategy(), 16..32), |ops| {
            rt.block_on(run_i5_case(ops))
        })
        .unwrap();
}

async fn run_i5_case(ops: Vec<Op>) -> Result<(), TestCaseError> {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let rel_id = pair_up(&inviter, &accepter).await;

    // Send order is delivery order (libsignal out-of-order windows are
    // exercised by the I11 test; here we keep the model simple).
    let mut sent: Vec<([u8; 16], Vec<u8>)> = Vec::new(); // (msg_id, record)
    let mut next_deliver = 0usize;
    let mut delivered: Vec<([u8; 16], Vec<u8>)> = Vec::new();
    // msg_id → expiry the receiver must hold (stamped at delivery).
    let mut expected_expiry: HashMap<[u8; 16], u64> = HashMap::new();
    let mut erased: HashSet<[u8; 16]> = HashSet::new();

    for op in ops {
        match op {
            Op::Advance(secs) => {
                inviter.clock.advance(secs);
                accepter.clock.advance(secs);
            }
            Op::Rollback(offset) => {
                inviter.clock.set(T0 + offset);
                accepter.clock.set(T0 + offset);
            }
            Op::Send => {
                let body = format!("m{}", sent.len());
                let (msg_id, _frame, record) = queue_text(&accepter.db, &rel_id, &body).await;
                sent.push((msg_id, record));
            }
            Op::Deliver => {
                if let Some((msg_id, record)) = sent.get(next_deliver) {
                    next_deliver += 1;
                    let now = inviter.clock.now_secs();
                    let frame = wire_frame::parse_record(record).unwrap();
                    let plaintext =
                        session::decrypt(inviter.db.conn(), &rel_id, frame, SystemTime::now())
                            .await
                            .unwrap();
                    let env = decode_envelope(&plaintext).unwrap();
                    match ingest_envelope(&inviter.db, &rel_id, &env) {
                        Ok(IngestOutcome::Stored { .. }) => {
                            let row = inviter.db.message(msg_id).unwrap().unwrap();
                            // I5: retention is stamped from the RECEIVER
                            // clock at receipt, never beyond
                            // receiver_now + TTL.
                            prop_assert_eq!(row.expires_at, Some(now + MESSAGE_TTL_SECS));
                            prop_assert!(row.sent_at <= now);
                            expected_expiry.insert(*msg_id, now + MESSAGE_TTL_SECS);
                            delivered.push((*msg_id, record.clone()));
                        }
                        Ok(IngestOutcome::Duplicate) => {
                            panic!("fresh in-order delivery deduped")
                        }
                        Err(schat_core::sync::SyncError::FutureTimestamp { .. }) => {
                            // The receiver clock rolled back past the
                            // sender's sent_at: fail-closed drop, and
                            // nothing may be stored.
                            prop_assert!(inviter.db.message(msg_id).unwrap().is_none());
                        }
                        Err(e) => panic!("unexpected ingest error: {e}"),
                    }
                }
            }
            Op::Redeliver(idx) => {
                if !delivered.is_empty() {
                    let (msg_id, record) = &delivered[idx.index(delivered.len())];
                    let frame = wire_frame::parse_record(record).unwrap();
                    // A re-delivered frame is a session-layer duplicate;
                    // anything else means the ratchet lost state.
                    let dup =
                        session::decrypt(inviter.db.conn(), &rel_id, frame, SystemTime::now())
                            .await;
                    prop_assert!(matches!(dup, Err(session::SessionError::Duplicate)));
                    // Erased rows never return; live rows keep their expiry.
                    let row = inviter.db.message(msg_id).unwrap();
                    if erased.contains(msg_id) {
                        prop_assert!(row.is_none(), "erased row resurrected");
                    } else {
                        prop_assert_eq!(
                            row.unwrap().expires_at,
                            expected_expiry.get(msg_id).copied(),
                            "redelivery moved retention"
                        );
                    }
                }
            }
            Op::Sweep => {
                Sync::new(&inviter.db).sweep_expired().unwrap();
                Sync::new(&accepter.db).sweep_expired().unwrap();
                let now = inviter.clock.now_secs();
                for (msg_id, exp) in &expected_expiry {
                    if *exp <= now {
                        erased.insert(*msg_id);
                    }
                }
            }
            Op::Evil(which) => {
                let now = inviter.clock.now_secs();
                let sent_at = match which {
                    0 => 0,
                    1 => u64::MAX,
                    2 => now.saturating_add(1_000_000_000),
                    _ => now + 60,
                };
                let (msg_id, _frame, record) =
                    queue_text_at(&accepter.db, &rel_id, "evil", sent_at).await;
                let frame = wire_frame::parse_record(&record).unwrap();
                let plaintext =
                    session::decrypt(inviter.db.conn(), &rel_id, frame, SystemTime::now())
                        .await
                        .unwrap();
                let env = decode_envelope(&plaintext).unwrap();
                let result = ingest_envelope(&inviter.db, &rel_id, &env);
                match which {
                    1 | 2 => {
                        // Far-future sent_at: rejected, nothing stored.
                        prop_assert!(result.is_err(), "far-future sent_at accepted");
                        prop_assert!(inviter.db.message(&msg_id).unwrap().is_none());
                    }
                    _ => {
                        prop_assert!(result.is_ok());
                        let row = inviter.db.message(&msg_id).unwrap().unwrap();
                        // Retention comes from the receiver clock.
                        prop_assert_eq!(row.expires_at, Some(now + MESSAGE_TTL_SECS));
                        // sent_at is clamped to at most receiver now.
                        prop_assert!(row.sent_at <= now);
                        if which == 3 {
                            prop_assert_eq!(row.sent_at, now, "near-future not clamped");
                        }
                        expected_expiry.insert(msg_id, now + MESSAGE_TTL_SECS);
                    }
                }
            }
        }

        // Standing assertions after every op:
        // (a) erased rows never return;
        for msg_id in &erased {
            prop_assert!(inviter.db.message(msg_id).unwrap().is_none());
        }
        // (c) rollback never extends retention of live rows.
        for (msg_id, exp) in &expected_expiry {
            if !erased.contains(msg_id) {
                let row = inviter.db.message(msg_id).unwrap().unwrap();
                prop_assert_eq!(row.expires_at, Some(*exp));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// I7 — idempotent delivery + unknown-type drops
// ---------------------------------------------------------------------------

#[test]
fn i7_k_deliveries_have_the_effect_of_one() {
    let rt = current_thread_runtime();
    let mut runner = TestRunner::new(ProptestConfig::with_cases(8));
    runner
        .run(&(1usize..=8), |k| rt.block_on(run_i7_case(k)))
        .unwrap();
}

async fn run_i7_case(k: usize) -> Result<(), TestCaseError> {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let rel_id = pair_up(&inviter, &accepter).await;
    let (msg_id, _frame, record) = queue_text(&accepter.db, &rel_id, "hello i7").await;

    let Instance { db, transport, .. } = inviter;
    let mut engine = Engine::new(db, transport);
    let service_id = load_relationship(engine.db.conn(), &rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let now = SystemTime::now();

    let mut message_events = 0usize;
    for delivery in 0..k {
        let outcome = ingest_frame(
            engine.db.conn(),
            &engine.transport,
            &service_id,
            None,
            &record,
            now,
        )
        .await
        .unwrap();
        match outcome {
            Ingest::Message { plaintext, .. } => {
                prop_assert_eq!(delivery, 0, "frame accepted twice");
                let events = engine.handle_plaintext(&rel_id, &plaintext).await.unwrap();
                let msgs = events
                    .iter()
                    .filter(
                        |e| matches!(e, EngineEvent::Message { msg_id: id, .. } if *id == msg_id),
                    )
                    .count();
                prop_assert_eq!(msgs, 1, "expected exactly one Message event");
                message_events += 1;
            }
            Ingest::Duplicate => {
                prop_assert!(delivery > 0, "first delivery dropped as duplicate");
            }
            other => panic!("unexpected ingest outcome {other:?}"),
        }
    }
    prop_assert_eq!(message_events, 1);
    // Exactly one ledger row; the session is untouched by redelivery.
    prop_assert_eq!(engine.db.thread(&rel_id, 10, None).unwrap().len(), 1);
    prop_assert_eq!(
        session::session_state(engine.db.conn(), &rel_id).unwrap(),
        SessionState::Active
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn i7_unknown_type_drops_with_session_unaffected() {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let rel_id = pair_up(&inviter, &accepter).await;

    // A structurally valid envelope with the unassigned type code 12,
    // encrypted under the live session.
    let mut unknown = vec![12u8];
    unknown.extend_from_slice(&[1u8; 16]);
    unknown.extend_from_slice(&1u64.to_be_bytes()); // app_seq
    unknown.extend_from_slice(&T0.to_be_bytes()); // sent_at
    unknown.push(0);
    unknown.extend_from_slice(&0u32.to_be_bytes());
    let frame = session::encrypt(
        accepter.db.conn(),
        &rel_id,
        "u1",
        &unknown,
        SystemTime::now(),
    )
    .await
    .unwrap();
    let record = wire_frame::build_record(&frame).unwrap();

    let Instance { db, transport, .. } = inviter;
    let mut engine = Engine::new(db, transport);
    let service_id = load_relationship(engine.db.conn(), &rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let now = SystemTime::now();

    let outcome = ingest_frame(
        engine.db.conn(),
        &engine.transport,
        &service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();
    let Ingest::Message { plaintext, .. } = outcome else {
        panic!("expected Message, got {outcome:?}")
    };
    // The envelope layer refuses it; nothing is ledgered.
    let err = engine.handle_plaintext(&rel_id, &plaintext).await;
    assert!(err.is_err(), "unknown type must not be handled");
    assert!(engine.db.thread(&rel_id, 10, None).unwrap().is_empty());
    assert_eq!(
        session::session_state(engine.db.conn(), &rel_id).unwrap(),
        SessionState::Active,
        "unknown type must not touch the session"
    );

    // The session still works: a legit message lands afterwards.
    let (msg_id, _frame, record) = queue_text(&accepter.db, &rel_id, "after unknown").await;
    let outcome = ingest_frame(
        engine.db.conn(),
        &engine.transport,
        &service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();
    let Ingest::Message { plaintext, .. } = outcome else {
        panic!("expected Message, got {outcome:?}")
    };
    let events = engine.handle_plaintext(&rel_id, &plaintext).await.unwrap();
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { msg_id: id, .. } if *id == msg_id)));
}

// ---------------------------------------------------------------------------
// I11 — immutable retransmission + ledger convergence under loss
// ---------------------------------------------------------------------------

#[test]
fn i11_resync_retransmits_bit_identical_and_converges() {
    let rt = current_thread_runtime();
    let mut runner = TestRunner::new(ProptestConfig::with_cases(8));
    let strategy = (1usize..=10, prop::collection::vec(any::<bool>(), 1..=10));
    runner
        .run(&strategy, |(n, loss)| rt.block_on(run_i11_case(n, loss)))
        .unwrap();
}

async fn run_i11_case(n: usize, loss: Vec<bool>) -> Result<(), TestCaseError> {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let rel_id = pair_up(&inviter, &accepter).await;
    let (sender, receiver) = (&accepter, &inviter);

    let mut sent: Vec<([u8; 16], Vec<u8>)> = Vec::new(); // (msg_id, frame)
    let mut first_ciphertext: HashMap<[u8; 16], Vec<u8>> = HashMap::new();
    for i in 0..n {
        let (msg_id, frame, _record) = queue_text(&sender.db, &rel_id, &format!("m{i}")).await;
        first_ciphertext.insert(msg_id, frame.clone());
        sent.push((msg_id, frame));
    }

    // Drain: every socket write "succeeds", but `loss` decides which
    // frames the receiver actually sees (blackholed after the write).
    let mut records = Vec::new();
    let outcome = drain(&sender.db, 64, |_, record| {
        records.push(record.to_vec());
        Ok(())
    })
    .unwrap();
    prop_assert_eq!(outcome.transmitted.len(), n);
    for (i, record) in records.iter().enumerate() {
        if !loss[i % loss.len()] {
            receive_record(receiver, &rel_id, record).await;
        }
    }

    // Resync until the receiver's ledger converges.
    for _ in 0..=n {
        let req = build_request(&receiver.db, &rel_id).unwrap();
        let retransmits = handle_request(&sender.db, &rel_id, &req).unwrap();
        if retransmits.is_empty() {
            break;
        }
        for rt in &retransmits {
            // I11: bit-identical to the first ciphertext, and equal to
            // the I11 cache's stored bytes.
            prop_assert_eq!(
                &rt.frame,
                &first_ciphertext[&rt.msg_id],
                "retransmission differs from first ciphertext"
            );
            let stored =
                session::stored_ciphertext(sender.db.conn(), &rel_id, &hex_encode(&rt.msg_id))
                    .unwrap()
                    .unwrap();
            prop_assert_eq!(&rt.frame, &stored);
            let record = wire_frame::build_record(&rt.frame).unwrap();
            receive_record(receiver, &rel_id, &record).await;
        }
    }

    // The peer's ledger converged to exactly the sent set.
    let view = receiver.db.receive_view(&rel_id, BITMAP_BITS).unwrap();
    prop_assert_eq!(view.max_contiguous_seq, n as u64);
    let thread = receiver.db.thread(&rel_id, 100, None).unwrap();
    prop_assert_eq!(thread.len(), n);
    let mut bodies: Vec<String> = thread
        .iter()
        .map(|m| String::from_utf8(m.payload.clone()).unwrap())
        .collect();
    bodies.sort();
    let mut want: Vec<String> = (0..n).map(|i| format!("m{i}")).collect();
    want.sort();
    prop_assert_eq!(bodies, want);

    // A final resync acks everything and retransmits nothing.
    let req = build_request(&receiver.db, &rel_id).unwrap();
    let retransmits = handle_request(&sender.db, &rel_id, &req).unwrap();
    prop_assert!(retransmits.is_empty());
    for (msg_id, _) in &sent {
        prop_assert_eq!(
            sender.db.message(msg_id).unwrap().unwrap().state,
            DeliveryState::Acknowledged
        );
    }
    Ok(())
}
