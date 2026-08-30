//! Sync reliability harness.
//!
//! Mock-transport + `FakeClock` only: instances are paired in memory (the
//! `schat_core::engine::tests` / `schat_core::sync::tests` pattern), frames
//! move through a lossy link the test controls, and the 24h TTL runs in
//! milliseconds. **No Chutney, no `SCHAT_CHUTNEY_NODES`, no tor binary.**
//!
//! Tests:
//! - `resync_correctness_at_scale` — 5 pairs, scripted offline windows
//!   (5m/1h/12h/23h), resync converges every queued message to
//!   `Acknowledged` with exactly-once receiver ledgers; then a 25h window:
//!   TTL erasure is final, redelivery never resurrects, and the sender's
//!   row surfaces `Failed`, never `Acknowledged`.
//! - `bitmap_edge_cases` — receive-window boundary seqs, seq 0/1, partial
//!   bitmaps, duplicate `RESYNC_REQ`, concurrent resync from both sides.
//! - `case_a_vs_case_b` — resync works while the session is Active; once
//!   Broken (tampered MAC), encrypt/decrypt/send all refuse and outbound
//!   rows surface `Failed`.
//! - `outbox_idempotency` — double mark_transmitted/mark_acknowledged,
//!   Transmitted→Transmitted requeue, byte-identical retransmits, and a
//!   flaky-sink drain that cannot spin.
//!
//! FIXED GAPS (found by this harness, fixed at the root cause; the tests
//! now assert the fixed behavior):
//! 1. `sync::resync::build_request`/`handle_request` were ledger-pure and
//!    never checked `session_state` — they now refuse on a Broken
//!    relationship, defense in depth behind the session-layer gates
//!    (`case_a_vs_case_b`).
//! 2. `Engine::fail_outbound` had **no callers** — `session::mark_broken`
//!    now fails the relationship's outbound queue as part of the break,
//!    so queued rows surface `Failed` at break time, not at the 24h TTL
//!    (`case_a_vs_case_b`).
//! 4. The I11 `message_ciphertexts` cache was append-only — the TTL sweep
//!    and `erase_history` now reclaim ciphertexts with their ledger rows,
//!    so "cryptographic erasure" covers the ciphertext
//!    (`resync_correctness_at_scale`).
//! 6. Replaying an *ancient* frame — one whose receiver chain libsignal
//!    has discarded — was classified `Broken`, a one-packet DoS via
//!    captured ciphertext. A TTL-bounded inbound frame-hash cache now
//!    drops byte-identical replays as `Duplicate` before crypto; past the
//!    horizon the same replay still fails closed
//!    (`ancient_replay_drops_before_crypto`).
//!
//! PINNED GAPS (assertions encode *current* behavior with loud comments):
//! 3. A *first* delivery that arrives past the 24h TTL is accepted by the
//!    production ingest path (skew only rejects far-future `sent_at`) and
//!    gets a fresh 24h lease from the receiver's clock — the sender shows
//!    `Failed` + erased while the receiver renders the message
//!    (`resync_correctness_at_scale`).
//! 5. `mark_acknowledged` twice fails closed (`BadTransition`) rather than
//!    being a no-op; the no-regression property holds either way and the
//!    path is unreachable in production (`unacked_outbound` filters
//!    queued/transmitted) (`outbox_idempotency`).

use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::OptionalExtension;
use schat_core::engine::{Engine, EngineError};
use schat_core::pairing::{self, Ingest};
use schat_core::session::{self, SessionError, SessionState};
use schat_core::store::clock::FakeClock;
use schat_core::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use schat_core::store::outbox::OutboxRepository;
use schat_core::store::{hex_encode, Db};
use schat_core::sync::outbox::{backoff, drain, mark_acknowledged, mark_transmitted};
use schat_core::sync::resync::{build_request, handle_request, is_missing, BITMAP_BITS};
use schat_core::sync::{ingest_envelope, IngestOutcome, Sync, SyncError, MESSAGE_TTL_SECS};
use schat_core::transport::Transport;
use schat_core::wire::frame as wire_frame;
use schat_core::wire_types::caps;
use schat_core::wire_types::envelope::{Envelope, EnvelopeType};
use schat_core::wire_types::resync::ResyncReq;

const T0: u64 = 1_700_000_000;
const REL: &str = "rel";

// ---------------------------------------------------------------------------
// Harness: one node = engine + in-memory store on a FakeClock (no tor).
// ---------------------------------------------------------------------------

struct Node {
    engine: Engine,
    clock: FakeClock,
    _tmp: tempfile::TempDir,
}

impl Node {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let clock = FakeClock::new(T0);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        Self {
            engine: Engine::new(db, transport),
            clock,
            _tmp: tmp,
        }
    }

    fn advance(&self, secs: u64) {
        self.clock.advance(secs);
    }

    /// The node's fake clock as a `SystemTime` — everything the session
    /// layer timestamps (incl. the replay cache's expiry) must agree with
    /// the store's clock or TTL sweeps diverge from insertion times.
    fn now(&self) -> SystemTime {
        use schat_core::store::clock::Clock;
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(self.clock.now_secs())
    }

    fn state(&self, msg_id: &[u8; 16]) -> DeliveryState {
        self.engine
            .db
            .message(msg_id)
            .unwrap()
            .unwrap_or_else(|| panic!("row {}", hex_encode(msg_id)))
            .state
    }

    fn session(&self, rel_id: &str) -> SessionState {
        session::session_state(self.engine.db.conn(), rel_id).unwrap()
    }

    /// Ledger rows whose payload is exactly `body` (MSG envelopes carry
    /// raw UTF-8 bodies).
    fn body_count(&self, rel_id: &str, body: &str) -> usize {
        self.engine
            .db
            .thread(rel_id, 500, None)
            .unwrap()
            .into_iter()
            .filter(|r| r.env_type == EnvelopeType::Msg.code() && r.payload == body.as_bytes())
            .count()
    }
}

/// The service a frame to `to` arrives at: the relationship's service, or
/// — before the peer has the relationship — the pending invitation. The
/// pending row is read straight from the store (`pairing::load_pending`
/// is `#[cfg(test)] pub(crate)` inside the core crate).
fn peer_service(to: &Node, rel_id: &str) -> Option<String> {
    if let Some(rel) = pairing::load_relationship(to.engine.db.conn(), rel_id).unwrap() {
        return Some(rel.service_id);
    }
    to.engine
        .db
        .conn()
        .query_row(
            "SELECT service_id FROM pending_pairing WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .optional()
        .unwrap()
}

/// What became of a record delivered through the production inbound route
/// (`pairing::ingest_frame` → `Engine::handle_plaintext`).
#[derive(Debug)]
enum Delivery {
    Stored,
    Duplicate,
    SessionBroken,
    Dropped,
}

async fn deliver_record(from: &Node, to: &mut Node, rel_id: &str, record: &[u8]) -> Delivery {
    let intro = pairing::load_relationship(from.engine.db.conn(), rel_id)
        .unwrap()
        .and_then(|r| r.intro_pending.then(|| r.our_qr_bytes.clone()));
    let service_id = peer_service(to, rel_id).expect("peer service");
    let outcome = pairing::ingest_frame(
        to.engine.db.conn(),
        &to.engine.transport,
        &service_id,
        intro.as_deref(),
        record,
        to.now(),
    )
    .await
    .unwrap();
    match outcome {
        Ingest::RequestReceived { plaintext, .. } | Ingest::Message { plaintext, .. } => {
            to.engine
                .handle_plaintext(rel_id, &plaintext)
                .await
                .unwrap();
            Delivery::Stored
        }
        Ingest::Duplicate => Delivery::Duplicate,
        Ingest::SessionBroken { .. } => Delivery::SessionBroken,
        Ingest::Dropped => Delivery::Dropped,
    }
}

/// Raw receive path (`schat_core::sync::tests` style): decrypt + ledger,
/// no engine dispatch — the test drives resync explicitly.
async fn deliver_record_raw(to: &Node, rel_id: &str, record: &[u8]) -> IngestOutcome {
    let frame = wire_frame::parse_record(record).unwrap();
    let plaintext = session::decrypt(to.engine.db.conn(), rel_id, frame, to.now())
        .await
        .unwrap();
    let env = Envelope::decode(&plaintext).unwrap();
    ingest_envelope(&to.engine.db, rel_id, &env).unwrap()
}

/// Socket-write honesty: once the test decides a frame went out, the row
/// leaves the outbox and the message is `Transmitted` — whether the frame
/// is then delivered, held, or blackholed is the link's business.
fn note_socket_write(from: &Node, msg_id: &[u8; 16]) {
    from.engine.db.dequeue(msg_id).unwrap();
    mark_transmitted(&from.engine.db, msg_id).unwrap();
}

/// Deliver every due record from → to through the engine path.
async fn pump(from: &Node, to: &mut Node, rel_id: &str) -> usize {
    let rows = from.engine.db.due(64).unwrap();
    let mut n = 0;
    for row in rows.into_iter().filter(|r| r.rel_id == rel_id) {
        deliver_record(from, to, rel_id, &row.record).await;
        note_socket_write(from, &row.msg_id);
        n += 1;
    }
    n
}

/// Pump both directions until nothing moves (cap 40 rounds).
async fn quiesce(a: &mut Node, b: &mut Node, rel_id: &str) {
    for _ in 0..40 {
        let na = pump(&*a, b, rel_id).await;
        let nb = pump(&*b, a, rel_id).await;
        if na == 0 && nb == 0 {
            return;
        }
    }
    panic!("pair did not quiesce");
}

/// One explicit resync round: `requester`'s receive view → `responder`'s
/// outbox verdicts (covered rows acked in place); retransmits delivered
/// back through the engine path. Returns the retransmit count.
async fn resync_round(requester: &mut Node, responder: &mut Node, rel_id: &str) -> usize {
    let req = build_request(&requester.engine.db, rel_id).unwrap();
    let retransmits = handle_request(&responder.engine.db, rel_id, &req).unwrap();
    let n = retransmits.len();
    for rt in retransmits {
        let record = wire_frame::build_record(&rt.frame).unwrap();
        deliver_record(responder, requester, rel_id, &record).await;
    }
    n
}

/// offer → accept → intro message → request accepted → activation bursts
/// settled. Both sides Active, outboxes empty.
async fn pair_up() -> (Node, Node, String) {
    let mut inviter = Node::new();
    let mut accepter = Node::new();
    let now = SystemTime::now();

    let offer = pairing::offer(inviter.engine.db.conn(), &inviter.engine.transport, now)
        .await
        .unwrap();
    let accepted = pairing::accept(
        accepter.engine.db.conn(),
        &accepter.engine.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .unwrap();
    let rel_id = accepted.rel_id.clone();

    accepter
        .engine
        .send_text(&rel_id, "hi, add me?", None)
        .await
        .unwrap();
    pump(&accepter, &mut inviter, &rel_id).await;
    inviter.engine.accept_request(&rel_id).await.unwrap();
    quiesce(&mut inviter, &mut accepter, &rel_id).await;

    for (node, who) in [(&inviter, "inviter"), (&accepter, "accepter")] {
        let rel = pairing::load_relationship(node.engine.db.conn(), &rel_id)
            .unwrap()
            .unwrap();
        assert_eq!(rel.state, "active", "{who} relationship active");
        assert_eq!(node.session(&rel_id), SessionState::Active, "{who} session");
    }
    (inviter, accepter, rel_id)
}

/// Insert one outbound ledger row on a bare store (no pairing needed for
/// the outbox/bitmap unit tests).
fn insert_out(db: &Db, rel_id: &str, seq: u64, state: DeliveryState) -> [u8; 16] {
    let mut msg_id = [0xABu8; 16];
    msg_id[..8].copy_from_slice(&seq.to_be_bytes());
    let now = db.clock().now_secs();
    db.insert_message(&NewMessage {
        msg_id,
        rel_id: rel_id.into(),
        direction: Direction::Out,
        app_seq: seq,
        sent_at: now,
        received_at: None,
        env_type: EnvelopeType::Msg.code(),
        ref_id: None,
        payload: format!("m{seq}").into_bytes(),
        state,
        expires_at: Some(now + MESSAGE_TTL_SECS),
    })
    .unwrap();
    msg_id
}

fn bare_db() -> (Db, FakeClock) {
    let clock = FakeClock::new(T0);
    let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
    (db, clock)
}

/// Take the due outbox row for `msg_id` (the record is the wire image).
fn due_record(node: &Node, msg_id: &[u8; 16]) -> Vec<u8> {
    node.engine
        .db
        .due(64)
        .unwrap()
        .into_iter()
        .find(|r| &r.msg_id == msg_id)
        .unwrap_or_else(|| panic!("{} queued", hex_encode(msg_id)))
        .record
}

// ---------------------------------------------------------------------------
// Resync correctness at scale.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resync_correctness_at_scale() {
    const WINDOWS: [u64; 4] = [5 * 60, 3600, 12 * 3600, 23 * 3600];

    for pair in 0..5u32 {
        let (mut sender, mut receiver, rel_id) = pair_up().await;
        // A frame the receiver already processed, kept for the
        // redelivery-after-erasure check below.
        let mut processed_frame: Option<Vec<u8>> = None;

        for (w, window) in WINDOWS.iter().enumerate() {
            // Four messages queued while the link is down.
            let mut ids = Vec::new();
            let mut bodies = Vec::new();
            for i in 0..4 {
                let body = format!("pair{pair}-win{w}-msg{i}");
                ids.push(sender.engine.send_text(&rel_id, &body, None).await.unwrap());
                bodies.push(body);
            }

            // The lossy link: every socket write "succeeds" (the row is
            // Transmitted) but the frames are held; every third is
            // blackholed outright — the case resync exists for.
            let mut held = Vec::new();
            for row in sender.engine.db.due(64).unwrap() {
                if row.rel_id != rel_id {
                    continue;
                }
                note_socket_write(&sender, &row.msg_id);
                held.push(row.record);
            }
            assert_eq!(held.len(), 4, "window {w}: four frames on the link");

            // The offline window passes on both FakeClocks.
            sender.advance(*window);
            receiver.advance(*window);

            for (i, rec) in held.iter().enumerate() {
                if i % 3 == 2 {
                    continue; // blackholed
                }
                // Keep the latest processed frame: at redelivery time it
                // must sit within libsignal's retained-chain window (an
                // *ancient* replay breaks the session instead of dropping
                // as a duplicate — see `ancient_replay_drops_before_crypto`).
                processed_frame = Some(rec.clone());
                assert!(
                    matches!(
                        deliver_record(&sender, &mut receiver, &rel_id, rec).await,
                        Delivery::Stored
                    ),
                    "window {w}: held frame {i} delivered"
                );
            }

            // The production loop converges: the gap fires a (throttled)
            // RESYNC_REQ, the sender retransmits from its I11 cache.
            quiesce(&mut sender, &mut receiver, &rel_id).await;
            assert_eq!(
                resync_round(&mut receiver, &mut sender, &rel_id).await,
                0,
                "window {w}: nothing left to retransmit"
            );

            // Every queued message is Acknowledged on the sender and
            // exactly-once on the receiver.
            for (id, body) in ids.iter().zip(&bodies) {
                assert_eq!(
                    sender.state(id),
                    DeliveryState::Acknowledged,
                    "window {w}: {body} acknowledged"
                );
                assert_eq!(
                    receiver.body_count(&rel_id, body),
                    1,
                    "window {w}: {body} exactly once"
                );
            }
        }

        // --- 25h window: past the 24h TTL, erasure is final. ---
        let doomed_body = format!("pair{pair}-doomed");
        let doomed = sender
            .engine
            .send_text(&rel_id, &doomed_body, None)
            .await
            .unwrap();
        // The link never completes the write: the row stays queued. Keep
        // the wire image as "the late frame".
        let late_record = due_record(&sender, &doomed);

        sender.advance(25 * 3600);
        receiver.advance(25 * 3600);

        // The sweep's first half (fail_expired + set_delivery) made
        // observable here: the outbox row surfaces Failed — never
        // Acknowledged — before the erasure half deletes the row.
        let expired = sender.engine.db.fail_expired().unwrap();
        assert!(
            expired.iter().any(|r| r.msg_id == doomed),
            "doomed row past its delivery horizon"
        );
        for row in &expired {
            sender
                .engine
                .db
                .set_delivery(&row.msg_id, DeliveryState::Failed)
                .unwrap();
        }
        assert_eq!(
            sender.state(&doomed),
            DeliveryState::Failed,
            "the sender's row is Failed, not Acknowledged"
        );
        let report = Sync::new(&sender.engine.db).sweep_expired().unwrap();
        assert!(report.messages_erased > 0, "TTL sweep erased rows");
        assert!(
            sender.engine.db.message(&doomed).unwrap().is_none(),
            "expired row cryptographically erased (secure_delete)"
        );
        // Fixed (was pinned finding 4): the sweep now reclaims the I11
        // cache with the ledger — the doomed message's frame bytes die
        // with its row, so "cryptographic erasure" covers the ciphertext.
        assert!(
            session::stored_ciphertext(sender.engine.db.conn(), &rel_id, &hex_encode(&doomed))
                .unwrap()
                .is_none(),
            "I11 ciphertext is swept with its ledger row"
        );

        // The sender can never resurrect it: a resync view that is missing
        // the doomed seq produces no retransmit for it (the ledger row —
        // and with it the retransmission candidate — is gone).
        let req = build_request(&receiver.engine.db, &rel_id).unwrap();
        let retransmits = handle_request(&sender.engine.db, &rel_id, &req).unwrap();
        assert!(
            retransmits.iter().all(|rt| rt.msg_id != doomed),
            "erased rows are never retransmitted"
        );

        // The receiver's copies are erased on schedule too.
        let report = Sync::new(&receiver.engine.db).sweep_expired().unwrap();
        assert!(report.messages_erased > 0);
        assert_eq!(receiver.body_count(&rel_id, &doomed_body), 0);

        // Redelivery of an already-processed frame after erasure: dropped
        // as a duplicate at the session layer (the ratchet remembers);
        // the ledger row is NOT recreated. The frame is from the last
        // window — inside the retained-chain window, where duplicate
        // detection actually works.
        let redup = processed_frame.expect("captured a processed frame");
        let rows_before = receiver.engine.db.thread(&rel_id, 500, None).unwrap().len();
        let redup_outcome = deliver_record(&sender, &mut receiver, &rel_id, &redup).await;
        assert!(
            matches!(redup_outcome, Delivery::Duplicate),
            "redelivery outcome: {redup_outcome:?}"
        );
        assert_eq!(
            receiver.engine.db.thread(&rel_id, 500, None).unwrap().len(),
            rows_before,
            "erased rows are never resurrected by redelivery"
        );

        // PINNED GAP (report finding): a *first* delivery 25h late — held
        // by the link, never processed — is still accepted by the
        // production ingest path. There is no past-age gate (skew rejects
        // only far-future sent_at) and the receiver grants a fresh 24h
        // lease from its own clock, so the sender shows Failed + erased
        // while the receiver renders the message. The "never
        // resurrected" rule covers re-delivery of erased rows (asserted above);
        // this late-first-delivery case is unhandled.
        assert!(matches!(
            deliver_record(&sender, &mut receiver, &rel_id, &late_record).await,
            Delivery::Stored
        ));
        assert_eq!(
            receiver.body_count(&rel_id, &doomed_body),
            1,
            "PINNED: late first delivery past the TTL is stored (flagged)"
        );
    }
}

// ---------------------------------------------------------------------------
// Bitmap edge cases.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bitmap_edge_cases() {
    // (a) Seq exactly at the window boundaries. BITMAP_BITS = 4096: the
    // window above the contiguous horizon is offsets 0..=4095, i.e. seqs
    // max+1 ..= max+4096.
    let full = vec![0xFFu8; BITMAP_BITS as usize / 8];
    let m = 100u64;
    assert!(!is_missing(m, &full, m), "at the horizon: covered");
    assert!(!is_missing(m, &full, m + 1), "first window bit");
    assert!(!is_missing(m, &full, m + 4095), "offset 4094");
    assert!(
        !is_missing(m, &full, m + 4096),
        "offset 4095: last in-window bit (the edge)"
    );
    assert!(
        is_missing(m, &full, m + 4097),
        "PINNED: offset 4096 == BITMAP_BITS is outside the window → treated missing"
    );
    assert!(
        is_missing(m, &[], m + 1),
        "empty bitmap: everything missing"
    );
    assert!(is_missing(m, &[], m + 4096));

    // (b) Seq 0/1 edge. Seq 0 is invalid by construction — always
    // "missing" so it can never be acked by a view.
    assert!(is_missing(0, &[], 0));
    assert!(is_missing(m, &full, 0), "seq 0 is never coverable");
    // PINNED: seq 1 against an empty view (max=0, no bitmap) is missing —
    // a peer with an empty ledger asks for everything from seq 1 up.
    assert!(is_missing(0, &[], 1));
    assert!(!is_missing(1, &[], 1), "seq 1 at the horizon is covered");
    assert!(!is_missing(m, &[], 1), "seq 1 below the horizon is covered");

    // (c) Partial peer bitmap: only the bytes up to the last set bit are
    // on the wire (receive_view truncates). Anything beyond the present
    // bytes is missing.
    let partial = [0b0000_0001u8]; // max=10, only seq 11 covered
    assert!(!is_missing(10, &partial, 11));
    assert!(is_missing(10, &partial, 12), "unset bit in a present byte");
    assert!(is_missing(10, &partial, 18), "last bit of the present byte");
    assert!(is_missing(10, &partial, 19), "first byte absent → missing");
    assert!(is_missing(10, &partial, 100), "beyond the present bytes");

    // (c') handle_request against a partial bitmap, bare store: rows at or
    // below the horizon ack via the view; missing rows with no I11 frame
    // cached are skipped (logged), neither acked nor failed.
    let (db, _clock) = bare_db();
    let mut ids = Vec::new();
    for seq in 1..=6u64 {
        ids.push(insert_out(&db, REL, seq, DeliveryState::Transmitted));
    }
    let req = ResyncReq {
        max_contiguous_seq: 2,
        received_seq_bitmap: vec![0b0000_0010], // covers seq 4 only
        caps: caps::LOCAL,
        history_hash: [0u8; 32],
    };
    let retransmits = handle_request(&db, REL, &req).unwrap();
    assert!(
        retransmits.is_empty(),
        "no I11 cache on a bare store → missing rows skipped, loudly logged"
    );
    for (i, id) in ids.iter().enumerate() {
        let seq = i as u64 + 1;
        let expect = match seq {
            1 | 2 | 4 => DeliveryState::Acknowledged, // covered by the view
            _ => DeliveryState::Transmitted,          // missing, skipped
        };
        assert_eq!(db.message(id).unwrap().unwrap().state, expect, "seq {seq}");
    }

    // (d) Duplicate RESYNC_REQ delivered twice: no double-apply, no extra
    // retransmit of already-acked rows, session unaffected.
    let (mut a, b, rel_id) = pair_up().await;
    let mut mids = Vec::new();
    for body in ["dup-1", "dup-2", "dup-3"] {
        mids.push(a.engine.send_text(&rel_id, body, None).await.unwrap());
    }
    // m1/m2 delivered raw, m3 blackholed.
    for (i, id) in mids.iter().enumerate() {
        let record = due_record(&a, id);
        note_socket_write(&a, id);
        if i < 2 {
            assert_eq!(
                deliver_record_raw(&b, &rel_id, &record).await,
                IngestOutcome::Stored { opens_gap: false }
            );
        }
    }
    let req = build_request(&b.engine.db, &rel_id).unwrap();
    let rt1 = handle_request(&a.engine.db, &rel_id, &req).unwrap();
    assert_eq!(rt1.len(), 1, "only the blackholed m3 is missing");
    assert_eq!(rt1[0].msg_id, mids[2]);
    assert_eq!(a.state(&mids[0]), DeliveryState::Acknowledged);
    assert_eq!(a.state(&mids[1]), DeliveryState::Acknowledged);

    // The SAME request again (Tor retransmit of the RESYNC_REQ):
    let rt2 = handle_request(&a.engine.db, &rel_id, &req).unwrap();
    assert_eq!(
        rt2.len(),
        1,
        "the still-unacked missing row is retransmitted again…"
    );
    assert_eq!(
        rt2[0].frame, rt1[0].frame,
        "…byte-identical (I11), and no already-acked row is retransmitted"
    );
    assert_eq!(a.state(&mids[0]), DeliveryState::Acknowledged, "no churn");
    assert_eq!(a.state(&mids[1]), DeliveryState::Acknowledged, "no churn");

    // Deliver the retransmit; the next view settles everything.
    let record = wire_frame::build_record(&rt1[0].frame).unwrap();
    assert_eq!(
        deliver_record_raw(&b, &rel_id, &record).await,
        IngestOutcome::Stored { opens_gap: false }
    );
    let req = build_request(&b.engine.db, &rel_id).unwrap();
    let rt3 = handle_request(&a.engine.db, &rel_id, &req).unwrap();
    assert!(rt3.is_empty(), "converged: nothing left to retransmit");
    assert_eq!(a.state(&mids[2]), DeliveryState::Acknowledged);

    // Session unaffected by the duplicate handling: a fresh message
    // round-trips.
    let alive = a
        .engine
        .send_text(&rel_id, "still alive", None)
        .await
        .unwrap();
    let record = due_record(&a, &alive);
    note_socket_write(&a, &alive);
    assert_eq!(
        deliver_record_raw(&b, &rel_id, &record).await,
        IngestOutcome::Stored { opens_gap: false }
    );
    assert_eq!(b.body_count(&rel_id, "still alive"), 1);
    assert_eq!(a.session(&rel_id), SessionState::Active);
    assert_eq!(b.session(&rel_id), SessionState::Active);

    // (e) Concurrent resync from both sides: each peer's RESYNC_REQ is
    // built before either handles the other's; the handling interleaves.
    let (a2, b2, rel_id2) = pair_up().await;
    let mut a2 = a2;
    let mut b2 = b2;
    let a_msgs = [
        a2.engine
            .send_text(&rel_id2, "a→b one", None)
            .await
            .unwrap(),
        a2.engine
            .send_text(&rel_id2, "a→b two", None)
            .await
            .unwrap(),
    ];
    let b_msgs = [
        b2.engine
            .send_text(&rel_id2, "b→a one", None)
            .await
            .unwrap(),
        b2.engine
            .send_text(&rel_id2, "b→a two", None)
            .await
            .unwrap(),
    ];
    // a→b: first delivered, second blackholed. b→a: first blackholed,
    // second delivered (so both sides have a gap to repair).
    for (i, id) in a_msgs.iter().enumerate() {
        let record = due_record(&a2, id);
        note_socket_write(&a2, id);
        if i == 0 {
            deliver_record_raw(&b2, &rel_id2, &record).await;
        }
    }
    for (i, id) in b_msgs.iter().enumerate() {
        let record = due_record(&b2, id);
        note_socket_write(&b2, id);
        if i == 1 {
            let outcome = deliver_record_raw(&a2, &rel_id2, &record).await;
            assert_eq!(
                outcome,
                IngestOutcome::Stored { opens_gap: true },
                "a's ledger opens a gap on b's second seq"
            );
        }
    }

    // Simultaneous snapshots, then interleaved handling.
    let req_from_a = build_request(&a2.engine.db, &rel_id2).unwrap();
    let req_from_b = build_request(&b2.engine.db, &rel_id2).unwrap();
    let rt_from_a = handle_request(&a2.engine.db, &rel_id2, &req_from_b).unwrap();
    let rt_from_b = handle_request(&b2.engine.db, &rel_id2, &req_from_a).unwrap();
    assert_eq!(rt_from_a.len(), 1, "a resends what b missed");
    assert_eq!(rt_from_a[0].msg_id, a_msgs[1]);
    assert_eq!(rt_from_b.len(), 1, "b resends what a missed");
    assert_eq!(rt_from_b[0].msg_id, b_msgs[0]);
    // The crossed views already acked the delivered halves.
    assert_eq!(a2.state(&a_msgs[0]), DeliveryState::Acknowledged);
    assert_eq!(b2.state(&b_msgs[1]), DeliveryState::Acknowledged);

    // Retransmits land; a final crossed round converges both sides.
    for rt in rt_from_a {
        let record = wire_frame::build_record(&rt.frame).unwrap();
        deliver_record_raw(&b2, &rel_id2, &record).await;
    }
    for rt in rt_from_b {
        let record = wire_frame::build_record(&rt.frame).unwrap();
        deliver_record_raw(&a2, &rel_id2, &record).await;
    }
    let req = build_request(&a2.engine.db, &rel_id2).unwrap();
    assert!(handle_request(&b2.engine.db, &rel_id2, &req)
        .unwrap()
        .is_empty());
    let req = build_request(&b2.engine.db, &rel_id2).unwrap();
    assert!(handle_request(&a2.engine.db, &rel_id2, &req)
        .unwrap()
        .is_empty());
    for id in a_msgs.iter().chain(b_msgs.iter()) {
        let node = if a_msgs.contains(id) { &a2 } else { &b2 };
        assert_eq!(node.state(id), DeliveryState::Acknowledged);
    }
    for body in ["a→b one", "a→b two"] {
        assert_eq!(b2.body_count(&rel_id2, body), 1, "{body} exactly once");
    }
    for body in ["b→a one", "b→a two"] {
        assert_eq!(a2.body_count(&rel_id2, body), 1, "{body} exactly once");
    }
    // No session break from the concurrent handling.
    assert_eq!(a2.session(&rel_id2), SessionState::Active);
    assert_eq!(b2.session(&rel_id2), SessionState::Active);
}

// ---------------------------------------------------------------------------
// Case A (session active) vs Case B (session broken).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn case_a_vs_case_b() {
    let (a, mut b, rel_id) = pair_up().await;
    let mut a = a;

    // (a) Case A: while the session is Active the resync path works.
    assert_eq!(a.session(&rel_id), SessionState::Active);
    assert_eq!(b.session(&rel_id), SessionState::Active);
    let m1 = a
        .engine
        .send_text(&rel_id, "case-a one", None)
        .await
        .unwrap();
    let m2 = a
        .engine
        .send_text(&rel_id, "case-a two", None)
        .await
        .unwrap();
    let rec1 = due_record(&a, &m1);
    note_socket_write(&a, &m1);
    deliver_record_raw(&b, &rel_id, &rec1).await;
    note_socket_write(&a, &m2); // blackholed: written to the socket, frame lost
    let req = build_request(&b.engine.db, &rel_id).unwrap();
    let rt = handle_request(&a.engine.db, &rel_id, &req).unwrap();
    assert_eq!(rt.len(), 1, "Case A: the gap is repairable");
    let record = wire_frame::build_record(&rt[0].frame).unwrap();
    deliver_record_raw(&b, &rel_id, &record).await;
    let req = build_request(&b.engine.db, &rel_id).unwrap();
    assert!(handle_request(&a.engine.db, &rel_id, &req)
        .unwrap()
        .is_empty());
    assert_eq!(a.state(&m1), DeliveryState::Acknowledged);
    assert_eq!(a.state(&m2), DeliveryState::Acknowledged);
    assert_eq!(b.body_count(&rel_id, "case-a two"), 1);

    // (b) Break the session: a tampered ciphertext (MAC region) fails
    // authentication at b → SessionState::Broken via classify_signal_error.
    let out_id = b
        .engine
        .send_text(&rel_id, "never leaving", None)
        .await
        .unwrap();
    let m3 = a
        .engine
        .send_text(&rel_id, "booby-trapped", None)
        .await
        .unwrap();
    let rec3 = due_record(&a, &m3);
    note_socket_write(&a, &m3);
    let mut frame3 = wire_frame::parse_record(&rec3).unwrap().to_vec();
    let n = frame3.len();
    frame3[n - 2] ^= 0x01; // the MAC region
    let tampered = wire_frame::build_record(&frame3).unwrap();
    assert!(matches!(
        deliver_record(&a, &mut b, &rel_id, &tampered).await,
        Delivery::SessionBroken
    ));
    assert_eq!(
        b.session(&rel_id),
        SessionState::Broken,
        "MAC failure breaks b"
    );
    assert_eq!(
        a.session(&rel_id),
        SessionState::Active,
        "the break is asymmetric: a still thinks the session is healthy"
    );

    // No RESYNC_REQ can be BUILT ON THE WIRE for the broken relationship:
    // the send path refuses before any crypto runs.
    assert!(matches!(
        b.engine.send_text(&rel_id, "nope", None).await,
        Err(EngineError::SessionBroken)
    ));
    assert!(
        matches!(
            session::encrypt(
                b.engine.db.conn(),
                &rel_id,
                "resync-attempt",
                b"x",
                SystemTime::now()
            )
            .await,
            Err(SessionError::Broken(_))
        ),
        "encrypt refuses → no RESYNC_REQ can be sent"
    );
    // And none can be HONORED: a fresh, valid frame from a is refused at
    // the state gate before crypto.
    let m4 = a
        .engine
        .send_text(&rel_id, "still healthy here", None)
        .await
        .unwrap();
    let rec4 = due_record(&a, &m4);
    note_socket_write(&a, &m4);
    assert!(matches!(
        deliver_record(&a, &mut b, &rel_id, &rec4).await,
        Delivery::SessionBroken
    ));
    assert!(
        matches!(
            session::decrypt(
                b.engine.db.conn(),
                &rel_id,
                wire_frame::parse_record(&rec4).unwrap(),
                SystemTime::now()
            )
            .await,
            Err(SessionError::Broken(_))
        ),
        "decrypt refuses → a peer's RESYNC_REQ can never be handled"
    );

    // Fixed (was pinned finding 1): the sync layer now enforces Case B
    // itself — both entry points refuse on a Broken relationship,
    // defense in depth behind the session-layer gates.
    assert!(
        matches!(
            build_request(&b.engine.db, &rel_id),
            Err(SyncError::Session(SessionError::Broken(_)))
        ),
        "build_request refuses on a broken relationship"
    );
    let req_from_a = build_request(&a.engine.db, &rel_id).unwrap();
    assert!(
        matches!(
            handle_request(&b.engine.db, &rel_id, &req_from_a),
            Err(SyncError::Session(SessionError::Broken(_)))
        ),
        "handle_request refuses on a broken relationship"
    );

    // (c) Outbound rows for the broken relationship surface Failed —
    // at break time now (was pinned finding 2: `fail_outbound` had no
    // callers). `mark_broken` fails the relationship's queue as part of
    // the state transition.
    assert_eq!(
        b.state(&out_id),
        DeliveryState::Failed,
        "the break itself fails outbound rows"
    );
    let failed = b.engine.fail_outbound(&rel_id).unwrap();
    assert_eq!(failed, 0, "the hook stays public and idempotent");
    assert!(
        b.engine
            .db
            .due(64)
            .unwrap()
            .iter()
            .all(|r| r.rel_id != rel_id),
        "the broken relationship's outbox is cleared"
    );

    // (d) encrypt/decrypt both refuse while Broken (asserted above); the
    // sender's side is untouched — its writes to the broken peer stay
    // Transmitted, never acked (the peer cannot answer).
    assert_eq!(a.state(&m4), DeliveryState::Transmitted);
}

/// Fixed (was pinned finding 6): libsignal only retains a bounded window
/// of receiver chains, and replaying a frame from a discarded chain used
/// to classify as `Broken` — a captured-and-replayed frame was a
/// one-packet DoS. The session layer now keeps a TTL-bounded cache of
/// decrypted inbound frame hashes: a byte-identical replay drops as
/// `Duplicate` BEFORE libsignal is consulted, inside and outside the
/// retained-chain window. Past the cache horizon (swept with the ledger,
/// I5) the same replay is indistinguishable from an attack and still
/// fails closed (`Broken`).
#[tokio::test]
async fn ancient_replay_drops_before_crypto() {
    let (a, mut b, rel_id) = pair_up().await;
    let mut a = a;

    // Six in-order messages a → b on one chain.
    let mut recs = Vec::new();
    for i in 0..6 {
        let id = a
            .engine
            .send_text(&rel_id, &format!("replay-{i}"), None)
            .await
            .unwrap();
        let rec = due_record(&a, &id);
        note_socket_write(&a, &id);
        deliver_record_raw(&b, &rel_id, &rec).await;
        recs.push(rec);
    }

    // Inside the retained window: every replay drops as a duplicate.
    for rec in &recs {
        assert!(matches!(
            deliver_record(&a, &mut b, &rel_id, rec).await,
            Delivery::Duplicate
        ));
    }
    assert_eq!(b.session(&rel_id), SessionState::Active);

    // Push the first chain out of the retention window: five direction
    // alternations (each a DH ratchet step).
    for round in 0..5 {
        let bm = b
            .engine
            .send_text(&rel_id, &format!("b turn {round}"), None)
            .await
            .unwrap();
        let br = due_record(&b, &bm);
        note_socket_write(&b, &bm);
        deliver_record_raw(&a, &rel_id, &br).await;
        let am = a
            .engine
            .send_text(&rel_id, &format!("a turn {round}"), None)
            .await
            .unwrap();
        let ar = due_record(&a, &am);
        note_socket_write(&a, &am);
        deliver_record_raw(&b, &rel_id, &ar).await;
    }
    assert_eq!(b.session(&rel_id), SessionState::Active);

    // Replaying the ancient frame now drops as a duplicate at the
    // replay cache — the discarded chain is never consulted.
    assert!(matches!(
        deliver_record(&a, &mut b, &rel_id, &recs[0]).await,
        Delivery::Duplicate
    ));
    assert_eq!(
        b.session(&rel_id),
        SessionState::Active,
        "an ancient replay inside the cache horizon leaves the session up"
    );

    // Past the retention horizon the cache row is swept with the ledger
    // (I5); the same replay is then indistinguishable from an attack and
    // fails closed.
    b.advance(MESSAGE_TTL_SECS + 3600);
    Sync::new(&b.engine.db).sweep_expired().unwrap();
    assert!(matches!(
        deliver_record(&a, &mut b, &rel_id, &recs[0]).await,
        Delivery::SessionBroken
    ));
    assert_eq!(
        b.session(&rel_id),
        SessionState::Broken,
        "a replay past the cache horizon fails closed"
    );
}

// ---------------------------------------------------------------------------
// Outbox idempotency.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn outbox_idempotency() {
    // (a) mark_transmitted / mark_acknowledged called twice.
    let (db, _clock) = bare_db();
    let id = insert_out(&db, REL, 1, DeliveryState::Queued);
    mark_transmitted(&db, &id).unwrap();
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Transmitted
    );
    mark_transmitted(&db, &id).unwrap();
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Transmitted,
        "Transmitted→Transmitted is a legal no-op (requeue drain)"
    );
    mark_acknowledged(&db, &id).unwrap();
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Acknowledged
    );
    // PINNED (report finding 5): a second mark_acknowledged FAILS CLOSED
    // with BadTransition — it is not a no-op. The property that matters
    // holds either way: no state regression (Acknowledged stays
    // Acknowledged). Unreachable in production: handle_request only acks
    // rows in queued/transmitted (unacked_outbound's filter).
    assert!(
        matches!(
            mark_acknowledged(&db, &id),
            Err(SyncError::BadTransition {
                from: DeliveryState::Acknowledged,
                to: DeliveryState::Acknowledged
            })
        ),
        "PINNED: double-ack fails closed rather than no-opping"
    );
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Acknowledged,
        "no state regression on the refused transition"
    );
    // Acknowledged is terminal: it cannot slide backwards either.
    assert!(matches!(
        mark_transmitted(&db, &id),
        Err(SyncError::BadTransition { .. })
    ));
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Acknowledged
    );

    // (b) Transmitted→Transmitted via requeue is legal and idempotent.
    let id = insert_out(&db, REL, 2, DeliveryState::Queued);
    db.enqueue(&id, REL, b"record-two", MESSAGE_TTL_SECS)
        .unwrap();
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let outcome = drain(&db, 10, |_, rec| {
        sent.push(rec.to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(outcome.transmitted, vec![id]);
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Transmitted
    );
    // The resync path requeues the same bytes under the same msg_id…
    db.requeue(&id, REL, b"record-two", MESSAGE_TTL_SECS)
        .unwrap();
    let outcome = drain(&db, 10, |_, rec| {
        sent.push(rec.to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(outcome.transmitted, vec![id]);
    assert_eq!(
        db.message(&id).unwrap().unwrap().state,
        DeliveryState::Transmitted,
        "re-draining a requeued row re-marks the same state"
    );
    assert_eq!(sent[0], sent[1], "the requeued record is byte-identical");
    assert_eq!(db.queued_len().unwrap(), 0);

    // (c) Retransmit always sends the byte-identical frame: queue N
    // messages, capture the ciphertexts, then answer a view that is
    // missing all N.
    let (c, _d, rel_id) = pair_up().await;
    let mut c = c;
    let mut captured: Vec<([u8; 16], Vec<u8>)> = Vec::new();
    for body in ["i11-1", "i11-2", "i11-3", "i11-4"] {
        let id = c.engine.send_text(&rel_id, body, None).await.unwrap();
        let record = due_record(&c, &id);
        let frame = wire_frame::parse_record(&record).unwrap().to_vec();
        captured.push((id, frame));
    }
    // A peer view that covers nothing: every outbound seq is missing.
    let req = ResyncReq {
        max_contiguous_seq: 0,
        received_seq_bitmap: Vec::new(),
        caps: caps::LOCAL,
        history_hash: [0u8; 32],
    };
    let retransmits = handle_request(&c.engine.db, &rel_id, &req).unwrap();
    for (id, original) in &captured {
        let rt = retransmits
            .iter()
            .find(|r| r.msg_id == *id)
            .expect("every missing row retransmitted");
        assert_eq!(
            &rt.frame, original,
            "retransmit is bit-for-bit the original"
        );
        let stored = session::stored_ciphertext(c.engine.db.conn(), &rel_id, &hex_encode(id))
            .unwrap()
            .unwrap();
        assert_eq!(rt.frame, stored, "…and exactly the I11 cache's bytes");
    }
    // The general property holds for every retransmit, not just ours.
    for rt in &retransmits {
        let stored =
            session::stored_ciphertext(c.engine.db.conn(), &rel_id, &hex_encode(&rt.msg_id))
                .unwrap()
                .unwrap();
        assert_eq!(rt.frame, stored);
    }

    // (d) Resync-requeued frames do not wedge the drain loop: a sink that
    // fails K times then succeeds; backoff keeps failed rows out of the
    // due set between passes (no busy loop), and the drain completes.
    let (db, clock) = bare_db();
    let mut ids = Vec::new();
    for seq in 1..=3u64 {
        let id = insert_out(&db, REL, seq, DeliveryState::Queued);
        db.enqueue(&id, REL, format!("rec-{seq}").as_bytes(), MESSAGE_TTL_SECS)
            .unwrap();
        ids.push(id);
    }
    // First pass: the link is down; every row defers and backs off.
    let outcome = drain(&db, 10, |_, _| Err(SyncError::Send("link down".into()))).unwrap();
    assert_eq!(outcome.deferred.len(), 3);
    assert!(outcome.transmitted.is_empty());
    assert!(
        db.due(10).unwrap().is_empty(),
        "backoff respected: failed rows leave the due set"
    );
    // An immediate second pass finds nothing to do — no spin.
    let outcome = drain(&db, 10, |_, _| Ok(())).unwrap();
    assert_eq!(outcome, Default::default(), "drain returns after the batch");

    // The resync path requeues the rows (attempts reset, due now)…
    for id in &ids {
        db.requeue(id, REL, b"retransmit", MESSAGE_TTL_SECS)
            .unwrap();
    }
    assert_eq!(db.due(10).unwrap().len(), 3);
    // …and a flaky sink (fails K=2 passes, then succeeds) cannot wedge it.
    for fail_pass in 0..2u32 {
        let outcome = drain(&db, 10, |_, _| Err(SyncError::Send("flaky".into()))).unwrap();
        assert_eq!(outcome.deferred.len(), 3, "pass {fail_pass}: all defer");
        assert!(outcome.transmitted.is_empty());
        assert!(
            db.due(10).unwrap().is_empty(),
            "no busy loop: nothing is due again until the clock moves"
        );
        // Bounded attempts: pass 1 fails at attempts=0 (→ +5s), pass 2 at
        // attempts=1 (→ +15s).
        clock.advance(backoff(fail_pass));
    }
    let outcome = drain(&db, 10, |_, _| Ok(())).unwrap();
    assert_eq!(outcome.transmitted.len(), 3, "the drain completes");
    assert!(outcome.deferred.is_empty());
    for id in &ids {
        assert_eq!(
            db.message(id).unwrap().unwrap().state,
            DeliveryState::Transmitted
        );
    }
    assert_eq!(db.queued_len().unwrap(), 0);
}
