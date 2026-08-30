//! Evil-peer adversarial harness (mock-transport half — the Chutney
//! scenario lives in `adversarial_testnet.rs`). An "evil peer" is a full
//! instance that paired honestly and then misbehaves by hand-crafting
//! envelopes under its real session (bypassing every outbound gate), plus
//! raw garbage at the record layer. Every scenario asserts the
//! outcome: the attack surface is dropped / deduped / throttled / failed
//! closed, the session state machine stays consistent, and the victim
//! keeps working.
//!
//! Covered:
//! - malformed frames (bad version, bad bucket, garbage ciphertext tag)
//! - replay floods (I7 idempotence)
//! - unknown / forbidden envelope types (I7 drop + counter)
//! - capability violations (gated type never advertised)
//! - RESYNC_REQ and typing/presence floods (rate limits)
//! - attachment chunks out of order, duplicated, and rogue (fail closed)
//! - tampered pairing: bad QR, expired offer, garbage intro frame
//! - identity flip mid-session (TOFU → broken, no auto-reset)
//! - cross-relationship frame delivery (I4: no plaintext leak)

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use libsignal_protocol::{message_encrypt, CiphertextMessage, ProtocolAddress};
use schat_core::attach::AttachmentSpec;
use schat_core::caps;
use schat_core::engine::{Engine, EngineEvent};
use schat_core::pairing::{self, Ingest};
use schat_core::ratelimit::{self, Surface};
use schat_core::session::{self, stores};
use schat_core::store::chunks::ChunksRepository;
use schat_core::store::clock::{Clock, FakeClock};
use schat_core::store::messages::{DeliveryState, MessagesRepository};
use schat_core::store::outbox::{OutboxRepository, OutboxRow};
use schat_core::store::{hex_encode, Db};
use schat_core::transport::{framing, Transport};
use schat_core::wire::envelope::unknown_type_drops;
use schat_core::wire_types::attach::AttachChunk;
use schat_core::wire_types::envelope::{Envelope, Payload};
use schat_core::wire_types::presence::Presence;
use schat_core::wire_types::resync::ResyncReq;
use schat_core::wire_types::typing::Typing;
use schat_core::wire_types::WirePayload;

const T0: u64 = 1_700_000_000;

/// Drop counters are process-global; tests asserting deltas serialize
/// on this async-aware lock.
static COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn counter_lock() -> tokio::sync::MutexGuard<'static, ()> {
    COUNTER_LOCK.lock().await
}

struct Peer {
    engine: Engine,
    clock: Arc<FakeClock>,
    _tmp: tempfile::TempDir,
}

impl Peer {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let clock = Arc::new(FakeClock::new(T0));
        let db = Db::open_in_memory_with_clock(clock.clone()).unwrap();
        Self {
            engine: Engine::new(db, transport),
            clock,
            _tmp: tmp,
        }
    }

    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(self.clock.now_secs())
    }

    fn session_state(&self, rel_id: &str) -> session::SessionState {
        session::session_state(self.engine.db.conn(), rel_id).unwrap()
    }
}

/// The service a frame to `to` arrives at: the relationship's service,
/// or — before the peer has a relationship — the pending invitation.
fn peer_service(to: &Peer, rel_id: &str, offer_service: Option<&str>) -> Option<String> {
    if let Some(rel) = pairing::load_relationship(to.engine.db.conn(), rel_id).unwrap() {
        return Some(rel.service_id);
    }
    offer_service.map(str::to_string)
}

async fn deliver_row(
    from: &Peer,
    to: &mut Peer,
    rel_id: &str,
    row: &OutboxRow,
    offer_service: Option<&str>,
) -> Vec<EngineEvent> {
    let intro = pairing::load_relationship(from.engine.db.conn(), rel_id)
        .unwrap()
        .and_then(|r| r.intro_pending.then(|| r.our_qr_bytes.clone()));
    let service_id = peer_service(to, rel_id, offer_service).expect("peer service");
    let packed = framing::pack(intro.as_deref(), &row.record, false).unwrap();
    let mut slice: &[u8] = &packed;
    let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
    let outcome = pairing::ingest_frame(
        to.engine.db.conn(),
        &to.engine.transport,
        &service_id,
        opaque.intro.as_deref(),
        &opaque.frame,
        to.now(),
    )
    .await
    .unwrap();
    from.engine.db.dequeue(&row.msg_id).unwrap();
    from.engine
        .db
        .set_delivery(&row.msg_id, DeliveryState::Transmitted)
        .unwrap();
    let plaintext = match outcome {
        Ingest::RequestReceived { plaintext, .. } | Ingest::Message { plaintext, .. } => plaintext,
        Ingest::Duplicate | Ingest::Dropped => return Vec::new(),
        other => panic!("unexpected ingest {other:?}"),
    };
    to.engine
        .handle_plaintext(rel_id, &plaintext)
        .await
        .unwrap()
}

async fn pump(
    from: &mut Peer,
    to: &mut Peer,
    rel_id: &str,
    offer_service: Option<&str>,
) -> Vec<EngineEvent> {
    let rows = from.engine.db.due(64).unwrap();
    let mut events = Vec::new();
    for row in rows {
        if row.rel_id != rel_id {
            continue;
        }
        if peer_service(to, rel_id, offer_service).is_none() {
            break;
        }
        events.extend(deliver_row(from, to, rel_id, &row, offer_service).await);
    }
    events
}

async fn quiesce(a: &mut Peer, b: &mut Peer, rel_id: &str) {
    for _ in 0..20 {
        pump(a, b, rel_id, None).await;
        pump(b, a, rel_id, None).await;
        if a.engine.db.due(64).unwrap().is_empty() && b.engine.db.due(64).unwrap().is_empty() {
            break;
        }
    }
}

/// Full pairing ceremony; returns both peers, the rel_id, and the
/// inviter's QR bytes (the identity-flip test reuses the bundle).
async fn pair_up() -> (Peer, Peer, String, Vec<u8>) {
    let mut inviter = Peer::new();
    let mut accepter = Peer::new();
    let now = inviter.now();

    let offer = pairing::offer(inviter.engine.db.conn(), &inviter.engine.transport, now)
        .await
        .unwrap();
    let qr_bytes = offer.qr_bytes.clone();
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
        .send_text(&rel_id, "hi", None)
        .await
        .unwrap();
    pump(
        &mut accepter,
        &mut inviter,
        &rel_id,
        Some(&offer.service_id),
    )
    .await;
    inviter.engine.accept_request(&rel_id).await.unwrap();
    quiesce(&mut inviter, &mut accepter, &rel_id).await;
    assert_eq!(
        inviter.session_state(&rel_id),
        session::SessionState::Active
    );
    assert_eq!(
        accepter.session_state(&rel_id),
        session::SessionState::Active
    );
    (inviter, accepter, rel_id, qr_bytes)
}

// ---------------------------------------------------------------------------
// Evil craft primitives: hand-built envelopes encrypted under the evil
// peer's real session, bypassing every outbound gate (caps, policy,
// rate limits). This is what a modified client can do.
// ---------------------------------------------------------------------------

/// Attacker-controlled envelope bytes with a fresh msg_id and the next
/// honest sequence number (so the victim's dedupe never swallows it).
fn craft_envelope(evil: &Peer, rel_id: &str, payload: Payload) -> Vec<u8> {
    let seq = evil.engine.db.next_out_seq(rel_id).unwrap();
    Envelope {
        msg_id: rand::random(),
        app_seq: seq,
        sent_at: evil.clock.now_secs(),
        ref_id: None,
        payload,
    }
    .encode()
    .unwrap()
}

/// An envelope whose type code this build does not know (I7).
fn craft_unknown_envelope(evil: &Peer, rel_id: &str, code: u8) -> Vec<u8> {
    let seq = evil.engine.db.next_out_seq(rel_id).unwrap();
    let mut bytes = vec![code];
    bytes.extend_from_slice(&rand::random::<[u8; 16]>());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(&evil.clock.now_secs().to_be_bytes());
    bytes.push(0); // no ref_id
    bytes.extend_from_slice(&0u32.to_be_bytes()); // empty payload
    bytes
}

/// Encrypt attacker plaintext under the evil peer's session and deliver
/// the record to the victim. Returns (ingest outcome, engine events).
/// `handle_plaintext` errors surface as `Err` in the second slot.
async fn evil_deliver(
    evil: &Peer,
    victim: &mut Peer,
    rel_id: &str,
    plaintext: &[u8],
) -> (
    Ingest,
    Result<Vec<EngineEvent>, schat_core::engine::EngineError>,
) {
    let msg_id: [u8; 16] = rand::random();
    let frame = session::encrypt(
        evil.engine.db.conn(),
        rel_id,
        &hex_encode(&msg_id),
        plaintext,
        evil.now(),
    )
    .await
    .unwrap();
    let record = framing::build_record(&frame).unwrap();
    let service_id = pairing::load_relationship(victim.engine.db.conn(), rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let outcome = pairing::ingest_frame(
        victim.engine.db.conn(),
        &victim.engine.transport,
        &service_id,
        None,
        &record,
        victim.now(),
    )
    .await
    .unwrap();
    let events = match &outcome {
        Ingest::Message { plaintext, .. } => {
            victim.engine.handle_plaintext(rel_id, plaintext).await
        }
        _ => Ok(Vec::new()),
    };
    (outcome, events)
}

/// Raw record delivery straight at the victim's ingest (no crypto).
async fn raw_deliver(victim: &mut Peer, rel_id: &str, record: &[u8]) -> Ingest {
    let service_id = pairing::load_relationship(victim.engine.db.conn(), rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    pairing::ingest_frame(
        victim.engine.db.conn(),
        &victim.engine.transport,
        &service_id,
        None,
        record,
        victim.now(),
    )
    .await
    .unwrap()
}

fn bodies(peer: &Peer, rel_id: &str) -> Vec<String> {
    peer.engine
        .db
        .thread_visible(rel_id, 500, None)
        .unwrap()
        .into_iter()
        .filter(|m| m.env_type == schat_core::wire_types::envelope::EnvelopeType::Msg.code())
        .filter_map(|m| String::from_utf8(m.payload).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// 1. Malformed frames: dropped before crypto, session unaffected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_records_dropped_session_safe() {
    let (mut victim, mut evil, rel_id, _) = pair_up().await;

    // A valid record to mutate.
    let valid_plain = craft_envelope(
        &evil,
        &rel_id,
        Payload::Msg(schat_core::wire_types::msg::Msg::new("ping".into()).unwrap()),
    );
    let msg_id: [u8; 16] = rand::random();
    let frame = session::encrypt(
        evil.engine.db.conn(),
        &rel_id,
        &hex_encode(&msg_id),
        &valid_plain,
        evil.now(),
    )
    .await
    .unwrap();
    let valid = framing::build_record(&frame).unwrap();

    let mut bad_version = valid.clone();
    bad_version[0] = 0x01; // legacy version byte
    let mut truncated = valid.clone();
    truncated.truncate(truncated.len() / 2); // no longer a bucket
    let mut oversized = valid.clone();
    oversized.extend_from_slice(&[0u8; 16]); // not a bucket either
    let empty = Vec::new();
    let short = vec![0u8; 7];
    // Valid record wrapping a frame with an unknown ciphertext tag.
    let mut garbage_frame = vec![0x07u8];
    garbage_frame.extend_from_slice(&[0xABu8; 64]);
    let garbage_tag = framing::build_record(&garbage_frame).unwrap();

    for (name, rec) in [
        ("bad version", bad_version),
        ("truncated", truncated),
        ("oversized", oversized),
        ("empty", empty),
        ("short", short),
        ("garbage tag", garbage_tag),
    ] {
        let outcome = raw_deliver(&mut victim, &rel_id, &rec).await;
        assert!(
            matches!(outcome, Ingest::Dropped),
            "{name}: expected Dropped, got {outcome:?}"
        );
    }

    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);
    // The victim is fully responsive afterwards.
    evil.engine
        .send_text(&rel_id, "still here", None)
        .await
        .unwrap();
    let events = pump(&mut evil, &mut victim, &rel_id, None).await;
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { .. })));
    assert!(bodies(&victim, &rel_id).iter().any(|b| b == "still here"));
}

// ---------------------------------------------------------------------------
// 2. Replay flood: one valid frame delivered 50 times → one effect (I7).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replay_flood_deduped_single_effect() {
    let (mut victim, mut evil, rel_id, _) = pair_up().await;

    evil.engine
        .send_text(&rel_id, "capture me", None)
        .await
        .unwrap();
    let row = evil
        .engine
        .db
        .due(64)
        .unwrap()
        .into_iter()
        .find(|r| r.rel_id == rel_id)
        .unwrap();

    let mut messages = 0;
    let mut duplicates = 0;
    for _ in 0..50 {
        let outcome = raw_deliver(&mut victim, &rel_id, &row.record).await;
        match outcome {
            Ingest::Message { plaintext, .. } => {
                messages += 1;
                victim
                    .engine
                    .handle_plaintext(&rel_id, &plaintext)
                    .await
                    .unwrap();
            }
            Ingest::Duplicate => duplicates += 1,
            other => panic!("replay: unexpected {other:?}"),
        }
    }
    assert_eq!(messages, 1, "exactly one delivery has an effect");
    assert_eq!(duplicates, 49);
    assert_eq!(
        bodies(&victim, &rel_id)
            .iter()
            .filter(|b| *b == "capture me")
            .count(),
        1
    );
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);
}

// ---------------------------------------------------------------------------
// 3. Unknown envelope type: dropped + counted, session unaffected (I7).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unknown_type_dropped_counted_session_safe() {
    let _guard = counter_lock().await;
    let (mut victim, mut evil, rel_id, _) = pair_up().await;
    let before = unknown_type_drops();

    for code in [12u8, 13, 200] {
        // 12/13 and 200 are unassigned codes.
        let plain = craft_unknown_envelope(&evil, &rel_id, code);
        let (outcome, events) = evil_deliver(&evil, &mut victim, &rel_id, &plain).await;
        assert!(matches!(outcome, Ingest::Message { .. }), "decrypts fine");
        let err = events.expect_err("unknown type must be dropped as an error");
        assert!(
            matches!(
                err,
                schat_core::engine::EngineError::Wire(
                    schat_core::wire_types::WireError::UnknownType { .. }
                )
            ),
            "unexpected drop error: {err:?}"
        );
    }
    assert_eq!(unknown_type_drops(), before + 3, "I7 counter moved");
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);

    evil.engine.send_text(&rel_id, "after", None).await.unwrap();
    let events = pump(&mut evil, &mut victim, &rel_id, None).await;
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { .. })));
}

// ---------------------------------------------------------------------------
// 4. Capability violation: a gated type the peer never advertised is
//    dropped; the session and baseline traffic are unaffected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn caps_violation_dropped_session_safe() {
    let _guard = counter_lock().await;
    let mut victim = Peer::new();
    let mut evil = Peer::new();
    let now = victim.now();
    let offer = pairing::offer(victim.engine.db.conn(), &victim.engine.transport, now)
        .await
        .unwrap();
    let accepted = pairing::accept(
        evil.engine.db.conn(),
        &evil.engine.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .unwrap();
    let rel_id = accepted.rel_id.clone();

    // Pair, but the evil peer's activation burst (which advertises its
    // caps via RESYNC_REQ) is never delivered to the victim.
    evil.engine.send_text(&rel_id, "hi", None).await.unwrap();
    pump(&mut evil, &mut victim, &rel_id, Some(&offer.service_id)).await;
    victim.engine.accept_request(&rel_id).await.unwrap();
    assert_eq!(
        caps::peer_caps(victim.engine.db.conn(), &rel_id).unwrap(),
        0,
        "victim has seen no caps advertisement"
    );

    let before = caps::gated_drops();
    let plain = craft_envelope(&evil, &rel_id, Payload::Typing(Typing { typing: true }));
    let (outcome, events) = evil_deliver(&evil, &mut victim, &rel_id, &plain).await;
    assert!(matches!(outcome, Ingest::Message { .. }));
    let events = events.unwrap();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, EngineEvent::Typing { .. })),
        "gated typing must not surface: {events:?}"
    );
    assert_eq!(caps::gated_drops(), before + 1, "caps drop counted");
    // The violation does not teach the victim the cap (no implied grant
    // on a gated drop).
    assert_eq!(
        caps::peer_caps(victim.engine.db.conn(), &rel_id).unwrap(),
        0
    );
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);

    // Baseline traffic still flows.
    evil.engine
        .send_text(&rel_id, "baseline", None)
        .await
        .unwrap();
    let events = pump(&mut evil, &mut victim, &rel_id, None).await;
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { .. })));
}

// ---------------------------------------------------------------------------
// 5. RESYNC_REQ storm: throttled, session safe, victim responsive.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resync_req_storm_victim_responsive() {
    let _guard = counter_lock().await;
    let (mut victim, mut evil, rel_id, _) = pair_up().await;
    // Refill the bucket drained by the pairing activation burst.
    victim.clock.advance(30);
    evil.clock.advance(30);

    let before = ratelimit::limited(Surface::ResyncReq);
    for _ in 0..40 {
        let plain = craft_envelope(
            &evil,
            &rel_id,
            Payload::ResyncReq(ResyncReq {
                max_contiguous_seq: 0,
                received_seq_bitmap: Vec::new(),
                caps: caps::local_caps(),
                history_hash: [0u8; 32],
            }),
        );
        let _ = evil_deliver(&evil, &mut victim, &rel_id, &plain).await;
    }
    let dropped = ratelimit::limited(Surface::ResyncReq) - before;
    assert_eq!(
        dropped,
        40 - u64::from(schat_core::limits::rate::RESYNC_REQ_BURST),
        "only the burst is handled"
    );
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);

    // The victim still answers honest traffic immediately.
    victim
        .engine
        .send_text(&rel_id, "you ok?", None)
        .await
        .unwrap();
    let events = pump(&mut victim, &mut evil, &rel_id, None).await;
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { .. })));
    assert!(bodies(&evil, &rel_id).iter().any(|b| b == "you ok?"));
}

// ---------------------------------------------------------------------------
// 6. Typing/presence flood: throttled; RAM state never grows.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ephemeral_flood_throttled_session_safe() {
    let _guard = counter_lock().await;
    let (mut victim, evil, rel_id, _) = pair_up().await;
    victim.clock.advance(30);
    evil.clock.advance(30);

    let before = ratelimit::limited(Surface::Ephemeral);
    let mut surfaced = 0usize;
    for i in 0..80 {
        let plain = if i % 2 == 0 {
            craft_envelope(
                &evil,
                &rel_id,
                Payload::Typing(Typing { typing: i % 4 == 0 }),
            )
        } else {
            craft_envelope(
                &evil,
                &rel_id,
                Payload::Presence(Presence {
                    in_app: i % 3 == 0,
                    do_not_disturb: false,
                }),
            )
        };
        let (_, events) = evil_deliver(&evil, &mut victim, &rel_id, &plain).await;
        surfaced += events
            .unwrap()
            .iter()
            .filter(|e| matches!(e, EngineEvent::Typing { .. } | EngineEvent::Presence { .. }))
            .count();
    }
    let dropped = ratelimit::limited(Surface::Ephemeral) - before;
    assert_eq!(
        dropped,
        80 - u64::from(schat_core::limits::rate::EPHEMERAL_BURST),
        "only the burst reaches RAM state"
    );
    assert!(
        surfaced <= schat_core::limits::rate::EPHEMERAL_BURST as usize,
        "events bounded by the burst (state no-ops may emit nothing): {surfaced}"
    );
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);
}

// ---------------------------------------------------------------------------
// 7. Attachment chunks out of order + duplicated (orphan path): exact
//    reassembly, one completion.
// ---------------------------------------------------------------------------

/// The chunk index of an outbound ATTACH_CHUNK ledger row.
fn chunk_index(sender: &Peer, msg_id: &[u8; 16]) -> u16 {
    let payload: Vec<u8> = sender
        .engine
        .db
        .conn()
        .query_row(
            "SELECT payload FROM messages WHERE msg_id = ?1",
            [hex_encode(msg_id)],
            |r| r.get(0),
        )
        .unwrap();
    AttachChunk::decode_payload(&payload).unwrap().index
}

fn is_pad(sender: &Peer, msg_id: &[u8; 16]) -> bool {
    let payload: Vec<u8> = sender
        .engine
        .db
        .conn()
        .query_row(
            "SELECT payload FROM messages WHERE msg_id = ?1",
            [hex_encode(msg_id)],
            |r| r.get(0),
        )
        .unwrap();
    AttachChunk::decode_payload(&payload).unwrap().pad
}

#[tokio::test]
async fn attachment_chunks_out_of_order_and_duplicated() {
    let (mut victim, mut evil, rel_id, _) = pair_up().await;
    let bytes: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let spec = AttachmentSpec {
        // Video passes the send path without sniffing/re-encode.
        media_class: schat_core::wire_types::attach::CLASS_VIDEO,
        mime_hint: "video/mp4".into(),
        orig_ext: "mp4".into(),
        bytes: bytes.clone(),
        caption: String::new(),
        view_once: false,
    };
    let head_id = evil.engine.send_attachment(&rel_id, &spec).await.unwrap();

    let rows: Vec<OutboxRow> = evil
        .engine
        .db
        .due(256)
        .unwrap()
        .into_iter()
        .filter(|r| r.rel_id == rel_id)
        .collect();
    let head_row = rows.iter().find(|r| r.msg_id == head_id).unwrap().clone();
    let mut chunks: Vec<&OutboxRow> = rows.iter().filter(|r| r.msg_id != head_id).collect();
    assert!(chunks.len() >= 3, "need a few chunks for reordering");

    // Adversarial order: data chunks reversed (orphans — head not yet
    // sent), one chunk duplicated, pads last, then the head completes.
    chunks.sort_by_key(|r| chunk_index(&evil, &r.msg_id));
    let (data_chunks, pads): (Vec<&OutboxRow>, Vec<&OutboxRow>) =
        chunks.into_iter().partition(|r| !is_pad(&evil, &r.msg_id));
    let mut order: Vec<&OutboxRow> = data_chunks.iter().rev().copied().collect();
    order.push(data_chunks[0]); // duplicate
    order.extend(pads);

    let mut events = Vec::new();
    for row in &order {
        events.extend(deliver_row(&evil, &mut victim, &rel_id, row, None).await);
    }
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, EngineEvent::AttachmentComplete { .. })),
        "no completion before the head"
    );
    events.extend(deliver_row(&evil, &mut victim, &rel_id, &head_row, None).await);

    let completions = events
        .iter()
        .filter(
            |e| matches!(e, EngineEvent::AttachmentComplete { head_id: h, .. } if *h == head_id),
        )
        .count();
    assert_eq!(completions, 1, "exactly one completion: {events:?}");
    let got = victim.engine.attachment_bytes(&head_id).unwrap().unwrap();
    assert_eq!(got, bytes, "byte-exact reassembly through reorder + dupes");
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);
}

// ---------------------------------------------------------------------------
// 8. Rogue chunks: wrong bytes poison nothing (fail closed, loud); an
//    out-of-range index is dropped, never stored.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attachment_rogue_chunks_fail_closed() {
    let (mut victim, mut evil, rel_id, _) = pair_up().await;
    let bytes: Vec<u8> = (0..60_000u32).map(|i| (i % 253) as u8).collect();
    let spec = AttachmentSpec {
        media_class: schat_core::wire_types::attach::CLASS_VIDEO,
        mime_hint: "video/mp4".into(),
        orig_ext: "mp4".into(),
        bytes: bytes.clone(),
        caption: String::new(),
        view_once: false,
    };
    let head_id = evil.engine.send_attachment(&rel_id, &spec).await.unwrap();
    let rows: Vec<OutboxRow> = evil
        .engine
        .db
        .due(256)
        .unwrap()
        .into_iter()
        .filter(|r| r.rel_id == rel_id)
        .collect();
    let head_row = rows.iter().find(|r| r.msg_id == head_id).unwrap().clone();

    // The head lands first (no orphan-cap involvement).
    deliver_row(&evil, &mut victim, &rel_id, &head_row, None).await;

    // (a) Out-of-range index: dropped loudly, never stored.
    let rogue_far = craft_envelope(
        &evil,
        &rel_id,
        Payload::AttachChunk(AttachChunk {
            head_id,
            index: 999,
            pad: false,
            data: vec![0xEE; 1024],
        }),
    );
    let (_, events) = evil_deliver(&evil, &mut victim, &rel_id, &rogue_far).await;
    let events = events.unwrap();
    assert!(
        events.iter().any(
            |e| matches!(e, EngineEvent::AttachmentChunkDropped { head_id: h, .. } if *h == head_id)
        ),
        "out-of-range chunk dropped loudly: {events:?}"
    );
    assert!(
        victim.engine.db.chunk(&head_id, 999).unwrap().is_none(),
        "out-of-range chunk must not be stored"
    );

    // (b) Wrong bytes at a valid index, before the honest chunk: the
    // honest chunk's conflicting write is refused (fail closed), the
    // transfer can never complete with corrupt bytes.
    let rogue_bad = craft_envelope(
        &evil,
        &rel_id,
        Payload::AttachChunk(AttachChunk {
            head_id,
            index: 0,
            pad: false,
            data: vec![0xAA; 128],
        }),
    );
    evil_deliver(&evil, &mut victim, &rel_id, &rogue_bad)
        .await
        .1
        .unwrap();

    let mut completed = false;
    for row in rows.iter().filter(|r| r.msg_id != head_id) {
        let service_id = pairing::load_relationship(victim.engine.db.conn(), &rel_id)
            .unwrap()
            .unwrap()
            .service_id;
        let packed = framing::pack(None, &row.record, false).unwrap();
        let mut slice: &[u8] = &packed;
        let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
        let outcome = pairing::ingest_frame(
            victim.engine.db.conn(),
            &victim.engine.transport,
            &service_id,
            None,
            &opaque.frame,
            victim.now(),
        )
        .await
        .unwrap();
        if let Ingest::Message { plaintext, .. } = outcome {
            // Conflicting chunk writes surface as store errors; the
            // transfer must never complete with corrupt bytes.
            if let Ok(events) = victim.engine.handle_plaintext(&rel_id, &plaintext).await {
                completed |= events
                    .iter()
                    .any(|e| matches!(e, EngineEvent::AttachmentComplete { .. }));
            }
        }
    }
    assert!(!completed, "poisoned transfer must not complete");
    assert!(
        victim.engine.attachment_bytes(&head_id).unwrap().is_none(),
        "corrupt bytes are never served"
    );
    // The session itself is untouched; honest traffic still flows.
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Active);
    evil.engine
        .send_text(&rel_id, "aftermath", None)
        .await
        .unwrap();
    let events = pump(&mut evil, &mut victim, &rel_id, None).await;
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { .. })));
}

// ---------------------------------------------------------------------------
// 9. Tampered pairing: bad QR, expired offer, garbage intro frame — all
//    fail closed with zero partial state; the offer survives attacks.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_pairing_variants_fail_closed() {
    let _guard = counter_lock().await;

    // (a) Tampered QR bytes: accept fails, nothing is written.
    {
        let inviter = Peer::new();
        let evil = Peer::new();
        let offer = pairing::offer(
            inviter.engine.db.conn(),
            &inviter.engine.transport,
            inviter.now(),
        )
        .await
        .unwrap();
        let mut tampered = offer.qr_bytes.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01; // signature region
        let result = pairing::accept(
            evil.engine.db.conn(),
            &evil.engine.transport,
            &tampered,
            evil.now(),
        )
        .await;
        assert!(result.is_err(), "tampered QR must be rejected");
        let rows: i64 = evil
            .engine
            .db
            .conn()
            .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "no partial relationship rows");
        let namespaces: i64 = evil
            .engine
            .db
            .conn()
            .query_row("SELECT COUNT(*) FROM signal_locals", [], |r| r.get(0))
            .unwrap();
        assert_eq!(namespaces, 0, "no persona residue");
    }

    // (b) Expired offer: rejected at decode/verify, nothing written.
    {
        let inviter = Peer::new();
        let evil = Peer::new();
        let offer = pairing::offer(
            inviter.engine.db.conn(),
            &inviter.engine.transport,
            inviter.now(),
        )
        .await
        .unwrap();
        inviter.clock.advance(pairing::qr::OFFER_TTL_SECONDS + 60);
        let result = pairing::accept(
            evil.engine.db.conn(),
            &evil.engine.transport,
            &offer.qr_bytes,
            inviter.now(),
        )
        .await;
        assert!(result.is_err(), "expired offer must be rejected");
        let rows: i64 = evil
            .engine
            .db
            .conn()
            .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0);
    }

    // (c) Garbage at the invitation service: dropped; the offer stays
    // open and an honest accepter still pairs (the fail-open fix).
    {
        let mut inviter = Peer::new();
        let mut honest = Peer::new();
        let offer = pairing::offer(
            inviter.engine.db.conn(),
            &inviter.engine.transport,
            inviter.now(),
        )
        .await
        .unwrap();

        // Frame without an intro at the invitation service.
        let outcome = pairing::ingest_frame(
            inviter.engine.db.conn(),
            &inviter.engine.transport,
            &offer.service_id,
            None,
            &[0u8; 64],
            inviter.now(),
        )
        .await
        .unwrap();
        assert!(matches!(outcome, Ingest::Dropped));

        // The honest accepter pairs; its intro is captured for the
        // garbage-frame attack below.
        let accepted = pairing::accept(
            honest.engine.db.conn(),
            &honest.engine.transport,
            &offer.qr_bytes,
            honest.now(),
        )
        .await
        .unwrap();
        let rel_id = accepted.rel_id.clone();
        let intro = pairing::load_relationship(honest.engine.db.conn(), &rel_id)
            .unwrap()
            .unwrap()
            .our_qr_bytes;

        // A valid intro carrying a garbage (undecryptable) frame: the
        // pairing is NOT created, and — critically — the offer's persona
        // survives (fail closed, not fail open).
        let garbage_record = framing::build_record(&{
            let mut f = vec![schat_core::session::TAG_PREKEY];
            f.extend_from_slice(&[0xCCu8; 200]);
            f
        })
        .unwrap();
        let outcome = pairing::ingest_frame(
            inviter.engine.db.conn(),
            &inviter.engine.transport,
            &offer.service_id,
            Some(&intro),
            &garbage_record,
            inviter.now(),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, Ingest::Dropped),
            "garbage intro frame dropped"
        );
        let rows: i64 = inviter
            .engine
            .db
            .conn()
            .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "no partial relationship from the attack");

        // The honest accepter's real first frame still lands (past the
        // intro throttle interval).
        inviter.clock.advance(5);
        honest.clock.advance(5);
        honest
            .engine
            .send_text(&rel_id, "real intro", None)
            .await
            .unwrap();
        let events = pump(&mut honest, &mut inviter, &rel_id, Some(&offer.service_id)).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, EngineEvent::Message { .. })),
            "honest pairing survives the attack: {events:?}"
        );
        inviter.engine.accept_request(&rel_id).await.unwrap();
        quiesce(&mut inviter, &mut honest, &rel_id).await;
        assert_eq!(
            inviter.session_state(&rel_id),
            session::SessionState::Active
        );
    }
}

// ---------------------------------------------------------------------------
// 10. Identity flip mid-session: TOFU pins the QR-verified identity; a
//     prekey message under a new identity breaks the session (fail
//     closed, no auto-reset).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn identity_flip_breaks_session_fail_closed() {
    let (mut victim, mut evil, rel_id, qr_bytes) = pair_up().await;

    // The evil peer runs a fresh PQXDH against the victim's original
    // bundle under a NEW identity (a scratch namespace), producing a
    // prekey message that presents the flipped identity.
    const SCRATCH: &str = "adversarial-flip";
    let persona = session::generate_persona().unwrap();
    session::store_persona(evil.engine.db.conn(), SCRATCH, &persona)
        .await
        .unwrap();
    let payload = pairing::qr::PairingPayload::decode(&qr_bytes).unwrap();
    session::process_bundle(
        evil.engine.db.conn(),
        SCRATCH,
        &payload.to_bundle().unwrap(),
        evil.now(),
    )
    .await
    .unwrap();
    let mut session_store = stores::SqliteSessionStore {
        db: evil.engine.db.conn(),
        namespace: SCRATCH.into(),
    };
    let mut identity_store = stores::SqliteIdentityStore {
        db: evil.engine.db.conn(),
        namespace: SCRATCH.into(),
    };
    let mut rng = session::csprng();
    let ct = message_encrypt(
        b"hello from my new identity",
        // The sender-side store key; the wire message carries no address
        // binding — the victim derives its own `remote_address(rel_id)`.
        &session::remote_address(SCRATCH).unwrap(),
        &ProtocolAddress::new(format!("self.{SCRATCH}"), 1u32.try_into().unwrap()),
        &mut session_store,
        &mut identity_store,
        evil.now(),
        &mut rng,
    )
    .await
    .unwrap();
    assert!(
        matches!(ct, CiphertextMessage::PreKeySignalMessage(_)),
        "first message under a fresh session is a prekey message"
    );
    let mut frame = vec![session::TAG_PREKEY];
    frame.extend_from_slice(ct.serialize());
    let record = framing::build_record(&frame).unwrap();

    let outcome = raw_deliver(&mut victim, &rel_id, &record).await;
    assert!(
        matches!(outcome, Ingest::SessionBroken { .. }),
        "identity flip breaks the session: {outcome:?}"
    );
    assert_eq!(victim.session_state(&rel_id), session::SessionState::Broken);

    // Fail closed: outbound refuses, further inbound refuses, and
    // nothing auto-resets the session.
    let send_result = victim
        .engine
        .send_text(&rel_id, "anyone there?", None)
        .await;
    assert!(
        matches!(
            send_result,
            Err(schat_core::engine::EngineError::SessionBroken)
        ),
        "broken session refuses outbound: {send_result:?}"
    );
    evil.engine
        .send_text(&rel_id, "honest retry", None)
        .await
        .unwrap();
    let row = evil
        .engine
        .db
        .due(64)
        .unwrap()
        .into_iter()
        .find(|r| r.rel_id == rel_id)
        .unwrap();
    let outcome = raw_deliver(&mut victim, &rel_id, &row.record).await;
    assert!(
        matches!(outcome, Ingest::SessionBroken { .. } | Ingest::Dropped),
        "broken session refuses inbound: {outcome:?}"
    );
    assert!(
        bodies(&victim, &rel_id).iter().all(|b| b != "honest retry"),
        "no plaintext lands after the break"
    );
    assert_eq!(
        victim.session_state(&rel_id),
        session::SessionState::Broken,
        "no auto-reset"
    );
    // The evil side's own session is unaffected (it saw nothing bad).
    assert_eq!(evil.session_state(&rel_id), session::SessionState::Active);
}

// ---------------------------------------------------------------------------
// 11. Cross-relationship delivery (I4): a valid frame from one
//     relationship routed at another relationship's service yields no
//     plaintext and no events; the source relationship is unaffected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_relationship_frame_no_leak() {
    // One victim, two evil peers on separate relationships.
    let (mut victim, mut evil1, rel1, _) = pair_up().await;
    let offer2 = pairing::offer(
        victim.engine.db.conn(),
        &victim.engine.transport,
        victim.now(),
    )
    .await
    .unwrap();
    let mut evil2 = Peer::new();
    let accepted2 = pairing::accept(
        evil2.engine.db.conn(),
        &evil2.engine.transport,
        &offer2.qr_bytes,
        evil2.now(),
    )
    .await
    .unwrap();
    let rel2 = accepted2.rel_id.clone();
    evil2.engine.send_text(&rel2, "hi", None).await.unwrap();
    pump(&mut evil2, &mut victim, &rel2, Some(&offer2.service_id)).await;
    victim.engine.accept_request(&rel2).await.unwrap();
    quiesce(&mut victim, &mut evil2, &rel2).await;

    // A valid frame minted under rel1 is delivered at rel2's service.
    evil1
        .engine
        .send_text(&rel1, "for rel1 only", None)
        .await
        .unwrap();
    let row = evil1
        .engine
        .db
        .due(64)
        .unwrap()
        .into_iter()
        .find(|r| r.rel_id == rel1)
        .unwrap();
    let service2 = pairing::load_relationship(victim.engine.db.conn(), &rel2)
        .unwrap()
        .unwrap()
        .service_id;
    let outcome = pairing::ingest_frame(
        victim.engine.db.conn(),
        &victim.engine.transport,
        &service2,
        None,
        &row.record,
        victim.now(),
    )
    .await
    .unwrap();
    // Undecryptable under rel2's keys: fail closed (a bad-MAC frame
    // breaks the session; reaching this path at all
    // requires the 256-bit service id plus client auth, so it is not
    // attacker-reachable in practice).
    assert!(
        matches!(outcome, Ingest::SessionBroken { .. } | Ingest::Dropped),
        "cross-delivered frame never decrypts: {outcome:?}"
    );
    assert!(
        bodies(&victim, &rel2).iter().all(|b| b != "for rel1 only"),
        "I4: no cross-relationship plaintext leak"
    );

    // rel1 is untouched: the frame still delivers correctly there.
    let outcome = raw_deliver(&mut victim, &rel1, &row.record).await;
    let Ingest::Message { plaintext, .. } = outcome else {
        panic!("rel1 frame must still decrypt: {outcome:?}")
    };
    victim
        .engine
        .handle_plaintext(&rel1, &plaintext)
        .await
        .unwrap();
    assert!(bodies(&victim, &rel1).iter().any(|b| b == "for rel1 only"));
    assert_eq!(victim.session_state(&rel1), session::SessionState::Active);
}
