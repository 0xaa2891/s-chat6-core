//! Rate-limit tests: abuse floods are throttled (counted, logged,
//! session-safe) and a calibrated honest heavy session never trips a
//! limit (`rate_limited() == 0` delta). Mock transport, `FakeClock`
//! driven — the Chutney calibration/flood gate lives in
//! `test-harness/tests/ratelimit_testnet.rs`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use schat_wire_types::envelope::Payload;
use schat_wire_types::typing::Typing;

use super::send::send_envelope;
use super::{Engine, EngineEvent};
use crate::pairing::{self, Ingest};
use crate::ratelimit::{self, Surface};
use crate::store::clock::FakeClock;
use crate::store::messages::{DeliveryState, MessagesRepository};
use crate::store::outbox::{OutboxRepository, OutboxRow};
use crate::store::Db;
use crate::transport::{framing, Transport};

const T0: u64 = 1_700_000_000;

/// The drop counters are process-global; tests asserting deltas must
/// not run concurrently (other suites never exceed honest levels, so
/// only this module's flood tests move the engine-side counters).
static COUNTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
}

fn peer_service(to: &Peer, rel_id: &str) -> Option<String> {
    if let Some(rel) = pairing::load_relationship(to.engine.db.conn(), rel_id).unwrap() {
        return Some(rel.service_id);
    }
    pairing::load_pending(to.engine.db.conn())
        .unwrap()
        .map(|p| p.service_id)
}

async fn deliver_at(
    from: &Peer,
    to: &mut Peer,
    rel_id: &str,
    row: &OutboxRow,
    now: SystemTime,
) -> Vec<EngineEvent> {
    let intro = pairing::load_relationship(from.engine.db.conn(), rel_id)
        .unwrap()
        .and_then(|r| r.intro_pending.then(|| r.our_qr_bytes.clone()));
    let service_id = peer_service(to, rel_id).expect("peer service");
    let packed = framing::pack(intro.as_deref(), &row.record, false).unwrap();
    let mut slice: &[u8] = &packed;
    let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
    let outcome = pairing::ingest_frame(
        to.engine.db.conn(),
        &to.engine.transport,
        &service_id,
        opaque.intro.as_deref(),
        &opaque.frame,
        now,
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
        Ingest::Duplicate => return Vec::new(),
        // Throttled / malformed drops: nothing reaches the engine.
        Ingest::Dropped => return Vec::new(),
        other => panic!("unexpected ingest {other:?}"),
    };
    to.engine
        .handle_plaintext(rel_id, &plaintext)
        .await
        .unwrap()
}

async fn pump(from: &mut Peer, to: &mut Peer, rel_id: &str) -> Vec<EngineEvent> {
    let rows = from.engine.db.due(64).unwrap();
    let mut events = Vec::new();
    for row in rows {
        if row.rel_id != rel_id {
            continue;
        }
        if peer_service(to, rel_id).is_none() {
            break;
        }
        events.extend(deliver_at(from, to, rel_id, &row, SystemTime::now()).await);
    }
    events
}

async fn quiesce(a: &mut Peer, b: &mut Peer, rel_id: &str) {
    for _ in 0..20 {
        let na = pump(a, b, rel_id).await.len();
        let nb = pump(b, a, rel_id).await.len();
        if na == 0 && nb == 0 {
            // pumps return events, not counts; use outbox emptiness.
        }
        let da = a.engine.db.due(64).unwrap();
        let db = b.engine.db.due(64).unwrap();
        if da.is_empty() && db.is_empty() {
            break;
        }
    }
}

async fn pair_up() -> (Peer, Peer, String) {
    let mut inviter = Peer::new();
    let mut accepter = Peer::new();
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
        .send_text(&rel_id, "hi", None)
        .await
        .unwrap();
    pump(&mut accepter, &mut inviter, &rel_id).await;
    inviter.engine.accept_request(&rel_id).await.unwrap();
    quiesce(&mut inviter, &mut accepter, &rel_id).await;
    (inviter, accepter, rel_id)
}

/// A RESYNC_REQ storm from the peer: the burst is handled, the rest is
/// dropped + counted, the session stays Active, and honest traffic is
/// unaffected.
#[tokio::test]
async fn resync_req_storm_throttled_session_safe() {
    let _guard = COUNTER_LOCK.lock().await;
    let (mut a, mut b, rel_id) = pair_up().await;
    // The pairing activation burst included a RESYNC_REQ; refill the
    // bucket so the storm measurement starts from a full budget.
    a.clock.advance(30);
    b.clock.advance(30);
    let before = ratelimit::limited(Surface::ResyncReq);

    const STORM: u32 = 20;
    for _ in 0..STORM {
        let req = crate::sync::resync::build_request(&b.engine.db, &rel_id).unwrap();
        send_envelope(
            &b.engine.db,
            &b.engine.transport,
            &rel_id,
            Payload::ResyncReq(req),
            None,
            false,
        )
        .await
        .unwrap();
    }
    pump(&mut b, &mut a, &rel_id).await;

    let dropped = ratelimit::limited(Surface::ResyncReq) - before;
    assert_eq!(
        dropped,
        u64::from(STORM - crate::limits::rate::RESYNC_REQ_BURST),
        "burst handled, rest throttled"
    );
    assert_eq!(
        crate::session::session_state(a.engine.db.conn(), &rel_id).unwrap(),
        crate::session::SessionState::Active,
        "storm must not break the session (I7)"
    );

    // Victim stays responsive: an honest message still flows.
    let msg_id = a
        .engine
        .send_text(&rel_id, "still here", None)
        .await
        .unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await;
    assert!(events.contains(&EngineEvent::Message {
        rel_id: rel_id.clone(),
        msg_id
    }));

    // After the refill window the peer's honest resync is handled again.
    a.clock.advance(10);
    let req = crate::sync::resync::build_request(&b.engine.db, &rel_id).unwrap();
    send_envelope(
        &b.engine.db,
        &b.engine.transport,
        &rel_id,
        Payload::ResyncReq(req),
        None,
        false,
    )
    .await
    .unwrap();
    let before2 = ratelimit::limited(Surface::ResyncReq);
    pump(&mut b, &mut a, &rel_id).await;
    assert_eq!(ratelimit::limited(Surface::ResyncReq), before2);
}

/// A typing/presence flood drops at the ephemeral bucket; the RAM
/// tables reflect only the admitted prefix; recovery after refill.
#[tokio::test]
async fn ephemeral_flood_throttled() {
    let _guard = COUNTER_LOCK.lock().await;
    let (mut a, mut b, rel_id) = pair_up().await;
    let before = ratelimit::limited(Surface::Ephemeral);

    const FLOOD: u32 = 40;
    for i in 0..FLOOD {
        send_envelope(
            &b.engine.db,
            &b.engine.transport,
            &rel_id,
            Payload::Typing(Typing { typing: i % 2 == 0 }),
            None,
            false,
        )
        .await
        .unwrap();
    }
    pump(&mut b, &mut a, &rel_id).await;

    let dropped = ratelimit::limited(Surface::Ephemeral) - before;
    assert_eq!(
        dropped,
        u64::from(FLOOD - crate::limits::rate::EPHEMERAL_BURST)
    );

    // Refill: honest typing flows again.
    a.clock.advance(10);
    send_envelope(
        &b.engine.db,
        &b.engine.transport,
        &rel_id,
        Payload::Typing(Typing { typing: true }),
        None,
        false,
    )
    .await
    .unwrap();
    let events = pump(&mut b, &mut a, &rel_id).await;
    assert!(events
        .iter()
        .any(|e| matches!(e, EngineEvent::Typing { typing: true, .. })));
}

/// Inbound messages stuffed with unknown `:e:` tokens must not turn us
/// into a WANT_ITEM fountain: fetches are throttled, counted, and the
/// messages themselves still land.
#[tokio::test]
async fn sticker_fetch_flood_throttled() {
    let _guard = COUNTER_LOCK.lock().await;
    let (mut a, mut b, rel_id) = pair_up().await;
    let before = ratelimit::limited(Surface::StickerFetch);

    const MSGS: u32 = 10;
    const TOKENS_PER_MSG: u32 = 10;
    for m in 0..MSGS {
        let mut body = String::new();
        for t in 0..TOKENS_PER_MSG {
            let n = m * TOKENS_PER_MSG + t;
            body.push_str(&format!(":e:{:016x}:", n));
        }
        b.engine.send_text(&rel_id, &body, None).await.unwrap();
    }
    let events = pump(&mut b, &mut a, &rel_id).await;

    let total = u64::from(MSGS * TOKENS_PER_MSG);
    let burst = u64::from(crate::limits::rate::STICKER_FETCH_BURST);
    assert_eq!(
        ratelimit::limited(Surface::StickerFetch) - before,
        total - burst
    );
    // Every message still landed (the throttle drops fetches, not data).
    let landed = events
        .iter()
        .filter(|e| matches!(e, EngineEvent::Message { .. }))
        .count();
    assert_eq!(landed, MSGS as usize);
    // Exactly the burst's worth of WANT_ITEMs sits in our outbox.
    let want_items = a
        .engine
        .db
        .due(64)
        .unwrap()
        .into_iter()
        .filter(|r| r.rel_id == rel_id)
        .count();
    assert_eq!(want_items, burst as usize);
}

/// An attacker intro that passes signature + identity checks but fails
/// the PQXDH decrypt keeps the offer open — that is the flood the
/// intro throttle exists for. First attempt sets the budget; the honest
/// accepter's intro inside the interval is dropped (counted, no partial
/// state); after the interval the honest intro is processed.
#[tokio::test]
async fn intro_flood_throttled() {
    let _guard = COUNTER_LOCK.lock().await;
    let inviter = Peer::new();
    let mut accepter = Peer::new();
    let wall = SystemTime::now();
    let before = ratelimit::limited(Surface::Intro);

    let offer = pairing::offer(inviter.engine.db.conn(), &inviter.engine.transport, wall)
        .await
        .unwrap();
    let accepted = pairing::accept(
        accepter.engine.db.conn(),
        &accepter.engine.transport,
        &offer.qr_bytes,
        wall,
    )
    .await
    .unwrap();
    let rel_id = accepted.rel_id.clone();
    accepter
        .engine
        .send_text(&rel_id, "hi", None)
        .await
        .unwrap();

    let service_id = pairing::load_pending(inviter.engine.db.conn())
        .unwrap()
        .expect("offer open")
        .service_id;
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(T0);

    // The accepter's real intro frame, with one ciphertext byte flipped
    // (structure intact, MAC broken): passes decode + identity binding,
    // fails the PQXDH decrypt.
    let row = accepter.engine.db.due(64).unwrap().remove(0);
    let intro = pairing::load_relationship(accepter.engine.db.conn(), &rel_id)
        .unwrap()
        .and_then(|r| r.intro_pending.then(|| r.our_qr_bytes.clone()));
    let frame = framing::parse_record(&row.record).unwrap();
    let mut evil = frame.to_vec();
    let n = evil.len();
    // Deep inside the SignalMessage ciphertext: protobuf structure and
    // the identity binding stay intact, the MAC check fails.
    evil[n * 3 / 5] ^= 0x01;
    let evil_record = framing::build_record(&evil).unwrap();

    let outcome_evil = pairing::ingest_frame(
        inviter.engine.db.conn(),
        &inviter.engine.transport,
        &service_id,
        intro.as_deref(),
        &evil_record,
        t,
    )
    .await
    .unwrap();
    assert!(
        matches!(outcome_evil, Ingest::Dropped),
        "corrupt intro dropped: {outcome_evil:?}"
    );
    assert!(
        pairing::load_pending(inviter.engine.db.conn())
            .unwrap()
            .is_some(),
        "failed decrypt keeps the offer open"
    );

    // The honest intro inside the min interval: throttled (counted, no
    // partial state).
    let outcome1 = pairing::ingest_frame(
        inviter.engine.db.conn(),
        &inviter.engine.transport,
        &service_id,
        intro.as_deref(),
        &row.record,
        t,
    )
    .await
    .unwrap();
    assert!(
        matches!(outcome1, Ingest::Dropped),
        "intro inside the interval throttled: {outcome1:?}"
    );
    assert_eq!(ratelimit::limited(Surface::Intro), before + 1);
    assert!(
        pairing::load_relationship(inviter.engine.db.conn(), &rel_id)
            .unwrap()
            .is_none(),
        "throttled intro leaves no partial state"
    );

    // After the interval the (re-delivered) honest intro is processed.
    let outcome2 = pairing::ingest_frame(
        inviter.engine.db.conn(),
        &inviter.engine.transport,
        &service_id,
        intro.as_deref(),
        &row.record,
        t + Duration::from_secs(crate::limits::rate::INTRO_MIN_INTERVAL_SECS + 1),
    )
    .await
    .unwrap();
    assert!(
        matches!(outcome2, Ingest::RequestReceived { .. }),
        "intro after the interval processed: {outcome2:?}"
    );
}

/// Honest-usage calibration (mock transport): an enthusiastic
/// but realistic session — rapid chat burst, edits inside the window,
/// typing/presence transitions, an attachment, a resync round — must
/// complete with `rate_limited() == 0` and full delivery.
#[tokio::test]
async fn honest_heavy_session_never_rate_limited() {
    let _guard = COUNTER_LOCK.lock().await;
    let (mut a, mut b, rel_id) = pair_up().await;
    // Per-surface baselines (the process-global total also covers the
    // transport/control surfaces exercised by other test modules).
    let surfaces = [
        Surface::ResyncReq,
        Surface::Ephemeral,
        Surface::Intro,
        Surface::StickerFetch,
        Surface::StickerServe,
    ];
    let baseline: Vec<u64> = surfaces.iter().map(|s| ratelimit::limited(*s)).collect();

    // Rapid chat burst: 30 messages in a minute (documented profile).
    for i in 0..30 {
        a.engine
            .send_text(&rel_id, &format!("burst {i}"), None)
            .await
            .unwrap();
    }
    let events = pump(&mut a, &mut b, &rel_id).await;
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, EngineEvent::Message { .. }))
            .count(),
        30
    );

    // Edits inside the window (1 s min interval respected).
    let target = a.engine.send_text(&rel_id, "edit me", None).await.unwrap();
    pump(&mut a, &mut b, &rel_id).await;
    for i in 0..5 {
        a.clock.advance(2);
        b.clock.advance(2);
        a.engine
            .send_edit(&rel_id, &target, &format!("edited {i}"))
            .await
            .unwrap();
        pump(&mut a, &mut b, &rel_id).await;
    }

    // Typing + presence transitions (protocol-paced).
    for _ in 0..2 {
        a.clock.advance(4);
        b.clock.advance(4);
        a.engine.send_typing(&rel_id, true).await.unwrap();
        a.engine.send_presence(&rel_id, true, false).await.unwrap();
        pump(&mut a, &mut b, &rel_id).await;
        a.clock.advance(4);
        b.clock.advance(4);
        a.engine.send_typing(&rel_id, false).await.unwrap();
        pump(&mut a, &mut b, &rel_id).await;
    }

    // A small (inline) attachment.
    a.engine
        .send_attachment(
            &rel_id,
            &crate::attach::AttachmentSpec {
                media_class: 2,
                mime_hint: "video/mp4".into(),
                orig_ext: "mp4".into(),
                bytes: vec![7u8; 4_000],
                caption: "clip".into(),
                view_once: false,
            },
        )
        .await
        .unwrap();
    quiesce(&mut a, &mut b, &rel_id).await;

    // One reconnect-style resync round.
    let req = crate::sync::resync::build_request(&b.engine.db, &rel_id).unwrap();
    send_envelope(
        &b.engine.db,
        &b.engine.transport,
        &rel_id,
        Payload::ResyncReq(req),
        None,
        false,
    )
    .await
    .unwrap();
    quiesce(&mut a, &mut b, &rel_id).await;

    for (i, s) in surfaces.iter().enumerate() {
        assert_eq!(
            ratelimit::limited(*s),
            baseline[i],
            "honest heavy session must never trip {s:?}"
        );
    }
    // Full delivery: the whole burst + the (edited) target landed.
    let bodies: Vec<String> = b
        .engine
        .db
        .thread_visible(&rel_id, 200, None)
        .unwrap()
        .into_iter()
        .filter(|r| r.env_type == schat_wire_types::envelope::EnvelopeType::Msg.code())
        .filter_map(|r| String::from_utf8(r.payload).ok())
        .collect();
    for i in 0..30 {
        assert!(
            bodies.iter().any(|b| b == &format!("burst {i}")),
            "burst {i} landed"
        );
    }
    assert!(bodies.iter().any(|b| b == "edited 4"), "final edit landed");
}
