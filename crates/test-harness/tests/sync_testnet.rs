//! The sync suite over real onion services, Chutney half.
//! The mock-transport half lives in `schat_core::sync::tests`; here the
//! same scenarios run with real tor processes on Chutney:
//!
//! - `all_17_types_over_testnet` — every wire type crosses a real onion
//!   service, decodes intact, and lands in the peer's ledger with
//!   contiguous app_seq (the resync receive-window never opens).
//! - `offline_resync_over_testnet` — clock-skew rejection at the wire,
//!   then one peer is killed (service removed) for a simulated hour,
//!   sends fail honestly (Queued, not "sent"), the peer returns, a
//!   blackholed frame opens a gap, and resync delivers everything in
//!   order; finally the 24h TTL erases on schedule.
//!
//! Both instances run on `FakeClock`s — 24h TTL tests
//! run in milliseconds; only the transport sees real time.
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes
//! dir (see `tools/testnet/run-testnet.sh`) and a `tor` binary is
//! available.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rand::RngCore;
use schat_core::engine::{Engine, EngineEvent};
use schat_core::pairing::{self, Ingest};
use schat_core::store::clock::{Clock, FakeClock};
use schat_core::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use schat_core::store::outbox::OutboxRepository;
use schat_core::store::{hex_encode, Db};
use schat_core::sync::MESSAGE_TTL_SECS;
use schat_core::transport::daemon::TorDaemon;
use schat_core::transport::inbound::InboundDrop;
use schat_core::wire::frame as wire_frame;
use schat_core::wire_types::envelope::{Envelope, Payload};
use schat_core::{session, sync};
use schat_test_harness::{chutney_nodes, tor_binary, TestInstance};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

const T0: u64 = 1_700_000_000;
const ONLINE_TIMEOUT: Duration = Duration::from_secs(240);
const PAIR_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(420);
const PUMP_INTERVAL: Duration = Duration::from_secs(2);

macro_rules! require_testnet {
    () => {
        match chutney_nodes() {
            Some(dir) if tor_binary().is_some() => dir,
            _ => {
                eprintln!(
                    "skip: set SCHAT_CHUTNEY_NODES to a running Chutney nodes dir \
                     (tools/testnet/run-testnet.sh s-chat6-min)"
                );
                return;
            }
        }
    };
}

/// One instance: transport + engine on a fake clock + its event log.
struct Node {
    name: String,
    inst: TestInstance,
    engine: Engine,
    clock: FakeClock,
    drops: broadcast::Receiver<InboundDrop>,
    events: Vec<EngineEvent>,
    /// rel_ids that arrived as message requests (inviter's bucket).
    requests: Vec<String>,
}

impl Node {
    async fn new(name: &str, nodes: &Path) -> Self {
        let inst = TestInstance::new(name, nodes).await.expect("instance");
        let clock = FakeClock::new(T0);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).expect("db");
        let engine = Engine::new(db, inst.transport.clone());
        let drops = inst.drops();
        Self {
            name: name.to_string(),
            inst,
            engine,
            clock,
            drops,
            events: Vec::new(),
            requests: Vec::new(),
        }
    }

    fn rel_state(&self, rel_id: &str) -> Option<String> {
        pairing::load_relationship(self.engine.db.conn(), rel_id)
            .ok()
            .flatten()
            .map(|r| r.state)
    }

    fn has_event(&self, f: impl Fn(&EngineEvent) -> bool) -> bool {
        self.events.iter().any(f)
    }

    fn max_contiguous(&self, rel_id: &str) -> u64 {
        self.engine
            .db
            .receive_view(rel_id, 4096)
            .map(|v| v.max_contiguous_seq)
            .unwrap_or(0)
    }
}

async fn dispatch(node: &mut Node, rel_id: &str, plaintext: &[u8]) {
    match node.engine.handle_plaintext(rel_id, plaintext).await {
        Ok(events) => node.events.extend(events),
        // Rejected envelopes (the skew test's far-future one) land here.
        Err(e) => eprintln!("{} handle: {e}", node.name),
    }
}

/// One upkeep round for one node: drain outbox, sweep, ingest all
/// pending drops into the engine.
async fn pump_one(node: &mut Node) {
    let span = tracing::info_span!("pump", n = %node.name);
    let _guard = span.enter();
    if let Err(e) = node.engine.drain_outbox().await {
        eprintln!("{} drain: {e}", node.name);
    }
    match node.engine.sweep().await {
        Ok(events) => node.events.extend(events),
        Err(e) => eprintln!("{} sweep: {e}", node.name),
    }
    loop {
        match node.drops.try_recv() {
            Ok(drop) => {
                let outcome = pairing::ingest_frame(
                    node.engine.db.conn(),
                    &node.engine.transport,
                    &drop.service_id,
                    drop.frame.intro.as_deref(),
                    &drop.frame.frame,
                    SystemTime::now(),
                )
                .await;
                match outcome {
                    Ok(Ingest::RequestReceived {
                        rel_id, plaintext, ..
                    }) => {
                        if !node.requests.contains(&rel_id) {
                            node.requests.push(rel_id.clone());
                        }
                        dispatch(node, &rel_id, &plaintext).await;
                    }
                    Ok(Ingest::Message { rel_id, plaintext }) => {
                        dispatch(node, &rel_id, &plaintext).await;
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("{} ingest: {e}", node.name),
                }
                node.inst.transport.note_inbound_drain();
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }
}

/// Pump the given nodes until `pred` holds. `clock_step` fake-seconds
/// elapse per round so outbox backoff keeps retrying while we wait.
async fn run_until(
    nodes: &mut [&mut Node],
    clock_step: u64,
    timeout: Duration,
    what: &str,
    pred: impl Fn(&[&Node]) -> bool,
) {
    let deadline = Instant::now() + timeout;
    loop {
        for node in nodes.iter_mut() {
            pump_one(node).await;
        }
        {
            let view: Vec<&Node> = nodes.iter().map(|n| &**n).collect();
            if pred(&view) {
                return;
            }
        }
        for node in nodes.iter_mut() {
            node.clock.advance(clock_step);
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(PUMP_INTERVAL).await;
    }
}

/// offer → accept → intro → request → inviter accepts → both active.
async fn pair_over_tor(a: &mut Node, b: &mut Node) -> String {
    let now = SystemTime::now();
    let offer = pairing::offer(a.engine.db.conn(), &a.engine.transport, now)
        .await
        .expect("offer");
    let accepted = pairing::accept(
        b.engine.db.conn(),
        &b.engine.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .expect("accept");
    let rel_id = accepted.rel_id.clone();
    b.engine
        .send_text(&rel_id, "hi, add me?", None)
        .await
        .expect("intro message");

    run_until(
        &mut [&mut *a, &mut *b],
        0,
        PAIR_TIMEOUT,
        "request",
        |nodes| nodes[0].requests.contains(&rel_id),
    )
    .await;
    a.engine
        .accept_request(&rel_id)
        .await
        .expect("accept request");
    run_until(
        &mut [&mut *a, &mut *b],
        0,
        PAIR_TIMEOUT,
        "activation",
        |nodes| {
            nodes[0].rel_state(&rel_id).is_some_and(|s| s == "active")
                && nodes[1].rel_state(&rel_id).is_some_and(|s| s == "active")
        },
    )
    .await;
    rel_id
}

fn random_msg_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Build, encrypt, ledger, and send one raw envelope over the real
/// onion — the mock suite's `queue_text`/`receive_record` with a real
/// wire between them. Returns (msg_id, app_seq).
async fn send_raw(
    from: &Node,
    rel_id: &str,
    peer_onion: &str,
    payload: Payload,
    ref_id: Option<[u8; 16]>,
) -> ([u8; 16], u64) {
    let msg_id = random_msg_id();
    let seq = from.engine.db.next_out_seq(rel_id).expect("seq");
    let now = from.clock.now_secs();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at: now,
        ref_id,
        payload,
    };
    let plaintext = env.encode().expect("encode envelope");
    let env_type = env.envelope_type().code();
    let payload_bytes = env.payload.encode().expect("encode payload");
    let frame = session::encrypt(
        from.engine.db.conn(),
        rel_id,
        &hex_encode(&msg_id),
        &plaintext,
        SystemTime::now(),
    )
    .await
    .expect("encrypt");
    let record = wire_frame::build_record(&frame).expect("record");
    // Sender-side ledger, mirroring what a real send records, so our
    // own seq counter advances and resync can map seq → frame.
    from.engine
        .db
        .insert_message(&NewMessage {
            msg_id,
            rel_id: rel_id.into(),
            direction: Direction::Out,
            app_seq: seq,
            sent_at: now,
            received_at: None,
            env_type,
            ref_id,
            payload: payload_bytes,
            state: DeliveryState::Transmitted,
            expires_at: Some(now + MESSAGE_TTL_SECS),
        })
        .expect("ledger");
    from.inst
        .transport
        .send_frame(peer_onion, &record, false)
        .await
        .expect("send frame");
    (msg_id, seq)
}

fn peer_onion(node: &Node, rel_id: &str) -> String {
    pairing::load_relationship(node.engine.db.conn(), rel_id)
        .expect("rel")
        .expect("present")
        .peer_onion
}

/// Two instances pair, then exchange all 17 envelope
/// types over a real onion service. Every one decodes intact and lands
/// in the ledger; the receive window stays contiguous throughout.
/// CONTACT_CLOSE goes last — it burns the relationship by design.
/// Route core logs into the test output (noop if already initialized).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "schat_core=info".into()),
        )
        .with_test_writer()
        .try_init();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_17_types_over_testnet() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let mut c = Node::new("c", &nodes_dir).await;
    let mut d = Node::new("d", &nodes_dir).await;
    for node in [&c, &d] {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "{} online",
            node.name
        );
    }
    let rel_id = pair_over_tor(&mut c, &mut d).await;
    let d_onion = peer_onion(&c, &rel_id);
    eprintln!("paired; sending all 17 types");

    use schat_core::wire_types::attach::{AttachChunk, AttachHead, AttachHeadPayload, CLASS_IMAGE};
    use schat_core::wire_types::contact::ContactClose;
    use schat_core::wire_types::delete::{Delete, DeleteAll};
    use schat_core::wire_types::edit::Edit;
    use schat_core::wire_types::policy::{self, ChatPolicy};
    use schat_core::wire_types::pref::Pref;
    use schat_core::wire_types::presence::Presence;
    use schat_core::wire_types::profile::{Profile, ProfileReq};
    use schat_core::wire_types::read::Read;
    use schat_core::wire_types::sticker::{limits, StickerCtrl, StickerItem};
    use schat_core::wire_types::typing::Typing;

    // Lockstep: each envelope must land contiguously before the next
    // goes out, so ordering on the wire can never open a window gap.
    let mut sent_seqs: Vec<u64> = Vec::new();
    macro_rules! send {
        ($payload:expr, $ref_id:expr) => {{
            let (id, seq) = send_raw(&c, &rel_id, &d_onion, $payload, $ref_id).await;
            sent_seqs.push(seq);
            run_until(
                &mut [&mut d],
                0,
                STEP_TIMEOUT,
                "contiguous delivery",
                |nodes| nodes[0].max_contiguous(&rel_id) >= seq,
            )
            .await;
            id
        }};
    }

    use schat_core::wire_types::msg::Msg;
    // 1 MSG — the edit/read/delete target below.
    let msg_id = send!(
        Payload::Msg(Msg::new("hello over tor".into()).unwrap()),
        None
    );
    // 2 EDIT (targets the MSG).
    send!(
        Payload::Edit(Edit::new("hello, edited".into()).unwrap()),
        Some(msg_id)
    );
    // 3 READ — targets D's own outbound intro row (receipts mark our
    // outbound rows read).
    let d_out = d
        .engine
        .db
        .thread(&rel_id, 50, None)
        .expect("thread")
        .into_iter()
        .find(|r| r.direction == Direction::Out)
        .map(|r| r.msg_id)
        .expect("d has an outbound row (the intro)");
    send!(Payload::Read(Read), Some(d_out));
    // 4 DELETE (targets the MSG).
    send!(Payload::Delete(Delete), Some(msg_id));
    // 5 DELETE_ALL — cuts history; later seqs are above the cut.
    send!(Payload::DeleteAll(DeleteAll), None);
    // 6 RESYNC_REQ — a well-formed request; the peer answers from its
    // I11 cache (nothing missing) and acks what the bitmap covers.
    let req = sync::resync::build_request(&c.engine.db, &rel_id).expect("resync req");
    send!(Payload::ResyncReq(req), None);
    // 7 ATTACH_HEAD (chunked, no inline) + 8 ATTACH_CHUNK.
    let head_id = send!(
        Payload::AttachHead(AttachHeadPayload {
            head: AttachHead {
                media_class: CLASS_IMAGE,
                mime_hint: "image/png".into(),
                orig_ext: "png".into(),
                uncompressed_n: 1000,
                chunk_count: 2,
                chunk_bucket: 2,
                content_sha256: [3u8; 32],
                caption: String::new(),
                flags: 0,
            },
            inline: None,
        }),
        None
    );
    send!(
        Payload::AttachChunk(AttachChunk {
            head_id,
            index: 0,
            pad: false,
            data: vec![1, 2, 3],
        }),
        None
    );
    // 9 PROFILE.
    send!(
        Payload::Profile(Profile {
            name: "Carol".into(),
            jpeg: Vec::new(),
        }),
        None
    );
    // 10 PREF.
    send!(
        Payload::Pref(Pref {
            receive_media: true,
            listen_saver: false,
            inactivity_erase_hours: 720,
        }),
        None
    );
    // 11 PROFILE_REQ.
    send!(Payload::ProfileReq(ProfileReq), None);
    // 12 STICKER (unknown pack: the peer's fetch state machine asks us
    // for it — tolerated) + 13 STICKER_CTRL.
    send!(
        Payload::Sticker(StickerItem {
            kind: limits::KIND_STICKER,
            visibility: limits::VISIBILITY_PUBLIC,
            pack_id: [5u8; 16],
            pack_pk: [6u8; 32],
            item_id: 1,
            w: 512,
            h: 512,
            content_sha256: [7u8; 32],
            bytes: None,
        }),
        None
    );
    send!(Payload::StickerCtrl(StickerCtrl::Ack([8u8; 32])), None);
    // 14 PRESENCE + 15 TYPING (ephemeral: seq-tracked, not stored).
    send!(
        Payload::Presence(Presence {
            in_app: true,
            do_not_disturb: false,
        }),
        None
    );
    send!(Payload::Typing(Typing { typing: true }), None);
    // 16 CHAT_POLICY (a fresh proposal lights up the rules sheet).
    send!(
        Payload::ChatPolicy(ChatPolicy {
            op: policy::OP_RULE_PROPOSE,
            ttl_sec: policy::TTL_24H,
            screenshot: false,
            attach_download: true,
            want_attach: false,
            want_emoji: false,
            want_presence: true,
            want_typing: false,
            want_receipts: false,
            cap_id: 0,
            cap_on: false,
            propose_id: random_msg_id(),
        }),
        None
    );

    assert_eq!(
        sent_seqs.len(),
        16,
        "16 types so far; CONTACT_CLOSE is last"
    );

    // Every event-ful type fired on D.
    type EventCheck = (&'static str, Box<dyn Fn(&EngineEvent) -> bool>);
    let expected: Vec<EventCheck> = vec![
        (
            "Message",
            Box::new(
                move |e: &EngineEvent| matches!(e, EngineEvent::Message { msg_id: id, .. } if *id == msg_id),
            ),
        ),
        (
            "Edited",
            Box::new(move |e| matches!(e, EngineEvent::Edited { msg_id: id, .. } if *id == msg_id)),
        ),
        (
            "Read",
            Box::new(move |e| matches!(e, EngineEvent::Read { msg_id: id, .. } if *id == d_out)),
        ),
        (
            "Deleted",
            Box::new(
                move |e| matches!(e, EngineEvent::Deleted { msg_id: id, .. } if *id == msg_id),
            ),
        ),
        (
            "HistoryCleared",
            Box::new(|e| matches!(e, EngineEvent::HistoryCleared { .. })),
        ),
        (
            "ProfileUpdated",
            Box::new(|e| matches!(e, EngineEvent::ProfileUpdated { .. })),
        ),
        (
            "PeerPrefs",
            Box::new(|e| matches!(e, EngineEvent::PeerPrefs { .. })),
        ),
        (
            "ProfileRequested",
            Box::new(|e| matches!(e, EngineEvent::ProfileRequested { .. })),
        ),
        (
            "Presence",
            Box::new(|e| matches!(e, EngineEvent::Presence { in_app: true, .. })),
        ),
        (
            "Typing",
            Box::new(|e| matches!(e, EngineEvent::Typing { typing: true, .. })),
        ),
        (
            "PolicyChanged",
            Box::new(|e| matches!(e, EngineEvent::PolicyChanged { .. })),
        ),
    ];
    for (what, pred) in &expected {
        assert!(d.has_event(pred), "D saw {what}: {:?}", d.events);
    }
    eprintln!("16 types delivered contiguously with their events");

    // 17 CONTACT_CLOSE — burns the relationship on receipt. No
    // continuity lockstep here: the burn wipes the seq tracker too, so
    // the receive window is gone by the time we could observe it.
    send_raw(
        &c,
        &rel_id,
        &d_onion,
        Payload::ContactClose(ContactClose),
        None,
    )
    .await;
    run_until(&mut [&mut d], 0, STEP_TIMEOUT, "contact close", |nodes| {
        nodes[0].has_event(|e| matches!(e, EngineEvent::ContactClosed { .. }))
            && nodes[0].rel_state(&rel_id).is_none()
    })
    .await;
    eprintln!("contact close burned the relationship");

    c.inst.stop().await;
    d.inst.stop().await;
}

/// Skew rejection at the wire, then offline delivery —
/// one peer is killed for a simulated hour, sends fail honestly, the
/// peer returns, a blackholed frame opens a gap, resync delivers
/// everything in order — then the 24h TTL erases on schedule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_resync_over_testnet() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let mut a = Node::new("a", &nodes_dir).await;
    let mut b = Node::new("b", &nodes_dir).await;
    for node in [&a, &b] {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "{} online",
            node.name
        );
    }
    let rel_id = pair_over_tor(&mut a, &mut b).await;
    let b_onion = peer_onion(&a, &rel_id);

    // -- clock skew at the wire -----------------------------------------
    use schat_core::wire_types::msg::Msg;

    // Grossly-future sent_at: rejected before the seq is noted, so the
    // honest re-send below reuses the same seq without opening a gap.
    let evil_seq = a.engine.db.next_out_seq(&rel_id).expect("seq");
    let evil_id = random_msg_id();
    let evil = Envelope {
        msg_id: evil_id,
        app_seq: evil_seq,
        sent_at: T0 + 3600,
        ref_id: None,
        payload: Payload::Msg(Msg::new("pin me to the top".into()).unwrap()),
    };
    let frame = session::encrypt(
        a.engine.db.conn(),
        &rel_id,
        &hex_encode(&evil_id),
        &evil.encode().unwrap(),
        SystemTime::now(),
    )
    .await
    .expect("encrypt");
    let record = wire_frame::build_record(&frame).expect("record");
    a.inst
        .transport
        .send_frame(&b_onion, &record, false)
        .await
        .expect("send evil");
    // Give the frame a fixed window to arrive — and be rejected.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        pump_one(&mut b).await;
        tokio::time::sleep(PUMP_INTERVAL).await;
    }
    assert!(b.engine.db.message(&evil_id).expect("lookup").is_none());
    assert!(
        !b.has_event(|e| matches!(e, EngineEvent::Message { msg_id, .. } if *msg_id == evil_id)),
        "far-future envelope rejected"
    );

    // Mildly-future sent_at (honest skew): clamped to B's clock, stored.
    let (mild_id, _) = send_raw(
        &a,
        &rel_id,
        &b_onion,
        Payload::Msg(Msg::new("ok".into()).unwrap()),
        None,
    )
    .await;
    run_until(
        &mut [&mut b],
        0,
        STEP_TIMEOUT,
        "mild-skew message",
        |nodes| {
            nodes[0].has_event(
                |e| matches!(e, EngineEvent::Message { msg_id, .. } if *msg_id == mild_id),
            )
        },
    )
    .await;
    let mild = b
        .engine
        .db
        .message(&mild_id)
        .expect("lookup")
        .expect("stored");
    assert!(
        (T0..=T0 + 30).contains(&mild.sent_at),
        "clamped to the receiver's clock (T0), got {}",
        mild.sent_at
    );
    eprintln!("skew: far-future rejected, near-future clamped");

    // -- kill B for a simulated hour --------------------------------------
    // B's tor process dies: B is genuinely unreachable (no intro points,
    // no rendezvous — A's socket writes fail honestly). B's app state
    // (engine, store, transport object) survives, as it would on a phone
    // whose network vanished; B's pump stays frozen while B is "away".
    b.inst.daemon.stop().await.expect("kill b's tor");

    // Let A's pooled SOCKS stream to B expire (CONVERSATION_HOLD = 60s):
    // a write to a half-dead stream can succeed at the TCP level while
    // the peer is gone — "transmitted" without delivery. With the pool
    // expired, every send is a fresh connect to a dead onion and fails
    // honestly.
    tokio::time::sleep(Duration::from_secs(65)).await;

    // A sends three messages into the void. While B is down every connect
    // fails honestly; B's supervisor self-heals after a few minutes (the
    // self-heal ladder: RELOAD → NEWNYM → restart), so late sends may already
    // deliver. Either way the outbox never marks a failed write "sent"
    // (that assertion lives in the mock suite, where timing is
    // deterministic) — what matters here is that B's frozen pump never
    // ingests them.
    let mut ids = Vec::new();
    for body in ["m1", "m2", "m3"] {
        ids.push(
            a.engine
                .send_text(&rel_id, body, None)
                .await
                .expect("queue text"),
        );
    }
    // Let the send attempts run their course (fail-or-deliver).
    run_until(
        &mut [&mut a],
        30,
        Duration::from_secs(300),
        "send attempts settle",
        |nodes| nodes[0].engine.db.due(64).expect("due").is_empty(),
    )
    .await;

    // One simulated hour passes; B returns. The tor daemon restarts on
    // the same work dir; B's supervisor notices the dead control
    // connection, reconnects, and re-publishes the SAME onion address
    // (persisted key blob) with no app-level action — exactly a phone
    // regaining its network. Wait for the service to be Reachable again.
    a.clock.advance(3600);
    b.clock.advance(3600);
    let b_service = pairing::load_relationship(b.engine.db.conn(), &rel_id)
        .expect("rel")
        .expect("present")
        .service_id;
    b.inst.daemon.start().await.expect("revive b's tor");
    let revive_deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let st = b.inst.transport.status();
        let back = matches!(st.tor, schat_core::transport::status::TorState::Online)
            && st.services.iter().any(|s| {
                s.service_id == b_service
                    && s.state == schat_core::transport::status::ServiceState::Reachable
            });
        if back {
            break;
        }
        assert!(
            Instant::now() < revive_deadline,
            "b's service did not republish after revive: {st:?}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    eprintln!("b revived: same onion republished by the supervisor");

    // A's retries now succeed at the socket level — but B's app is still
    // "dead": it never processes the drops, then comes back to find them
    // gone (blackholed after the write — the case resync exists for).
    run_until(
        &mut [&mut a],
        30,
        Duration::from_secs(600),
        "m1..m3 transmitted after revive",
        |nodes| {
            ids.iter().all(|id| {
                nodes[0]
                    .engine
                    .db
                    .message(id)
                    .expect("lookup")
                    .expect("row")
                    .state
                    == DeliveryState::Transmitted
            })
        },
    )
    .await;
    // Blackhole m1..m3 — and prove the deliveries were real, not writes
    // into a corpse stream (the whole point of the hold-expiry wait).
    let mut blackholed = 0u32;
    while b.drops.try_recv().is_ok() {
        blackholed += 1;
    }
    assert!(
        blackholed >= 3,
        "expected m1..m3 in b's drop channel, got {blackholed} — sends were not real deliveries"
    );

    // B's first sign of life is m4: a seq gap opens, B fires a
    // RESYNC_REQ, A retransmits m1..m3 immutably from its I11 cache.
    let m4 = a.engine.send_text(&rel_id, "m4", None).await.expect("m4");
    let diag_deadline = Instant::now() + Duration::from_secs(600);
    let mut last_diag = Instant::now() - Duration::from_secs(60);
    loop {
        pump_one(&mut a).await;
        pump_one(&mut b).await;
        let gap_fired = b.has_event(|e| matches!(e, EngineEvent::GapDetected { .. }));
        let mut rows = b.engine.db.thread(&rel_id, 50, None).expect("thread");
        rows.sort_by_key(|r| r.app_seq);
        let bodies: Vec<&[u8]> = rows
            .iter()
            .filter(|r| r.direction == Direction::In)
            .map(|r| r.payload.as_slice())
            .collect();
        let all_present = ["m1", "m2", "m3", "m4"]
            .iter()
            .all(|m| bodies.contains(&m.as_bytes()));
        let ordered = all_present && {
            let pos: Vec<usize> = ["m1", "m2", "m3", "m4"]
                .iter()
                .map(|m| bodies.iter().position(|b| *b == m.as_bytes()).unwrap())
                .collect();
            pos.windows(2).all(|w| w[0] < w[1])
        };
        // The req that first covers m4 can race m4's arrival (a stale
        // view built before m4 landed requeues it); the NEXT req — fired
        // when the retransmits arrive — covers it and settles the ack.
        // Wait for that round-trip instead of asserting mid-flight.
        let m4_acked = matches!(
            a.engine.db.message(&m4).expect("lookup").map(|r| r.state),
            Some(DeliveryState::Acknowledged)
        );
        if gap_fired && ordered && m4_acked {
            break;
        }
        if last_diag.elapsed() >= Duration::from_secs(30) {
            last_diag = Instant::now();
            let noted: Vec<u64> = b
                .engine
                .db
                .conn()
                .prepare("SELECT app_seq FROM inbound_seqs WHERE rel_id = ?1 ORDER BY app_seq")
                .expect("prep")
                .query_map(rusqlite::params![rel_id], |r| r.get::<_, i64>(0))
                .expect("query")
                .map(|v| v.unwrap() as u64)
                .collect();
            let a_out: Vec<String> = a
                .engine
                .db
                .conn()
                .prepare(
                    "SELECT app_seq, env_type, state FROM messages
                     WHERE rel_id = ?1 AND direction = 'out' ORDER BY app_seq",
                )
                .expect("prep")
                .query_map(rusqlite::params![rel_id], |r| {
                    Ok(format!(
                        "{}/t{}/{:?}",
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?
                    ))
                })
                .expect("query")
                .map(|v| v.unwrap())
                .collect();
            let b_due = b.engine.db.due(64).expect("due").len();
            eprintln!(
                "diag: gap_fired={gap_fired} b_noted={noted:?} b_in={:?} a_out={a_out:?} b_due={b_due}",
                rows.iter()
                    .filter(|r| r.direction == Direction::In)
                    .map(|r| format!(
                        "s{}:t{}:{}",
                        r.app_seq,
                        r.env_type,
                        String::from_utf8_lossy(&r.payload[..r.payload.len().min(12)])
                    ))
                    .collect::<Vec<_>>(),
            );
        }
        a.clock.advance(30);
        b.clock.advance(30);
        assert!(
            Instant::now() < diag_deadline,
            "timed out waiting for gap detected + resync delivers m1..m4 + m4 ack"
        );
        tokio::time::sleep(PUMP_INTERVAL).await;
    }
    eprintln!("resync delivered m1..m4 in order; m4 acknowledged");

    // -- TTL erases on schedule -------------------------------------------
    let doomed_ab = a
        .engine
        .send_text(&rel_id, "doomed a→b", None)
        .await
        .expect("send");
    let doomed_ba = b
        .engine
        .send_text(&rel_id, "doomed b→a", None)
        .await
        .expect("send");
    run_until(
        &mut [&mut a, &mut b],
        10,
        STEP_TIMEOUT,
        "doomed messages delivered",
        |nodes| {
            nodes[1].has_event(
                |e| matches!(e, EngineEvent::Message { msg_id, .. } if *msg_id == doomed_ab),
            ) && nodes[0].has_event(
                |e| matches!(e, EngineEvent::Message { msg_id, .. } if *msg_id == doomed_ba),
            )
        },
    )
    .await;

    // Past the 24h horizon: both sweeps erase the expired rows.
    a.clock.advance(MESSAGE_TTL_SECS + 61);
    b.clock.advance(MESSAGE_TTL_SECS + 61);
    let ra = a.engine.sweep().await.expect("sweep a");
    let rb = b.engine.sweep().await.expect("sweep b");
    a.events.extend(ra);
    b.events.extend(rb);
    for (node, id, what) in [
        (&a, doomed_ab, "own outbound"),
        (&b, doomed_ab, "inbound"),
        (&b, doomed_ba, "own outbound"),
        (&a, doomed_ba, "inbound"),
    ] {
        assert!(
            node.engine.db.message(&id).expect("lookup").is_none(),
            "{}: {what} doomed row erased",
            node.name
        );
    }
    eprintln!("24h TTL erased on schedule, both sides");

    a.inst.stop().await;
    b.inst.stop().await;
}
