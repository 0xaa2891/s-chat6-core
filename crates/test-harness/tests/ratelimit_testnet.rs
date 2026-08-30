//! Honest-usage calibration gate on real Tor (Chutney): a scripted
//! "max realistic user" session — pairing, a rapid 30-message chat burst,
//! edits, a chunked attachment upload, typing/presence — must complete
//! with **zero** rate-limit drops on both sides (`rate_limited() == 0`
//! delta) and full delivery. The abuse-flood half lives in
//! `adversarial_testnet.rs`; per-surface mock calibration in
//! `schat_core::engine::tests_rate`.
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes
//! dir (see `tools/testnet/run-testnet.sh`) and a `tor` binary is
//! available.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use schat_core::attach::AttachmentSpec;
use schat_core::engine::{Engine, EngineEvent};
use schat_core::pairing::{self, Ingest};
use schat_core::ratelimit;
use schat_core::store::clock::FakeClock;
use schat_core::store::messages::MessagesRepository;
use schat_core::store::Db;
use schat_core::transport::inbound::InboundDrop;
use schat_core::wire_types::envelope::EnvelopeType;
use schat_test_harness::{chutney_nodes, tor_binary, TestInstance};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

const T0: u64 = 1_700_000_000;
const ONLINE_TIMEOUT: Duration = Duration::from_secs(240);
const PAIR_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(600);
const PUMP_INTERVAL: Duration = Duration::from_secs(2);
/// The honest-usage profile (notes/rate-limits.md): 30 messages/minute.
const BURST_MESSAGES: usize = 30;

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

struct Node {
    name: String,
    inst: TestInstance,
    engine: Engine,
    clock: FakeClock,
    drops: broadcast::Receiver<InboundDrop>,
    events: Vec<EngineEvent>,
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

    fn bodies(&self, rel_id: &str) -> Vec<String> {
        self.engine
            .db
            .thread_visible(rel_id, 500, None)
            .unwrap()
            .into_iter()
            .filter(|m| m.env_type == EnvelopeType::Msg.code())
            .filter_map(|m| String::from_utf8(m.payload).ok())
            .collect()
    }

    fn attachment_done(&self, head_id: &[u8; 16]) -> bool {
        self.events.iter().any(
            |e| matches!(e, EngineEvent::AttachmentComplete { head_id: h, .. } if h == head_id),
        )
    }
}

async fn dispatch(node: &mut Node, rel_id: &str, plaintext: &[u8]) {
    match node.engine.handle_plaintext(rel_id, plaintext).await {
        Ok(events) => node.events.extend(events),
        Err(e) => eprintln!("{} handle: {e}", node.name),
    }
}

async fn pump_one(node: &mut Node) {
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
        5,
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
        5,
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

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "schat_core=info".into()),
        )
        .with_test_writer()
        .try_init();
}

/// The calibration gate: enthusiastic honest use never trips a
/// rate limit, on either side, over real Tor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn honest_heavy_session_never_rate_limited_testnet() {
    init_tracing();
    let nodes = require_testnet!();

    let mut alice = Node::new("alice", &nodes).await;
    let mut bob = Node::new("bob", &nodes).await;
    for node in [&alice, &bob] {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "transport online"
        );
    }

    let limited_before = ratelimit::rate_limited();
    let rel_id = pair_over_tor(&mut alice, &mut bob).await;

    // Rapid chat burst: 30 messages back-to-back (the documented p99
    // honest profile), plus an edit inside the window.
    for i in 0..BURST_MESSAGES {
        bob.engine
            .send_text(&rel_id, &format!("burst {i}"), None)
            .await
            .expect("burst send");
    }
    run_until(
        &mut [&mut alice, &mut bob],
        5,
        STEP_TIMEOUT,
        "burst delivery",
        |nodes| {
            let view = nodes[0].bodies(&rel_id);
            (0..BURST_MESSAGES).all(|i| view.contains(&format!("burst {i}")))
        },
    )
    .await;

    let first = alice
        .engine
        .db
        .thread_visible(&rel_id, 500, None)
        .unwrap()
        .into_iter()
        .find(|m| m.payload == b"burst 7")
        .expect("burst 7 row");
    bob.engine
        .send_edit(&rel_id, &first.msg_id, "burst 7 (edited)")
        .await
        .expect("edit");

    // A chunked attachment upload at full speed (~40 KiB → 2 data
    // chunks + pads; video passes through unsniffed).
    let bytes: Vec<u8> = (0..40_000u32).map(|i| (i % 239) as u8).collect();
    let head_id = bob
        .engine
        .send_attachment(
            &rel_id,
            &AttachmentSpec {
                media_class: schat_core::wire_types::attach::CLASS_VIDEO,
                mime_hint: "video/mp4".into(),
                orig_ext: "mp4".into(),
                bytes: bytes.clone(),
                caption: String::new(),
                view_once: false,
            },
        )
        .await
        .expect("attachment send");

    // Typing + presence at a normal cadence (need-to-send policy).
    bob.engine.send_typing(&rel_id, true).await.expect("typing");
    bob.clock.advance(4);
    bob.engine
        .send_typing(&rel_id, false)
        .await
        .expect("typing");

    run_until(
        &mut [&mut alice, &mut bob],
        5,
        STEP_TIMEOUT,
        "edit + attachment + ephemeral delivery",
        |nodes| {
            let view = nodes[0].bodies(&rel_id);
            view.iter().any(|b| b == "burst 7 (edited)") && nodes[0].attachment_done(&head_id)
        },
    )
    .await;

    let got = alice
        .engine
        .attachment_bytes(&head_id)
        .expect("attachment bytes")
        .expect("complete");
    assert_eq!(got, bytes, "byte-exact attachment over real Tor");

    // The calibration assertion: not one rate-limit drop on either side.
    assert_eq!(
        ratelimit::rate_limited(),
        limited_before,
        "honest heavy session must never trip a rate limit"
    );
}

/// Reconnect resync stays under the limit: one peer goes silent for a
/// simulated hour (FakeClock), backlog accumulates, and the catch-up
/// burst + RESYNC_REQ complete with zero drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reconnect_resync_never_rate_limited_testnet() {
    init_tracing();
    let nodes = require_testnet!();

    let mut alice = Node::new("alice", &nodes).await;
    let mut bob = Node::new("bob", &nodes).await;
    for node in [&alice, &bob] {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "transport online"
        );
    }

    let limited_before = ratelimit::rate_limited();
    let rel_id = pair_over_tor(&mut alice, &mut bob).await;

    // Alice goes "offline": Bob queues a backlog; nothing is pumped.
    for i in 0..12 {
        bob.engine
            .send_text(&rel_id, &format!("backlog {i}"), None)
            .await
            .expect("backlog send");
    }
    // Simulated hour passes for both clocks (outbox backoff matures).
    alice.clock.advance(3600);
    bob.clock.advance(3600);

    // Alice returns; the backlog + any resync converges.
    run_until(
        &mut [&mut alice, &mut bob],
        30,
        STEP_TIMEOUT,
        "backlog catch-up",
        |nodes| {
            let view = nodes[0].bodies(&rel_id);
            (0..12).all(|i| view.contains(&format!("backlog {i}")))
        },
    )
    .await;

    assert_eq!(
        ratelimit::rate_limited(),
        limited_before,
        "reconnect resync must never trip a rate limit"
    );
}
