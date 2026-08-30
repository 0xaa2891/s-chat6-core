//! Evil-peer Chutney scenario: an evil instance floods a victim with
//! replayed frames and a RESYNC_REQ storm over real onion services while
//! an honest pair chats on the same victim. Asserted outcomes:
//!
//! - replays produce exactly one ledger effect (I7 idempotence; the
//!   transport seen-ring and the session layer both dedupe),
//! - the RESYNC_REQ storm is throttled by the per-relationship
//!   bucket (counted; the session is unaffected),
//! - the honest pair's traffic is fully delivered during and after the
//!   flood — the victim stays responsive.
//!
//! The mock-transport half of the evil-peer harness (malformed frames,
//! unknown types, caps violations, rogue chunks, tampered pairing,
//! identity flip, cross-relationship delivery) lives in
//! `adversarial.rs`.
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes
//! dir (see `tools/testnet/run-testnet.sh`) and a `tor` binary is
//! available.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use schat_core::engine::{Engine, EngineEvent};
use schat_core::pairing::{self, Ingest};
use schat_core::ratelimit::{self, Surface};
use schat_core::session;
use schat_core::store::clock::{Clock, FakeClock};
use schat_core::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use schat_core::store::{hex_encode, Db};
use schat_core::sync::MESSAGE_TTL_SECS;
use schat_core::transport::inbound::InboundDrop;
use schat_core::wire::frame as wire_frame;
use schat_core::wire_types::envelope::{Envelope, EnvelopeType, Payload};
use schat_core::wire_types::resync::ResyncReq;
use schat_test_harness::{chutney_nodes, tor_binary, TestInstance};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

const T0: u64 = 1_700_000_000;
const ONLINE_TIMEOUT: Duration = Duration::from_secs(240);
const PAIR_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(600);
const PUMP_INTERVAL: Duration = Duration::from_secs(2);
/// Flood sizes: comfortably past the rate-limit bursts, small enough to keep
/// the real-Tor runtime reasonable.
const REPLAY_FLOOD: usize = 12;
const RESYNC_FLOOD: usize = 12;

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

    fn session_state(&self, rel_id: &str) -> session::SessionState {
        session::session_state(self.engine.db.conn(), rel_id).expect("session state")
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

fn peer_onion(node: &Node, rel_id: &str) -> String {
    pairing::load_relationship(node.engine.db.conn(), rel_id)
        .expect("rel")
        .expect("present")
        .peer_onion
}

/// Evil craft: build, encrypt, ledger, and send one attacker-controlled
/// envelope over the real onion, returning the wire record (for replays).
async fn evil_send(from: &Node, rel_id: &str, peer_onion: &str, payload: Payload) -> Vec<u8> {
    let msg_id = rand::random::<[u8; 16]>();
    let seq = from.engine.db.next_out_seq(rel_id).expect("seq");
    let now = from.clock.now_secs();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at: now,
        ref_id: None,
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
            ref_id: None,
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
    record
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

/// The Chutney scenario: Eve floods Alice with replays and a
/// RESYNC_REQ storm while Bob exchanges honest messages with Alice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn evil_flood_honest_pair_unaffected() {
    init_tracing();
    let nodes = require_testnet!();

    let mut alice = Node::new("alice", &nodes).await;
    let mut bob = Node::new("bob", &nodes).await;
    let mut eve = Node::new("eve", &nodes).await;
    // Transports must be online before pairing: an offline first send
    // lands in the outbox with a fake-clock backoff that never matures.
    for node in [&alice, &bob, &eve] {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "transport online"
        );
    }

    // Two relationships on Alice: honest (Bob) and evil (Eve).
    let rel_ab = pair_over_tor(&mut alice, &mut bob).await;
    let rel_ae = pair_over_tor(&mut alice, &mut eve).await;
    let alice_onion_for_eve = peer_onion(&eve, &rel_ae);

    // Eve captures one valid frame (Alice receives it exactly once).
    let captured = evil_send(
        &eve,
        &rel_ae,
        &alice_onion_for_eve,
        Payload::Msg(schat_core::wire_types::msg::Msg::new("captured".into()).unwrap()),
    )
    .await;
    run_until(
        &mut [&mut alice, &mut eve],
        5,
        STEP_TIMEOUT,
        "captured delivery",
        |nodes| nodes[0].bodies(&rel_ae).iter().any(|b| b == "captured"),
    )
    .await;

    // Honest traffic first (clock steps mature any outbox backoff).
    for i in 0..5 {
        bob.engine
            .send_text(&rel_ab, &format!("honest bob {i}"), None)
            .await
            .expect("bob send");
        alice
            .engine
            .send_text(&rel_ab, &format!("honest alice {i}"), None)
            .await
            .expect("alice send");
    }
    run_until(
        &mut [&mut alice, &mut bob, &mut eve],
        5,
        STEP_TIMEOUT,
        "honest delivery",
        |nodes| {
            let alice_view = nodes[0].bodies(&rel_ab);
            let bob_view = nodes[1].bodies(&rel_ab);
            (0..5).all(|i| {
                let b = format!("honest bob {i}");
                let a = format!("honest alice {i}");
                alice_view.contains(&b) && bob_view.contains(&a)
            })
        },
    )
    .await;

    // The flood: replays of the captured frame, then a RESYNC_REQ storm.
    // From here Alice's clock stays frozen — the token buckets are
    // engine-clock driven, and advancing it (the usual backoff-maturation
    // step) would refill the RESYNC_REQ bucket between arrivals and make
    // the throttle count timing-dependent. Ingest itself is not
    // clock-gated, so the flood still flows.
    for _ in 0..REPLAY_FLOOD {
        eve.inst
            .transport
            .send_frame(&alice_onion_for_eve, &captured, false)
            .await
            .expect("replay send");
    }
    let resync_before = ratelimit::limited(Surface::ResyncReq);
    for _ in 0..RESYNC_FLOOD {
        evil_send(
            &eve,
            &rel_ae,
            &alice_onion_for_eve,
            Payload::ResyncReq(ResyncReq {
                max_contiguous_seq: 0,
                received_seq_bitmap: Vec::new(),
                caps: schat_core::caps::local_caps(),
                history_hash: [0u8; 32],
            }),
        )
        .await;
    }

    // Let the flood wash through Alice's ingest (frozen clocks).
    run_until(
        &mut [&mut alice, &mut eve],
        0,
        STEP_TIMEOUT,
        "flood settles",
        |nodes| {
            let _ = nodes;
            ratelimit::limited(Surface::ResyncReq) - resync_before
                >= (RESYNC_FLOOD as u64)
                    .saturating_sub(u64::from(schat_core::limits::rate::RESYNC_REQ_BURST))
        },
    )
    .await;

    // The victim is responsive after the flood: one more honest
    // round-trip on each relationship.
    bob.engine
        .send_text(&rel_ab, "post-flood bob", None)
        .await
        .expect("bob post-flood");
    eve.engine
        .send_text(&rel_ae, "post-flood eve", None)
        .await
        .expect("eve post-flood");
    run_until(
        &mut [&mut alice, &mut bob, &mut eve],
        5,
        STEP_TIMEOUT,
        "post-flood responsiveness",
        |nodes| {
            nodes[0]
                .bodies(&rel_ab)
                .iter()
                .any(|b| b == "post-flood bob")
                && nodes[0]
                    .bodies(&rel_ae)
                    .iter()
                    .any(|b| b == "post-flood eve")
        },
    )
    .await;

    // Asserted outcomes.
    let alice_eve = alice.bodies(&rel_ae);
    assert_eq!(
        alice_eve.iter().filter(|b| *b == "captured").count(),
        1,
        "replay flood: exactly one ledger effect (I7): {alice_eve:?}"
    );
    let throttled = ratelimit::limited(Surface::ResyncReq) - resync_before;
    assert!(
        throttled
            >= (RESYNC_FLOOD as u64)
                .saturating_sub(u64::from(schat_core::limits::rate::RESYNC_REQ_BURST)),
        "RESYNC_REQ storm throttled past the burst: {throttled}"
    );
    assert_eq!(
        alice.session_state(&rel_ab),
        session::SessionState::Active,
        "honest session unaffected"
    );
    assert_eq!(
        alice.session_state(&rel_ae),
        session::SessionState::Active,
        "evil session throttled, not broken"
    );
    assert_eq!(
        eve.session_state(&rel_ae),
        session::SessionState::Active,
        "evil peer's own session consistent"
    );
}
