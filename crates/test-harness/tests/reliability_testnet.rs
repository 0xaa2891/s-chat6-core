//! The send/receive reliability suite over real onion
//! services on the Chutney `s-chat6-min` network. Every scenario writes
//! `target/reliability/<scenario>.json` and asserts the delivery
//! invariant: `sent == received == acknowledged` (or honest `Failed`),
//! zero silent drops, zero cross-peer delivery (I4).
//!
//! Scenarios:
//! - `peer_offline_mid_send` — burst, peer's tor stops mid-burst,
//!   restarts, everything is delivered and acknowledged.
//! - `tor_kill9_supervisor_restart` — SIGKILL the sender's tor
//!   mid-outbox-drain; the health supervisor climbs the heal ladder
//!   (RELOAD → NEWNYM → restart, bounded, each rung logged) and delivery
//!   completes.
//! - `kill_switch_toggle_mid_drain` — sends refuse with
//!   `TransportError::KillSwitch` while engaged; the queued drain
//!   completes after release.
//! - `descriptor_republish_after_roaming_flap` — `on_network_changed`
//!   roaming reset; the peer re-fetches the descriptor over fresh
//!   circuits and delivery resumes in both directions.
//! - `duplicate_frame_hash_dedup` — identical frame bytes twice on the
//!   wire: one ledger row, one `Message` event, one `first_sight=false`
//!   drop (SeenRing fingerprint = first 16 bytes of SHA-256 over the
//!   frame; engine-level dedup by msg_id/app_seq backs it up).
//! - `burst_quiet_alert` — 100 quiet + 20 alert frames; all delivered;
//!   each alert frame surfaces exactly one arrival.
//! - `attachment_multichunk_relay_death` — ~200 KiB (8 chunks); the
//!   receiver's tor dies mid-transfer and restarts; resync/retransmit
//!   completes the transfer byte-exact.
//!
//! Deviations forced by the public API (no core edits allowed):
//! - "kill -9" is `SubprocessTor::stop()`, which is tokio's
//!   `Child::kill` — SIGKILL on Unix. There is no public handle to the
//!   child pid; the observable semantics (process dies instantly, the
//!   supervisor must heal) are identical.
//! - "Mid-outbox-drain" for the kill-9 scenario queues records built
//!   with `build_raw_envelope` + `Db::enqueue` so the kill lands while
//!   the drain loop has work, instead of blocking `send_text` on a dead
//!   SOCKS port for minutes per message.
//! - Acks are settled explicitly via `request_resync`: the codebase has
//!   no receipt envelope — a sender's row is acked only when the peer's
//!   RESYNC_REQ receive-view covers its seq (see `reliability.rs`).
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes
//! dir and a `tor` binary is available. Run single-threaded:
//! `--test-threads=1`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use schat_core::store::messages::{DeliveryState, MessagesRepository};
use schat_core::store::outbox::OutboxRepository;
use schat_core::sync;
use schat_core::transport::daemon::TorDaemon;
use schat_core::transport::error::TransportError;
use schat_core::transport::status::TorState;
use schat_core::transport::TransportEvent;
use schat_core::wire_types::envelope::Payload;
use schat_core::wire_types::msg::Msg;
use schat_test_harness::reliability::{
    build_raw_envelope, pair_nodes, peer_onion, pump_one, reliability_dir, request_resync,
    run_until, send_quiet_text, service_reachable, spawn_status_watcher, DeliveryTracker, Outcome,
    RelNode, ScenarioMetrics,
};
use schat_test_harness::{chutney_nodes, tor_binary};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(240);
const PAIR_TIMEOUT: Duration = Duration::from_secs(600);
const STEP_TIMEOUT: Duration = Duration::from_secs(420);
const HEAL_TIMEOUT: Duration = Duration::from_secs(900);
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

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "schat_core=info".into()),
        )
        .with_test_writer()
        .try_init();
}

/// Two fresh instances, online and paired.
async fn paired_nodes(
    a_name: &str,
    b_name: &str,
    nodes_dir: &std::path::Path,
) -> (RelNode, RelNode, String) {
    let mut a = RelNode::new(a_name, nodes_dir).await;
    let mut b = RelNode::new(b_name, nodes_dir).await;
    for node in [&a, &b] {
        assert!(
            node.inst.wait_online(ONLINE_TIMEOUT).await,
            "{} online",
            node.name
        );
    }
    let rel_id = pair_nodes(&mut a, &mut b, PAIR_TIMEOUT).await;
    eprintln!("{a_name}/{b_name} paired");
    (a, b, rel_id)
}

/// Compute metrics, record the outcome, write the JSON, and fail the
/// test on an invariant violation.
fn finish_scenario(
    tracker: &DeliveryTracker,
    sender_db: &schat_core::store::Db,
) -> ScenarioMetrics {
    let mut metrics = tracker.finish(sender_db);
    if let Err(reason) = tracker.assert_invariants(&metrics) {
        metrics.outcome = Outcome::Fail { reason };
    }
    let path = schat_test_harness::reliability::write_metrics(&metrics, &reliability_dir())
        .expect("write metrics");
    eprintln!(
        "scenario {}: sent={} received={} acked={} failed={} dup_drops={} -> {}",
        metrics.scenario,
        metrics.sent,
        metrics.received,
        metrics.acknowledged,
        metrics.failed,
        metrics.duplicate_drop_count,
        path.display()
    );
    if let Outcome::Fail { reason } = &metrics.outcome {
        let sent: Vec<String> = tracker
            .sent_ids()
            .iter()
            .map(|id| schat_core::store::hex_encode(id))
            .collect();
        eprintln!("{} sent ids: {sent:?}", metrics.scenario);
        panic!("{} invariant violated: {reason}", metrics.scenario);
    }
    metrics
}

/// Pump until every tracked message is acked (or honestly failed) on the
/// sender, driving the receiver's resync first.
async fn settle_acks(
    sender: &mut RelNode,
    receiver: &mut RelNode,
    rel_id: &str,
    tracker: &DeliveryTracker,
) {
    request_resync(receiver, rel_id)
        .await
        .expect("resync request");
    run_until(
        &mut [&mut *sender, &mut *receiver],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "all acknowledged",
        |nodes| {
            let (_, _, pending) = tracker.poll_states(&nodes[0].engine.db);
            pending == 0
        },
    )
    .await;
}

/// A sends a burst to B; B's tor stops mid-burst and restarts;
/// every message reaches Acknowledged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_offline_mid_send() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("poa", "pob", &nodes_dir).await;
    let mut tracker = DeliveryTracker::new("peer_offline_mid_send");

    // First half of the burst with B online.
    for i in 0..4 {
        let id = a
            .engine
            .send_text(&rel_id, &format!("burst-{i}"), None)
            .await
            .expect("send");
        tracker.note_sent(id);
    }
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "first half delivered",
        |nodes| tracker.arrivals_from(nodes[1]) >= 4,
    )
    .await;
    tracker.sync_received(&b);
    eprintln!("first half delivered; killing b's tor mid-burst");

    // B's tor dies mid-burst. The remaining immediate sends fail
    // honestly (connect to a dead onion) and the rows ride the outbox.
    b.inst.daemon.stop().await.expect("kill b's tor");
    for i in 4..7 {
        let id = a
            .engine
            .send_text(&rel_id, &format!("burst-{i}"), None)
            .await
            .expect("queue");
        tracker.note_sent(id);
    }
    tracker.observe_outbox_age(&a.engine.db);

    // B returns; the supervisor republishes the same onion (persisted
    // key blob), no app-level action.
    b.inst.daemon.start().await.expect("revive b's tor");
    run_until(
        &mut [&mut b],
        PUMP_INTERVAL,
        ONLINE_TIMEOUT,
        "b's service republished",
        |nodes| service_reachable(nodes[0], &rel_id),
    )
    .await;
    eprintln!("b revived; waiting for the second half");

    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "all delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == tracker.sent_count(),
    )
    .await;
    tracker.sync_received(&b);
    assert!(tracker.all_received());
    tracker.observe_outbox_age(&a.engine.db);

    settle_acks(&mut a, &mut b, &rel_id, &tracker).await;
    let metrics = finish_scenario(&tracker, &a.engine.db);
    assert_eq!(metrics.failed, 0, "no honest failures expected here");

    a.inst.stop().await;
    b.inst.stop().await;
}

/// kill -9 the sender's tor subprocess mid-outbox-drain; the
/// supervisor must restart it (bounded, logged); delivery completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_kill9_supervisor_restart() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("k9a", "k9b", &nodes_dir).await;
    let mut tracker = DeliveryTracker::new("tor_kill9_supervisor_restart");
    let heal_log = Arc::new(Mutex::new(Vec::new()));
    let watcher = spawn_status_watcher(&a.inst.transport, heal_log.clone());

    // Baseline delivery works.
    let id0 = a
        .engine
        .send_text(&rel_id, "before the kill", None)
        .await
        .expect("send");
    tracker.note_sent(id0);
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "baseline delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == 1,
    )
    .await;

    // Queue a small outbox batch, then kill -9 (tokio Child::kill =
    // SIGKILL) while a drain pass is working on it.
    for i in 0..3 {
        let (id, _seq, record) = build_raw_envelope(
            &a,
            &rel_id,
            Payload::Msg(Msg::new(format!("drain-{i}")).unwrap()),
            None,
            DeliveryState::Queued,
        )
        .await
        .expect("build");
        a.engine
            .db
            .enqueue(&id, &rel_id, &record, sync::MESSAGE_TTL_SECS)
            .expect("enqueue");
        tracker.note_sent(id);
    }
    tracker.observe_outbox_age(&a.engine.db);
    {
        let engine = &mut a.engine;
        let daemon = &a.inst.daemon;
        let (drain_res, _) = tokio::join!(engine.drain_outbox(), async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            // kill -9: SIGKILL without reaping the handle — the
            // supervisor's unexpected-exit poll owns detection + restart.
            daemon.simulate_crash().await.expect("kill -9 a's tor");
            eprintln!("a's tor killed (SIGKILL) mid-drain");
        });
        // The drain's sends failed honestly; rows stay queued.
        let _ = drain_res;
    }

    // The supervisor must notice the dead control connection, climb the
    // heal ladder and restart tor (bounded: MAX_RESTARTS per window).
    let deadline = Instant::now() + HEAL_TIMEOUT;
    loop {
        let st = a.inst.transport.status();
        if matches!(st.tor, TorState::Online) {
            break;
        }
        assert!(
            !matches!(st.tor, TorState::Dead { .. }),
            "supervisor declared tor dead (restart budget exhausted?): {st:?}"
        );
        assert!(
            Instant::now() < deadline,
            "supervisor did not bring tor back online; last status {st:?}"
        );
        tokio::time::sleep(PUMP_INTERVAL).await;
    }
    eprintln!("supervisor restarted a's tor; waiting for republish");
    run_until(
        &mut [&mut a],
        PUMP_INTERVAL,
        ONLINE_TIMEOUT,
        "a's service republished",
        |nodes| service_reachable(nodes[0], &rel_id),
    )
    .await;

    // Delivery completes.
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "queued batch delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == tracker.sent_count(),
    )
    .await;
    tracker.sync_received(&b);
    assert!(tracker.all_received());

    settle_acks(&mut a, &mut b, &rel_id, &tracker).await;

    for event in heal_log.lock().expect("heal log").iter() {
        tracker.note_heal(event.clone());
    }
    watcher.abort();
    let metrics = finish_scenario(&tracker, &a.engine.db);
    assert!(
        !metrics.heal_events.is_empty(),
        "TransportStatus must surface the heal transitions"
    );
    assert!(
        metrics
            .heal_events
            .iter()
            .any(|e| e.contains("Degraded") || e.contains("heal")),
        "expected a Degraded transition or a logged heal rung: {:?}",
        metrics.heal_events
    );

    a.inst.stop().await;
    b.inst.stop().await;
}

/// queue messages, engage the kill switch mid-drain (sends
/// refuse at the Transport trait level), release, drain completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_switch_toggle_mid_drain() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("ksa", "ksb", &nodes_dir).await;
    let mut tracker = DeliveryTracker::new("kill_switch_toggle_mid_drain");
    let b_onion = peer_onion(&a, &rel_id);

    // Baseline delivery works.
    let id0 = a
        .engine
        .send_text(&rel_id, "before the switch", None)
        .await
        .expect("send");
    tracker.note_sent(id0);
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "baseline delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == 1,
    )
    .await;

    // Engage: sends refuse at the Transport trait level.
    a.inst
        .transport
        .set_kill_switch(true)
        .await
        .expect("kill switch on");
    let err = a
        .inst
        .transport
        .send_frame(
            &b_onion,
            &schat_test_harness::TestInstance::text_record("refused"),
            false,
        )
        .await
        .expect_err("send must be refused while the kill switch is on");
    assert!(
        matches!(err, TransportError::KillSwitch),
        "expected KillSwitch refusal, got {err:?}"
    );
    assert!(a.inst.transport.status().kill_switch);

    // Queue a batch: the immediate send fails honestly, rows stay queued.
    for i in 0..5 {
        let id = a
            .engine
            .send_text(&rel_id, &format!("queued-{i}"), None)
            .await
            .expect("queue");
        tracker.note_sent(id);
    }
    // Mid-drain with the switch on: every attempt refuses, nothing leaves.
    let _ = a.engine.drain_outbox().await;
    let (_, _, pending) = tracker.poll_states(&a.engine.db);
    assert_eq!(pending, 6, "everything still queued behind the switch");
    tracker.observe_outbox_age(&a.engine.db);
    tracker.sync_received(&b);
    assert_eq!(
        tracker.arrivals_from(&b),
        1,
        "only the pre-switch baseline arrived"
    );

    // Release: the drain completes.
    a.inst
        .transport
        .set_kill_switch(false)
        .await
        .expect("kill switch off");
    run_until(
        &mut [&mut a],
        PUMP_INTERVAL,
        ONLINE_TIMEOUT,
        "a back online",
        |nodes| matches!(nodes[0].inst.transport.status().tor, TorState::Online),
    )
    .await;
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "queued batch delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == tracker.sent_count(),
    )
    .await;
    tracker.sync_received(&b);
    assert!(tracker.all_received());

    settle_acks(&mut a, &mut b, &rel_id, &tracker).await;
    finish_scenario(&tracker, &a.engine.db);

    a.inst.stop().await;
    b.inst.stop().await;
}

/// pair, verify reachability, drive `on_network_changed`
/// (roaming reset) on B; B's tor re-fetches A's descriptor over fresh
/// circuits and delivery resumes. (The descriptor re-fetch itself is
/// tor-internal; delivery resumption after the flap is the observable
/// proof — B cannot reach A's onion without it.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn descriptor_republish_after_roaming_flap() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("rfa", "rfb", &nodes_dir).await;
    // The tracked direction is B -> A: B is the roaming client that must
    // re-fetch A's descriptor after the flap.
    let mut tracker = DeliveryTracker::new("descriptor_republish_after_roaming_flap");
    let heal_log = Arc::new(Mutex::new(Vec::new()));
    let watcher = spawn_status_watcher(&b.inst.transport, heal_log.clone());

    // Baseline A -> B proves both descriptors resolve pre-flap.
    let baseline = a
        .engine
        .send_text(&rel_id, "pre-flap a->b", None)
        .await
        .expect("send");
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "baseline delivered",
        |nodes| {
            nodes[1].has_event(
                |e| matches!(e, schat_core::engine::EngineEvent::Message { msg_id, .. } if *msg_id == baseline),
            )
        },
    )
    .await;
    assert!(service_reachable(&a, &rel_id), "a reachable pre-flap");
    assert!(service_reachable(&b, &rel_id), "b reachable pre-flap");

    // Roaming flap on B: path lost, then regained (DisableNetwork
    // 1 -> 0 bounce roaming reset).
    b.inst
        .transport
        .on_network_changed(false)
        .await
        .expect("path lost");
    assert!(matches!(
        b.inst.transport.status().tor,
        TorState::Degraded { .. }
    ));
    b.inst
        .transport
        .on_network_changed(true)
        .await
        .expect("path regained");
    run_until(
        &mut [&mut b],
        PUMP_INTERVAL,
        ONLINE_TIMEOUT,
        "b back online after flap",
        |nodes| service_reachable(nodes[0], &rel_id),
    )
    .await;
    eprintln!("b survived the roaming flap; sending b->a");

    // B -> A over fresh circuits (descriptor re-fetch), then A -> B.
    for i in 0..3 {
        let id = b
            .engine
            .send_text(&rel_id, &format!("post-flap b->a {i}"), None)
            .await
            .expect("send");
        tracker.note_sent(id);
    }
    let ab = a
        .engine
        .send_text(&rel_id, "post-flap a->b", None)
        .await
        .expect("send");
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "post-flap delivery both directions",
        |nodes| {
            tracker.arrivals_from(nodes[0]) == tracker.sent_count()
                && nodes[1].has_event(
                    |e| matches!(e, schat_core::engine::EngineEvent::Message { msg_id, .. } if *msg_id == ab),
                )
        },
    )
    .await;
    tracker.sync_received(&a);
    assert!(tracker.all_received());

    settle_acks(&mut b, &mut a, &rel_id, &tracker).await;
    for event in heal_log.lock().expect("heal log").iter() {
        tracker.note_heal(event.clone());
    }
    watcher.abort();
    let metrics = finish_scenario(&tracker, &b.engine.db);
    assert!(
        metrics
            .heal_events
            .iter()
            .any(|e| e.contains("Degraded") && e.contains("Online")),
        "the flap must be visible in b's TransportStatus: {:?}",
        metrics.heal_events
    );

    a.inst.stop().await;
    b.inst.stop().await;
}

/// the same raw frame bytes twice on the wire. The SeenRing
/// fingerprints frame bytes (first 16 bytes of SHA-256) and flags the
/// replay `first_sight=false`; the engine's msg_id/app_seq dedup backs
/// it up. Exactly one ledger row, one Message event, one duplicate drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_frame_hash_dedup() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("dpa", "dpb", &nodes_dir).await;
    let mut tracker = DeliveryTracker::new("duplicate_frame_hash_dedup");
    let b_onion = peer_onion(&a, &rel_id);

    let (msg_id, _seq, record) = build_raw_envelope(
        &a,
        &rel_id,
        Payload::Msg(Msg::new("exactly once".into()).unwrap()),
        None,
        DeliveryState::Transmitted,
    )
    .await
    .expect("build");
    tracker.note_sent(msg_id);

    // Identical bytes, twice, through the real send path.
    a.inst
        .transport
        .send_frame(&b_onion, &record, false)
        .await
        .expect("first send");
    a.inst
        .transport
        .send_frame(&b_onion, &record, false)
        .await
        .expect("replay send");

    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "message delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == 1,
    )
    .await;
    // Give the replay its window to arrive and be dropped.
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        pump_one(&mut b).await;
        if b.dup_drops >= 1 {
            break;
        }
        tokio::time::sleep(PUMP_INTERVAL).await;
    }
    tracker.sync_received(&b);

    assert_eq!(
        b.dup_drops, 1,
        "exactly one first_sight=false drop (the replay)"
    );
    assert_eq!(
        b.count_events(
            |e| matches!(e, schat_core::engine::EngineEvent::Message { msg_id: id, .. } if *id == msg_id)
        ),
        1,
        "exactly one Message event"
    );
    assert!(
        b.engine
            .db
            .message(&msg_id)
            .expect("lookup")
            .is_some_and(|r| r.direction == schat_core::store::messages::Direction::In),
        "exactly one inbound ledger row"
    );
    tracker.note_duplicate_drops(b.dup_drops);

    settle_acks(&mut a, &mut b, &rel_id, &tracker).await;
    let metrics = finish_scenario(&tracker, &a.engine.db);
    assert_eq!(metrics.duplicate_drop_count, 1);

    a.inst.stop().await;
    b.inst.stop().await;
}

/// 100 quiet + 20 alert frames as fast as the send path goes;
/// all delivered; every alert frame surfaces exactly one arrival
/// (first_sight) and exactly one `TransportEvent::Arrival`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn burst_quiet_alert() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("bqa", "bqb", &nodes_dir).await;
    let mut tracker = DeliveryTracker::new("burst_quiet_alert");

    let arrival_count = Arc::new(AtomicU32::new(0));
    {
        let mut rx = b.inst.transport.subscribe_events();
        let counter = arrival_count.clone();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(TransportEvent::Arrival { .. }) => {
                        counter.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("arrival collector lagged by {n}");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // The burst: 100 quiet, then 20 alert, back-to-back.
    for i in 0..100 {
        let id = send_quiet_text(&mut a, &rel_id, &format!("quiet-{i}"))
            .await
            .expect("quiet send");
        tracker.note_sent(id);
    }
    for i in 0..20 {
        let id = a
            .engine
            .send_text(&rel_id, &format!("alert-{i}"), None)
            .await
            .expect("alert send");
        tracker.note_sent(id);
    }
    eprintln!("120 frames sent; waiting for delivery");

    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        STEP_TIMEOUT,
        "burst delivered",
        |nodes| tracker.arrivals_from(nodes[1]) == tracker.sent_count(),
    )
    .await;
    tracker.sync_received(&b);
    assert!(tracker.all_received());
    assert_eq!(b.dup_drops, 0, "no duplicates in a clean burst");
    assert_eq!(
        b.alert_arrivals, 20,
        "each alert frame surfaced as a first-sight arrival exactly once"
    );
    // The Arrival event rides the same alert&&first_sight gate.
    let arrivals = arrival_count.load(Ordering::SeqCst);
    assert_eq!(arrivals, 20, "TransportEvent::Arrival fired once per alert");
    tracker.note_duplicate_drops(b.dup_drops);
    tracker.extra("alert_frames", serde_json::Value::from(20));
    tracker.extra("quiet_frames", serde_json::Value::from(100));

    settle_acks(&mut a, &mut b, &rel_id, &tracker).await;
    finish_scenario(&tracker, &a.engine.db);

    a.inst.stop().await;
    b.inst.stop().await;
}

/// ~200 KiB attachment (8 data chunks, bucket 8 — no pads);
/// B's tor dies once the transfer is visibly underway and restarts;
/// resync/retransmit completes the transfer byte-exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachment_multichunk_relay_death() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let (mut a, mut b, rel_id) = paired_nodes("ata", "atb", &nodes_dir).await;
    let mut tracker = DeliveryTracker::new("attachment_multichunk_relay_death");

    let payload: Vec<u8> = (0..200 * 1024u32).map(|i| (i % 251) as u8).collect();
    let spec = schat_core::attach::AttachmentSpec {
        media_class: schat_core::attach::class_for_mime("video/mp4"),
        mime_hint: "video/mp4".into(),
        orig_ext: "mp4".into(),
        bytes: payload.clone(),
        caption: "file".into(),
        view_once: false,
    };

    // Kill B's tor once five frames (head + 4 chunks) have landed at B's
    // listener — a genuine mid-transfer death — then bring it back.
    let mut peek = b.inst.drops();
    let daemon = b.inst.daemon.clone();
    let killer = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut seen = 0u32;
        while seen < 5 && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(10), peek.recv()).await {
                Ok(Ok(_)) => seen += 1,
                Ok(Err(_)) => continue,
                Err(_) => {}
            }
        }
        daemon.stop().await.expect("kill b's tor mid-transfer");
        eprintln!("b's tor killed mid-transfer after {seen} inbound frames");
        tokio::time::sleep(Duration::from_secs(3)).await;
        daemon.start().await.expect("revive b's tor");
        eprintln!("b's tor restarted");
    });

    let head_id = a
        .engine
        .send_attachment(&rel_id, &spec)
        .await
        .expect("send attachment");
    tracker.note_sent(head_id);
    killer.await.expect("killer task");
    tracker.observe_outbox_age(&a.engine.db);

    run_until(
        &mut [&mut b],
        PUMP_INTERVAL,
        ONLINE_TIMEOUT,
        "b's service republished",
        |nodes| service_reachable(nodes[0], &rel_id),
    )
    .await;

    // Resync/retransmit converges the transfer.
    run_until(
        &mut [&mut a, &mut b],
        PUMP_INTERVAL,
        Duration::from_secs(600),
        "attachment complete",
        |nodes| {
            nodes[1].has_event(
                |e| matches!(e, schat_core::engine::EngineEvent::AttachmentComplete { head_id: id, .. } if *id == head_id),
            )
        },
    )
    .await;
    let got = b
        .engine
        .attachment_bytes(&head_id)
        .expect("bytes")
        .expect("complete");
    assert_eq!(got, payload, "reassembled bytes match after relay death");
    tracker.note_received(head_id);
    tracker.extra(
        "payload_bytes",
        serde_json::Value::from(payload.len() as u64),
    );
    tracker.extra("data_chunks", serde_json::Value::from(8));

    settle_acks(&mut a, &mut b, &rel_id, &tracker).await;
    finish_scenario(&tracker, &a.engine.db);

    a.inst.stop().await;
    b.inst.stop().await;
}
