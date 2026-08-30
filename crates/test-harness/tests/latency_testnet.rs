//! Hot-path latency over real onion services on the
//! Chutney `s-chat6-min` network.
//!
//! "Hot": `TransportStatus.tor == Online`, the
//! per-relationship service `Reachable`, and a SOCKS stream to the peer
//! inside the 60 s post-send reuse window (`CONVERSATION_HOLD`). Each
//! sample verifies the first two legs against the live status and the
//! third by construction (samples are back-to-back; a sample later than
//! 60 s after the previous send is counted as a hot-window violation).
//! Warm-up: one full round-trip per pair before measuring.
//!
//! Ack path (documented in `reliability.rs`): there is no receipt
//! envelope — a sender's row reaches `Acknowledged` only when the peer's
//! RESYNC_REQ receive-view covers its seq. One-shot messages never get
//! acked without a resync, so each sample drives the receiver's resync
//! explicitly (`request_resync`) and the two legs are measured as
//! separate series: `arrival` (t_send -> peer Message event) and
//! `round_trip` (t_send -> sender-side Acknowledged). The `msg_hot`
//! budget gates the round-trip series.
//!
//! Resync pacing: handling a RESYNC_REQ costs the sender a receive-view
//! scan, so core rate-limits it per relationship (burst 8, refill 1/s —
//! `limits::rate::RESYNC_REQ_*`). Samples are therefore paced
//! (`SAMPLE_PERIOD` apart, send-to-send) so each driven resync is
//! handled; the pacing sits *between* samples and never inside a
//! measured leg. An occasional dropped request is re-driven while
//! waiting for the ack.
//!
//! Cold path: reported separately, NOT gated. Deviation forced by the
//! public API: there is no NEWNYM handle on `Transport`, so "cold" here
//! is (a) the fresh-pair warm-up sample and (b) the first message after
//! the 60 s conversation-hold expiry (fresh SOCKS connect + circuit;
//! tor's descriptor cache survives — a real NEWNYM would also drop
//! descriptors, so these numbers are a lower bound on true cold).
//!
//! Budgets: `tools/reliability/latency-budgets.json` (override with
//! `SCHAT_LATENCY_BUDGETS` — point dev runs at a throwaway copy so the
//! checked-in baseline is only written by full runs). The test fails
//! when a gate is exceeded or when a series regresses >10% vs its
//! baseline entry; a missing baseline entry is written from the run.
//!
//! Knobs: `SCHAT_LATENCY_SAMPLES` (default 200) per scenario,
//! `SCHAT_LATENCY_COLD_SAMPLES` (default 3).
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes
//! dir and a `tor` binary is available. Run single-threaded:
//! `--test-threads=1`.

use std::path::Path;
use std::time::{Duration, Instant, SystemTime};

use schat_core::engine::EngineEvent;
use schat_core::store::messages::{DeliveryState, MessagesRepository};
use schat_test_harness::latency::{Budgets, LatencySeries};
use schat_test_harness::reliability::{
    pair_nodes, pump_one, reliability_dir, request_resync, send_quiet_text, service_reachable,
    write_metrics, Outcome, RelNode, ScenarioMetrics,
};
use schat_test_harness::{chutney_nodes, tor_binary};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(240);
const PAIR_TIMEOUT: Duration = Duration::from_secs(600);
/// Latency sampling pumps fast — the 2 s reliability interval would
/// dominate the measurement.
const FAST_PUMP: Duration = Duration::from_millis(50);
/// Per-sample leg timeout: a miss is a reliability bug, not an outlier.
const SAMPLE_TIMEOUT: Duration = Duration::from_secs(90);
const ATTACH_SAMPLE_TIMEOUT: Duration = Duration::from_secs(180);
/// `socks::CONVERSATION_HOLD` — the hot window.
const HOLD: Duration = Duration::from_secs(60);
/// Send-to-send spacing so each driven RESYNC_REQ fits the sender-side
/// per-relationship token bucket (refill 1/s). Sits between samples,
/// never inside a measured leg.
const SAMPLE_PERIOD: Duration = Duration::from_millis(1200);
/// While waiting for an ack, re-drive the resync this often in case the
/// request lost the token-bucket race.
const RESYNC_RETRY: Duration = Duration::from_millis(2500);

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

fn samples_env() -> usize {
    std::env::var("SCHAT_LATENCY_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
}

fn cold_samples_env() -> usize {
    std::env::var("SCHAT_LATENCY_COLD_SAMPLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3)
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn paired(a_name: &str, b_name: &str, nodes_dir: &Path) -> (RelNode, RelNode, String) {
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

/// One timed quiet-text sample: t_send -> peer arrival -> (receiver
/// resync) -> sender-side Acknowledged. Returns (arrival, round_trip).
async fn timed_sample(
    a: &mut RelNode,
    b: &mut RelNode,
    rel_id: &str,
    body: &str,
) -> (Duration, Duration) {
    let t0 = Instant::now();
    let id = send_quiet_text(a, rel_id, body).await.expect("send");
    loop {
        pump_one(b).await;
        if b.has_event(|e| matches!(e, EngineEvent::Message { msg_id, .. } if *msg_id == id)) {
            break;
        }
        assert!(
            t0.elapsed() < SAMPLE_TIMEOUT,
            "arrival timeout for {body} (a reliability bug, not a latency outlier)"
        );
        tokio::time::sleep(FAST_PUMP).await;
    }
    let arrival = t0.elapsed();

    request_resync(b, rel_id).await.expect("resync");
    let mut last_retry = Instant::now();
    loop {
        pump_one(a).await;
        pump_one(b).await;
        let acked = a
            .engine
            .db
            .message(&id)
            .expect("lookup")
            .is_some_and(|r| r.state == DeliveryState::Acknowledged);
        if acked {
            break;
        }
        assert!(t0.elapsed() < SAMPLE_TIMEOUT, "ack timeout for {body}");
        if last_retry.elapsed() >= RESYNC_RETRY {
            // The request may have lost the token-bucket race at the
            // sender; drive it again.
            request_resync(b, rel_id).await.expect("resync retry");
            last_retry = Instant::now();
        }
        tokio::time::sleep(FAST_PUMP).await;
    }
    (arrival, t0.elapsed())
}

/// `timed_sample` + inter-sample pacing: returns only after
/// `SAMPLE_PERIOD` has elapsed since t_send, keeping driven resyncs
/// inside the sender's 1/s refill. The sleep is outside both measured
/// legs.
async fn paced_sample(
    a: &mut RelNode,
    b: &mut RelNode,
    rel_id: &str,
    body: &str,
) -> (Duration, Duration) {
    let (arrival, round_trip) = timed_sample(a, b, rel_id, body).await;
    if round_trip < SAMPLE_PERIOD {
        tokio::time::sleep(SAMPLE_PERIOD - round_trip).await;
    }
    (arrival, round_trip)
}

fn latency_metrics(
    scenario: &str,
    sample_count: u32,
    started_at: u64,
    started: Instant,
    extra: serde_json::Map<String, serde_json::Value>,
) -> ScenarioMetrics {
    ScenarioMetrics {
        scenario: scenario.into(),
        sent: sample_count,
        received: sample_count,
        acknowledged: sample_count,
        failed: 0,
        delivery_rate: 1.0,
        duplicate_drop_count: 0,
        false_negative_count: 0,
        heal_events: Vec::new(),
        max_outbox_age_secs: 0,
        started_at,
        finished_at: epoch_secs(),
        duration_secs: started.elapsed().as_secs_f64(),
        outcome: Outcome::Pass,
        extra,
    }
}

/// Gate a measured series: write the baseline on first run, fail the
/// test on budget or regression violations.
fn gate_scenario(
    budgets: &mut Budgets,
    scenario: &str,
    measured: &schat_test_harness::latency::Percentiles,
    metrics: &mut ScenarioMetrics,
) {
    let violations = budgets.violations(scenario, measured);
    match budgets.ensure_baseline(scenario, measured) {
        Ok(true) => eprintln!("baseline for {scenario} written to the budgets file"),
        Ok(false) => {}
        Err(e) => eprintln!("baseline write failed: {e}"),
    }
    metrics.extra.insert(
        format!("{scenario}_violations"),
        serde_json::Value::from(violations.clone()),
    );
    if !violations.is_empty() {
        metrics.outcome = Outcome::Fail {
            reason: violations.join("; "),
        };
    }
}

fn pct_value(p: &schat_test_harness::latency::Percentiles) -> serde_json::Value {
    serde_json::to_value(p).expect("percentiles serialize")
}

/// Hot MSG latency (arrival + round-trip series,
/// ≥200 samples), cold path reported separately.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn msg_hot_and_cold_latency() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let samples = samples_env();
    let cold_samples = cold_samples_env();
    let (mut a, mut b, rel_id) = paired("lha", "lhb", &nodes_dir).await;
    let started_at = epoch_secs();
    let started = Instant::now();

    // Warm-up: one full round-trip. This is also the fresh-pair cold
    // sample (no pooled stream, first descriptor fetch).
    let (cold_arrival, cold_round_trip) = paced_sample(&mut a, &mut b, &rel_id, "warm-up").await;
    let mut cold_arrivals = LatencySeries::new("msg_cold_arrival");
    let mut cold_round_trips = LatencySeries::new("msg_cold_round_trip");
    cold_arrivals.record(cold_arrival);
    cold_round_trips.record(cold_round_trip);
    eprintln!("warm-up (cold #0): arrival {cold_arrival:?}, round-trip {cold_round_trip:?}");

    // Hot loop.
    let mut arrivals = LatencySeries::new("msg_hot_arrival");
    let mut round_trips = LatencySeries::new("msg_hot_round_trip");
    let mut hot_violations = 0u32;
    let mut last_send = Instant::now();
    for i in 0..samples {
        if !(service_reachable(&a, &rel_id)
            && service_reachable(&b, &rel_id)
            && last_send.elapsed() < HOLD)
        {
            hot_violations += 1;
        }
        let (arrival, round_trip) =
            paced_sample(&mut a, &mut b, &rel_id, &format!("hot-{i}")).await;
        last_send = Instant::now();
        arrivals.record(arrival);
        round_trips.record(round_trip);
        if i % 25 == 24 || i + 1 == samples {
            eprintln!(
                "hot {}/{samples}: arrival {:?}, round-trip {:?}",
                i + 1,
                arrivals.percentiles().p50_ms,
                round_trips.percentiles().p50_ms
            );
        }
    }
    assert_eq!(hot_violations, 0, "hot preconditions must hold per sample");

    // Cold series: first message after the conversation-hold expiry.
    for k in 0..cold_samples {
        eprintln!("cold #{k}: waiting out the 60 s hold window");
        tokio::time::sleep(HOLD + Duration::from_secs(5)).await;
        let (arrival, round_trip) =
            timed_sample(&mut a, &mut b, &rel_id, &format!("cold-{k}")).await;
        cold_arrivals.record(arrival);
        cold_round_trips.record(round_trip);
        eprintln!(
            "cold #{}: arrival {arrival:?}, round-trip {round_trip:?}",
            k + 1
        );
    }

    // Metrics + budgets.
    let budgets_path = schat_test_harness::latency::budgets_path();
    let mut budgets = Budgets::load(&budgets_path).expect("load latency budgets");

    let arrival_pct = arrivals.percentiles();
    let round_trip_pct = round_trips.percentiles();
    eprintln!("hot arrival: {arrival_pct:?}");
    eprintln!("hot round-trip: {round_trip_pct:?}");

    let mut extra = serde_json::Map::new();
    extra.insert("arrival".into(), pct_value(&arrival_pct));
    extra.insert("round_trip".into(), pct_value(&round_trip_pct));
    extra.insert("samples".into(), serde_json::Value::from(samples as u64));
    extra.insert(
        "ack_mechanism".into(),
        serde_json::Value::from("receiver RESYNC_REQ receive-view (request_resync)"),
    );
    let mut metrics = latency_metrics(
        "latency_msg_hot",
        samples as u32,
        started_at,
        started,
        extra,
    );
    gate_scenario(&mut budgets, "msg_hot", &round_trip_pct, &mut metrics);
    let path = write_metrics(&metrics, &reliability_dir()).expect("write metrics");
    eprintln!("wrote {}", path.display());

    // Cold: reported, never gated.
    let mut cold_extra = serde_json::Map::new();
    cold_extra.insert("arrival".into(), pct_value(&cold_arrivals.percentiles()));
    cold_extra.insert(
        "round_trip".into(),
        pct_value(&cold_round_trips.percentiles()),
    );
    cold_extra.insert(
        "definition".into(),
        serde_json::Value::from(
            "fresh-pair warm-up + first message after the 60 s conversation-hold expiry \
             (no public NEWNYM handle; see test header)",
        ),
    );
    let cold_metrics = latency_metrics(
        "latency_msg_cold",
        cold_arrivals.samples_ms.len() as u32,
        started_at,
        started,
        cold_extra,
    );
    let path = write_metrics(&cold_metrics, &reliability_dir()).expect("write metrics");
    eprintln!("wrote {}", path.display());

    a.inst.stop().await;
    b.inst.stop().await;

    if let Outcome::Fail { reason } = &metrics.outcome {
        panic!("msg_hot budget violated: {reason}");
    }
}

/// Attachment head + 4 chunks round-trip latency.
/// (`chunk_count == 4` at 100 KiB; the bucket granularity pads the
/// transfer to 8 chunk frames — 4 data + 4 pads — which all ride along.
/// Completion fires on the 4 data chunks.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attach_head_plus_4_chunks_latency() {
    init_tracing();
    let nodes_dir = require_testnet!();
    let samples = samples_env();
    let (mut a, mut b, rel_id) = paired("ala", "alb", &nodes_dir).await;
    let started_at = epoch_secs();
    let started = Instant::now();

    let payload: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    let spec = schat_core::attach::AttachmentSpec {
        media_class: schat_core::attach::class_for_mime("video/mp4"),
        mime_hint: "video/mp4".into(),
        orig_ext: "mp4".into(),
        bytes: payload.clone(),
        caption: "file".into(),
        view_once: false,
    };

    // Warm-up round-trip (also primes the pool).
    let (wa, wr) = timed_sample(&mut a, &mut b, &rel_id, "warm-up").await;
    eprintln!("warm-up: arrival {wa:?}, round-trip {wr:?}");

    let mut series = LatencySeries::new("attach_head_plus_4_chunks");
    let mut head_ids = Vec::new();
    for i in 0..samples {
        let t0 = Instant::now();
        let head_id = a
            .engine
            .send_attachment(&rel_id, &spec)
            .await
            .expect("send attachment");
        head_ids.push(head_id);
        loop {
            pump_one(&mut b).await;
            if b.has_event(
                |e| matches!(e, EngineEvent::AttachmentComplete { head_id: id, .. } if *id == head_id),
            ) {
                break;
            }
            assert!(
                t0.elapsed() < ATTACH_SAMPLE_TIMEOUT,
                "attachment {i} did not complete (a reliability bug, not an outlier)"
            );
            tokio::time::sleep(FAST_PUMP).await;
        }
        series.record(t0.elapsed());
        if i % 10 == 9 || i + 1 == samples {
            eprintln!(
                "attach {}/{samples}: {:?}",
                i + 1,
                series.percentiles().p50_ms
            );
        }
        let got = b
            .engine
            .attachment_bytes(&head_id)
            .expect("bytes")
            .expect("complete");
        assert_eq!(got, payload, "sample {i}: reassembled bytes match");
    }

    // Settle acks once (one resync covers every transfer) so the metrics
    // tell the truth about the ledger.
    request_resync(&mut b, &rel_id).await.expect("resync");
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        pump_one(&mut a).await;
        pump_one(&mut b).await;
        let pending = head_ids
            .iter()
            .filter(|id| {
                !a.engine
                    .db
                    .message(id)
                    .expect("lookup")
                    .is_some_and(|r| r.state == DeliveryState::Acknowledged)
            })
            .count();
        if pending == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "attach acks did not settle");
        tokio::time::sleep(FAST_PUMP).await;
    }

    let pct = series.percentiles();
    eprintln!("attach head+4 chunks: {pct:?}");
    let budgets_path = schat_test_harness::latency::budgets_path();
    let mut budgets = Budgets::load(&budgets_path).expect("load latency budgets");
    let mut extra = serde_json::Map::new();
    extra.insert("round_trip".into(), pct_value(&pct));
    extra.insert("samples".into(), serde_json::Value::from(samples as u64));
    extra.insert(
        "payload_bytes".into(),
        serde_json::Value::from(payload.len() as u64),
    );
    extra.insert(
        "note".into(),
        serde_json::Value::from(
            "chunk_count=4; bucket granularity pads to 8 chunk frames (4 data + 4 pads)",
        ),
    );
    let mut metrics = latency_metrics(
        "latency_attach_head_plus_4_chunks",
        samples as u32,
        started_at,
        started,
        extra,
    );
    gate_scenario(
        &mut budgets,
        "attach_head_plus_4_chunks",
        &pct,
        &mut metrics,
    );
    let path = write_metrics(&metrics, &reliability_dir()).expect("write metrics");
    eprintln!("wrote {}", path.display());

    a.inst.stop().await;
    b.inst.stop().await;

    if let Outcome::Fail { reason } = &metrics.outcome {
        panic!("attach budget violated: {reason}");
    }
}
