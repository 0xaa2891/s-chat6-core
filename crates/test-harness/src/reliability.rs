//! Send/receive reliability harness.
//!
//! Scenario metrics ([`ScenarioMetrics`] + [`write_metrics`]), the
//! [`DeliveryTracker`] (records sends, arrivals, duplicate drops and heal
//! events; computes and asserts the delivery invariants), and the
//! shared node/pump plumbing the Chutney suites in
//! `tests/reliability_testnet.rs` and `tests/latency_testnet.rs` drive.
//!
//! Ack path (read before extending): there is no receipt envelope for
//! ordinary delivery. A sender's row reaches `DeliveryState::Acknowledged`
//! only when the peer's `RESYNC_REQ` receive-view covers its `app_seq`
//! (`sync::resync::handle_request` → `mark_acknowledged`). Receivers emit
//! `RESYNC_REQ` on activation and on a detected seq gap (throttled); the
//! harness settles acks explicitly with [`request_resync`].

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use schat_core::engine::{send::send_envelope, Engine, EngineError, EngineEvent};
use schat_core::pairing::{self, Ingest};
use schat_core::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use schat_core::store::{hex_encode, Db};
use schat_core::transport::inbound::InboundDrop;
use schat_core::transport::status::{ServiceState, TorState};
use schat_core::transport::Transport;
use schat_core::wire_types::envelope::{Envelope, Payload};
use schat_core::{session, sync};
use serde::Serialize;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::TryRecvError;

use crate::TestInstance;

/// Where scenario metrics land: `$SCHAT_RELIABILITY_DIR` or
/// `<workspace>/target/reliability`.
pub fn reliability_dir() -> PathBuf {
    std::env::var_os("SCHAT_RELIABILITY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/reliability")
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail { reason: String },
}

/// One scenario's asserted outcomes + metrics.
#[derive(Clone, Debug, Serialize)]
pub struct ScenarioMetrics {
    pub scenario: String,
    pub sent: u32,
    pub received: u32,
    pub acknowledged: u32,
    pub failed: u32,
    pub delivery_rate: f64,
    pub duplicate_drop_count: u32,
    /// Marked `Failed` on the sender but actually delivered — the
    /// honesty tripwire.
    pub false_negative_count: u32,
    /// Supervisor heal transitions observed, with reasons.
    pub heal_events: Vec<String>,
    pub max_outbox_age_secs: u64,
    pub started_at: u64,
    pub finished_at: u64,
    pub duration_secs: f64,
    pub outcome: Outcome,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Serialize one scenario's metrics to `<dir>/<scenario>.json`,
/// creating the directory tree as needed.
pub fn write_metrics(metrics: &ScenarioMetrics, dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{}.json", metrics.scenario));
    let body = serde_json::to_string_pretty(metrics).map_err(std::io::Error::other)?;
    std::fs::write(&path, body)?;
    Ok(path)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Records what a scenario sent and what the peer (say it received),
/// then computes the delivery matrix and asserts the delivery
/// invariants: `sent == received == acknowledged` (or honest `Failed`),
/// zero silent drops, zero cross-peer delivery (I4).
pub struct DeliveryTracker {
    scenario: String,
    sent: Vec<[u8; 16]>,
    sent_set: HashSet<[u8; 16]>,
    received: HashSet<[u8; 16]>,
    /// Arrivals whose msg_id was never sent by the tracked sender (I4).
    foreign: Vec<[u8; 16]>,
    /// Engine-level duplicate arrivals (a second `Message` event for an
    /// already-received msg_id — must never happen).
    duplicate_arrivals: u32,
    duplicate_drop_count: u32,
    /// Per-node fold cursor (node name → events already folded), so
    /// repeated `sync_received` calls stay idempotent.
    scanned: std::collections::HashMap<String, usize>,
    heal_events: Vec<String>,
    max_outbox_age_secs: u64,
    started: Instant,
    started_at: u64,
    extra: serde_json::Map<String, serde_json::Value>,
}

impl DeliveryTracker {
    pub fn new(scenario: &str) -> Self {
        Self {
            scenario: scenario.to_string(),
            sent: Vec::new(),
            sent_set: HashSet::new(),
            received: HashSet::new(),
            foreign: Vec::new(),
            duplicate_arrivals: 0,
            duplicate_drop_count: 0,
            scanned: std::collections::HashMap::new(),
            heal_events: Vec::new(),
            max_outbox_age_secs: 0,
            started: Instant::now(),
            started_at: now_secs(),
            extra: serde_json::Map::new(),
        }
    }

    pub fn note_sent(&mut self, msg_id: [u8; 16]) {
        self.sent.push(msg_id);
        self.sent_set.insert(msg_id);
    }

    pub fn note_received(&mut self, msg_id: [u8; 16]) {
        if !self.sent_set.contains(&msg_id) {
            eprintln!(
                "[{}] foreign arrival: {}",
                self.scenario,
                hex_encode(&msg_id)
            );
            self.foreign.push(msg_id);
        } else if !self.received.insert(msg_id) {
            eprintln!(
                "[{}] duplicate arrival: {}",
                self.scenario,
                hex_encode(&msg_id)
            );
            self.duplicate_arrivals += 1;
        }
    }

    /// Fold a node's accumulated `Message` events into the tracker.
    /// Idempotent — a per-node cursor folds only events appended since
    /// the last call. (The node's event log is append-only; pairing
    /// traffic is cleared by `pair_nodes` before scenarios start.)
    pub fn sync_received(&mut self, node: &RelNode) {
        let from = *self.scanned.get(&node.name).unwrap_or(&0);
        // A cleared log (pair_nodes) resets the fold.
        let from = from.min(node.events.len());
        for event in &node.events[from..] {
            if let EngineEvent::Message { msg_id, .. } = event {
                self.note_received(*msg_id);
            }
        }
        self.scanned.insert(node.name.clone(), node.events.len());
    }

    /// Distinct tracked msg_ids that arrived at `node` (via its event
    /// log — cheap predicate input for `run_until`).
    pub fn arrivals_from(&self, node: &RelNode) -> usize {
        node.events
            .iter()
            .filter_map(|e| match e {
                EngineEvent::Message { msg_id, .. } => Some(*msg_id),
                _ => None,
            })
            .filter(|id| self.sent_set.contains(id))
            .collect::<HashSet<_>>()
            .len()
    }

    pub fn sent_count(&self) -> usize {
        self.sent.len()
    }

    pub fn sent_ids(&self) -> &[[u8; 16]] {
        &self.sent
    }

    pub fn all_received(&self) -> bool {
        self.sent_set.len() == self.received.len() && self.sent_set == self.received
    }

    pub fn note_duplicate_drops(&mut self, count: u32) {
        self.duplicate_drop_count = count;
    }

    pub fn note_heal(&mut self, event: impl Into<String>) {
        self.heal_events.push(event.into());
    }

    /// Oldest outbox row age right now (0 when the queue is empty).
    pub fn observe_outbox_age(&mut self, db: &Db) {
        let oldest: Option<i64> = db
            .conn()
            .query_row("SELECT MIN(created_at) FROM outbox", [], |r| r.get(0))
            .unwrap_or(None);
        if let Some(created) = oldest {
            let age = (db.clock().now_secs()).saturating_sub(created as u64);
            self.max_outbox_age_secs = self.max_outbox_age_secs.max(age);
        }
    }

    pub fn extra(&mut self, key: &str, value: serde_json::Value) {
        self.extra.insert(key.to_string(), value);
    }

    /// Sender-side delivery states: (acknowledged, failed, pending).
    pub fn poll_states(&self, sender_db: &Db) -> (u32, u32, u32) {
        let mut acked = 0;
        let mut failed = 0;
        let mut pending = 0;
        for id in &self.sent {
            match sender_db.message(id).ok().flatten().map(|r| r.state) {
                Some(DeliveryState::Acknowledged) => acked += 1,
                Some(DeliveryState::Failed) => failed += 1,
                _ => pending += 1,
            }
        }
        (acked, failed, pending)
    }

    /// Compute the metrics snapshot from the sender's ledger.
    pub fn finish(&self, sender_db: &Db) -> ScenarioMetrics {
        let (acknowledged, failed, pending) = self.poll_states(sender_db);
        let sent = self.sent.len() as u32;
        let received = self.received.len() as u32;
        let false_negative_count = self
            .sent
            .iter()
            .filter(|id| {
                self.received.contains(*id)
                    && sender_db
                        .message(id)
                        .ok()
                        .flatten()
                        .is_some_and(|r| r.state == DeliveryState::Failed)
            })
            .count() as u32;
        let mut extra = self.extra.clone();
        if pending > 0 {
            extra.insert("pending".into(), serde_json::Value::from(pending));
        }
        if self.duplicate_arrivals > 0 {
            extra.insert(
                "duplicate_arrival_events".into(),
                serde_json::Value::from(self.duplicate_arrivals),
            );
        }
        if !self.foreign.is_empty() {
            extra.insert(
                "foreign_arrivals".into(),
                serde_json::Value::from(
                    self.foreign
                        .iter()
                        .map(|id| hex_encode(id))
                        .collect::<Vec<_>>(),
                ),
            );
        }
        ScenarioMetrics {
            scenario: self.scenario.clone(),
            sent,
            received,
            acknowledged,
            failed,
            delivery_rate: if sent == 0 {
                1.0
            } else {
                f64::from(received) / f64::from(sent)
            },
            duplicate_drop_count: self.duplicate_drop_count,
            false_negative_count,
            heal_events: self.heal_events.clone(),
            max_outbox_age_secs: self.max_outbox_age_secs,
            started_at: self.started_at,
            finished_at: now_secs(),
            duration_secs: self.started.elapsed().as_secs_f64(),
            outcome: Outcome::Pass,
            extra,
        }
    }

    /// The delivery invariant. `metrics` must come from
    /// [`Self::finish`]. Returns the failure reason.
    pub fn assert_invariants(&self, metrics: &ScenarioMetrics) -> Result<(), String> {
        if !self.foreign.is_empty() {
            return Err(format!(
                "I4 violated: {} cross-peer arrivals: {:?}",
                self.foreign.len(),
                self.foreign
                    .iter()
                    .map(|id| hex_encode(id))
                    .collect::<Vec<_>>()
            ));
        }
        if self.duplicate_arrivals > 0 {
            return Err(format!(
                "{} duplicate arrival events (engine dedup broken)",
                self.duplicate_arrivals
            ));
        }
        if metrics.false_negative_count > 0 {
            return Err(format!(
                "{} messages marked Failed but actually delivered",
                metrics.false_negative_count
            ));
        }
        // Zero silent drops: everything sent was either received or
        // honestly failed.
        if metrics.received + metrics.failed != metrics.sent {
            return Err(format!(
                "silent drops: sent {} but received {} + failed {} = {}",
                metrics.sent,
                metrics.received,
                metrics.failed,
                metrics.received + metrics.failed
            ));
        }
        if metrics.acknowledged + metrics.failed != metrics.sent {
            return Err(format!(
                "unsettled rows: sent {} but acknowledged {} + failed {} = {}",
                metrics.sent,
                metrics.acknowledged,
                metrics.failed,
                metrics.acknowledged + metrics.failed
            ));
        }
        Ok(())
    }
}

/// One reliability-suite instance: transport + engine on the system
/// clock + its event log. (The sync suite's `Node`, minus the
/// `FakeClock` — reliability scenarios want real backoff timings.)
pub struct RelNode {
    pub name: String,
    pub inst: TestInstance,
    pub engine: Engine,
    pub drops: broadcast::Receiver<InboundDrop>,
    pub events: Vec<EngineEvent>,
    /// rel_ids that arrived as message requests (inviter's bucket).
    pub requests: Vec<String>,
    /// Inbound drops with `first_sight == false` (SeenRing duplicates).
    pub dup_drops: u32,
    /// Inbound drops with `alert && first_sight` (arrival notifications).
    pub alert_arrivals: u32,
}

impl RelNode {
    pub async fn new(name: &str, nodes: &Path) -> Self {
        let inst = TestInstance::new(name, nodes).await.expect("instance");
        let db = Db::open_in_memory().expect("db");
        let engine = Engine::new(db, inst.transport.clone());
        let drops = inst.drops();
        Self {
            name: name.to_string(),
            inst,
            engine,
            drops,
            events: Vec::new(),
            requests: Vec::new(),
            dup_drops: 0,
            alert_arrivals: 0,
        }
    }

    pub fn rel_state(&self, rel_id: &str) -> Option<String> {
        pairing::load_relationship(self.engine.db.conn(), rel_id)
            .ok()
            .flatten()
            .map(|r| r.state)
    }

    pub fn has_event(&self, f: impl Fn(&EngineEvent) -> bool) -> bool {
        self.events.iter().any(f)
    }

    pub fn count_events(&self, f: impl Fn(&EngineEvent) -> bool) -> usize {
        self.events.iter().filter(|e| f(e)).count()
    }
}

fn ingest_tag(o: &Ingest) -> &'static str {
    match o {
        Ingest::Message { .. } => "message",
        Ingest::RequestReceived { .. } => "request",
        Ingest::Duplicate => "duplicate",
        Ingest::SessionBroken { .. } => "session-broken",
        Ingest::Dropped => "dropped",
    }
}

async fn dispatch(node: &mut RelNode, rel_id: &str, plaintext: &[u8]) {
    match node.engine.handle_plaintext(rel_id, plaintext).await {
        Ok(events) => {
            for e in &events {
                if let EngineEvent::Message { msg_id, .. } = e {
                    eprintln!(
                        "{} event Message id={}",
                        node.name,
                        schat_core::store::hex_encode(msg_id)
                    );
                }
            }
            node.events.extend(events);
        }
        Err(e) => eprintln!("{} handle: {e}", node.name),
    }
}

/// One upkeep round for one node: drain outbox, sweep, ingest all
/// pending drops into the engine. Counts duplicate drops and alert
/// arrivals for the metrics.
pub async fn pump_one(node: &mut RelNode) {
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
                if !drop.first_sight {
                    node.dup_drops += 1;
                } else if drop.frame.alert {
                    node.alert_arrivals += 1;
                }
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
                    Ok(ref o) => eprintln!(
                        "{} ingest outcome: {} first_sight={}",
                        node.name,
                        ingest_tag(o),
                        drop.first_sight
                    ),
                    Err(e) => eprintln!("{} ingest: {e}", node.name),
                }
                node.inst.transport.note_inbound_drain();
            }
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }
}

/// Pump the given nodes until `pred` holds (real clock throughout).
pub async fn run_until(
    nodes: &mut [&mut RelNode],
    interval: Duration,
    timeout: Duration,
    what: &str,
    pred: impl Fn(&[&RelNode]) -> bool,
) {
    let deadline = Instant::now() + timeout;
    loop {
        for node in nodes.iter_mut() {
            pump_one(node).await;
        }
        {
            let view: Vec<&RelNode> = nodes.iter().map(|n| &**n).collect();
            if pred(&view) {
                return;
            }
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(interval).await;
    }
}

/// offer → accept → intro → request → inviter accepts → both active.
pub async fn pair_nodes(a: &mut RelNode, b: &mut RelNode, timeout: Duration) -> String {
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
        Duration::from_secs(2),
        timeout,
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
        Duration::from_secs(2),
        timeout,
        "activation",
        |nodes| {
            nodes[0].rel_state(&rel_id).is_some_and(|s| s == "active")
                && nodes[1].rel_state(&rel_id).is_some_and(|s| s == "active")
        },
    )
    .await;
    // Pairing traffic (the "hi, add me?" intro message, activation
    // burst) is not part of any scenario: start every scenario from a
    // clean event log so the tracker only sees scenario sends.
    for node in [&mut *a, &mut *b] {
        node.events.clear();
        node.dup_drops = 0;
        node.alert_arrivals = 0;
    }
    rel_id
}

pub fn peer_onion(node: &RelNode, rel_id: &str) -> String {
    pairing::load_relationship(node.engine.db.conn(), rel_id)
        .expect("rel")
        .expect("present")
        .peer_onion
}

/// The node's own hosted service for this relationship is published and
/// reachable, and tor is online.
pub fn service_reachable(node: &RelNode, rel_id: &str) -> bool {
    let Ok(Some(rel)) = pairing::load_relationship(node.engine.db.conn(), rel_id) else {
        return false;
    };
    let st = node.inst.transport.status();
    matches!(st.tor, TorState::Online)
        && st
            .services
            .iter()
            .any(|s| s.service_id == rel.service_id && s.state == ServiceState::Reachable)
}

/// Settle acks: send the peer a `RESYNC_REQ` whose receive-view covers
/// every seq it has noted; the peer's `handle_request` then marks all
/// covered outbound rows `Acknowledged`. This is the codebase's only ack
/// mechanism (no receipt envelope) — see the module docs.
pub async fn request_resync(node: &mut RelNode, rel_id: &str) -> Result<(), EngineError> {
    let req = sync::resync::build_request(&node.engine.db, rel_id)?;
    send_envelope(
        &node.engine.db,
        &node.engine.transport,
        rel_id,
        Payload::ResyncReq(req),
        None,
        false,
    )
    .await?;
    Ok(())
}

/// Quiet text frame (alert=false) — the latency-budget envelope
/// shape. Returns the msg_id.
pub async fn send_quiet_text(
    node: &mut RelNode,
    rel_id: &str,
    body: &str,
) -> Result<[u8; 16], EngineError> {
    let sent = send_envelope(
        &node.engine.db,
        &node.engine.transport,
        rel_id,
        Payload::Msg(schat_core::wire_types::msg::Msg::new(body.to_string())?),
        None,
        false,
    )
    .await?;
    Ok(sent.msg_id)
}

/// Build, encrypt and ledger one raw envelope WITHOUT sending it;
/// returns `(msg_id, app_seq, record)` so the caller controls the send
/// — including sending the identical bytes twice (dedup scenario) or
/// queueing the record straight into the outbox (kill-mid-drain
/// scenario). Mirrors the sync suite's `send_raw` ledger semantics.
pub async fn build_raw_envelope(
    from: &RelNode,
    rel_id: &str,
    payload: Payload,
    ref_id: Option<[u8; 16]>,
    ledger_state: DeliveryState,
) -> Result<([u8; 16], u64, Vec<u8>), EngineError> {
    use rand::RngCore;
    let mut msg_id = [0u8; 16];
    rand::rng().fill_bytes(&mut msg_id);
    let seq = from.engine.db.next_out_seq(rel_id)?;
    let now = from.engine.now();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at: now,
        ref_id,
        payload,
    };
    let plaintext = env.encode()?;
    let env_type = env.envelope_type().code();
    let payload_bytes = env.payload.encode()?;
    let frame = session::encrypt(
        from.engine.db.conn(),
        rel_id,
        &hex_encode(&msg_id),
        &plaintext,
        SystemTime::now(),
    )
    .await?;
    let record = schat_core::transport::framing::build_record(&frame)?;
    from.engine.db.insert_message(&NewMessage {
        msg_id,
        rel_id: rel_id.into(),
        direction: Direction::Out,
        app_seq: seq,
        sent_at: now,
        received_at: None,
        env_type,
        ref_id,
        payload: payload_bytes,
        state: ledger_state,
        expires_at: Some(now + sync::MESSAGE_TTL_SECS),
    })?;
    Ok((msg_id, seq, record))
}

/// Watch a transport's status stream, recording tor-state transitions
/// and every new `last_error` (the supervisor logs each heal rung there)
/// into `sink`. Abort the returned handle at scenario end.
pub fn spawn_status_watcher(
    transport: &Arc<Transport>,
    sink: Arc<Mutex<Vec<String>>>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = transport.subscribe();
    tokio::spawn(async move {
        let mut last_tor = rx.borrow().tor.clone();
        let mut last_err = rx.borrow().last_error.clone();
        loop {
            if rx.changed().await.is_err() {
                break;
            }
            let st = rx.borrow().clone();
            if st.tor != last_tor {
                sink.lock()
                    .expect("sink")
                    .push(format!("tor {last_tor:?} -> {:?}", st.tor));
                last_tor = st.tor.clone();
            }
            if st.last_error != last_err {
                if let Some(e) = &st.last_error {
                    sink.lock().expect("sink").push(format!("last_error: {e}"));
                }
                last_err = st.last_error.clone();
            }
        }
    })
}
