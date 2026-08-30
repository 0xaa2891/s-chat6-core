//! `transport/` — Tor daemon lifecycle, control-port orchestration, onion
//! service hosting, SOCKS5 send path, inbound listeners, kill switch,
//! circumvention. Decomposed, headless-testable Rust.
//!
//! Module separation (TB1/TB2): this module never imports `session/` or
//! `store/` decryption paths. Inbound produces `OpaqueFrame` — bytes, not
//! plaintext.
//!
//! The [`Transport`] impl is split by concern: `lifecycle` (bring-up +
//! health supervisor), `services` (onion hosting + client auth), `sending`
//! (outbound), `policy` (kill switch / circumvention / roaming).

pub mod circumvention;
pub mod control;
pub mod daemon;
pub mod error;
pub mod framing;
pub mod heal;
pub mod inbound;
pub mod killswitch;
pub mod onion;
pub mod seen;
pub mod socks;
pub mod status;

mod lifecycle;
mod policy;
mod sending;
mod services;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::sync::{broadcast, watch, Mutex, RwLock};

use control::{ControlAuth, ControlClient};
use daemon::{AttachedDaemon, TorDaemon};
use error::TransportError;
use inbound::{InboundDrop, InboundListener};
use killswitch::KillSwitch;
use onion::{FileKeyStore, KeyStore};
use seen::SeenRing;
use socks::Sender;
use status::{now_secs, OnionMode, ServiceState, TorState, TransportStatus};

/// Events the transport pushes to the rest of the core (mapped onto the
/// single `SchatEvent` UniFFI stream in `lib.rs`).
#[derive(Clone, Debug)]
pub enum TransportEvent {
    Status(TransportStatus),
    /// Alert flag on a first-sight frame: the client's notification decision.
    Arrival {
        service_id: String,
    },
}

struct HostedEntry {
    onion: String,
    state: ServiceState,
    target: String,
    client_auth: Vec<String>,
    /// Whether this service is currently live in the tor daemon
    /// (`ADD_ONION` succeeded on the current control connection). Reset
    /// on every (re)connect; publishing only happens while online —
    /// adding a service before tor has directory info gives it a broken
    /// descriptor upload schedule (observed on Chutney: first upload
    /// deferred ~90 min).
    published: bool,
    #[allow(dead_code)]
    listener: Arc<InboundListener>,
}

pub struct Transport {
    /// Where `.auth_private` files go for client-attached daemons.
    client_auth_dir: PathBuf,
    status_tx: watch::Sender<TransportStatus>,
    state: std::sync::Mutex<TransportStatus>,
    events: broadcast::Sender<TransportEvent>,
    drops: broadcast::Sender<InboundDrop>,

    kill_switch: KillSwitch,
    online: Arc<AtomicBool>,
    mode: watch::Sender<OnionMode>,
    shutdown: watch::Sender<bool>,

    seen: Arc<Mutex<SeenRing>>,
    keys: Arc<dyn KeyStore>,

    daemon: RwLock<Option<Arc<dyn TorDaemon>>>,
    control: RwLock<Option<Arc<ControlClient>>>,
    sender: RwLock<Option<Arc<Sender>>>,
    services: Mutex<HashMap<String, HostedEntry>>,

    /// Epoch seconds of the last inbox drain report from the drop consumer
    /// (`note_inbound_drain`). Drives `InboxStatus.last_drain_secs_ago`.
    last_drain: std::sync::Mutex<Option<u64>>,

    supervisor: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Transport {
    pub fn new(data_dir: &Path) -> Arc<Self> {
        let (status_tx, _) = watch::channel(TransportStatus::default());
        let (events, _) = broadcast::channel(256);
        let (drops, _) = broadcast::channel(1024);
        let (mode_tx, _) = watch::channel(OnionMode::Normal);
        let (shutdown_tx, _) = watch::channel(false);
        let kill_switch = KillSwitch::load(data_dir);
        Arc::new(Self {
            client_auth_dir: data_dir.join("client_auth"),
            status_tx,
            state: std::sync::Mutex::new(TransportStatus::default()),
            events,
            drops,
            kill_switch,
            online: Arc::new(AtomicBool::new(false)),
            mode: mode_tx,
            shutdown: shutdown_tx,
            seen: Arc::new(Mutex::new(SeenRing::default())),
            keys: Arc::new(FileKeyStore::new(data_dir.join("keys"))),
            daemon: RwLock::new(None),
            control: RwLock::new(None),
            sender: RwLock::new(None),
            services: Mutex::new(HashMap::new()),
            last_drain: std::sync::Mutex::new(None),
            supervisor: Mutex::new(None),
        })
    }

    // -- wiring ----------------------------------------------------------

    /// Client-provided daemon: the shell started tor and
    /// passes endpoints + auth in. The core never spawns processes here.
    pub async fn attach_tor(
        &self,
        socks: SocketAddr,
        control: SocketAddr,
        auth: ControlAuth,
    ) -> Result<(), TransportError> {
        let daemon = AttachedDaemon {
            socks_addr: socks,
            control_addr: control,
            auth,
            client_auth_dir: self.client_auth_dir.clone(),
        };
        *self.daemon.write().await = Some(Arc::new(daemon));
        Ok(())
    }

    /// Desktop/CI path: hand over a subprocess (or test) daemon.
    pub async fn set_daemon(&self, daemon: Arc<dyn TorDaemon>) {
        *self.daemon.write().await = Some(daemon);
    }

    pub fn subscribe(&self) -> watch::Receiver<TransportStatus> {
        self.status_tx.subscribe()
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<TransportEvent> {
        self.events.subscribe()
    }

    /// Raw inbound frames (test harness / CLI). Still opaque bytes.
    pub fn subscribe_drops(&self) -> broadcast::Receiver<InboundDrop> {
        self.drops.subscribe()
    }

    pub fn status(&self) -> TransportStatus {
        self.status_tx.borrow().clone()
    }

    pub fn set_mode(&self, mode: OnionMode) {
        self.mode.send_replace(mode);
        self.update_status(|s| s.mode = mode);
    }

    pub fn kill_switch_flag(&self) -> Arc<AtomicBool> {
        self.kill_switch.flag()
    }

    // -- status helpers --------------------------------------------------

    async fn control(&self) -> Result<Arc<ControlClient>, TransportError> {
        self.control
            .read()
            .await
            .clone()
            .ok_or_else(|| TransportError::Control("not attached".into()))
    }

    fn update_status(&self, f: impl FnOnce(&mut TransportStatus)) {
        let mut guard = self.state.lock().expect("status state");
        f(&mut guard);
        guard.updated_at = now_secs();
        // send_replace, not send: watch::Sender::send drops the value when
        // no receivers exist, leaving status() permanently stale.
        self.status_tx.send_replace(guard.clone());
        let _ = self.events.send(TransportEvent::Status(guard.clone()));
    }

    fn set_tor_state(&self, tor: TorState) {
        self.update_status(|s| s.tor = tor);
    }

    fn note_inbound(&self) {
        self.update_status(|s| s.inbox.pending = s.inbox.pending.saturating_add(1));
    }

    /// The drop consumer (CLI daemon or client shell) reports a drained
    /// inbox: pending resets and the drain timestamp feeds
    /// `InboxStatus.last_drain_secs_ago`. Without this, `pending` only ever
    /// grew and the status struct lied about the inbox.
    pub fn note_inbound_drain(&self) {
        *self.last_drain.lock().expect("last_drain") = Some(now_secs());
        self.update_status(|s| {
            s.inbox.pending = 0;
            s.inbox.last_drain_secs_ago = Some(0);
        });
    }

    pub(super) fn last_drain_secs_ago(&self, now: u64) -> Option<u64> {
        self.last_drain
            .lock()
            .expect("last_drain")
            .map(|t| now.saturating_sub(t))
    }

    async fn refresh_services_status(&self) {
        let services: Vec<status::ServiceStatus> = self
            .services
            .lock()
            .await
            .iter()
            .map(|(id, e)| status::ServiceStatus {
                service_id: id.clone(),
                onion: Some(e.onion.clone()),
                state: e.state,
            })
            .collect();
        self.update_status(|s| s.services = services);
    }
}
