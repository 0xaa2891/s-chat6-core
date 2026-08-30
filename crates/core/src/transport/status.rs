//! Consolidated transport status — the **only** transport signal.
//!
//! One struct pushed through one `watch` channel
//! internally and one UniFFI listener at the FFI boundary.

/// Daemon / link state. Mirrors the supervised daemon state machine
/// (`Starting → Bootstrapping → Online → Degraded → Dead`).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TorState {
    Off,
    Starting,
    Bootstrapping { pct: u8 },
    Online,
    Degraded { reason: String },
    Dead { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ServiceState {
    Publishing,
    Reachable,
    Unreachable,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct ServiceStatus {
    pub service_id: String,
    pub onion: Option<String>,
    pub state: ServiceState,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct OutboxStatus {
    pub queued: u32,
    pub oldest_age_secs: u64,
    pub next_retry_secs: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct InboxStatus {
    pub pending: u32,
    pub last_drain_secs_ago: Option<u64>,
}

/// App-level mode: Fast / Normal / Saver.
/// None of these keep a send circuit warm. Fast/Saver are client UX labels
/// until later phases give them a real cost (e.g. battery); they must not
/// grow keepalives or dummy frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Enum)]
pub enum OnionMode {
    Fast,
    #[default]
    Normal,
    Saver,
}

impl OnionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            OnionMode::Fast => "fast",
            OnionMode::Normal => "normal",
            OnionMode::Saver => "saver",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "fast" => OnionMode::Fast,
            "saver" => OnionMode::Saver,
            _ => OnionMode::Normal,
        }
    }
}

/// The one transport status struct.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TransportStatus {
    pub tor: TorState,
    pub services: Vec<ServiceStatus>,
    pub outbox: OutboxStatus,
    pub inbox: InboxStatus,
    pub kill_switch: bool,
    pub mode: OnionMode,
    pub last_error: Option<String>,
    pub updated_at: u64,
}

impl Default for TransportStatus {
    fn default() -> Self {
        Self {
            tor: TorState::Off,
            services: Vec::new(),
            outbox: OutboxStatus::default(),
            inbox: InboxStatus::default(),
            kill_switch: false,
            mode: OnionMode::Normal,
            last_error: None,
            updated_at: 0,
        }
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
