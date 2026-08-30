//! `policy/` — per-chat rules and capability wants.
//!
//! Rules (TTL, screenshots, attachment download) change only via
//! PROPOSE + ACCEPT — both sides must agree. Capability wants are
//! one-to-disable (either side turns a feature off for both,
//! immediately) and two-to-enable (it comes back only when both want
//! it). The *enforced* value is `local_want & peer_want`.
//!
//! `machine` is pure (state in, state + effects out); `store` persists
//! on the `relationships` row; the engine owns transport.

pub mod engine;
pub mod machine;
pub mod store;

pub use machine::ApplyOutcome;
pub use store::{load_policy, save_policy};

pub use schat_wire_types::policy::{
    cap_bit, cap_id_of, is_allowed_ttl, ChatPolicy, CAP_ID_ATTACH, CAP_ID_EMOJI, CAP_ID_MAX,
    CAP_ID_PRESENCE, CAP_ID_RECEIPTS, CAP_ID_TYPING, FLAG_WANT_ATTACH, FLAG_WANT_EMOJI,
    FLAG_WANT_PRESENCE, FLAG_WANT_RECEIPTS, FLAG_WANT_TYPING, OP_CAP_SET, OP_RULE_ACCEPT,
    OP_RULE_PROPOSE, OP_SYNC, TTL_NEVER, TTL_OPTIONS,
};

/// Every want this build knows about (the default for both sides).
pub const WANT_ALL: u32 =
    FLAG_WANT_ATTACH | FLAG_WANT_EMOJI | FLAG_WANT_PRESENCE | FLAG_WANT_TYPING | FLAG_WANT_RECEIPTS;

/// Hourly re-advertisement cadence.
pub const SYNC_INTERVAL_SEC: u64 = 3_600;
/// Min interval between sync replies to inbound resyncs.
pub const SYNC_REPLY_MIN_SEC: u64 = 30;

/// A rule proposal awaiting the other side's ACCEPT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingProposal {
    pub ttl_sec: u32,
    pub screenshot: bool,
    pub attach_download: bool,
    /// true = they proposed (we may accept); false = we proposed.
    pub inbound: bool,
    pub propose_id: [u8; 16],
}

/// Full per-relationship policy state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyState {
    /// Agreed message TTL (`TTL_NEVER` = no expiry).
    pub ttl_sec: u32,
    /// Agreed rule flags.
    pub screenshot: bool,
    pub attach_download: bool,
    pub local_want: u32,
    pub peer_want: u32,
    pub pending: Option<PendingProposal>,
    pub last_sync_at: u64,
}

impl Default for PolicyState {
    fn default() -> Self {
        Self {
            ttl_sec: schat_wire_types::policy::TTL_24H,
            screenshot: true,
            attach_download: true,
            local_want: WANT_ALL,
            peer_want: WANT_ALL,
            pending: None,
            last_sync_at: 0,
        }
    }
}

impl PolicyState {
    /// Two-to-enable: on only if BOTH sides want it.
    pub fn enforced(&self, bit: u32) -> bool {
        self.local_want & self.peer_want & bit != 0
    }

    pub fn attachments(&self) -> bool {
        self.enforced(FLAG_WANT_ATTACH)
    }
    pub fn emoji(&self) -> bool {
        self.enforced(FLAG_WANT_EMOJI)
    }
    pub fn presence(&self) -> bool {
        self.enforced(FLAG_WANT_PRESENCE)
    }
    pub fn typing(&self) -> bool {
        self.enforced(FLAG_WANT_TYPING)
    }
    pub fn receipts(&self) -> bool {
        self.enforced(FLAG_WANT_RECEIPTS)
    }

    /// Message expiry for a message created at `floor` under the
    /// agreed TTL. `None` = never expires (the ledger's NULL, not a
    /// far-future sentinel).
    pub fn expiry_at(&self, floor: u64) -> Option<u64> {
        if self.ttl_sec == TTL_NEVER {
            None
        } else {
            Some(floor + u64::from(self.ttl_sec))
        }
    }
}
