//! `typing/` — typing indicators. Like
//! presence: **RAM-only**, never persisted, never resynced. Inbound
//! TYPING envelopes light a peer's indicator for `TYPING_TTL_SECS`;
//! outbound sends are throttled to one per `TYPING_SEND_INTERVAL_SECS`
//! of continuous typing.

use std::collections::HashMap;

pub use schat_wire_types::typing::Typing;

/// How long a peer's typing indicator stays lit without a refresh
/// (receiver-anchored; the wire carries no timestamp).
pub const TYPING_TTL_SECS: u64 = 5;
/// Minimum interval between our outbound typing=true envelopes.
pub const TYPING_SEND_INTERVAL_SECS: u64 = 3;

/// RAM-only typing table. One per engine instance.
#[derive(Default)]
pub struct TypingTable {
    /// rel_id → when the peer's typing indicator expires (unix secs).
    inbound: HashMap<String, u64>,
    /// rel_id → when we last *sent* a typing=true envelope (throttle).
    last_sent: HashMap<String, u64>,
}

impl TypingTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a peer's TYPING envelope. Returns `Some(typing)` only on
    /// an indicator *change* (off→on or on→off); refreshes of an
    /// already-lit indicator are not events.
    pub fn note(&mut self, rel_id: &str, typing: bool, now: u64) -> Option<bool> {
        let was = self.is_typing(rel_id, now);
        if typing {
            self.inbound
                .insert(rel_id.to_string(), now + TYPING_TTL_SECS);
        } else {
            self.inbound.remove(rel_id);
        }
        if was == typing {
            None
        } else {
            Some(typing)
        }
    }

    pub fn is_typing(&self, rel_id: &str, now: u64) -> bool {
        matches!(self.inbound.get(rel_id), Some(exp) if *exp > now)
    }

    /// Expire indicators whose TTL elapsed. Returns the rel_ids whose
    /// indicator went off (one event each).
    pub fn sweep(&mut self, now: u64) -> Vec<String> {
        let mut cleared = Vec::new();
        self.inbound.retain(|rel_id, exp| {
            if *exp <= now {
                cleared.push(rel_id.clone());
                false
            } else {
                true
            }
        });
        cleared
    }

    /// Outbound throttle: may we send another typing=true now?
    pub fn should_send(&self, rel_id: &str, now: u64) -> bool {
        match self.last_sent.get(rel_id) {
            Some(at) => now.saturating_sub(*at) >= TYPING_SEND_INTERVAL_SECS,
            None => true,
        }
    }

    pub fn note_sent(&mut self, rel_id: &str, now: u64) {
        self.last_sent.insert(rel_id.to_string(), now);
    }

    /// Drop all state for a relationship.
    pub fn forget(&mut self, rel_id: &str) {
        self.inbound.remove(rel_id);
        self.last_sent.remove(rel_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_lights_and_expires() {
        let mut t = TypingTable::new();
        assert_eq!(t.note("rel", true, 100), Some(true));
        assert_eq!(t.note("rel", true, 102), None, "refresh is not an event");
        assert!(t.is_typing("rel", 104));
        assert!(
            !t.is_typing("rel", 102 + TYPING_TTL_SECS),
            "refresh anchored expiry"
        );
        assert_eq!(t.sweep(102 + TYPING_TTL_SECS), vec!["rel".to_string()]);
        assert!(t.sweep(1000).is_empty(), "already cleared");
    }

    #[test]
    fn explicit_stop_clears_immediately() {
        let mut t = TypingTable::new();
        t.note("rel", true, 100);
        assert_eq!(t.note("rel", false, 101), Some(false));
        assert!(!t.is_typing("rel", 101));
    }

    #[test]
    fn outbound_throttle() {
        let mut t = TypingTable::new();
        assert!(t.should_send("rel", 100));
        t.note_sent("rel", 100);
        assert!(!t.should_send("rel", 101));
        assert!(t.should_send("rel", 100 + TYPING_SEND_INTERVAL_SECS));
    }
}
