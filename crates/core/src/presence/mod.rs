//! `presence/` — presence dots. **RAM-only**: presence is
//! never persisted, never resynced, never replayed. The table remembers
//! the last advertised flags per peer and reports *transitions only* —
//! a repeated identical PRESENCE is not an event.
//!
//! Freshness: a peer that stops sending PRESENCE envelopes decays to
//! not-in-app after `PRESENCE_TTL_SECS` (`sweep` reports the
//! transition). The receiver anchors TTLs to its own clock (the wire
//! carries no timestamp); no timestamps are computed, persisted, or
//! exposed.

use std::collections::HashMap;

pub use schat_wire_types::presence::Presence;

/// Receiver-anchored freshness window for a PRESENCE advertisement
/// (45 s).
pub const PRESENCE_TTL_SECS: u64 = 45;

/// What a client shows for a peer: the flags, or nothing (offline).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerPresence {
    pub in_app: bool,
    pub do_not_disturb: bool,
}

/// RAM-only presence table. One per engine instance.
#[derive(Default)]
pub struct PresenceTable {
    /// rel_id → (flags, when last refreshed, unix secs).
    peers: HashMap<String, (Presence, u64)>,
}

impl PresenceTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a peer's PRESENCE envelope. Returns `Some(presence)` only
    /// on a *change* — callers emit events for transitions only.
    pub fn note(&mut self, rel_id: &str, p: Presence, now: u64) -> Option<PeerPresence> {
        let prev = self.peers.get(rel_id).map(|(old, _)| *old);
        self.peers.insert(rel_id.to_string(), (p, now));
        if prev == Some(p) {
            None
        } else {
            Some(PeerPresence {
                in_app: p.in_app,
                do_not_disturb: p.do_not_disturb,
            })
        }
    }

    /// Current presence, applying the TTL: a stale entry reads offline.
    pub fn state(&self, rel_id: &str, now: u64) -> PeerPresence {
        match self.peers.get(rel_id) {
            Some((p, at)) if now.saturating_sub(*at) < PRESENCE_TTL_SECS => PeerPresence {
                in_app: p.in_app,
                do_not_disturb: p.do_not_disturb,
            },
            _ => PeerPresence {
                in_app: false,
                do_not_disturb: false,
            },
        }
    }

    /// Decay stale entries. Returns the peers that *transitioned* to
    /// offline (were fresh in-app, now stale) — one event each.
    pub fn sweep(&mut self, now: u64) -> Vec<String> {
        let mut decayed = Vec::new();
        self.peers.retain(|rel_id, (p, at)| {
            let fresh = now.saturating_sub(*at) < PRESENCE_TTL_SECS;
            if !fresh && p.in_app {
                decayed.push(rel_id.clone());
            }
            fresh
        });
        decayed
    }

    /// Drop all state for a relationship (contact closed/removed).
    pub fn forget(&mut self, rel_id: &str) {
        self.peers.remove(rel_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(in_app: bool, dnd: bool) -> Presence {
        Presence {
            in_app,
            do_not_disturb: dnd,
        }
    }

    #[test]
    fn transitions_only() {
        let mut t = PresenceTable::new();
        assert!(t.note("rel", p(true, false), 100).is_some());
        assert_eq!(
            t.note("rel", p(true, false), 110),
            None,
            "repeat is not an event"
        );
        assert!(
            t.note("rel", p(true, true), 120).is_some(),
            "dnd flip is a transition"
        );
        assert_eq!(
            t.state("rel", 121),
            PeerPresence {
                in_app: true,
                do_not_disturb: true
            }
        );
        assert!(!t.state("unknown", 121).in_app);
    }

    #[test]
    fn ttl_decay_reports_transition_once() {
        let mut t = PresenceTable::new();
        t.note("rel", p(true, false), 100);
        assert!(
            t.sweep(100 + PRESENCE_TTL_SECS - 1).is_empty(),
            "still fresh"
        );
        assert_eq!(t.sweep(100 + PRESENCE_TTL_SECS), vec!["rel".to_string()]);
        assert!(
            t.sweep(100 + PRESENCE_TTL_SECS + 10).is_empty(),
            "already decayed"
        );
        assert!(!t.state("rel", 100 + PRESENCE_TTL_SECS).in_app);
    }

    #[test]
    fn explicit_not_in_app_is_a_transition() {
        let mut t = PresenceTable::new();
        t.note("rel", p(true, false), 100);
        assert!(t.note("rel", p(false, false), 101).is_some());
        assert!(!t.state("rel", 102).in_app);
    }
}
