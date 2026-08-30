//! The policy state machine — pure functions over `PolicyState`.
//!
//! Every op carries the sender's *local* wants, so the semantics are
//! uniform: wants = "what I want".

use schat_wire_types::policy::{self, ChatPolicy};

use super::{PendingProposal, PolicyState};

/// Side effects the caller must apply after a state transition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The agreed rules or an enforced capability changed.
    pub changed: bool,
    /// TTL shrank: clamp every live message's expiry to this instant.
    pub clamp_expiry_to: Option<u64>,
    /// Attachments turned off while enforced: erase attachment
    /// messages + chunk data.
    pub erase_attachments: bool,
}

fn wants(p: &ChatPolicy) -> u32 {
    let mut w = 0;
    if p.want_attach {
        w |= policy::FLAG_WANT_ATTACH;
    }
    if p.want_emoji {
        w |= policy::FLAG_WANT_EMOJI;
    }
    if p.want_presence {
        w |= policy::FLAG_WANT_PRESENCE;
    }
    if p.want_typing {
        w |= policy::FLAG_WANT_TYPING;
    }
    if p.want_receipts {
        w |= policy::FLAG_WANT_RECEIPTS;
    }
    w
}

fn payload(
    op: u8,
    state: &PolicyState,
    cap_id: u8,
    cap_on: bool,
    propose_id: [u8; 16],
) -> ChatPolicy {
    ChatPolicy {
        op,
        ttl_sec: state.ttl_sec,
        screenshot: state.screenshot,
        attach_download: state.attach_download,
        want_attach: state.local_want & policy::FLAG_WANT_ATTACH != 0,
        want_emoji: state.local_want & policy::FLAG_WANT_EMOJI != 0,
        want_presence: state.local_want & policy::FLAG_WANT_PRESENCE != 0,
        want_typing: state.local_want & policy::FLAG_WANT_TYPING != 0,
        want_receipts: state.local_want & policy::FLAG_WANT_RECEIPTS != 0,
        cap_id,
        cap_on,
        propose_id,
    }
}

/// Apply agreed rules; clamp existing messages when the TTL shrinks.
fn apply_rules(
    mut state: PolicyState,
    ttl_sec: u32,
    screenshot: bool,
    attach_download: bool,
    now: u64,
) -> (PolicyState, ApplyOutcome) {
    let prev_ttl = state.ttl_sec;
    state.ttl_sec = ttl_sec;
    state.screenshot = screenshot;
    state.attach_download = attach_download;
    state.pending = None;
    let clamp =
        if ttl_sec != policy::TTL_NEVER && (prev_ttl == policy::TTL_NEVER || ttl_sec < prev_ttl) {
            Some(now + u64::from(ttl_sec))
        } else {
            None
        };
    (
        state,
        ApplyOutcome {
            changed: true,
            clamp_expiry_to: clamp,
            erase_attachments: false,
        },
    )
}

// ---- inbound ----

/// Inbound PROPOSE: record it as an inbound-pending proposal.
/// `None` = disallowed TTL, drop (already validated by the codec).
pub fn apply_propose(mut state: PolicyState, parsed: &ChatPolicy, msg_id: [u8; 16]) -> PolicyState {
    // The wire carries the proposer's id; fall back to the envelope id
    // for peers that send a zeroed field.
    let propose_id = if parsed.propose_id == [0u8; 16] {
        msg_id
    } else {
        parsed.propose_id
    };
    state.pending = Some(PendingProposal {
        ttl_sec: parsed.ttl_sec,
        screenshot: parsed.screenshot,
        attach_download: parsed.attach_download,
        inbound: true,
        propose_id,
    });
    state
}

/// Inbound ACCEPT: valid only against OUR unanswered proposal with a
/// matching `propose_id`. `None` = stale/forged accept, drop.
pub fn apply_accept(
    state: PolicyState,
    parsed: &ChatPolicy,
    now: u64,
) -> Option<(PolicyState, ApplyOutcome)> {
    let pending = state.pending?;
    if pending.inbound || pending.propose_id != parsed.propose_id {
        return None;
    }
    Some(apply_rules(
        state,
        pending.ttl_sec,
        pending.screenshot,
        pending.attach_download,
        now,
    ))
}

/// Inbound CAP_SET (one-to-disable, two-to-enable): disabling clears
/// BOTH sides' want bits; enabling sets only the peer's.
pub fn apply_cap_set(state: &PolicyState, cap_id: u8, on: bool) -> (PolicyState, ApplyOutcome) {
    let bit = policy::cap_bit(cap_id);
    if bit == 0 {
        return (*state, ApplyOutcome::default());
    }
    let before = state.enforced(bit);
    let mut next = *state;
    if on {
        next.peer_want |= bit;
    } else {
        next.local_want &= !bit;
        next.peer_want &= !bit;
    }
    let after = next.enforced(bit);
    (
        next,
        ApplyOutcome {
            changed: before != after || !on,
            clamp_expiry_to: None,
            erase_attachments: !on && bit == policy::FLAG_WANT_ATTACH && before,
        },
    )
}

/// Inbound SYNC: replace the peer's wants wholesale.
pub fn apply_sync(state: &PolicyState, parsed: &ChatPolicy) -> (PolicyState, ApplyOutcome) {
    let peer = wants(parsed);
    if peer == state.peer_want {
        return (*state, ApplyOutcome::default());
    }
    let before_attach = state.attachments();
    let mut next = *state;
    next.peer_want = peer;
    (
        next,
        ApplyOutcome {
            changed: true,
            clamp_expiry_to: None,
            erase_attachments: before_attach && !next.attachments(),
        },
    )
}

// ---- outbound ----

/// Build a PROPOSE: the proposal's id is
/// the envelope's own msg_id. `None` = disallowed TTL.
pub fn build_propose(
    mut state: PolicyState,
    ttl_sec: u32,
    screenshot: bool,
    attach_download: bool,
    propose_id: [u8; 16],
) -> Option<(PolicyState, ChatPolicy)> {
    if !policy::is_allowed_ttl(ttl_sec) {
        return None;
    }
    state.pending = Some(PendingProposal {
        ttl_sec,
        screenshot,
        attach_download,
        inbound: false,
        propose_id,
    });
    let mut p = payload(policy::OP_RULE_PROPOSE, &state, 0, false, propose_id);
    // The proposal carries the PROPOSED rules, not the current ones.
    p.ttl_sec = ttl_sec;
    p.screenshot = screenshot;
    p.attach_download = attach_download;
    Some((state, p))
}

/// Build an ACCEPT for the pending inbound proposal: rules apply
/// locally first, then the accept goes out.
pub fn build_accept(
    state: PolicyState,
    now: u64,
) -> Option<(PolicyState, ChatPolicy, ApplyOutcome)> {
    let pending = state.pending?;
    if !pending.inbound {
        return None;
    }
    let (next, outcome) = apply_rules(
        state,
        pending.ttl_sec,
        pending.screenshot,
        pending.attach_download,
        now,
    );
    let mut p = payload(policy::OP_RULE_ACCEPT, &next, 0, false, pending.propose_id);
    p.ttl_sec = pending.ttl_sec;
    p.screenshot = pending.screenshot;
    p.attach_download = pending.attach_download;
    Some((next, p, outcome))
}

/// Build a CAP_SET: disabling clears
/// both sides locally; enabling sets only ours (theirs must follow).
/// `None` = no-op (already in the desired local state).
pub fn build_cap_set(
    state: &PolicyState,
    cap_id: u8,
    on: bool,
) -> Option<(PolicyState, ChatPolicy, ApplyOutcome)> {
    let bit = policy::cap_bit(cap_id);
    if bit == 0 {
        return None;
    }
    let have = state.local_want & bit != 0;
    if on == have {
        return None;
    }
    let before = state.enforced(bit);
    let mut next = *state;
    if on {
        next.local_want |= bit;
    } else {
        next.local_want &= !bit;
        next.peer_want &= !bit;
    }
    let after = next.enforced(bit);
    let p = payload(policy::OP_CAP_SET, &next, cap_id, on, [0u8; 16]);
    Some((
        next,
        p,
        ApplyOutcome {
            changed: before != after || !on,
            clamp_expiry_to: None,
            erase_attachments: !on && bit == policy::FLAG_WANT_ATTACH && before,
        },
    ))
}

/// Build a SYNC advertisement of our current wants (hourly cadence +
/// resync replies).
pub fn build_sync(mut state: PolicyState, now: u64) -> (PolicyState, ChatPolicy) {
    state.last_sync_at = now;
    let p = payload(policy::OP_SYNC, &state, 0, false, [0u8; 16]);
    (state, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn propose_accept_round_trip() {
        let a = PolicyState::default(); // us
        let b = PolicyState::default(); // peer
        let id = [7u8; 16];

        // We propose 1h TTL, no screenshots.
        let (a1, prop) = build_propose(a, policy::TTL_1H, false, true, id).unwrap();
        assert!(a1.pending.is_some_and(|p| !p.inbound && p.propose_id == id));

        // Peer records the inbound proposal, then accepts.
        let b1 = apply_propose(b, &prop, id);
        let (b2, accept, b_out) = build_accept(b1, 1000).unwrap();
        assert!(b_out.changed);
        assert_eq!(b2.ttl_sec, policy::TTL_1H);
        assert!(!b2.screenshot);
        assert!(b2.pending.is_none());
        // TTL shrank from 24h to 1h: clamp.
        assert_eq!(b_out.clamp_expiry_to, Some(1000 + 3600));

        // We apply their accept (must match our pending id).
        let wrong = ChatPolicy {
            propose_id: [9u8; 16],
            ..accept.clone()
        };
        assert!(
            apply_accept(a1, &wrong, 1000).is_none(),
            "forged id dropped"
        );
        let (a2, a_out) = apply_accept(a1, &accept, 1000).unwrap();
        assert_eq!(a2.ttl_sec, policy::TTL_1H);
        assert!(a2.pending.is_none());
        assert_eq!(a_out.clamp_expiry_to, Some(1000 + 3600));
    }

    #[test]
    fn accept_without_pending_is_dropped() {
        let s = PolicyState::default();
        let p = ChatPolicy {
            op: policy::OP_RULE_ACCEPT,
            ttl_sec: policy::TTL_1H,
            screenshot: true,
            attach_download: true,
            want_attach: true,
            want_emoji: true,
            want_presence: true,
            want_typing: true,
            want_receipts: true,
            cap_id: 0,
            cap_on: false,
            propose_id: [1u8; 16],
        };
        assert!(apply_accept(s, &p, 0).is_none());
    }

    #[test]
    fn cap_set_one_to_disable_two_to_enable() {
        let s = PolicyState::default();
        assert!(s.typing());

        // Peer disables typing: BOTH wants clear locally.
        let (s1, out) = apply_cap_set(&s, policy::CAP_ID_TYPING, false);
        assert!(!s1.typing());
        assert!(
            s1.local_want & policy::FLAG_WANT_TYPING == 0,
            "our want cleared too"
        );
        assert!(out.changed);

        // Peer re-enables: only THEIR want returns; still off for us.
        let (s2, _) = apply_cap_set(&s1, policy::CAP_ID_TYPING, true);
        assert!(!s2.typing(), "two-to-enable: our want still cleared");

        // We re-enable too: now it's on.
        let (s3, _, _) = build_cap_set(&s2, policy::CAP_ID_TYPING, true).unwrap();
        assert!(s3.typing());
    }

    #[test]
    fn cap_set_attach_disable_erases() {
        let s = PolicyState::default();
        let (_, out) = apply_cap_set(&s, policy::CAP_ID_ATTACH, false);
        assert!(out.erase_attachments);
        // Re-disable when already off: no erase (was not enforced).
        let (s1, _) = apply_cap_set(&s, policy::CAP_ID_ATTACH, false);
        let (_, out2) = apply_cap_set(&s1, policy::CAP_ID_ATTACH, false);
        assert!(!out2.erase_attachments);
    }

    #[test]
    fn sync_replaces_peer_wants() {
        let s = PolicyState::default();
        let mut p = build_sync(s, 0).1;
        p.want_typing = false;
        p.want_receipts = false;
        let (s1, out) = apply_sync(&s, &p);
        assert!(out.changed);
        assert!(!s1.typing() && !s1.receipts());
        assert!(s1.presence() && s1.attachments() && s1.emoji());
        // Identical sync: no change.
        let (_, out2) = apply_sync(&s1, &p);
        assert!(!out2.changed);
    }

    #[test]
    fn ttl_never_then_shrink_clamps() {
        let s = PolicyState {
            ttl_sec: policy::TTL_NEVER,
            ..PolicyState::default()
        };
        let (s1, out) = apply_rules(s, policy::TTL_7D, true, true, 5000);
        assert_eq!(
            out.clamp_expiry_to,
            Some(5000 + 604_800),
            "never → 7d clamps"
        );
        let (s2, out2) = apply_rules(s1, policy::TTL_14D, true, true, 6000);
        assert_eq!(out2.clamp_expiry_to, None, "growing the TTL never clamps");
        assert_eq!(s2.ttl_sec, policy::TTL_14D);
    }
}
