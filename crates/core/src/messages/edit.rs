//! Edit decisions. The window is
//! receiver-local: `first_received_at + 3600`, never `sent_at` — a
//! store-and-forward copy arriving late must not extend it.

use schat_wire_types::envelope::EnvelopeType;

use crate::store::messages::{Direction, MessageRow};

use super::{EDIT_MAX_EDITS, EDIT_WINDOW_SEC};

/// Why an inbound EDIT was applied or dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditDecision {
    Apply,
    /// The EDIT's own msg_id was tombstoned (its DELETE landed first).
    DropTombstone,
    /// Below the relationship's history cut (DELETE_ALL).
    DropHistoryCut,
    /// No ledger row for `ref_id`.
    DropMissing,
    /// Only the original author edits: target must be an inbound row.
    DropAuthorship,
    /// Only plain text (MSG) is editable.
    DropKind,
    /// Target past its TTL.
    DropExpired,
    /// Past the receiver-local edit window.
    DropWindow,
    /// 30 edits per message.
    DropCap,
    /// `app_seq` not newer than the last applied edit's.
    DropStaleSeq,
    DropTooLarge,
}

/// Sender-side gate: our own outbound text
/// message, inside the window, under the edit cap. The caps check
/// (`CAP_V15`) is the engine's job — it owns peer caps.
pub fn can_offer_edit(row: &MessageRow, now: u64) -> bool {
    if row.direction != Direction::Out {
        return false;
    }
    if row.env_type != EnvelopeType::Msg.code() {
        return false;
    }
    if row.tombstone || row.edit_count >= EDIT_MAX_EDITS {
        return false;
    }
    now < row.sent_at + EDIT_WINDOW_SEC
}

/// Receiver-side decision. `tombstoned` is
/// whether the EDIT's own msg_id sits in the tombstone set.
pub fn edit_decision(
    target: Option<&MessageRow>,
    now: u64,
    incoming_app_seq: u64,
    body_bytes: usize,
    max_body_bytes: usize,
    tombstoned: bool,
    history_cut_seq: u64,
) -> EditDecision {
    if history_cut_seq > 0 && incoming_app_seq < history_cut_seq {
        return EditDecision::DropHistoryCut;
    }
    if tombstoned {
        return EditDecision::DropTombstone;
    }
    let Some(target) = target else {
        return EditDecision::DropMissing;
    };
    if target.direction != Direction::In {
        return EditDecision::DropAuthorship;
    }
    if target.env_type != EnvelopeType::Msg.code() {
        return EditDecision::DropKind;
    }
    if let Some(exp) = target.expires_at {
        if now >= exp {
            return EditDecision::DropExpired;
        }
    }
    let first_received = target.received_at.unwrap_or(target.created_at);
    if now >= first_received + EDIT_WINDOW_SEC {
        return EditDecision::DropWindow;
    }
    if target.edit_count >= EDIT_MAX_EDITS {
        return EditDecision::DropCap;
    }
    if incoming_app_seq <= target.last_edit_seq {
        return EditDecision::DropStaleSeq;
    }
    if body_bytes > max_body_bytes {
        return EditDecision::DropTooLarge;
    }
    EditDecision::Apply
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::messages::DeliveryState;

    fn target() -> MessageRow {
        MessageRow {
            msg_id: [1u8; 16],
            rel_id: "rel".into(),
            direction: Direction::In,
            app_seq: 5,
            sent_at: 100,
            received_at: Some(200),
            env_type: EnvelopeType::Msg.code(),
            ref_id: None,
            payload: b"hello".to_vec(),
            state: DeliveryState::Received,
            expires_at: None,
            created_at: 200,
            edited: false,
            tombstone: false,
            read_at: None,
            edit_count: 0,
            last_edit_seq: 0,
        }
    }

    #[test]
    fn happy_path_and_window_anchor() {
        let t = target();
        // Inside the receiver-local window (received at 200 + 3600).
        assert_eq!(
            edit_decision(Some(&t), 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::Apply
        );
        // Past it.
        assert_eq!(
            edit_decision(Some(&t), 200 + EDIT_WINDOW_SEC, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropWindow
        );
    }

    #[test]
    fn check_order_matches_spec() {
        let t = target();
        // History cut beats tombstone beats everything.
        assert_eq!(
            edit_decision(Some(&t), 300, 6, 10, 16 * 1024, true, 7),
            EditDecision::DropHistoryCut
        );
        assert_eq!(
            edit_decision(Some(&t), 300, 6, 10, 16 * 1024, true, 0),
            EditDecision::DropTombstone
        );
        assert_eq!(
            edit_decision(None, 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropMissing
        );
        // Authorship: our own outbound row.
        let mut out = t.clone();
        out.direction = Direction::Out;
        assert_eq!(
            edit_decision(Some(&out), 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropAuthorship
        );
        // Kind: attachments are not editable.
        let mut att = t.clone();
        att.env_type = EnvelopeType::AttachHead.code();
        assert_eq!(
            edit_decision(Some(&att), 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropKind
        );
        // Expiry.
        let mut exp = t.clone();
        exp.expires_at = Some(250);
        assert_eq!(
            edit_decision(Some(&exp), 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropExpired
        );
        // Cap.
        let mut capped = t.clone();
        capped.edit_count = EDIT_MAX_EDITS;
        assert_eq!(
            edit_decision(Some(&capped), 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropCap
        );
        // Stale seq.
        let mut edited = t.clone();
        edited.last_edit_seq = 6;
        assert_eq!(
            edit_decision(Some(&edited), 300, 6, 10, 16 * 1024, false, 0),
            EditDecision::DropStaleSeq
        );
        assert_eq!(
            edit_decision(Some(&edited), 300, 7, 10, 16 * 1024, false, 0),
            EditDecision::Apply
        );
        // Too large.
        assert_eq!(
            edit_decision(Some(&t), 300, 6, 20_000, 16 * 1024, false, 0),
            EditDecision::DropTooLarge
        );
    }

    #[test]
    fn offer_gate() {
        let mut row = target();
        row.direction = Direction::Out;
        assert!(can_offer_edit(&row, 200));
        assert!(
            !can_offer_edit(&row, 100 + EDIT_WINDOW_SEC),
            "window from sent_at"
        );
        let mut inbound = row.clone();
        inbound.direction = Direction::In;
        assert!(!can_offer_edit(&inbound, 200), "only our own messages");
        let mut tomb = row.clone();
        tomb.tombstone = true;
        assert!(!can_offer_edit(&tomb, 200));
    }
}
