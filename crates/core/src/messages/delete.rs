//! Delete semantics: history-type
//! classification and the tombstone/history-cut inbound drop. The cut
//! itself lives on the `relationships` row — see
//! `store::relationships::{history_cut, raise_history_cut}`.

use schat_wire_types::envelope::EnvelopeType;

/// The types that tombstones and
/// the history cut apply to. Control frames (DELETE itself, RESYNC,
/// policy, …) are never cut.
pub fn is_history_type(t: EnvelopeType) -> bool {
    matches!(
        t,
        EnvelopeType::Msg
            | EnvelopeType::Edit
            | EnvelopeType::AttachHead
            | EnvelopeType::AttachChunk
            | EnvelopeType::Sticker
    )
}

/// A history-type envelope
/// is dropped when its msg_id is tombstoned or its seq is below the
/// relationship's history cut.
pub fn should_drop_inbound(
    t: EnvelopeType,
    app_seq: u64,
    history_cut_seq: u64,
    tombstoned: bool,
) -> bool {
    if !is_history_type(t) {
        return false;
    }
    if tombstoned {
        return true;
    }
    history_cut_seq > 0 && app_seq < history_cut_seq
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_types_match_spec() {
        for t in [
            EnvelopeType::Msg,
            EnvelopeType::Edit,
            EnvelopeType::AttachHead,
            EnvelopeType::AttachChunk,
            EnvelopeType::Sticker,
        ] {
            assert!(is_history_type(t), "{t:?}");
        }
        for t in [
            EnvelopeType::Delete,
            EnvelopeType::DeleteAll,
            EnvelopeType::ContactClose,
            EnvelopeType::ResyncReq,
            EnvelopeType::Profile,
            EnvelopeType::Pref,
            EnvelopeType::ProfileReq,
            EnvelopeType::StickerCtrl,
            EnvelopeType::Presence,
            EnvelopeType::ChatPolicy,
            EnvelopeType::Typing,
            EnvelopeType::Read,
        ] {
            assert!(!is_history_type(t), "{t:?}");
        }
    }

    #[test]
    fn drop_rule() {
        // Control types: never dropped.
        assert!(!should_drop_inbound(EnvelopeType::Typing, 1, 100, true));
        // History: tombstone or cut.
        assert!(should_drop_inbound(EnvelopeType::Msg, 5, 0, true));
        assert!(should_drop_inbound(EnvelopeType::Msg, 5, 6, false));
        assert!(
            !should_drop_inbound(EnvelopeType::Msg, 6, 6, false),
            "cut is exclusive"
        );
        assert!(!should_drop_inbound(EnvelopeType::Msg, 5, 0, false));
    }
}
