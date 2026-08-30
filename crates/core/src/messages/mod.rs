//! `messages/` — the MSG/EDIT/DELETE/DELETE_ALL feature logic. Pure
//! decision functions over ledger rows; the engine applies the outcomes.
//!
//! Wire facts that shape everything here:
//! - EDIT is a *new* envelope (fresh msg_id, I11) whose `ref_id` is the
//!   original MSG id — never a previous EDIT's id. Payload = new body.
//! - DELETE's `ref_id` is the target msg_id; DELETE_ALL and
//!   CONTACT_CLOSE carry no ref and empty payloads.
//! - "History types" (MSG, EDIT, ATTACH_HEAD, ATTACH_CHUNK, STICKER)
//!   are subject to tombstone and history-cut drops; control types are
//!   not.

pub mod delete;
pub mod edit;

pub use delete::{is_history_type, should_drop_inbound};
pub use edit::{can_offer_edit, edit_decision, EditDecision};

pub use crate::store::tombstones::{TOMBSTONE_CAP, TOMBSTONE_TTL_SEC};

/// Edits live for one hour, anchored receiver-side to the original's
/// `received_at`, sender-side to our `sent_at`.
pub const EDIT_WINDOW_SEC: u64 = 3_600;
/// Per-message edit cap.
pub const EDIT_MAX_EDITS: u32 = 30;
/// Sender-side edit throttle.
pub const EDIT_MIN_INTERVAL_MS: u64 = 1_000;

// Declared once in the wire-types bounds catalog and
// re-exported here.
pub use schat_wire_types::limits::msg::MAX_BODY_BYTES;

/// Is this envelope type a thread row (client-rendered)? Content and
/// system lines are; control frames (typing, presence, read, resync,
/// edits, deletes, chunks, sticker ctrl, close) are not — they mutate
/// thread rows but never render as bubbles themselves.
pub fn is_thread_row(env_type: u8) -> bool {
    use schat_wire_types::envelope::EnvelopeType;
    matches!(
        EnvelopeType::from_code(env_type),
        Some(
            EnvelopeType::Msg
                | EnvelopeType::AttachHead
                | EnvelopeType::Sticker
                | EnvelopeType::ChatPolicy
                | EnvelopeType::Profile
                | EnvelopeType::ProfileReq
                | EnvelopeType::Pref
        )
    )
}
