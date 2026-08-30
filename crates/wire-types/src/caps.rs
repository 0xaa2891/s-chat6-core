//! Capability bits carried inside `RESYNC_REQ` (the only place caps live —
//! they ride inside the encrypted channel, never cleartext).
//!
//! Capability bits are numbered densely. There is no downgrade path and
//! no backward compatibility with old clients, so a sparse layout would
//! only preserve dead bits.
//!
//! Old → new: `CAP_V15` 1<<0 → 1<<0 · `CAP_V19` 1<<5 → 1<<1 ·
//! `CAP_STICKER` 1<<6 → 1<<2 · `CAP_PRESENCE` 1<<7 → 1<<3 ·
//! `CAP_CHAT_POLICY` 1<<8 → 1<<4 · `CAP_TYPING` 1<<10 → 1<<5 ·
//! `CAP_RECEIPTS` 1<<11 → 1<<6.

/// Baseline feature set (attachments, profile, pref, policy requests).
pub const CAP_V15: u32 = 1 << 0;
/// Sync v2: 4096-bit repair window + history hash, and the receive view
/// doubles as the delivery ACK.
pub const CAP_V19: u32 = 1 << 1;
/// STICKER / STICKER_CTRL (custom emoji + sticker packs).
pub const CAP_STICKER: u32 = 1 << 2;
/// PRESENCE (live in-app flag; RAM-only, no timestamps).
pub const CAP_PRESENCE: u32 = 1 << 3;
/// CHAT_POLICY (per-chat rules + capability latches).
pub const CAP_POLICY: u32 = 1 << 4;
/// TYPING envelopes.
pub const CAP_TYPING: u32 = 1 << 5;
/// READ read-receipt envelopes.
pub const CAP_READ: u32 = 1 << 6;

/// Everything this build speaks.
pub const LOCAL: u32 =
    CAP_V15 | CAP_V19 | CAP_STICKER | CAP_PRESENCE | CAP_POLICY | CAP_TYPING | CAP_READ;

pub fn has(peer_caps: u32, bit: u32) -> bool {
    peer_caps & bit != 0
}
