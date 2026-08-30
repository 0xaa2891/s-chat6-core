//! Static bounds catalog for the wire protocol.
//!
//! Every numeric cap enforced on peer-supplied data is declared **here**
//! and only here; the feature modules re-export their constants so
//! existing import paths (`msg::MAX_BODY_BYTES`, `sticker::limits::…`)
//! keep working. The human-readable table with rationales lives in
//! `notes/limits.md`; every row there maps to a `limits::*` constant in
//! this file or in `schat_core::limits`.
//!
//! Structural constants (versions, flags, tags, fixed field widths) are
//! *not* caps and stay with their formats.

/// `MSG` body ceiling.
pub mod msg {
    /// Ceiling for a single message body.
    pub const MAX_BODY_BYTES: usize = 16 * 1024;
}

/// `PROFILE` field ceilings.
pub mod profile {
    /// Display name: NFC-normalized, 1..=32 UTF-8 bytes.
    pub const MAX_NAME_BYTES: usize = 32;
    /// Already-compressed profile JPEG ceiling.
    pub const MAX_JPEG: usize = 24 * 1024;
}

/// `ATTACH_HEAD` / `ATTACH_CHUNK` ceilings.
pub mod attach {
    /// Per-attachment uncompressed ceiling (25 MiB).
    pub const MAX_ATTACH: u32 = 25 * 1024 * 1024;
    /// One chunk's plaintext ceiling — fills one envelope.
    pub const CHUNK_DATA_MAX: usize = 27_900;

    pub const MAX_MIME: usize = 64;
    pub const MAX_EXT: usize = 8;
    pub const MAX_CAPTION: usize = 16 * 1024;

    pub const MAX_CHUNKS: u16 = 1024;
}

/// Envelope ceiling.
pub mod envelope {
    /// Payload ceiling: the
    /// encoded envelope must fit the largest record bucket with crypto
    /// overhead to spare.
    pub const MAX_ENVELOPE_BYTES: usize = 27_996;
}

/// `RESYNC_REQ` repair-window ceilings.
pub mod resync {
    /// v2 repair window: 4096 outstanding seqs (the old v1 had 1024).
    pub const MAX_BITMAP_BYTES: usize = 512;
    pub const BITMAP_BITS: usize = MAX_BITMAP_BYTES * 8;

    /// Seq range below `max_contiguous_seq` folded into the history hash.
    pub const DEEP_WINDOW: u64 = 4096;
}

/// `PREF` field ceilings.
pub mod pref {
    /// Inactivity-erase horizon ceiling (one year, in hours).
    pub const MAX_ERASE_HOURS: u32 = 24 * 365;
}

/// Sticker/pack limits: per-item
/// bytes/pixels/aspect, per-pack item counts, and device quotas so a
/// peer cannot fill the device. Everything fails closed: an over-cap
/// item or pack is refused, not truncated.
pub mod sticker {
    pub const KIND_EMOJI: u8 = 1;
    pub const KIND_STICKER: u8 = 2;

    pub const VISIBILITY_PUBLIC: u8 = 1;
    pub const VISIBILITY_PRIVATE: u8 = 2;

    pub const MAX_ITEMS_EMOJI: usize = 64;
    pub const MAX_ITEMS_STICKER: usize = 50;

    pub const MAX_EDGE_EMOJI: u32 = 160;
    pub const MAX_EDGE_STICKER: u32 = 512;

    pub const MAX_BYTES_EMOJI: usize = 64 * 1024;
    pub const MAX_BYTES_STICKER: usize = 512 * 1024;

    /// Stickers may be rectangular but not absurdly so (1:3 .. 3:1).
    pub const STICKER_ASPECT_NUM: u32 = 3;

    pub const MAX_TITLE_CHARS: usize = 32;

    /// Inline STICKER payloads above this ride as ITEM_BODY chunks instead.
    pub const INLINE_BYTES_MAX: usize = 27_500;

    /// ITEM_BODY chunk plaintext cap (fills one envelope).
    pub const ITEM_CHUNK_MAX: usize = 27_500;
    pub const MAX_ITEM_CHUNKS: u16 = 24;

    /// PACK_BODY chunking + reassembly caps (whole signed pack document).
    pub const PACK_CHUNK_MAX: usize = 27_500;
    pub const MAX_PACK_CHUNKS: u16 = 1280;

    /// Per-item preview thumbnail: decoded pixels and encoded bytes.
    pub const THUMB_EDGE: u32 = 96;
    pub const MAX_THUMB_BYTES: usize = 8 * 1024;

    /// THUMBS_BODY reassembly caps (whole unsigned thumbnail document).
    pub const MAX_THUMBS_DOC_BYTES: usize = 512 * 1024;
    pub const MAX_THUMBS_CHUNKS: u16 = 24;

    /// Absolute ceiling for a reassembled pack document (50 × 512 KiB +
    /// slack).
    pub const MAX_PACK_DOC_BYTES: usize = 28 * 1024 * 1024;

    // ---- Device-level quotas (the "infinite packs" kill switch) ----

    /// Created + installed packs. Beyond this, installs are refused.
    pub const MAX_PACKS_TOTAL: usize = 100;
    /// Packs fetched from a single peer (auto-cached + installed combined).
    pub const MAX_PACKS_PER_SENDER: usize = 16;
    /// Auto-cached public packs (not user-installed); LRU-evicted beyond.
    pub const MAX_CACHED_PACKS: usize = 32;
    /// Sum of blob bytes referenced by non-cached packs.
    pub const MAX_PACK_BLOB_BYTES: u64 = 512 * 1024 * 1024;
    /// Loose-item receive cache (private packs, uninstalled items).
    pub const MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;
    pub const MAX_CACHE_ENTRIES: usize = 4096;
    /// Week-long cache lifetime for auto-cached packs and loose items.
    pub const CACHE_TTL_SEC: u64 = 7 * 86_400;
    /// WANT_PACK answers per peer per day (outbound pack serving quota).
    pub const PACK_SERVES_PER_PEER_PER_DAY: u32 = 8;
    /// Orphan ITEM_BODY / PACK_BODY chunk buffers (RAM, per peer).
    pub const MAX_PENDING_ITEMS: usize = 64;
    pub const MAX_PENDING_ITEM_BYTES: usize = 8 * 1024 * 1024;
    pub const MAX_PENDING_PACKS: usize = 4;
    pub const PENDING_CHUNK_TTL_SEC: u64 = 600;

    pub fn max_items(kind: u8) -> usize {
        match kind {
            KIND_EMOJI => MAX_ITEMS_EMOJI,
            KIND_STICKER => MAX_ITEMS_STICKER,
            _ => 0,
        }
    }

    pub fn max_edge(kind: u8) -> u32 {
        match kind {
            KIND_EMOJI => MAX_EDGE_EMOJI,
            KIND_STICKER => MAX_EDGE_STICKER,
            _ => 0,
        }
    }

    pub fn max_bytes(kind: u8) -> usize {
        match kind {
            KIND_EMOJI => MAX_BYTES_EMOJI,
            KIND_STICKER => MAX_BYTES_STICKER,
            _ => 0,
        }
    }

    pub fn valid_kind(kind: u8) -> bool {
        kind == KIND_EMOJI || kind == KIND_STICKER
    }

    pub fn valid_visibility(visibility: u8) -> bool {
        visibility == VISIBILITY_PUBLIC || visibility == VISIBILITY_PRIVATE
    }

    /// Emoji must be exactly square; stickers may range from 1:3 to 3:1.
    /// Dimensions are post-decode bounds, never sender-claimed alone.
    pub fn aspect_ok(kind: u8, w: u32, h: u32) -> bool {
        if w == 0 || h == 0 {
            return false;
        }
        match kind {
            KIND_EMOJI => w == h,
            KIND_STICKER => {
                u64::from(w) <= u64::from(h) * u64::from(STICKER_ASPECT_NUM)
                    && u64::from(h) <= u64::from(w) * u64::from(STICKER_ASPECT_NUM)
            }
            _ => false,
        }
    }

    /// Full per-item validation against the caps for `kind`.
    pub fn item_ok(kind: u8, w: u32, h: u32, byte_len: usize) -> bool {
        valid_kind(kind)
            && byte_len > 0
            && byte_len <= max_bytes(kind)
            && aspect_ok(kind, w, h)
            && w.max(h) <= max_edge(kind)
    }
}
