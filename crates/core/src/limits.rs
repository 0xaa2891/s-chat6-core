//! Static operational bounds for the core.
//!
//! Every numeric cap enforced on peer-supplied or API-supplied data is
//! declared **here** and only here; the owning modules re-export their
//! constants so existing import paths keep working. Wire-payload caps
//! live in `schat_wire_types::limits`; this module holds the core's
//! operational caps (connections, storage, reassembly, media ingress).
//! The human-readable table with rationales lives in `notes/limits.md`.
//!
//! Temporal knobs (TTLs, timeouts, backoff) and structural constants
//! (versions, flags, field widths) are not caps and stay with their
//! modules.

/// Transport ingress/egress budgets.
pub mod transport {
    /// Simultaneous inbound rendezvous connections per hosted service.
    pub const MAX_CONNECTIONS: usize = 32;
    /// Listen backlog per hosted service.
    pub const ACCEPT_BACKLOG: u32 = 50;
    /// Per-connection reassembly buffer while a record is in flight.
    pub const RECV_BUFFER_BYTES: usize = 512 * 1024;

    /// Intro (pairing payload) ceiling on the wire.
    pub const MAX_INTRO_BYTES: usize = 8192;
    /// Per-connection budgets: a connection that exceeds either is
    /// terminated.
    pub const MAX_CONN_PACKETS: u32 = 1025;
    pub const MAX_CONN_BYTES: u64 = 44 * 1024 * 1024 + MAX_INTRO_BYTES as u64;
}

/// Tier-A queue-at-rest caps. Fail toward loss: past the cap new drops
/// are refused, loudly.
pub mod queue {
    pub const MAX_FILES: usize = 2048;
    pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
}

/// Tombstone ledger caps.
pub mod tombstones {
    /// Tombstones kept per relationship.
    pub const TOMBSTONE_CAP: u64 = 4096;
}

/// Media-prep ingress bounds (decode-side; applied before any pixel
/// work so a hostile "image" cannot exhaust memory or CPU).
pub mod media {
    /// Encoded input ceiling for `prepare_attachment`.
    pub const MAX_INPUT_BYTES: usize = 25 * 1024 * 1024;
    /// Decoded-pixel ceiling per edge (decompression-bomb guard).
    pub const MAX_DECODE_EDGE: u32 = 8192;
    /// Long edge after re-encode.
    pub const LONG_EDGE: u32 = 1080;
    /// Re-encode quality is stepped down until the JPEG fits this.
    pub const JPEG_TARGET_BYTES: usize = 400 * 1024;
    /// Profile-photo renditions (large, medium, small).
    pub const PROFILE_EDGES: [u32; 3] = [512, 384, 256];
}

/// Attachment send-side bounds.
pub mod attach {
    /// At/below this the attachment rides inline in a v2 head.
    pub const INLINE_MAX: usize = 27_000;
    /// Chunk count is padded up to a multiple of this so the true file
    /// size is hidden within `BUCKET_GRANULARITY × CHUNK_DATA_MAX`.
    pub const BUCKET_GRANULARITY: u16 = 8;
}

/// Store read-path bounds.
pub mod store {
    /// Upper bound on rows scanned to answer one `thread()` page —
    /// control rows interleaved in the ledger are skipped, so a page of
    /// thread rows may require scanning many ledger rows.
    pub const VIEW_SCAN_LIMIT: u32 = 65_536;

    /// Inbound replay-cache retention (session-layer dedup of
    /// byte-identical frames). Mirrors the 24 h message TTL: inside the
    /// window a replay drops as a duplicate before crypto; past it the
    /// row is swept and a replay fails closed at the session layer.
    pub const INBOUND_FRAME_TTL_SECS: i64 = 24 * 3_600;
}

/// Orphan attachment chunks (chunks whose ATTACH_HEAD has not arrived
/// yet). Chunks are stored durably in SQLCipher, so the caps are
/// enforced at insert and a TTL sweep (`sync::sweep_expired`) reclaims
/// the rest.
pub mod orphan {
    /// Chunks held for one not-yet-seen head.
    pub const MAX_ORPHAN_CHUNKS_PER_HEAD: u32 = 1024;
    /// Bytes held for one not-yet-seen head.
    pub const MAX_ORPHAN_BYTES_PER_HEAD: u64 = 25 * 1024 * 1024;
    /// New (durable store): per-relationship ceiling across all heads,
    /// so one peer cannot fill the device with headless chunks.
    pub const MAX_ORPHAN_CHUNKS_PER_REL: u32 = 4096;
    pub const MAX_ORPHAN_BYTES_PER_REL: u64 = 64 * 1024 * 1024;
    /// Orphans older than this are swept (the durable store needs an
    /// explicit horizon).
    pub const ORPHAN_TTL_SECS: i64 = 24 * 3_600;
}

/// Pairing-surface bounds.
pub mod pairing {
    /// Total QR payload ceiling at decode (sum of all fields; each
    /// field is additionally capped at 4096 by the codec).
    pub const MAX_QR_PAYLOAD_BYTES: usize = 8192;
    /// Inbound message requests awaiting acceptance per open offer.
    /// Past the cap new intros are dropped (fail toward loss, logged).
    pub const MAX_PENDING_REQUESTS: u32 = 256;
    /// Total relationships (local-action bound; generous headroom).
    pub const MAX_RELATIONSHIPS: u32 = 1024;
}

/// UniFFI ingress bounds.
pub mod ffi {
    /// `thread()` page ceiling — the client pages; it cannot request
    /// the whole ledger in one call.
    pub const MAX_THREAD_PAGE: u32 = 200;

    /// Clamp a client-requested `thread()` page size to the ceiling.
    pub fn clamp_thread_page(limit: u32) -> u32 {
        limit.min(MAX_THREAD_PAGE)
    }
}

/// Outbox drain batching.
pub mod drain {
    /// Messages attempted per drain pass.
    pub const DRAIN_BATCH: u32 = 64;
}

/// Temporal anti-flood limits. These bound **abusive peer
/// traffic** and **runaway internal loops** — they are not UX throttles.
/// Every threshold sits ≥10× above the documented honest-usage p99 for
/// its surface; profiles and rationales live in `notes/rate-limits.md`.
/// Enforcement lives in `ratelimit.rs` and the owning modules.
pub mod rate {
    /// Inbound frames per hosted service, dropped **before crypto**
    /// (transport listener). Honest p99: reconnect catch-up ≈ 33
    /// frames/s sustained, one full connection (1025 packets) as a
    /// burst — see notes/rate-limits.md.
    pub const INBOUND_FRAME_PER_SEC: u32 = 256;
    pub const INBOUND_FRAME_BURST: u32 = 4096;

    /// RESYNC_REQ *handling* per relationship (each handling costs a
    /// receive-view scan + retransmits). Honest p99: one request per
    /// reconnect, self-throttled to ≤1 per 10 s at the sender.
    pub const RESYNC_REQ_PER_SEC: u32 = 1;
    pub const RESYNC_REQ_BURST: u32 = 8;

    /// Inbound typing + presence envelopes per relationship. Honest
    /// p99: typing start/stop is protocol-throttled to ≤1 per 3 s.
    pub const EPHEMERAL_PER_SEC: u32 = 4;
    pub const EPHEMERAL_BURST: u32 = 16;

    /// Pairing intro processing per invitation service (each costs a
    /// PQXDH decrypt). Honest p99: one intro per 5-minute offer window.
    pub const INTRO_MIN_INTERVAL_SECS: u64 = 1;

    /// Control-port commands (supervisor loop guard). Honest p99: boot
    /// ≈ 20 commands, heal ladder a handful — never sustained.
    pub const CONTROL_CMD_PER_SEC: u32 = 8;
    pub const CONTROL_CMD_BURST: u32 = 64;

    /// Outbound sticker fetches (WANT_ITEM) triggered by *inbound*
    /// message content, per relationship. Honest p99: a few unknown
    /// emoji per message in fast chat.
    pub const STICKER_FETCH_PER_SEC: u32 = 8;
    pub const STICKER_FETCH_BURST: u32 = 32;

    /// Answering sticker WANT_ITEM / WANT_THUMBS, per relationship
    /// (serving costs chunked outbound frames + thumbnail re-encode
    /// CPU). Honest p99: one pack sync ≈ 64 items over seconds.
    pub const STICKER_SERVE_PER_SEC: u32 = 16;
    pub const STICKER_SERVE_BURST: u32 = 128;
}
