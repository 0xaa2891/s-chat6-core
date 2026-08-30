//! Temporal anti-flood limits.
//!
//! Static bounds live elsewhere (sizes, counts — `limits.rs` and
//! `notes/limits.md`); this module owns *temporal* ones: token buckets
//! that bound abusive peer traffic and runaway internal loops. The
//! honest-user rule is non-negotiable: every threshold sits ≥10× above
//! the documented honest-usage p99 for its surface (profiles and
//! rationales: `notes/rate-limits.md`). Enthusiastic real use — rapid
//! chat bursts, full attachment uploads, reconnect resync, sticker-pack
//! fetches, pairing — must never increment [`rate_limited`].
//!
//! Limits are **per-relationship inbound** or **internal loop guards** —
//! never a cap on the user's own outbound messages. Every drop is
//! counted (queryable in tests) and logged with a reason (standing
//! rule: no silent recovery).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::limits::rate;

/// The network-facing surfaces that carry temporal limits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Surface {
    /// Inbound frames at a hosted service's listener, dropped before
    /// crypto (transport layer, wall clock).
    InboundFrame,
    /// RESYNC_REQ handling (receive-view scan + retransmits).
    ResyncReq,
    /// Inbound typing + presence envelopes.
    Ephemeral,
    /// Pairing intro processing (PQXDH decrypt) at an invitation
    /// service. Enforced as a persisted min-interval, not a bucket.
    Intro,
    /// Control-port commands (supervisor loop guard).
    ControlCmd,
    /// Outbound sticker fetches triggered by inbound content.
    StickerFetch,
    /// Answering sticker WANT_ITEM / WANT_THUMBS.
    StickerServe,
}

impl Surface {
    /// `(burst capacity, refill per second)` for bucketed surfaces.
    fn bucket_params(self) -> (u32, u32) {
        match self {
            Surface::InboundFrame => (rate::INBOUND_FRAME_BURST, rate::INBOUND_FRAME_PER_SEC),
            Surface::ResyncReq => (rate::RESYNC_REQ_BURST, rate::RESYNC_REQ_PER_SEC),
            Surface::Ephemeral => (rate::EPHEMERAL_BURST, rate::EPHEMERAL_PER_SEC),
            Surface::ControlCmd => (rate::CONTROL_CMD_BURST, rate::CONTROL_CMD_PER_SEC),
            Surface::StickerFetch => (rate::STICKER_FETCH_BURST, rate::STICKER_FETCH_PER_SEC),
            Surface::StickerServe => (rate::STICKER_SERVE_BURST, rate::STICKER_SERVE_PER_SEC),
            Surface::Intro => unreachable!("intro uses a persisted min-interval"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Surface::InboundFrame => "inbound_frame",
            Surface::ResyncReq => "resync_req",
            Surface::Ephemeral => "ephemeral",
            Surface::Intro => "intro",
            Surface::ControlCmd => "control_cmd",
            Surface::StickerFetch => "sticker_fetch",
            Surface::StickerServe => "sticker_serve",
        }
    }
}

static INBOUND_FRAME: AtomicU64 = AtomicU64::new(0);
static RESYNC_REQ: AtomicU64 = AtomicU64::new(0);
static EPHEMERAL: AtomicU64 = AtomicU64::new(0);
static INTRO: AtomicU64 = AtomicU64::new(0);
static CONTROL_CMD: AtomicU64 = AtomicU64::new(0);
static STICKER_FETCH: AtomicU64 = AtomicU64::new(0);
static STICKER_SERVE: AtomicU64 = AtomicU64::new(0);

fn counter(surface: Surface) -> &'static AtomicU64 {
    match surface {
        Surface::InboundFrame => &INBOUND_FRAME,
        Surface::ResyncReq => &RESYNC_REQ,
        Surface::Ephemeral => &EPHEMERAL,
        Surface::Intro => &INTRO,
        Surface::ControlCmd => &CONTROL_CMD,
        Surface::StickerFetch => &STICKER_FETCH,
        Surface::StickerServe => &STICKER_SERVE,
    }
}

/// Record one rate-limited drop (counted, logged with a reason).
pub fn note_limited(surface: Surface, key: &str) {
    let n = counter(surface).fetch_add(1, Ordering::Relaxed) + 1;
    tracing::warn!(
        surface = surface.name(),
        key,
        total = n,
        "rate limited; work dropped"
    );
}

/// Drops on one surface since process start.
pub fn limited(surface: Surface) -> u64 {
    counter(surface).load(Ordering::Relaxed)
}

/// Total rate-limited drops across all surfaces since process start.
/// The honest-user gate: calibration scenarios assert this stays 0.
pub fn rate_limited() -> u64 {
    let surfaces = [
        Surface::InboundFrame,
        Surface::ResyncReq,
        Surface::Ephemeral,
        Surface::Intro,
        Surface::ControlCmd,
        Surface::StickerFetch,
        Surface::StickerServe,
    ];
    surfaces.iter().map(|s| limited(*s)).sum()
}

/// Lazily refilled token bucket. The clock is caller-supplied
/// (seconds), so tests drive it with `FakeClock` and the transport
/// layer uses wall time. Clock rollback never refills (saturating).
pub struct TokenBucket {
    capacity: u32,
    tokens: u32,
    refill_per_sec: u32,
    last_refill: u64,
}

impl TokenBucket {
    /// A fresh bucket starts full (first honest burst always passes).
    pub fn new(capacity: u32, refill_per_sec: u32, now: u64) -> Self {
        Self {
            capacity,
            tokens: capacity,
            refill_per_sec,
            last_refill: now,
        }
    }

    /// Consume one token; `false` when the bucket is empty.
    pub fn check(&mut self, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last_refill);
        if elapsed > 0 {
            let add = elapsed.saturating_mul(u64::from(self.refill_per_sec));
            self.tokens = self
                .tokens
                .saturating_add(add.min(u64::from(self.capacity)) as u32)
                .min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Per-key bucket tables for the engine-side surfaces (one engine per
/// instance; keys are relationship ids, bounded by
/// `limits::pairing::MAX_RELATIONSHIPS`).
#[derive(Default)]
pub struct RateTables {
    buckets: HashMap<(Surface, String), TokenBucket>,
}

impl RateTables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume one token for `(surface, key)`; on exhaustion the drop
    /// is counted + logged and `false` is returned (caller drops the
    /// work, session unaffected).
    pub fn check(&mut self, surface: Surface, key: &str, now: u64) -> bool {
        let (capacity, refill) = surface.bucket_params();
        let bucket = self
            .buckets
            .entry((surface, key.to_string()))
            .or_insert_with(|| TokenBucket::new(capacity, refill, now));
        if bucket.check(now) {
            true
        } else {
            note_limited(surface, key);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_starts_full_and_refills() {
        let mut b = TokenBucket::new(4, 2, 1000);
        for _ in 0..4 {
            assert!(b.check(1000));
        }
        assert!(!b.check(1000), "empty after the burst");
        assert!(b.check(1001), "2 tokens refilled after 1 s");
        assert!(b.check(1001));
        assert!(!b.check(1001));
        // Long idle caps at capacity, never accumulates beyond it.
        for _ in 0..4 {
            assert!(b.check(2000));
        }
        assert!(!b.check(2000));
    }

    #[test]
    fn clock_rollback_never_refills() {
        let mut b = TokenBucket::new(1, 1000, 1000);
        assert!(b.check(1000));
        assert!(!b.check(500), "backwards clock grants nothing");
        assert!(!b.check(999));
        assert!(b.check(1001));
    }

    #[test]
    fn tables_count_and_log_drops() {
        let mut tables = RateTables::new();
        let before = limited(Surface::ResyncReq);
        let (cap, _) = Surface::ResyncReq.bucket_params();
        for i in 0..cap {
            assert!(
                tables.check(Surface::ResyncReq, "rel", 1000),
                "burst token {i} passes"
            );
        }
        assert!(!tables.check(Surface::ResyncReq, "rel", 1000));
        assert_eq!(limited(Surface::ResyncReq), before + 1);
        // A different relationship has its own bucket.
        assert!(tables.check(Surface::ResyncReq, "other-rel", 1000));
    }
}
