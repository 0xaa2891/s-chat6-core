//! `Clock` — the only source of time for `store/` and `sync/`.
//!
//! Production uses [`SystemClock`]; tests use [`FakeClock`] so a 24-hour
//! TTL sweep runs in milliseconds. Nothing in the store layer calls
//! `SystemTime::now` directly.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

pub trait Clock: Send + Sync {
    fn now_secs(&self) -> u64;
}

/// Wall-clock time (production).
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Manually advanced clock (tests). Cheap to clone — all copies share
/// the same underlying time.
#[derive(Clone, Debug, Default)]
pub struct FakeClock {
    secs: Arc<AtomicU64>,
}

impl FakeClock {
    pub fn new(start_secs: u64) -> Self {
        Self {
            secs: Arc::new(AtomicU64::new(start_secs)),
        }
    }

    pub fn advance(&self, secs: u64) {
        self.secs.fetch_add(secs, Ordering::SeqCst);
    }

    pub fn set(&self, secs: u64) {
        self.secs.store(secs, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_secs(&self) -> u64 {
        self.secs.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_advances() {
        let c = FakeClock::new(1_000);
        assert_eq!(c.now_secs(), 1_000);
        c.advance(86_400);
        assert_eq!(c.now_secs(), 87_400);
        // Clones share time.
        let c2 = c.clone();
        c2.set(5);
        assert_eq!(c.now_secs(), 5);
    }
}
