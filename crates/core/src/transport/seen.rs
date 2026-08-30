//! Frame-hash dedup.
//!
//! In-memory ring of recent frame fingerprints. Duplicates are dropped before
//! any crypto is touched. Gates **notification only**, never storage: a lost
//! ring means a possible extra arrival event, never message loss.

use std::collections::{HashSet, VecDeque};

use sha3::{Digest, Sha3_256};

pub const FP_BYTES: usize = 16;
pub const DEFAULT_CAPACITY: usize = 8192;

/// First 16 bytes of SHA-256 over the frame bytes (intro is not hashed).
pub fn fingerprint(frame: &[u8]) -> [u8; FP_BYTES] {
    let digest = Sha3_256::digest(frame);
    let mut fp = [0u8; FP_BYTES];
    fp.copy_from_slice(&digest[..FP_BYTES]);
    fp
}

pub struct SeenRing {
    capacity: usize,
    order: VecDeque<[u8; FP_BYTES]>,
    set: HashSet<[u8; FP_BYTES]>,
}

impl SeenRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            set: HashSet::with_capacity(capacity),
        }
    }

    /// Returns `true` if the frame was seen before. Marks it seen either way;
    /// a re-sight moves the fingerprint to the newest position (LRU).
    pub fn seen_or_mark(&mut self, frame: &[u8]) -> bool {
        let fp = fingerprint(frame);
        if self.set.contains(&fp) {
            self.order.retain(|f| f != &fp);
            self.order.push_back(fp);
            return true;
        }
        self.set.insert(fp);
        self.order.push_back(fp);
        while self.order.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        false
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

impl Default for SeenRing {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sight_false_second_true() {
        let mut ring = SeenRing::default();
        assert!(!ring.seen_or_mark(b"frame-a"));
        assert!(ring.seen_or_mark(b"frame-a"));
        assert!(!ring.seen_or_mark(b"frame-b"));
    }

    #[test]
    fn evicts_oldest_at_capacity() {
        let mut ring = SeenRing::new(4);
        for i in 0..4u8 {
            assert!(!ring.seen_or_mark(&[i]));
        }
        assert!(!ring.seen_or_mark(&[9])); // evicts [0]
        assert!(ring.seen_or_mark(&[1])); // still present
        assert!(!ring.seen_or_mark(&[0])); // [0] was evicted → new again
        assert_eq!(ring.len(), 4);
    }

    #[test]
    fn resight_refreshes_lru_position() {
        let mut ring = SeenRing::new(2);
        ring.seen_or_mark(&[1]);
        ring.seen_or_mark(&[2]);
        ring.seen_or_mark(&[1]); // refresh [1]; [2] is now oldest
        ring.seen_or_mark(&[3]); // evicts [2]
        assert!(ring.seen_or_mark(&[1]));
        assert!(!ring.seen_or_mark(&[2]));
    }
}
