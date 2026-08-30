//! `tombstones` table repository: a DELETE
//! records the target msg_id here so a late-arriving copy of that
//! message (resync replay, out-of-order delivery) is dropped on sight.
//! Entries live `TOMBSTONE_TTL_SEC` and are capped per relationship —
//! prune expired first, then oldest.

use rusqlite::params;

use super::{hex_encode, Db, StoreError};

/// Tombstone lifetime: a DELETE tombstone expires after one day.
pub const TOMBSTONE_TTL_SEC: u64 = 86_400;

// Tombstone cap, declared in the bounds catalog.
pub use crate::limits::tombstones::TOMBSTONE_CAP;

pub trait TombstonesRepository {
    /// Record a delete of `ref_id`. Idempotent (re-delete refreshes the
    /// expiry, matching a re-delivered DELETE).
    fn add_tombstone(&self, rel_id: &str, ref_id: &[u8; 16]) -> Result<(), StoreError>;
    /// Is this msg_id deleted right now? (Unexpired entry exists.)
    fn is_tombstoned(&self, rel_id: &str, ref_id: &[u8; 16]) -> Result<bool, StoreError>;
    /// Drop expired entries, then oldest beyond the per-rel cap.
    /// Returns rows removed.
    fn prune_tombstones(&self, rel_id: &str) -> Result<u64, StoreError>;
    fn tombstone_count(&self, rel_id: &str) -> Result<u64, StoreError>;
}

impl TombstonesRepository for Db {
    fn add_tombstone(&self, rel_id: &str, ref_id: &[u8; 16]) -> Result<(), StoreError> {
        let expiry = self.clock().now_secs() + TOMBSTONE_TTL_SEC;
        self.conn().execute(
            "INSERT INTO tombstones (rel_id, ref_id, expiry) VALUES (?1, ?2, ?3)
             ON CONFLICT (rel_id, ref_id) DO UPDATE SET expiry = excluded.expiry",
            params![rel_id, hex_encode(ref_id), expiry as i64],
        )?;
        Ok(())
    }

    fn is_tombstoned(&self, rel_id: &str, ref_id: &[u8; 16]) -> Result<bool, StoreError> {
        let now = self.clock().now_secs() as i64;
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM tombstones
             WHERE rel_id = ?1 AND ref_id = ?2 AND expiry > ?3",
            params![rel_id, hex_encode(ref_id), now],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    fn prune_tombstones(&self, rel_id: &str) -> Result<u64, StoreError> {
        let now = self.clock().now_secs() as i64;
        let expired = self.conn().execute(
            "DELETE FROM tombstones WHERE rel_id = ?1 AND expiry <= ?2",
            params![rel_id, now],
        )?;
        // Over cap: drop the oldest (soonest expiry) beyond the cap.
        let over = self.conn().execute(
            "DELETE FROM tombstones WHERE rel_id = ?1 AND ref_id IN (
                SELECT ref_id FROM tombstones WHERE rel_id = ?1
                ORDER BY expiry DESC LIMIT -1 OFFSET ?2
             )",
            params![rel_id, TOMBSTONE_CAP as i64],
        )?;
        Ok((expired + over) as u64)
    }

    fn tombstone_count(&self, rel_id: &str) -> Result<u64, StoreError> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM tombstones WHERE rel_id = ?1",
            params![rel_id],
            |r| r.get(0),
        )?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::clock::FakeClock;
    use std::sync::Arc;

    #[test]
    fn add_check_expire_prune() {
        let clock = FakeClock::new(1_000_000);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        let id = [1u8; 16];
        assert!(!db.is_tombstoned("rel", &id).unwrap());
        db.add_tombstone("rel", &id).unwrap();
        assert!(db.is_tombstoned("rel", &id).unwrap());
        assert!(!db.is_tombstoned("other", &id).unwrap());

        clock.advance(TOMBSTONE_TTL_SEC);
        assert!(
            !db.is_tombstoned("rel", &id).unwrap(),
            "expired reads false"
        );
        assert_eq!(db.prune_tombstones("rel").unwrap(), 1);
        assert_eq!(db.tombstone_count("rel").unwrap(), 0);
    }

    #[test]
    fn cap_prunes_oldest() {
        let clock = FakeClock::new(1_000_000);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        for i in 0..(TOMBSTONE_CAP + 10) as u16 {
            let mut id = [0u8; 16];
            id[..2].copy_from_slice(&i.to_be_bytes());
            db.add_tombstone("rel", &id).unwrap();
            clock.advance(1); // strictly increasing expiry = age order
        }
        assert_eq!(db.tombstone_count("rel").unwrap(), TOMBSTONE_CAP + 10);
        let removed = db.prune_tombstones("rel").unwrap();
        assert_eq!(removed, 10);
        assert_eq!(db.tombstone_count("rel").unwrap(), TOMBSTONE_CAP);
        // The oldest (lowest ids) are gone; the newest survive.
        assert!(!db.is_tombstoned("rel", &[0u8; 16]).unwrap());
        let mut newest = [0u8; 16];
        newest[..2].copy_from_slice(&((TOMBSTONE_CAP + 9) as u16).to_be_bytes());
        assert!(db.is_tombstoned("rel", &newest).unwrap());
    }
}
