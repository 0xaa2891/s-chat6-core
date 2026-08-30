//! `inbound_seqs` table repository:
//! every inbound envelope's `app_seq`, history and ephemeral alike. The
//! resync receive view is computed from this table — ephemeral beats
//! (typing/presence) consume sequence numbers and must count toward
//! continuity, but never touch the message ledger.

use rusqlite::params;

use super::{Db, StoreError};

pub trait InboundSeqsRepository {
    /// Record an inbound `app_seq`. Returns true if newly seen, false
    /// on redelivery (same seq = same envelope; seqs are unique per
    /// sender).
    fn note_inbound_seq(&self, rel_id: &str, app_seq: u64) -> Result<bool, StoreError>;
    fn has_inbound_seq(&self, rel_id: &str, app_seq: u64) -> Result<bool, StoreError>;
}

impl InboundSeqsRepository for Db {
    fn note_inbound_seq(&self, rel_id: &str, app_seq: u64) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "INSERT OR IGNORE INTO inbound_seqs (rel_id, app_seq) VALUES (?1, ?2)",
            params![rel_id, app_seq as i64],
        )?;
        Ok(n > 0)
    }

    fn has_inbound_seq(&self, rel_id: &str, app_seq: u64) -> Result<bool, StoreError> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM inbound_seqs WHERE rel_id = ?1 AND app_seq = ?2",
            params![rel_id, app_seq as i64],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_is_idempotent() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.note_inbound_seq("rel", 1).unwrap());
        assert!(!db.note_inbound_seq("rel", 1).unwrap(), "redelivery");
        assert!(db.note_inbound_seq("rel", 2).unwrap());
        assert!(db.note_inbound_seq("other", 1).unwrap(), "per-relationship");
        assert!(db.has_inbound_seq("rel", 2).unwrap());
        assert!(!db.has_inbound_seq("rel", 3).unwrap());
    }
}
