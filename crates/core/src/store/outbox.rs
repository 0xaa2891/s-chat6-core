//! `outbox` table repository: the delivery queue. Rows hold send-ready
//! wire records (already bucketed + padded by `wire::frame`); the sync
//! layer drains `due()` and hands records to the transport. A row leaves
//! the outbox on transmit or expiry — retransmission after that is the
//! I11 ciphertext cache's job, not the queue's.

use rusqlite::{params, Connection, OptionalExtension};

use super::{hex_decode, hex_encode, Db, StoreError};

/// Fail every undelivered outbound row for a relationship and clear
/// its queue — the Case B path: a broken session can
/// never deliver what is queued, so the rows surface `failed` at break
/// time instead of sitting until the 24 h TTL. Returns how many ledger
/// rows moved. Idempotent.
pub fn fail_relationship_outbound(db: &Connection, rel_id: &str) -> Result<u64, StoreError> {
    let n = db.execute(
        "UPDATE messages SET state = 'failed'
         WHERE rel_id = ?1 AND direction = 'out' AND state IN ('queued', 'transmitted')",
        params![rel_id],
    )?;
    db.execute("DELETE FROM outbox WHERE rel_id = ?1", params![rel_id])?;
    Ok(n as u64)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxRow {
    pub msg_id: [u8; 16],
    pub rel_id: String,
    pub record: Vec<u8>,
    pub attempts: u32,
    pub next_attempt_at: u64,
    pub expires_at: u64,
    pub created_at: u64,
}

pub trait OutboxRepository {
    /// Queue a record for delivery. `ttl_secs` is the delivery horizon:
    /// undelivered past `now + ttl` the message fails (never silently
    /// dropped — the message row's state becomes `failed`).
    fn enqueue(
        &self,
        msg_id: &[u8; 16],
        rel_id: &str,
        record: &[u8],
        ttl_secs: u64,
    ) -> Result<(), StoreError>;
    /// Re-queue a retransmission: identical bytes under the same msg_id,
    /// attempts reset, fresh delivery horizon. Replaces any still-queued
    /// original (the record is byte-identical by I11).
    fn requeue(
        &self,
        msg_id: &[u8; 16],
        rel_id: &str,
        record: &[u8],
        ttl_secs: u64,
    ) -> Result<(), StoreError>;
    /// Records whose `next_attempt_at` has passed, oldest first.
    fn due(&self, limit: u32) -> Result<Vec<OutboxRow>, StoreError>;
    /// Note a failed send: bump attempts, schedule the next attempt
    /// `backoff_secs` from now.
    fn note_attempt(&self, msg_id: &[u8; 16], backoff_secs: u64) -> Result<(), StoreError>;
    /// Remove from the queue after a successful socket write. The
    /// message row moves to `transmitted` separately (sync's job).
    fn dequeue(&self, msg_id: &[u8; 16]) -> Result<Option<OutboxRow>, StoreError>;
    /// Delete and return every entry past its delivery horizon.
    fn fail_expired(&self) -> Result<Vec<OutboxRow>, StoreError>;
    fn queued_len(&self) -> Result<u64, StoreError>;
}

impl OutboxRepository for Db {
    fn enqueue(
        &self,
        msg_id: &[u8; 16],
        rel_id: &str,
        record: &[u8],
        ttl_secs: u64,
    ) -> Result<(), StoreError> {
        let now = self.clock().now_secs();
        self.conn().execute(
            "INSERT INTO outbox (
                msg_id, rel_id, record, attempts, next_attempt_at, expires_at, created_at
             ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?4)",
            params![
                hex_encode(msg_id),
                rel_id,
                record,
                now as i64,
                (now + ttl_secs) as i64,
            ],
        )?;
        Ok(())
    }

    fn requeue(
        &self,
        msg_id: &[u8; 16],
        rel_id: &str,
        record: &[u8],
        ttl_secs: u64,
    ) -> Result<(), StoreError> {
        let now = self.clock().now_secs();
        self.conn().execute(
            "INSERT OR REPLACE INTO outbox (
                msg_id, rel_id, record, attempts, next_attempt_at, expires_at, created_at
             ) VALUES (?1, ?2, ?3, 0, ?4, ?5, ?4)",
            params![
                hex_encode(msg_id),
                rel_id,
                record,
                now as i64,
                (now + ttl_secs) as i64,
            ],
        )?;
        Ok(())
    }

    fn due(&self, limit: u32) -> Result<Vec<OutboxRow>, StoreError> {
        let now = self.clock().now_secs() as i64;
        let mut stmt = self.conn().prepare(
            "SELECT msg_id, rel_id, record, attempts, next_attempt_at, expires_at, created_at
             FROM outbox WHERE next_attempt_at <= ?1
             ORDER BY next_attempt_at ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now, limit], row_to_outbox)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn note_attempt(&self, msg_id: &[u8; 16], backoff_secs: u64) -> Result<(), StoreError> {
        let next = (self.clock().now_secs() + backoff_secs) as i64;
        self.conn().execute(
            "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ?2
             WHERE msg_id = ?1",
            params![hex_encode(msg_id), next],
        )?;
        Ok(())
    }

    fn dequeue(&self, msg_id: &[u8; 16]) -> Result<Option<OutboxRow>, StoreError> {
        let row = self
            .conn()
            .query_row(
                "SELECT msg_id, rel_id, record, attempts, next_attempt_at, expires_at, created_at
                 FROM outbox WHERE msg_id = ?1",
                params![hex_encode(msg_id)],
                row_to_outbox,
            )
            .optional()?;
        if row.is_some() {
            self.conn().execute(
                "DELETE FROM outbox WHERE msg_id = ?1",
                params![hex_encode(msg_id)],
            )?;
        }
        Ok(row)
    }

    fn fail_expired(&self) -> Result<Vec<OutboxRow>, StoreError> {
        let now = self.clock().now_secs() as i64;
        let mut stmt = self.conn().prepare(
            "SELECT msg_id, rel_id, record, attempts, next_attempt_at, expires_at, created_at
             FROM outbox WHERE expires_at <= ?1",
        )?;
        let expired = stmt
            .query_map(params![now], row_to_outbox)?
            .collect::<Result<Vec<_>, _>>()?;
        self.conn()
            .execute("DELETE FROM outbox WHERE expires_at <= ?1", params![now])?;
        Ok(expired)
    }

    fn queued_len(&self) -> Result<u64, StoreError> {
        let n: i64 = self
            .conn()
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get(0))?;
        Ok(n as u64)
    }
}

fn row_to_outbox(r: &rusqlite::Row) -> rusqlite::Result<OutboxRow> {
    let msg_id: String = r.get(0)?;
    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    Ok(OutboxRow {
        msg_id: hex_decode(&msg_id)
            .map_err(corrupt)?
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("outbox.msg_id: not 16 bytes".into())))?,
        rel_id: r.get(1)?,
        record: r.get(2)?,
        attempts: r.get::<_, u32>(3)?,
        next_attempt_at: r.get::<_, i64>(4)? as u64,
        expires_at: r.get::<_, i64>(5)? as u64,
        created_at: r.get::<_, i64>(6)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::clock::FakeClock;
    use std::sync::Arc;

    fn db() -> (Db, FakeClock) {
        let clock = FakeClock::new(1_000_000);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        (db, clock)
    }

    #[test]
    fn enqueue_due_dequeue_cycle() {
        let (db, clock) = db();
        let id = [1u8; 16];
        db.enqueue(&id, "rel", b"record", 3600).unwrap();
        assert_eq!(db.queued_len().unwrap(), 1);

        // Due immediately (next_attempt_at = now).
        let due = db.due(10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].record, b"record");

        // Failed send → backoff takes it out of the due set.
        db.note_attempt(&id, 600).unwrap();
        assert!(db.due(10).unwrap().is_empty());
        clock.advance(600);
        assert_eq!(db.due(10).unwrap().len(), 1);
        assert_eq!(db.due(10).unwrap()[0].attempts, 1);

        // Successful send → gone from the queue.
        let row = db.dequeue(&id).unwrap().unwrap();
        assert_eq!(row.attempts, 1);
        assert_eq!(db.queued_len().unwrap(), 0);
        assert!(db.dequeue(&id).unwrap().is_none());
    }

    #[test]
    fn expiry_fails_undelivered() {
        let (db, clock) = db();
        db.enqueue(&[1u8; 16], "rel", b"a", 100).unwrap();
        db.enqueue(&[2u8; 16], "rel", b"b", 10_000).unwrap();
        clock.advance(101);
        let expired = db.fail_expired().unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].msg_id, [1u8; 16]);
        assert_eq!(db.queued_len().unwrap(), 1);
    }
}
