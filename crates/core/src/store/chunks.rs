//! `attachment_chunks` table repository: chunk *payloads* for the
//! attachment pipeline. Metadata and the completion bitmap live in
//! `attachments`; this table is pure blob storage keyed by
//! (head_id, idx). Reassembly + hash verification are the attach
//! feature module's job — this layer stays CRUD.

use rusqlite::params;

use super::{hex_encode, Db, StoreError};

pub trait ChunksRepository {
    /// Store one chunk payload. Re-puts are idempotent (same index,
    /// same bytes expected; a conflicting rewrite is refused).
    /// `rel_id`/`now` attribute the row for the orphan caps and TTL
    /// sweep; they are ignored on an idempotent re-put.
    fn put_chunk(
        &self,
        head_id: &[u8; 16],
        index: u16,
        data: &[u8],
        rel_id: &str,
        now: i64,
    ) -> Result<(), StoreError>;
    fn chunk(&self, head_id: &[u8; 16], index: u16) -> Result<Option<Vec<u8>>, StoreError>;
    /// All chunks of a transfer, ordered by index (missing indexes are
    /// simply absent — the caller checks the bitmap in `attachments`).
    fn chunks_for(&self, head_id: &[u8; 16]) -> Result<Vec<Vec<u8>>, StoreError>;
    /// Drop every chunk of a transfer (tombstone, sweep, failed hash).
    fn delete_chunks(&self, head_id: &[u8; 16]) -> Result<u64, StoreError>;
    /// (count, bytes) of chunks stored for `head_id`. Only meaningful
    /// while the head is unknown — once the ATTACH_HEAD lands the
    /// transfer's own `chunk_count`/`uncompressed_n` govern.
    fn orphan_head_stats(&self, head_id: &[u8; 16]) -> Result<(u32, u64), StoreError>;
    /// (count, bytes) of orphan chunks across one relationship: rows
    /// whose head has no `attachments` entry yet.
    fn orphan_rel_stats(&self, rel_id: &str) -> Result<(u32, u64), StoreError>;
    /// Delete orphan chunks (no `attachments` row) that arrived before
    /// `older_than`. Returns rows deleted.
    fn sweep_orphans(&self, older_than: i64) -> Result<u64, StoreError>;
}

impl ChunksRepository for Db {
    fn put_chunk(
        &self,
        head_id: &[u8; 16],
        index: u16,
        data: &[u8],
        rel_id: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        let id = hex_encode(head_id);
        let existing: Option<Vec<u8>> = self.chunk(head_id, index)?;
        if let Some(prev) = existing {
            if prev != data {
                return Err(StoreError::Corrupt(format!(
                    "chunk {id}:{index} rewritten with different bytes"
                )));
            }
            return Ok(()); // redelivery of the same chunk
        }
        self.conn().execute(
            "INSERT INTO attachment_chunks (head_id, idx, data, rel_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, index, data, rel_id, now],
        )?;
        Ok(())
    }

    fn chunk(&self, head_id: &[u8; 16], index: u16) -> Result<Option<Vec<u8>>, StoreError> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT data FROM attachment_chunks WHERE head_id = ?1 AND idx = ?2",
                params![hex_encode(head_id), index],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn chunks_for(&self, head_id: &[u8; 16]) -> Result<Vec<Vec<u8>>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare("SELECT data FROM attachment_chunks WHERE head_id = ?1 ORDER BY idx ASC")?;
        let rows = stmt.query_map(params![hex_encode(head_id)], |r| r.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn delete_chunks(&self, head_id: &[u8; 16]) -> Result<u64, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM attachment_chunks WHERE head_id = ?1",
            params![hex_encode(head_id)],
        )?;
        Ok(n as u64)
    }

    fn orphan_head_stats(&self, head_id: &[u8; 16]) -> Result<(u32, u64), StoreError> {
        self.conn()
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(data)), 0)
                 FROM attachment_chunks WHERE head_id = ?1",
                params![hex_encode(head_id)],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u64>(1)?)),
            )
            .map_err(Into::into)
    }

    fn orphan_rel_stats(&self, rel_id: &str) -> Result<(u32, u64), StoreError> {
        self.conn()
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(LENGTH(c.data)), 0)
                 FROM attachment_chunks c
                 WHERE c.rel_id = ?1
                   AND NOT EXISTS (SELECT 1 FROM attachments a WHERE a.head_id = c.head_id)",
                params![rel_id],
                |r| Ok((r.get::<_, u32>(0)?, r.get::<_, u64>(1)?)),
            )
            .map_err(Into::into)
    }

    fn sweep_orphans(&self, older_than: i64) -> Result<u64, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM attachment_chunks
             WHERE created_at < ?1
               AND NOT EXISTS (SELECT 1 FROM attachments a WHERE a.head_id = attachment_chunks.head_id)",
            params![older_than],
        )?;
        Ok(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_get_idempotent_conflict_refused() {
        let db = Db::open_in_memory().unwrap();
        let head = [7u8; 16];
        db.put_chunk(&head, 0, b"aaa", "rel1", 100).unwrap();
        db.put_chunk(&head, 2, b"ccc", "rel1", 100).unwrap();
        // Same bytes again: idempotent redelivery.
        db.put_chunk(&head, 0, b"aaa", "rel1", 100).unwrap();
        // Different bytes at the same index: fail closed.
        assert!(db.put_chunk(&head, 0, b"zzz", "rel1", 100).is_err());

        assert_eq!(
            db.chunk(&head, 0).unwrap().as_deref(),
            Some(b"aaa".as_slice())
        );
        assert!(db.chunk(&head, 1).unwrap().is_none());
        let all = db.chunks_for(&head).unwrap();
        assert_eq!(all, vec![b"aaa".to_vec(), b"ccc".to_vec()]);

        assert_eq!(db.delete_chunks(&head).unwrap(), 2);
        assert!(db.chunks_for(&head).unwrap().is_empty());
    }

    #[test]
    fn orphan_stats_and_sweep() {
        let db = Db::open_in_memory().unwrap();
        let head_a = [1u8; 16];
        let head_b = [2u8; 16];
        db.put_chunk(&head_a, 0, b"aaaa", "rel1", 100).unwrap();
        db.put_chunk(&head_a, 1, b"bbbb", "rel1", 200).unwrap();
        db.put_chunk(&head_b, 0, b"cc", "rel2", 100).unwrap();

        // Per-head stats count everything stored under that head.
        assert_eq!(db.orphan_head_stats(&head_a).unwrap(), (2, 8));
        // Per-rel stats skip chunks whose head is known (none here).
        assert_eq!(db.orphan_rel_stats("rel1").unwrap(), (2, 8));
        assert_eq!(db.orphan_rel_stats("rel2").unwrap(), (1, 2));
        assert_eq!(db.orphan_rel_stats("rel3").unwrap(), (0, 0));

        // Sweep with a cutoff: only older orphans go.
        assert_eq!(db.sweep_orphans(150).unwrap(), 2);
        assert_eq!(db.orphan_head_stats(&head_a).unwrap(), (1, 4));
        assert!(db.orphan_rel_stats("rel2").unwrap().0 == 0);
    }
}
