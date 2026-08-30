//! `attachments` table repository: transfer state for chunked media.
//! Chunk *payloads* live in the media layer; this table tracks
//! the head metadata and an LSB-first bitmap of completed chunk indexes.

use rusqlite::{params, OptionalExtension};

use super::messages::Direction;
use super::{hex_decode, hex_encode, Db, StoreError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentRow {
    pub head_id: [u8; 16],
    pub rel_id: String,
    pub msg_id: [u8; 16],
    pub direction: Direction,
    pub media_class: u8,
    pub mime_hint: String,
    pub uncompressed_n: u32,
    pub chunk_count: u16,
    pub chunk_bucket: u16,
    pub content_sha256: [u8; 32],
    pub caption: String,
    pub flags: u8,
    pub orig_ext: String,
    /// LSB-first bitmap of completed chunk indexes.
    pub chunks: Vec<u8>,
    pub complete: bool,
    /// View-once media: set after the client renders it; chunk payloads
    /// are erased at that moment.
    pub consumed: bool,
    pub expires_at: Option<u64>,
    pub created_at: u64,
}

/// Head fields needed to start tracking a transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAttachment {
    pub head_id: [u8; 16],
    pub rel_id: String,
    pub msg_id: [u8; 16],
    pub direction: Direction,
    pub media_class: u8,
    pub mime_hint: String,
    pub uncompressed_n: u32,
    pub chunk_count: u16,
    pub chunk_bucket: u16,
    pub content_sha256: [u8; 32],
    pub caption: String,
    pub flags: u8,
    pub orig_ext: String,
    pub expires_at: Option<u64>,
}

const COLS: &str = "head_id, rel_id, msg_id, direction, media_class, mime_hint,
    uncompressed_n, chunk_count, chunk_bucket, content_sha256,
    caption, flags, orig_ext, chunks, complete, consumed, expires_at, created_at";

pub trait AttachmentsRepository {
    fn insert_head(&self, head: &NewAttachment) -> Result<(), StoreError>;
    fn attachment(&self, head_id: &[u8; 16]) -> Result<Option<AttachmentRow>, StoreError>;
    fn for_message(&self, msg_id: &[u8; 16]) -> Result<Vec<AttachmentRow>, StoreError>;
    /// Mark chunk `index` done. Returns `Some(true)` when that chunk
    /// completed the transfer, `Some(false)` otherwise, `None` if the
    /// head is unknown or the index is out of range (fail closed: the
    /// wire layer already range-checked, so this is a bug, not an event).
    fn note_chunk(&self, head_id: &[u8; 16], index: u16) -> Result<Option<bool>, StoreError>;
    /// View-once: the client rendered it; payloads are erased.
    fn mark_consumed(&self, head_id: &[u8; 16]) -> Result<bool, StoreError>;
    /// Delete transfers past their TTL. Returns the number swept.
    fn sweep_expired(&self) -> Result<u64, StoreError>;
    /// Delete one transfer row (tombstone, capability erase, failed
    /// hash). Chunk payloads are the caller's job (`chunks` repo).
    fn delete_attachment(&self, head_id: &[u8; 16]) -> Result<bool, StoreError>;
}

impl AttachmentsRepository for Db {
    fn insert_head(&self, head: &NewAttachment) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO attachments (
                head_id, rel_id, msg_id, direction, media_class, mime_hint,
                uncompressed_n, chunk_count, chunk_bucket, content_sha256,
                caption, flags, orig_ext, chunks, complete, consumed, expires_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, X'', 0, 0, ?14, ?15)",
            params![
                hex_encode(&head.head_id),
                head.rel_id,
                hex_encode(&head.msg_id),
                head.direction.as_str(),
                head.media_class,
                head.mime_hint,
                head.uncompressed_n,
                head.chunk_count,
                head.chunk_bucket,
                head.content_sha256.as_slice(),
                head.caption,
                head.flags,
                head.orig_ext,
                head.expires_at.map(|v| v as i64),
                self.clock().now_secs() as i64,
            ],
        )?;
        Ok(())
    }

    fn attachment(&self, head_id: &[u8; 16]) -> Result<Option<AttachmentRow>, StoreError> {
        self.conn()
            .query_row(
                &format!("SELECT {COLS} FROM attachments WHERE head_id = ?1"),
                params![hex_encode(head_id)],
                row_to_attachment,
            )
            .optional()
            .map_err(Into::into)
    }

    fn for_message(&self, msg_id: &[u8; 16]) -> Result<Vec<AttachmentRow>, StoreError> {
        let mut stmt = self
            .conn()
            .prepare(&format!("SELECT {COLS} FROM attachments WHERE msg_id = ?1"))?;
        let rows = stmt.query_map(params![hex_encode(msg_id)], row_to_attachment)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn mark_consumed(&self, head_id: &[u8; 16]) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE attachments SET consumed = 1 WHERE head_id = ?1",
            params![hex_encode(head_id)],
        )?;
        Ok(n > 0)
    }

    fn note_chunk(&self, head_id: &[u8; 16], index: u16) -> Result<Option<bool>, StoreError> {
        let tx = self.conn().unchecked_transaction()?;
        let row = tx
            .query_row(
                "SELECT chunk_count, chunks FROM attachments WHERE head_id = ?1",
                params![hex_encode(head_id)],
                |r| Ok((r.get::<_, u16>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        let Some((chunk_count, mut chunks)) = row else {
            tx.rollback()?;
            return Ok(None);
        };
        if index >= chunk_count {
            tx.rollback()?;
            return Ok(None);
        }
        let need = (chunk_count as usize).div_ceil(8);
        chunks.resize(need, 0);
        chunks[index as usize / 8] |= 1 << (index % 8);
        let done = chunks.iter().map(|b| b.count_ones()).sum::<u32>() >= u32::from(chunk_count);
        // Bitmap only: `complete` flips in `try_complete` after the
        // content hash verifies — never here.
        tx.execute(
            "UPDATE attachments SET chunks = ?2 WHERE head_id = ?1",
            params![hex_encode(head_id), chunks],
        )?;
        tx.commit()?;
        Ok(Some(done))
    }

    fn sweep_expired(&self) -> Result<u64, StoreError> {
        let now = self.clock().now_secs() as i64;
        let n = self.conn().execute(
            "DELETE FROM attachments WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        Ok(n as u64)
    }

    fn delete_attachment(&self, head_id: &[u8; 16]) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM attachments WHERE head_id = ?1",
            params![hex_encode(head_id)],
        )?;
        Ok(n > 0)
    }
}

fn row_to_attachment(r: &rusqlite::Row) -> rusqlite::Result<AttachmentRow> {
    let head_id: String = r.get(0)?;
    let msg_id: String = r.get(2)?;
    let direction: String = r.get(3)?;
    let sha: Vec<u8> = r.get(9)?;
    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    let id16 = |h: String, at: &'static str| {
        hex_decode(&h)
            .map_err(corrupt)?
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt(format!("{at}: not 16 bytes"))))
    };
    Ok(AttachmentRow {
        head_id: id16(head_id, "attachments.head_id")?,
        rel_id: r.get(1)?,
        msg_id: id16(msg_id, "attachments.msg_id")?,
        direction: Direction::parse(&direction).map_err(corrupt)?,
        media_class: r.get(4)?,
        mime_hint: r.get(5)?,
        uncompressed_n: r.get(6)?,
        chunk_count: r.get(7)?,
        chunk_bucket: r.get(8)?,
        content_sha256: sha
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("attachments.sha: not 32 bytes".into())))?,
        caption: r.get(10)?,
        flags: r.get(11)?,
        orig_ext: r.get(12)?,
        chunks: r.get(13)?,
        complete: r.get::<_, i64>(14)? != 0,
        consumed: r.get::<_, i64>(15)? != 0,
        expires_at: r.get::<_, Option<i64>>(16)?.map(|v| v as u64),
        created_at: r.get::<_, i64>(17)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::clock::{Clock, FakeClock};
    use std::sync::Arc;

    fn db() -> (Db, FakeClock) {
        let clock = FakeClock::new(1_000_000);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        (db, clock)
    }

    fn head(id: u8, chunks: u16) -> NewAttachment {
        NewAttachment {
            head_id: [id; 16],
            rel_id: "rel".into(),
            msg_id: [9u8; 16],
            direction: Direction::In,
            media_class: 1,
            mime_hint: "image/jpeg".into(),
            uncompressed_n: 1000,
            chunk_count: chunks,
            chunk_bucket: 2,
            content_sha256: [3u8; 32],
            caption: String::new(),
            flags: 0,
            orig_ext: "jpg".into(),
            expires_at: None,
        }
    }

    #[test]
    fn chunk_bitmap_tracks_completion() {
        let (db, _) = db();
        db.insert_head(&head(1, 3)).unwrap();

        assert_eq!(db.note_chunk(&[1u8; 16], 0).unwrap(), Some(false));
        assert_eq!(db.note_chunk(&[1u8; 16], 2).unwrap(), Some(false));
        // Duplicate chunk: idempotent, still incomplete.
        assert_eq!(db.note_chunk(&[1u8; 16], 0).unwrap(), Some(false));
        assert_eq!(db.note_chunk(&[1u8; 16], 1).unwrap(), Some(true));

        let row = db.attachment(&[1u8; 16]).unwrap().unwrap();
        // The bitmap tracks arrival; `complete` flips only after the
        // content hash verifies (attach::try_complete's job).
        assert!(!row.complete);
        assert_eq!(row.chunks, vec![0b0000_0111]);

        // Out of range and unknown head fail closed.
        assert_eq!(db.note_chunk(&[1u8; 16], 3).unwrap(), None);
        assert_eq!(db.note_chunk(&[7u8; 16], 0).unwrap(), None);
    }

    #[test]
    fn for_message_and_expiry() {
        let (db, clock) = db();
        let mut h = head(1, 1);
        h.expires_at = Some(clock.now_secs() + 50);
        db.insert_head(&h).unwrap();
        db.insert_head(&head(2, 1)).unwrap();

        assert_eq!(db.for_message(&[9u8; 16]).unwrap().len(), 2);
        clock.advance(51);
        assert_eq!(db.sweep_expired().unwrap(), 1);
        assert_eq!(db.for_message(&[9u8; 16]).unwrap().len(), 1);
    }
}
