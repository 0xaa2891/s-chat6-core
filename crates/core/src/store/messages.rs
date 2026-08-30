//! `messages` table repository: the per-relationship ledger, both
//! directions. Rows are the SQL↔domain mapping layer — the sync layer
//! converts `MessageRow` ↔ `Envelope` and never writes SQL itself.

use rusqlite::{params, OptionalExtension};

use super::settings::SettingsRepository;
use super::{hex_decode, hex_encode, Db, StoreError};

// Inbound ledger rows scanned when building a receive view; declared in
// the bounds catalog.
use crate::limits::store::VIEW_SCAN_LIMIT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "in" => Ok(Direction::In),
            "out" => Ok(Direction::Out),
            other => Err(StoreError::Corrupt(format!("direction {other:?}"))),
        }
    }
}

/// Delivery lifecycle: clients never see "sent = socket
/// write". Inbound rows are always `Received`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryState {
    Received,
    Queued,
    Transmitted,
    Acknowledged,
    Failed,
}

impl DeliveryState {
    pub fn as_str(self) -> &'static str {
        match self {
            DeliveryState::Received => "received",
            DeliveryState::Queued => "queued",
            DeliveryState::Transmitted => "transmitted",
            DeliveryState::Acknowledged => "acknowledged",
            DeliveryState::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "received" => Ok(DeliveryState::Received),
            "queued" => Ok(DeliveryState::Queued),
            "transmitted" => Ok(DeliveryState::Transmitted),
            "acknowledged" => Ok(DeliveryState::Acknowledged),
            "failed" => Ok(DeliveryState::Failed),
            other => Err(StoreError::Corrupt(format!("delivery state {other:?}"))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageRow {
    pub msg_id: [u8; 16],
    pub rel_id: String,
    pub direction: Direction,
    pub app_seq: u64,
    pub sent_at: u64,
    pub received_at: Option<u64>,
    pub env_type: u8,
    pub ref_id: Option<[u8; 16]>,
    pub payload: Vec<u8>,
    pub state: DeliveryState,
    pub expires_at: Option<u64>,
    pub created_at: u64,
    /// An EDIT replaced the payload (the original body is gone).
    pub edited: bool,
    /// A DELETE wiped the payload; the row stays for threading/seqs.
    pub tombstone: bool,
    /// Peer's READ receipt landed (outbound rows only).
    pub read_at: Option<u64>,
    /// How many EDITs this row has absorbed (cap: `EDIT_MAX_EDITS`).
    pub edit_count: u32,
    /// Highest peer `app_seq` of an applied EDIT (stale-seq rule).
    pub last_edit_seq: u64,
}

/// Everything needed to insert a row; `created_at` comes from the clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewMessage {
    pub msg_id: [u8; 16],
    pub rel_id: String,
    pub direction: Direction,
    pub app_seq: u64,
    pub sent_at: u64,
    pub received_at: Option<u64>,
    pub env_type: u8,
    pub ref_id: Option<[u8; 16]>,
    pub payload: Vec<u8>,
    pub state: DeliveryState,
    pub expires_at: Option<u64>,
}

/// The receive view over the inbound ledger:
/// max contiguous seq + LSB-first repair bitmap,
/// trimmed to the last set byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceiveView {
    pub max_contiguous_seq: u64,
    pub bitmap: Vec<u8>,
}

pub trait MessagesRepository {
    fn insert_message(&self, msg: &NewMessage) -> Result<(), StoreError>;
    fn message(&self, msg_id: &[u8; 16]) -> Result<Option<MessageRow>, StoreError>;
    /// Newest-first window over a relationship's ledger.
    fn thread(
        &self,
        rel_id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<MessageRow>, StoreError>;
    /// Thread rows the client renders (content + system lines only;
    /// control frames filtered out).
    fn thread_visible(
        &self,
        rel_id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<MessageRow>, StoreError>;
    /// Update the delivery state. Returns false if the row is gone.
    fn set_delivery(&self, msg_id: &[u8; 16], state: DeliveryState) -> Result<bool, StoreError>;
    fn delete_message(&self, msg_id: &[u8; 16]) -> Result<bool, StoreError>;
    /// Delete every row past its TTL. Returns the number swept.
    fn sweep_expired(&self) -> Result<u64, StoreError>;
    /// Receive view over the inbound ledger (for `RESYNC_REQ`).
    fn receive_view(&self, rel_id: &str, bitmap_bits: u32) -> Result<ReceiveView, StoreError>;
    /// Inbound seqs in `[base, max]` for the history hash's deep window.
    fn deep_seqs(&self, rel_id: &str, base: u64, max: u64) -> Result<Vec<u64>, StoreError>;
    /// Outbound rows with `app_seq` in `(after, after + window]`, oldest
    /// first — the candidate set for resync retransmission.
    fn outbound_window(
        &self,
        rel_id: &str,
        after: u64,
        window: u32,
    ) -> Result<Vec<MessageRow>, StoreError>;
    /// Outbound rows still awaiting a delivery verdict (`queued` or
    /// `transmitted`) with `app_seq <= through`, oldest first. A peer's
    /// resync view settles every one of these: covered → acked, missing →
    /// retransmit.
    fn unacked_outbound(&self, rel_id: &str, through: u64) -> Result<Vec<MessageRow>, StoreError>;
    /// Next outbound `app_seq` for a relationship (MAX + 1; self-healing).
    fn next_out_seq(&self, rel_id: &str) -> Result<u64, StoreError>;
    /// Apply an EDIT: replace the payload, bump the edit count, record
    /// the editor's `app_seq` (stale-seq rule). Returns false if the
    /// row is gone or already tombstoned.
    fn mark_edited(
        &self,
        msg_id: &[u8; 16],
        payload: &[u8],
        edit_seq: u64,
    ) -> Result<bool, StoreError>;
    /// Apply a DELETE: wipe the payload, set the tombstone marker.
    /// Returns false if the row is gone.
    fn mark_tombstoned(&self, msg_id: &[u8; 16]) -> Result<bool, StoreError>;
    /// Apply a DELETE_ALL: tombstone every live row in the relationship.
    /// Returns the number tombstoned.
    fn tombstone_thread(&self, rel_id: &str) -> Result<u64, StoreError>;
    /// Apply a peer's READ receipt to an outbound row.
    fn mark_read(&self, msg_id: &[u8; 16], read_at: u64) -> Result<bool, StoreError>;
    /// Wipe a relationship's ledger (DELETE_ALL / close), keeping the
    /// listed msg_ids (the in-flight control frames). Returns rows
    /// removed.
    fn erase_history(&self, rel_id: &str, keep: &[[u8; 16]]) -> Result<u64, StoreError>;
}

fn parse_id16(hex: &str, at: &str) -> Result<[u8; 16], StoreError> {
    let bytes = hex_decode(hex)?;
    bytes
        .try_into()
        .map_err(|_| StoreError::Corrupt(format!("{at}: not 16 bytes")))
}

/// Full column list in `row_to_message` order.
const COLS: &str = "msg_id, rel_id, direction, app_seq, sent_at, received_at,
                    env_type, ref_id, payload, state, expires_at, created_at,
                    edited, tombstone, read_at, edit_count, last_edit_seq";

impl MessagesRepository for Db {
    fn insert_message(&self, msg: &NewMessage) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT INTO messages (
                msg_id, rel_id, direction, app_seq, sent_at, received_at,
                env_type, ref_id, payload, state, expires_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                hex_encode(&msg.msg_id),
                msg.rel_id,
                msg.direction.as_str(),
                msg.app_seq as i64,
                msg.sent_at as i64,
                msg.received_at.map(|v| v as i64),
                msg.env_type,
                msg.ref_id.as_ref().map(|id| hex_encode(id)),
                msg.payload,
                msg.state.as_str(),
                msg.expires_at.map(|v| v as i64),
                self.clock().now_secs() as i64,
            ],
        )?;
        Ok(())
    }

    fn message(&self, msg_id: &[u8; 16]) -> Result<Option<MessageRow>, StoreError> {
        self.conn()
            .query_row(
                &format!("SELECT {COLS} FROM messages WHERE msg_id = ?1"),
                params![hex_encode(msg_id)],
                row_to_message,
            )
            .optional()
            .map_err(Into::into)
    }

    fn thread(
        &self,
        rel_id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<MessageRow>, StoreError> {
        let mut stmt = match before_seq {
            Some(_) => self.conn().prepare(&format!(
                "SELECT {COLS} FROM messages
                 WHERE rel_id = ?1 AND app_seq < ?3
                 ORDER BY app_seq DESC LIMIT ?2"
            ))?,
            None => self.conn().prepare(&format!(
                "SELECT {COLS} FROM messages
                 WHERE rel_id = ?1
                 ORDER BY app_seq DESC LIMIT ?2"
            ))?,
        };
        let rows = match before_seq {
            Some(before) => {
                stmt.query_map(params![rel_id, limit, before as i64], row_to_message)?
            }
            None => stmt.query_map(params![rel_id, limit], row_to_message)?,
        };
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn thread_visible(
        &self,
        rel_id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<MessageRow>, StoreError> {
        // Over-fetch then filter: control frames (typing, edits, chunks,
        // …) share the ledger but never render as bubbles, and
        // tombstoned rows render as nothing at all.
        let rows = self.thread(rel_id, limit.saturating_mul(4), before_seq)?;
        Ok(rows
            .into_iter()
            .filter(|r| crate::messages::is_thread_row(r.env_type) && !r.tombstone)
            .take(limit as usize)
            .collect())
    }

    fn set_delivery(&self, msg_id: &[u8; 16], state: DeliveryState) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET state = ?2 WHERE msg_id = ?1",
            params![hex_encode(msg_id), state.as_str()],
        )?;
        Ok(n > 0)
    }

    fn delete_message(&self, msg_id: &[u8; 16]) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM messages WHERE msg_id = ?1",
            params![hex_encode(msg_id)],
        )?;
        Ok(n > 0)
    }

    fn sweep_expired(&self) -> Result<u64, StoreError> {
        let now = self.clock().now_secs() as i64;
        let n = self.conn().execute(
            "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?1",
            params![now],
        )?;
        // I5: the I11 retransmission cache dies with the ledger row — a
        // swept message's ciphertext must not survive its erasure. Rows
        // still queued/transmitted keep theirs (resync retransmission
        // reads this cache); the outbox itself never does — it carries
        // the built record.
        self.conn().execute(
            "DELETE FROM message_ciphertexts
             WHERE msg_id NOT IN (SELECT msg_id FROM messages)",
            [],
        )?;
        // The inbound replay cache shares the retention horizon.
        self.conn().execute(
            "DELETE FROM inbound_frames WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(n as u64)
    }

    fn receive_view(&self, rel_id: &str, bitmap_bits: u32) -> Result<ReceiveView, StoreError> {
        // The view covers EVERY inbound envelope (inbound_seqs), not
        // just ledgered ones — ephemeral beats consume seqs too.
        let mut stmt = self.conn().prepare(
            "SELECT app_seq FROM inbound_seqs
             WHERE rel_id = ?1
             ORDER BY app_seq ASC LIMIT ?2",
        )?;
        let seqs = stmt
            .query_map(params![rel_id, VIEW_SCAN_LIMIT], |r| r.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;

        // Walk the contiguous horizon,
        // then set bits for received seqs in the repair window above it.
        let mut max: u64 = 0;
        let mut iter = seqs.iter().map(|s| *s as u64).peekable();
        while let Some(&seq) = iter.peek() {
            if seq == max + 1 {
                max = seq;
                iter.next();
            } else {
                break;
            }
        }
        let mut bitmap = vec![0u8; (bitmap_bits as usize).div_ceil(8)];
        let mut last_set: Option<usize> = None;
        for seq in iter {
            let offset = seq.saturating_sub(max + 1) as usize;
            if offset >= bitmap_bits as usize {
                break;
            }
            bitmap[offset / 8] |= 1 << (offset % 8);
            last_set = Some(offset);
        }
        bitmap.truncate(last_set.map_or(0, |i| i / 8 + 1));
        Ok(ReceiveView {
            max_contiguous_seq: max,
            bitmap,
        })
    }

    fn deep_seqs(&self, rel_id: &str, base: u64, max: u64) -> Result<Vec<u64>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT app_seq FROM inbound_seqs
             WHERE rel_id = ?1 AND app_seq BETWEEN ?2 AND ?3
             ORDER BY app_seq ASC",
        )?;
        let rows = stmt.query_map(params![rel_id, base as i64, max as i64], |r| {
            r.get::<_, i64>(0)
        })?;
        rows.map(|r| r.map(|v| v as u64).map_err(Into::into))
            .collect()
    }

    fn outbound_window(
        &self,
        rel_id: &str,
        after: u64,
        window: u32,
    ) -> Result<Vec<MessageRow>, StoreError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLS} FROM messages
             WHERE rel_id = ?1 AND direction = 'out' AND app_seq > ?2 AND app_seq <= ?3
             ORDER BY app_seq ASC"
        ))?;
        let rows = stmt.query_map(
            params![rel_id, after as i64, (after + u64::from(window)) as i64],
            row_to_message,
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn unacked_outbound(&self, rel_id: &str, through: u64) -> Result<Vec<MessageRow>, StoreError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {COLS} FROM messages
             WHERE rel_id = ?1 AND direction = 'out' AND app_seq <= ?2
               AND state IN ('queued', 'transmitted')
             ORDER BY app_seq ASC"
        ))?;
        let rows = stmt.query_map(params![rel_id, through as i64], row_to_message)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn next_out_seq(&self, rel_id: &str) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn().query_row(
            "SELECT MAX(app_seq) FROM messages WHERE rel_id = ?1 AND direction = 'out'",
            params![rel_id],
            |r| r.get(0),
        )?;
        let from_ledger = max.map(|v| v as u64 + 1).unwrap_or(1);
        // Retention erases ledger rows, so MAX(app_seq) alone is not
        // monotonic: after a full TTL sweep or DELETE_ALL it would
        // restart at 1, and the peer's dedupe / history-cut gates
        // would silently drop genuinely new messages. A persisted
        // high-water mark keeps the sequence strictly increasing for
        // the relationship's lifetime.
        let key = crate::store::settings::keys::out_seq_floor(rel_id);
        let floor = SettingsRepository::setting(self, &key)?
            .and_then(|v| {
                <[u8; 8]>::try_from(v.as_slice())
                    .ok()
                    .map(u64::from_be_bytes)
            })
            .unwrap_or(1);
        let next = from_ledger.max(floor);
        SettingsRepository::set_setting(self, &key, &next.saturating_add(1).to_be_bytes())?;
        Ok(next)
    }

    fn mark_edited(
        &self,
        msg_id: &[u8; 16],
        payload: &[u8],
        edit_seq: u64,
    ) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET payload = ?2, edited = 1,
                    edit_count = edit_count + 1, last_edit_seq = ?3
             WHERE msg_id = ?1 AND tombstone = 0",
            params![hex_encode(msg_id), payload, edit_seq as i64],
        )?;
        Ok(n > 0)
    }

    fn mark_tombstoned(&self, msg_id: &[u8; 16]) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET payload = X'', tombstone = 1 WHERE msg_id = ?1",
            params![hex_encode(msg_id)],
        )?;
        Ok(n > 0)
    }

    fn tombstone_thread(&self, rel_id: &str) -> Result<u64, StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET payload = X'', tombstone = 1
             WHERE rel_id = ?1 AND tombstone = 0",
            params![rel_id],
        )?;
        Ok(n as u64)
    }

    fn mark_read(&self, msg_id: &[u8; 16], read_at: u64) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "UPDATE messages SET read_at = ?2
             WHERE msg_id = ?1 AND direction = 'out' AND read_at IS NULL",
            params![hex_encode(msg_id), read_at as i64],
        )?;
        Ok(n > 0)
    }

    fn erase_history(&self, rel_id: &str, keep: &[[u8; 16]]) -> Result<u64, StoreError> {
        let n = if keep.is_empty() {
            self.conn()
                .execute("DELETE FROM messages WHERE rel_id = ?1", params![rel_id])?
        } else {
            let placeholders = keep.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let sql =
                format!("DELETE FROM messages WHERE rel_id = ? AND msg_id NOT IN ({placeholders})");
            let mut values: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(rel_id.to_string())];
            for id in keep {
                values.push(Box::new(hex_encode(id)));
            }
            self.conn()
                .execute(&sql, rusqlite::params_from_iter(values))?
        };
        // Erasure covers the I11 cache too: ciphertexts whose ledger
        // rows just died must not linger (same rule as the TTL sweep).
        self.conn().execute(
            "DELETE FROM message_ciphertexts
             WHERE rel_id = ?1 AND msg_id NOT IN (SELECT msg_id FROM messages)",
            params![rel_id],
        )?;
        Ok(n as u64)
    }
}

fn row_to_message(r: &rusqlite::Row) -> rusqlite::Result<MessageRow> {
    let msg_id: String = r.get(0)?;
    let rel_id: String = r.get(1)?;
    let direction: String = r.get(2)?;
    let app_seq: i64 = r.get(3)?;
    let sent_at: i64 = r.get(4)?;
    let received_at: Option<i64> = r.get(5)?;
    let env_type: u8 = r.get(6)?;
    let ref_id: Option<String> = r.get(7)?;
    let payload: Vec<u8> = r.get(8)?;
    let state: String = r.get(9)?;
    let expires_at: Option<i64> = r.get(10)?;
    let created_at: i64 = r.get(11)?;
    let edited: i64 = r.get(12)?;
    let tombstone: i64 = r.get(13)?;
    let read_at: Option<i64> = r.get(14)?;
    let edit_count: i64 = r.get(15)?;
    let last_edit_seq: i64 = r.get(16)?;

    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    Ok(MessageRow {
        msg_id: parse_id16(&msg_id, "messages.msg_id").map_err(corrupt)?,
        rel_id,
        direction: Direction::parse(&direction).map_err(corrupt)?,
        app_seq: app_seq as u64,
        sent_at: sent_at as u64,
        received_at: received_at.map(|v| v as u64),
        env_type,
        ref_id: ref_id
            .map(|h| parse_id16(&h, "messages.ref_id"))
            .transpose()
            .map_err(corrupt)?,
        payload,
        state: DeliveryState::parse(&state).map_err(corrupt)?,
        expires_at: expires_at.map(|v| v as u64),
        created_at: created_at as u64,
        edited: edited != 0,
        tombstone: tombstone != 0,
        read_at: read_at.map(|v| v as u64),
        edit_count: edit_count as u32,
        last_edit_seq: last_edit_seq as u64,
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

    fn inbound(rel: &str, seq: u64) -> NewMessage {
        let mut msg_id = [0u8; 16];
        msg_id[..8].copy_from_slice(&seq.to_be_bytes());
        NewMessage {
            msg_id,
            rel_id: rel.into(),
            direction: Direction::In,
            app_seq: seq,
            sent_at: 1,
            received_at: Some(2),
            env_type: 1,
            ref_id: None,
            payload: b"hi".to_vec(),
            state: DeliveryState::Received,
            expires_at: None,
        }
    }

    #[test]
    fn receive_view_matches_resync_support_semantics() {
        let (db, _) = db();
        // Inbound seqs: 1,2,3 contiguous; 5 and 8 in the repair window;
        // 9000 out. (The view reads inbound_seqs — every envelope, not
        // just ledgered ones.)
        for seq in [1u64, 2, 3, 5, 8, 9000] {
            db.insert_message(&inbound("rel", seq)).unwrap();
            crate::store::inbound_seqs::InboundSeqsRepository::note_inbound_seq(&db, "rel", seq)
                .unwrap();
        }
        let view = db.receive_view("rel", 4096).unwrap();
        assert_eq!(view.max_contiguous_seq, 3);
        // Bit 1 = seq 5, bit 4 = seq 8 (offset = seq - max - 1).
        assert_eq!(view.bitmap, vec![0b0001_0010]);
    }

    #[test]
    fn receive_view_empty_ledger() {
        let (db, _) = db();
        let view = db.receive_view("nobody", 4096).unwrap();
        assert_eq!(view, ReceiveView::default());
    }

    /// Regression (found by `state_machine.rs`): retention
    /// sweeps erase the outbound ledger, so `MAX(app_seq)` alone would
    /// restart the sequence at 1 — and the peer's dedupe / history-cut
    /// gates would then silently drop genuinely new messages. The
    /// persisted high-water mark must keep seqs strictly increasing.
    #[test]
    fn next_out_seq_survives_ledger_sweep() {
        let (db, clock) = db();
        assert_eq!(db.next_out_seq("rel").unwrap(), 1);
        let mut out = inbound("rel", 1);
        out.direction = Direction::Out;
        out.received_at = None;
        out.expires_at = Some(1_000_010);
        db.insert_message(&out).unwrap();
        assert_eq!(db.next_out_seq("rel").unwrap(), 2);
        // TTL sweep erases every outbound row.
        clock.advance(11);
        assert_eq!(db.sweep_expired().unwrap(), 1);
        assert!(db.message(&out.msg_id).unwrap().is_none());
        // Seq must NOT restart at 1.
        assert_eq!(db.next_out_seq("rel").unwrap(), 3);
        // …and a fresh ledger row never lowers it either.
        let mut out3 = inbound("rel", 3);
        out3.direction = Direction::Out;
        out3.received_at = None;
        db.insert_message(&out3).unwrap();
        assert_eq!(db.next_out_seq("rel").unwrap(), 4);
    }

    #[test]
    fn ttl_sweep_with_fake_clock() {
        let (db, clock) = db();
        let mut doomed = inbound("rel", 1);
        doomed.expires_at = Some(clock.now_secs() + 100);
        db.insert_message(&doomed).unwrap();
        db.insert_message(&inbound("rel", 2)).unwrap(); // no expiry

        clock.advance(99);
        assert_eq!(db.sweep_expired().unwrap(), 0);
        clock.advance(1);
        assert_eq!(db.sweep_expired().unwrap(), 1);
        assert!(db.message(&doomed.msg_id).unwrap().is_none());
        assert!(db.message(&inbound("rel", 2).msg_id).unwrap().is_some());
    }

    #[test]
    fn delivery_state_transitions() {
        let (db, _) = db();
        let mut out = inbound("rel", 1);
        out.direction = Direction::Out;
        out.state = DeliveryState::Queued;
        out.received_at = None;
        db.insert_message(&out).unwrap();

        assert!(db
            .set_delivery(&out.msg_id, DeliveryState::Transmitted)
            .unwrap());
        assert_eq!(
            db.message(&out.msg_id).unwrap().unwrap().state,
            DeliveryState::Transmitted
        );
        assert!(db
            .set_delivery(&out.msg_id, DeliveryState::Acknowledged)
            .unwrap());
        assert!(!db.set_delivery(&[9u8; 16], DeliveryState::Failed).unwrap());
    }

    #[test]
    fn thread_window_paginates_newest_first() {
        let (db, _) = db();
        for seq in 1..=10u64 {
            db.insert_message(&inbound("rel", seq)).unwrap();
        }
        let page1 = db.thread("rel", 3, None).unwrap();
        assert_eq!(
            page1.iter().map(|m| m.app_seq).collect::<Vec<_>>(),
            vec![10, 9, 8]
        );
        let page2 = db.thread("rel", 3, Some(8)).unwrap();
        assert_eq!(
            page2.iter().map(|m| m.app_seq).collect::<Vec<_>>(),
            vec![7, 6, 5]
        );
    }
}
