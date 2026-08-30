//! `sticker_cache` + `sticker_serves` repositories: the loose-item
//! receive cache (private-pack items, items from packs we never
//! installed) and the outbound pack-serving quota. Eviction policy
//! (LRU/TTL/byte caps from `wire_types::sticker::limits`) is the
//! sticker module's job; this layer is CRUD + the quota counter.

use rusqlite::{params, OptionalExtension};

use super::{hex_decode, hex_encode, Db, StoreError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedItemRow {
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
    pub w: u16,
    pub h: u16,
    pub kind: u8,
    pub pack_id: Option<[u8; 16]>,
    pub from_rel: Option<String>,
    pub created_at: u64,
}

pub struct NewCachedItem<'a> {
    pub sha256: &'a [u8; 32],
    pub bytes: &'a [u8],
    pub w: u16,
    pub h: u16,
    pub kind: u8,
    pub pack_id: Option<&'a [u8; 16]>,
    pub from_rel: Option<&'a str>,
}

pub trait StickerCacheRepository {
    /// Cache one loose item. Identical re-insert is idempotent.
    fn cache_put(&self, item: &NewCachedItem) -> Result<(), StoreError>;
    fn cache_get(&self, sha256: &[u8; 32]) -> Result<Option<CachedItemRow>, StoreError>;
    /// Oldest-first listing for LRU eviction.
    fn cache_list_oldest(&self, limit: u32) -> Result<Vec<CachedItemRow>, StoreError>;
    fn cache_delete(&self, sha256: &[u8; 32]) -> Result<bool, StoreError>;
    fn cache_stats(&self) -> Result<(u64, u64), StoreError>;
    /// Drop cache entries older than `before` (TTL eviction).
    fn cache_evict_before(&self, before: u64) -> Result<u64, StoreError>;

    /// Bump and return the peer's pack-serve count for `day`
    /// (unix secs / 86_400). The caller compares against the quota.
    fn note_pack_serve(&self, rel_id: &str, day: u64) -> Result<u32, StoreError>;
}

fn row_to_cached(r: &rusqlite::Row) -> rusqlite::Result<CachedItemRow> {
    let sha: Vec<u8> = r.get(0)?;
    let pack_id: Option<String> = r.get(5)?;
    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    Ok(CachedItemRow {
        sha256: sha
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("sticker_cache.sha256".into())))?,
        bytes: r.get(1)?,
        w: r.get(2)?,
        h: r.get(3)?,
        kind: r.get(4)?,
        pack_id: pack_id
            .map(|h| {
                hex_decode(&h)?
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("sticker_cache.pack_id".into()))
            })
            .transpose()
            .map_err(corrupt)?,
        from_rel: r.get(6)?,
        created_at: r.get::<_, i64>(7)? as u64,
    })
}

const CACHE_COLS: &str = "sha256, bytes, w, h, kind, pack_id, from_rel, created_at";

impl StickerCacheRepository for Db {
    fn cache_put(&self, item: &NewCachedItem) -> Result<(), StoreError> {
        if self.cache_get(item.sha256)?.is_some() {
            return Ok(());
        }
        self.conn().execute(
            "INSERT INTO sticker_cache (
                sha256, bytes, w, h, kind, pack_id, from_rel, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                item.sha256.as_slice(),
                item.bytes,
                item.w,
                item.h,
                item.kind,
                item.pack_id.map(|p| hex_encode(p)),
                item.from_rel,
                self.clock().now_secs() as i64,
            ],
        )?;
        Ok(())
    }

    fn cache_get(&self, sha256: &[u8; 32]) -> Result<Option<CachedItemRow>, StoreError> {
        self.conn()
            .query_row(
                &format!("SELECT {CACHE_COLS} FROM sticker_cache WHERE sha256 = ?1"),
                params![sha256.as_slice()],
                row_to_cached,
            )
            .optional()
            .map_err(Into::into)
    }

    fn cache_list_oldest(&self, limit: u32) -> Result<Vec<CachedItemRow>, StoreError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {CACHE_COLS} FROM sticker_cache ORDER BY created_at ASC LIMIT ?1"
        ))?;
        let rows = stmt.query_map(params![limit], row_to_cached)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn cache_delete(&self, sha256: &[u8; 32]) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM sticker_cache WHERE sha256 = ?1",
            params![sha256.as_slice()],
        )?;
        Ok(n > 0)
    }

    /// (entry count, total bytes) for quota checks.
    fn cache_stats(&self) -> Result<(u64, u64), StoreError> {
        let (n, bytes): (i64, Option<i64>) = self.conn().query_row(
            "SELECT COUNT(*), SUM(LENGTH(bytes)) FROM sticker_cache",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((n as u64, bytes.unwrap_or(0) as u64))
    }

    fn cache_evict_before(&self, before: u64) -> Result<u64, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM sticker_cache WHERE created_at < ?1",
            params![before as i64],
        )?;
        Ok(n as u64)
    }

    fn note_pack_serve(&self, rel_id: &str, day: u64) -> Result<u32, StoreError> {
        self.conn().execute(
            "INSERT INTO sticker_serves (rel_id, day, count) VALUES (?1, ?2, 1)
             ON CONFLICT (rel_id, day) DO UPDATE SET count = count + 1",
            params![rel_id, day as i64],
        )?;
        let count: u32 = self.conn().query_row(
            "SELECT count FROM sticker_serves WHERE rel_id = ?1 AND day = ?2",
            params![rel_id, day as i64],
            |r| r.get(0),
        )?;
        Ok(count)
    }
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

    #[test]
    fn cache_put_get_evict() {
        let (db, clock) = db();
        let sha = [0xaau8; 32];
        let it = NewCachedItem {
            sha256: &sha,
            bytes: &[0xaa; 8],
            w: 96,
            h: 96,
            kind: 2,
            pack_id: None,
            from_rel: Some("rel"),
        };
        db.cache_put(&it).unwrap();
        db.cache_put(&it).unwrap(); // idempotent
        assert_eq!(db.cache_stats().unwrap(), (1, 8));
        assert_eq!(db.cache_get(&sha).unwrap().unwrap().w, 96);

        clock.advance(100);
        assert_eq!(db.cache_evict_before(clock.now_secs()).unwrap(), 1);
        assert!(db.cache_get(&sha).unwrap().is_none());
    }

    #[test]
    fn serve_quota_counts_per_day() {
        let (db, _) = db();
        assert_eq!(db.note_pack_serve("rel", 100).unwrap(), 1);
        assert_eq!(db.note_pack_serve("rel", 100).unwrap(), 2);
        assert_eq!(db.note_pack_serve("rel", 101).unwrap(), 1);
        assert_eq!(db.note_pack_serve("other", 100).unwrap(), 1);
    }
}
