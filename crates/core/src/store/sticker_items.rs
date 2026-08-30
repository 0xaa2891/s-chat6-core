//! `sticker_items` + `sticker_pack_keys` repositories: item blobs for
//! installed packs, and the signing keys for packs we created. Pack
//! metadata lives in `stickers` (`stickers.rs`); the loose-item cache
//! and serve quota live in `sticker_cache.rs`.

use rusqlite::{params, OptionalExtension};

use super::{hex_decode, hex_encode, Db, StoreError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerItemRow {
    pub pack_id: [u8; 16],
    pub item_id: u16,
    pub w: u16,
    pub h: u16,
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
}

pub trait StickerItemsRepository {
    /// Insert one item blob. Re-insert of identical bytes is idempotent;
    /// a conflicting rewrite is refused (fail closed).
    fn put_item(&self, item: &StickerItemRow) -> Result<(), StoreError>;
    fn item(&self, pack_id: &[u8; 16], item_id: u16) -> Result<Option<StickerItemRow>, StoreError>;
    fn items_for(&self, pack_id: &[u8; 16]) -> Result<Vec<StickerItemRow>, StoreError>;
    /// Resolve an item by content hash across installed packs.
    fn item_by_sha(&self, sha256: &[u8; 32]) -> Result<Option<StickerItemRow>, StoreError>;
    fn delete_items(&self, pack_id: &[u8; 16]) -> Result<u64, StoreError>;

    /// Our pack signing key (created packs only). 32-byte Curve25519
    /// private key; the sticker module owns what it signs.
    fn put_pack_key(&self, pack_id: &[u8; 16], secret: &[u8]) -> Result<(), StoreError>;
    fn pack_key(&self, pack_id: &[u8; 16]) -> Result<Option<Vec<u8>>, StoreError>;
}

fn row_to_item(r: &rusqlite::Row) -> rusqlite::Result<StickerItemRow> {
    let pack_id: String = r.get(0)?;
    let sha: Vec<u8> = r.get(4)?;
    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    Ok(StickerItemRow {
        pack_id: hex_decode(&pack_id)
            .map_err(corrupt)?
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("sticker_items.pack_id".into())))?,
        item_id: r.get(1)?,
        w: r.get(2)?,
        h: r.get(3)?,
        sha256: sha
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("sticker_items.sha256".into())))?,
        bytes: r.get(5)?,
    })
}

const ITEM_COLS: &str = "pack_id, item_id, w, h, sha256, bytes";

impl StickerItemsRepository for Db {
    fn put_item(&self, item: &StickerItemRow) -> Result<(), StoreError> {
        if let Some(prev) = self.item(&item.pack_id, item.item_id)? {
            if prev.sha256 != item.sha256 || prev.bytes != item.bytes {
                return Err(StoreError::Corrupt(format!(
                    "sticker item {}:{} rewritten",
                    hex_encode(&item.pack_id),
                    item.item_id
                )));
            }
            return Ok(());
        }
        self.conn().execute(
            "INSERT INTO sticker_items (pack_id, item_id, w, h, sha256, bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                hex_encode(&item.pack_id),
                item.item_id,
                item.w,
                item.h,
                item.sha256.as_slice(),
                item.bytes,
            ],
        )?;
        Ok(())
    }

    fn item(&self, pack_id: &[u8; 16], item_id: u16) -> Result<Option<StickerItemRow>, StoreError> {
        self.conn()
            .query_row(
                &format!(
                    "SELECT {ITEM_COLS} FROM sticker_items WHERE pack_id = ?1 AND item_id = ?2"
                ),
                params![hex_encode(pack_id), item_id],
                row_to_item,
            )
            .optional()
            .map_err(Into::into)
    }

    fn items_for(&self, pack_id: &[u8; 16]) -> Result<Vec<StickerItemRow>, StoreError> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {ITEM_COLS} FROM sticker_items WHERE pack_id = ?1 ORDER BY item_id ASC"
        ))?;
        let rows = stmt.query_map(params![hex_encode(pack_id)], row_to_item)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn item_by_sha(&self, sha256: &[u8; 32]) -> Result<Option<StickerItemRow>, StoreError> {
        self.conn()
            .query_row(
                &format!("SELECT {ITEM_COLS} FROM sticker_items WHERE sha256 = ?1 LIMIT 1"),
                params![sha256.as_slice()],
                row_to_item,
            )
            .optional()
            .map_err(Into::into)
    }

    fn delete_items(&self, pack_id: &[u8; 16]) -> Result<u64, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM sticker_items WHERE pack_id = ?1",
            params![hex_encode(pack_id)],
        )?;
        Ok(n as u64)
    }

    fn put_pack_key(&self, pack_id: &[u8; 16], secret: &[u8]) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO sticker_pack_keys (pack_id, secret) VALUES (?1, ?2)",
            params![hex_encode(pack_id), secret],
        )?;
        Ok(())
    }

    fn pack_key(&self, pack_id: &[u8; 16]) -> Result<Option<Vec<u8>>, StoreError> {
        self.conn()
            .query_row(
                "SELECT secret FROM sticker_pack_keys WHERE pack_id = ?1",
                params![hex_encode(pack_id)],
                |r| r.get(0),
            )
            .optional()
            .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(pack: u8, id: u16, byte: u8) -> StickerItemRow {
        StickerItemRow {
            pack_id: [pack; 16],
            item_id: id,
            w: 512,
            h: 512,
            sha256: [byte; 32],
            bytes: vec![byte; 16],
        }
    }

    #[test]
    fn items_roundtrip_and_conflict() {
        let db = Db::open_in_memory().unwrap();
        db.put_item(&item(1, 1, 0xaa)).unwrap();
        db.put_item(&item(1, 2, 0xbb)).unwrap();
        db.put_item(&item(1, 1, 0xaa)).unwrap(); // idempotent
        assert!(db.put_item(&item(1, 1, 0xcc)).is_err()); // conflict refused

        assert_eq!(db.items_for(&[1u8; 16]).unwrap().len(), 2);
        assert_eq!(
            db.item_by_sha(&[0xbb; 32]).unwrap().unwrap().item_id,
            2,
            "hash resolution across packs"
        );
        assert_eq!(db.delete_items(&[1u8; 16]).unwrap(), 2);
    }

    #[test]
    fn pack_keys_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.pack_key(&[1u8; 16]).unwrap().is_none());
        db.put_pack_key(&[1u8; 16], &[9u8; 32]).unwrap();
        assert_eq!(db.pack_key(&[1u8; 16]).unwrap().unwrap(), vec![9u8; 32]);
    }
}
