//! `stickers` table repository: installed pack metadata. Item bodies and
//! thumbnails ride the attachment pipeline; this table answers
//! "which packs are installed" and "what do we advertise".

use rusqlite::{params, OptionalExtension};

use super::{hex_decode, hex_encode, Db, StoreError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerPackRow {
    pub pack_id: [u8; 16],
    pub pack_pk: [u8; 32],
    pub title: String,
    pub kind: u8,
    pub visibility: u8,
    pub item_count: u16,
    pub icon_item_id: u16,
    pub installed_at: u64,
}

pub trait StickersRepository {
    /// Install (or replace) a pack. Replacement is how pack updates land.
    fn install_pack(&self, pack: &StickerPackRow) -> Result<(), StoreError>;
    fn pack(&self, pack_id: &[u8; 16]) -> Result<Option<StickerPackRow>, StoreError>;
    fn list_packs(&self) -> Result<Vec<StickerPackRow>, StoreError>;
    fn remove_pack(&self, pack_id: &[u8; 16]) -> Result<bool, StoreError>;
}

impl StickersRepository for Db {
    fn install_pack(&self, pack: &StickerPackRow) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO stickers (
                pack_id, pack_pk, title, kind, visibility, item_count,
                icon_item_id, installed_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                hex_encode(&pack.pack_id),
                pack.pack_pk.as_slice(),
                pack.title,
                pack.kind,
                pack.visibility,
                pack.item_count,
                pack.icon_item_id,
                self.clock().now_secs() as i64,
            ],
        )?;
        Ok(())
    }

    fn pack(&self, pack_id: &[u8; 16]) -> Result<Option<StickerPackRow>, StoreError> {
        self.conn()
            .query_row(
                "SELECT pack_id, pack_pk, title, kind, visibility, item_count,
                        icon_item_id, installed_at
                 FROM stickers WHERE pack_id = ?1",
                params![hex_encode(pack_id)],
                row_to_pack,
            )
            .optional()
            .map_err(Into::into)
    }

    fn list_packs(&self) -> Result<Vec<StickerPackRow>, StoreError> {
        let mut stmt = self.conn().prepare(
            "SELECT pack_id, pack_pk, title, kind, visibility, item_count,
                    icon_item_id, installed_at
             FROM stickers ORDER BY installed_at ASC",
        )?;
        let rows = stmt.query_map([], row_to_pack)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn remove_pack(&self, pack_id: &[u8; 16]) -> Result<bool, StoreError> {
        let n = self.conn().execute(
            "DELETE FROM stickers WHERE pack_id = ?1",
            params![hex_encode(pack_id)],
        )?;
        Ok(n > 0)
    }
}

fn row_to_pack(r: &rusqlite::Row) -> rusqlite::Result<StickerPackRow> {
    let pack_id: String = r.get(0)?;
    let pack_pk: Vec<u8> = r.get(1)?;
    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    Ok(StickerPackRow {
        pack_id: hex_decode(&pack_id)
            .map_err(corrupt)?
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("stickers.pack_id: not 16 bytes".into())))?,
        pack_pk: pack_pk
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("stickers.pack_pk: not 32 bytes".into())))?,
        title: r.get(2)?,
        kind: r.get(3)?,
        visibility: r.get(4)?,
        item_count: r.get(5)?,
        icon_item_id: r.get(6)?,
        installed_at: r.get::<_, i64>(7)? as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::clock::FakeClock;
    use std::sync::Arc;

    fn db() -> Db {
        let clock = FakeClock::new(1_000_000);
        Db::open_in_memory_with_clock(Arc::new(clock)).unwrap()
    }

    fn pack(id: u8, title: &str) -> StickerPackRow {
        StickerPackRow {
            pack_id: [id; 16],
            pack_pk: [id; 32],
            title: title.into(),
            kind: 2,
            visibility: 1,
            item_count: 12,
            icon_item_id: 1,
            installed_at: 0, // clock fills
        }
    }

    #[test]
    fn install_list_replace_remove() {
        let db = db();
        db.install_pack(&pack(1, "one")).unwrap();
        db.install_pack(&pack(2, "two")).unwrap();
        assert_eq!(db.list_packs().unwrap().len(), 2);

        // Replace keeps one row, updates the title.
        db.install_pack(&pack(1, "one-v2")).unwrap();
        assert_eq!(db.list_packs().unwrap().len(), 2);
        assert_eq!(db.pack(&[1u8; 16]).unwrap().unwrap().title, "one-v2");

        assert!(db.remove_pack(&[1u8; 16]).unwrap());
        assert!(!db.remove_pack(&[1u8; 16]).unwrap());
        assert_eq!(db.list_packs().unwrap().len(), 1);
    }
}
