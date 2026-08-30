//! Pack lifecycle: create (sign), install (verify), remove, list, and
//! the device quotas. Item
//! bytes are hash-verified by the wire codec before this layer sees
//! them; signature verification is `keys::verify_with`.

use rusqlite::params;
use schat_wire_types::sticker::limits;
use schat_wire_types::sticker::{PackDocItem, StickerPackDoc};

use crate::engine::{Engine, EngineError};
use crate::store::sticker_items::{StickerItemRow, StickerItemsRepository};
use crate::store::{hex_decode, hex_encode, Db, StoreError};
use crate::util::sha256;

use super::keys::{self, PackKey};

/// A pack as the client renders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackInfo {
    pub pack_id: [u8; 16],
    pub pack_pk: [u8; 32],
    pub title: String,
    pub kind: u8,
    pub visibility: u8,
    pub item_count: u32,
    pub icon_item_id: u16,
    /// We hold the signing key (we created it).
    pub ours: bool,
    /// Auto-cached public pack (not user-installed).
    pub cached: bool,
}

fn row_to_info(r: &rusqlite::Row) -> rusqlite::Result<PackInfo> {
    let corrupt = |e: StoreError| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    };
    let pack_id: String = r.get(0)?;
    let pk: Vec<u8> = r.get(1)?;
    Ok(PackInfo {
        pack_id: hex_decode(&pack_id)
            .map_err(corrupt)?
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("stickers.pack_id".into())))?,
        pack_pk: pk
            .try_into()
            .map_err(|_| corrupt(StoreError::Corrupt("stickers.pack_pk".into())))?,
        title: r.get(2)?,
        kind: r.get(3)?,
        visibility: r.get(4)?,
        item_count: r.get(5)?,
        icon_item_id: r.get(6)?,
        ours: r.get::<_, i64>(7)? != 0,
        cached: r.get::<_, i64>(8)? != 0,
    })
}

const INFO_COLS: &str = "p.pack_id, p.pack_pk, p.title, p.kind, p.visibility,
    p.item_count, p.icon_item_id, (k.pack_id IS NOT NULL), p.cached";

pub fn list_packs(db: &Db) -> Result<Vec<PackInfo>, StoreError> {
    let mut stmt = db.conn().prepare(&format!(
        "SELECT {INFO_COLS} FROM stickers p
         LEFT JOIN sticker_pack_keys k ON k.pack_id = p.pack_id
         ORDER BY p.installed_at ASC"
    ))?;
    let rows = stmt.query_map([], row_to_info)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn pack_info(db: &Db, pack_id: &[u8; 16]) -> Result<Option<PackInfo>, StoreError> {
    use rusqlite::OptionalExtension;
    db.conn()
        .query_row(
            &format!(
                "SELECT {INFO_COLS} FROM stickers p
                 LEFT JOIN sticker_pack_keys k ON k.pack_id = p.pack_id
                 WHERE p.pack_id = ?1"
            ),
            params![hex_encode(pack_id)],
            row_to_info,
        )
        .optional()
        .map_err(Into::into)
}

/// Quota check before installing/caching a pack.
fn admit_pack(db: &Db, from_rel: Option<&str>, cached: bool) -> Result<(), EngineError> {
    let total: i64 = db
        .conn()
        .query_row("SELECT COUNT(*) FROM stickers", [], |r| r.get(0))?;
    if total as usize >= limits::MAX_PACKS_TOTAL {
        return Err(EngineError::EditDenied("pack quota reached"));
    }
    if let Some(rel) = from_rel {
        let from_peer: i64 = db.conn().query_row(
            "SELECT COUNT(*) FROM stickers WHERE from_rel = ?1",
            params![rel],
            |r| r.get(0),
        )?;
        if from_peer as usize >= limits::MAX_PACKS_PER_SENDER {
            return Err(EngineError::EditDenied("per-sender pack quota reached"));
        }
    }
    if cached {
        let cached_n: i64 =
            db.conn()
                .query_row("SELECT COUNT(*) FROM stickers WHERE cached = 1", [], |r| {
                    r.get(0)
                })?;
        if cached_n as usize >= limits::MAX_CACHED_PACKS {
            return Err(EngineError::EditDenied("cached pack quota reached"));
        }
    }
    Ok(())
}

/// Insert a verified pack + its items.
fn install_doc(
    db: &Db,
    doc: &StickerPackDoc,
    pack_pk: &[u8; 32],
    from_rel: Option<&str>,
    cached: bool,
) -> Result<(), EngineError> {
    admit_pack(db, from_rel, cached)?;
    let now = db.clock().now_secs();
    db.conn().execute(
        "INSERT OR REPLACE INTO stickers (
            pack_id, pack_pk, title, kind, visibility, item_count,
            icon_item_id, installed_at, cached, from_rel, last_used_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            hex_encode(&doc.pack_id),
            pack_pk.as_slice(),
            doc.title,
            doc.kind,
            doc.visibility,
            doc.items.len() as i64,
            doc.icon_item_id,
            now as i64,
            cached as i64,
            from_rel,
            now as i64,
        ],
    )?;
    db.delete_items(&doc.pack_id)?;
    for it in &doc.items {
        db.put_item(&StickerItemRow {
            pack_id: doc.pack_id,
            item_id: it.item_id,
            w: it.w,
            h: it.h,
            sha256: it.sha256,
            bytes: it.bytes.clone(),
        })?;
    }
    Ok(())
}

impl Engine {
    /// Create a pack we sign. Returns (pack_id, pack_pk).
    pub fn create_pack(
        &mut self,
        title: &str,
        kind: u8,
        visibility: u8,
        icon_item_id: u16,
        items: Vec<PackDocItem>,
    ) -> Result<([u8; 16], [u8; 32]), EngineError> {
        let pack_id = keys::random_pack_id();
        let key = PackKey::generate();
        let doc = StickerPackDoc {
            pack_id,
            kind,
            visibility,
            title: title.to_string(),
            icon_item_id,
            items,
        };
        // Validate + canonicalize (fails closed on cap violations).
        let body = doc.body_bytes()?;
        let _sig = key.sign(&body);
        install_doc(&self.db, &doc, &key.public, None, false)?;
        keys::store_pack_key(&self.db, &pack_id, &key)?;
        Ok((pack_id, key.public))
    }

    /// The signed pack document blob (`body ‖ sig`) for serving.
    pub fn pack_document(&self, pack_id: &[u8; 16]) -> Result<Option<Vec<u8>>, EngineError> {
        let Some(info) = pack_info(&self.db, pack_id)? else {
            return Ok(None);
        };
        let items = self.db.items_for(pack_id)?;
        let doc = StickerPackDoc {
            pack_id: *pack_id,
            kind: info.kind,
            visibility: info.visibility,
            title: info.title,
            icon_item_id: info.icon_item_id,
            items: items
                .into_iter()
                .map(|r| PackDocItem {
                    item_id: r.item_id,
                    w: r.w,
                    h: r.h,
                    sha256: r.sha256,
                    bytes: r.bytes,
                })
                .collect(),
        };
        let body = doc.body_bytes()?;
        let Some(key) = keys::load_pack_key(&self.db, pack_id)? else {
            return Ok(None); // not ours: we cannot re-sign
        };
        let sig = key.sign(&body);
        let mut blob = body;
        blob.extend_from_slice(&sig);
        Ok(Some(blob))
    }

    /// Install a reassembled, signature-verified pack document.
    pub fn install_pack_blob(
        &mut self,
        blob: &[u8],
        pack_pk: &[u8; 32],
        from_rel: Option<&str>,
        cached: bool,
    ) -> Result<[u8; 16], EngineError> {
        let doc = StickerPackDoc::decode_signed(blob, pack_pk, keys::verify_with, sha256)?;
        install_doc(&self.db, &doc, pack_pk, from_rel, cached)?;
        Ok(doc.pack_id)
    }

    /// Remove a pack and its items (and signing key, if ours).
    pub fn remove_pack(&mut self, pack_id: &[u8; 16]) -> Result<bool, EngineError> {
        let n = self.db.conn().execute(
            "DELETE FROM stickers WHERE pack_id = ?1",
            params![hex_encode(pack_id)],
        )?;
        self.db.delete_items(pack_id)?;
        self.db.conn().execute(
            "DELETE FROM sticker_pack_keys WHERE pack_id = ?1",
            params![hex_encode(pack_id)],
        )?;
        Ok(n > 0)
    }
}
