//! Outbound sticker paths: sending an item (inline or by reference),
//! pushing inline `:e:` bodies with text, and answering WANT_ITEM /
//! WANT_PACK / WANT_THUMBS (the serving side of the fetch dance).

use rusqlite::params;
use schat_wire_types::envelope::Payload;
use schat_wire_types::sticker::limits;
use schat_wire_types::sticker::{PackRef, StickerCtrl, StickerItem, StickerThumbsDoc, Thumb};

use crate::engine::send::send_envelope;
use crate::engine::{Engine, EngineError};
use crate::store::sticker_cache::StickerCacheRepository;
use crate::store::sticker_items::{StickerItemRow, StickerItemsRepository};
use crate::store::{hex_encode, Db, StoreError};

use super::{packs, tokens};

/// An item plus its pack context (what ITEM_BODY's PackRef carries).
pub struct ItemWithPack {
    pub item: StickerItemRow,
    pub pack: PackRef,
}

/// Resolve a content hash — full 32 bytes or an 8-byte `:e:` prefix —
/// against installed packs. Prefix collisions resolve to the first
/// match (16 hex chars make collisions adversarial-only, and a wrong
/// guess fails the receiver's hash check).
pub fn find_item(db: &Db, sha: &[u8]) -> Result<Option<ItemWithPack>, StoreError> {
    use rusqlite::OptionalExtension;
    let row = if sha.len() == 32 {
        let full: [u8; 32] = sha
            .try_into()
            .map_err(|_| StoreError::Corrupt("sha".into()))?;
        db.item_by_sha(&full)?
    } else {
        let prefix = hex_encode(sha);
        db.conn()
            .query_row(
                "SELECT pack_id, item_id, w, h, sha256, bytes FROM sticker_items
                 WHERE hex(sha256) LIKE ?1 || '%' LIMIT 1",
                params![prefix],
                |r| {
                    let corrupt = |e: StoreError| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    };
                    let pack_hex: String = r.get(0)?;
                    let sha_raw: Vec<u8> = r.get(4)?;
                    Ok(StickerItemRow {
                        pack_id: crate::store::hex_decode(&pack_hex)
                            .map_err(corrupt)?
                            .try_into()
                            .map_err(|_| corrupt(StoreError::Corrupt("pack_id".into())))?,
                        item_id: r.get(1)?,
                        w: r.get(2)?,
                        h: r.get(3)?,
                        sha256: sha_raw
                            .try_into()
                            .map_err(|_| corrupt(StoreError::Corrupt("sha256".into())))?,
                        bytes: r.get(5)?,
                    })
                },
            )
            .optional()?
    };
    let Some(item) = row else {
        return Ok(None);
    };
    let Some(info) = packs::pack_info(db, &item.pack_id)? else {
        return Ok(None);
    };
    Ok(Some(ItemWithPack {
        pack: PackRef {
            pack_id: item.pack_id,
            pack_pk: info.pack_pk,
            kind: info.kind,
            visibility: info.visibility,
            item_id: item.item_id,
            w: item.w,
            h: item.h,
        },
        item,
    }))
}

impl Engine {
    /// Send a sticker from an installed pack. Small items ride inline;
    /// larger ones go by reference (the peer fetches via WANT_ITEM).
    pub async fn send_sticker(
        &mut self,
        rel_id: &str,
        pack_id: &[u8; 16],
        item_id: u16,
    ) -> Result<[u8; 16], EngineError> {
        let item = self
            .db
            .item(pack_id, item_id)?
            .ok_or(EngineError::NotFound)?;
        let info = packs::pack_info(&self.db, pack_id)?.ok_or(EngineError::NotFound)?;
        let inline = (item.bytes.len() <= limits::INLINE_BYTES_MAX).then(|| item.bytes.clone());
        let sent = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Sticker(StickerItem {
                kind: info.kind,
                visibility: info.visibility,
                pack_id: *pack_id,
                pack_pk: info.pack_pk,
                item_id,
                w: item.w,
                h: item.h,
                content_sha256: item.sha256,
                bytes: inline,
            }),
            None,
            true,
        )
        .await?;
        Ok(sent.msg_id)
    }

    /// After sending text with `:e:` tokens, push the item bodies so
    /// the peer renders immediately.
    pub(crate) async fn push_inline_emoji(
        &mut self,
        rel_id: &str,
        body: &str,
    ) -> Result<(), EngineError> {
        for prefix in tokens::extract(body) {
            if let Some(found) = find_item(&self.db, &prefix)? {
                self.serve_item(rel_id, &found).await?;
            }
        }
        Ok(())
    }

    /// Serve one item as ITEM_BODY chunk(s) with its pack context.
    pub(crate) async fn serve_item(
        &mut self,
        rel_id: &str,
        found: &ItemWithPack,
    ) -> Result<(), EngineError> {
        let bytes = &found.item.bytes;
        let chunk_count = (bytes.len().div_ceil(limits::ITEM_CHUNK_MAX)).max(1) as u16;
        for (index, piece) in bytes.chunks(limits::ITEM_CHUNK_MAX).enumerate() {
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::StickerCtrl(StickerCtrl::ItemBody {
                    sha: found.item.sha256,
                    chunk_index: index as u16,
                    chunk_count,
                    data: piece.to_vec(),
                    pack: Some(found.pack.clone()),
                }),
                None,
                false,
            )
            .await?;
        }
        Ok(())
    }

    /// Answer WANT_ITEM (full hash or `:e:` prefix). Unknown hashes are
    /// ignored — items have no refusal op (never a hang: the requester
    /// retries bounded times client-side).
    pub(crate) async fn answer_want_item(
        &mut self,
        rel_id: &str,
        sha: &[u8],
    ) -> Result<(), EngineError> {
        // Anti-flood: serving is chunked outbound work; a WANT flood from the
        // peer must not spin it. Dropped wants are answered by the
        // peer's own retry, never by our loop.
        if !self.rate_allow(crate::ratelimit::Surface::StickerServe, rel_id) {
            return Ok(());
        }
        if let Some(found) = find_item(&self.db, sha)? {
            self.serve_item(rel_id, &found).await?;
        }
        Ok(())
    }

    /// Typed pack refusal (never a hang).
    async fn refuse_pack(
        &mut self,
        rel_id: &str,
        pack_id: &[u8; 16],
        pack_pk: &[u8; 32],
        reason: u8,
    ) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::StickerCtrl(StickerCtrl::PackRefused {
                pack_id: *pack_id,
                pack_pk: *pack_pk,
                reason,
            }),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Answer WANT_PACK: visibility + per-peer daily quota, then the
    /// signed document as PACK_BODY chunks. Typed refusals, never a
    /// hang.
    pub(crate) async fn answer_want_pack(
        &mut self,
        rel_id: &str,
        pack_id: &[u8; 16],
        pack_pk: &[u8; 32],
    ) -> Result<(), EngineError> {
        let Some(info) = packs::pack_info(&self.db, pack_id)? else {
            return self
                .refuse_pack(
                    rel_id,
                    pack_id,
                    pack_pk,
                    schat_wire_types::sticker::REFUSED_UNKNOWN,
                )
                .await;
        };
        if info.pack_pk != *pack_pk {
            return self
                .refuse_pack(
                    rel_id,
                    pack_id,
                    pack_pk,
                    schat_wire_types::sticker::REFUSED_UNKNOWN,
                )
                .await;
        }
        if info.visibility == limits::VISIBILITY_PRIVATE {
            return self
                .refuse_pack(
                    rel_id,
                    pack_id,
                    pack_pk,
                    schat_wire_types::sticker::REFUSED_PRIVATE,
                )
                .await;
        }
        let day = self.now() / 86_400;
        let serves = self.db.note_pack_serve(rel_id, day)?;
        if serves > limits::PACK_SERVES_PER_PEER_PER_DAY {
            return self
                .refuse_pack(
                    rel_id,
                    pack_id,
                    pack_pk,
                    schat_wire_types::sticker::REFUSED_RATE_LIMITED,
                )
                .await;
        }
        let Some(blob) = self.pack_document(pack_id)? else {
            return self
                .refuse_pack(
                    rel_id,
                    pack_id,
                    pack_pk,
                    schat_wire_types::sticker::REFUSED_UNKNOWN,
                )
                .await;
        };
        let chunk_count = (blob.len().div_ceil(limits::PACK_CHUNK_MAX)).max(1) as u16;
        for (index, piece) in blob.chunks(limits::PACK_CHUNK_MAX).enumerate() {
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::StickerCtrl(StickerCtrl::PackBody {
                    pack_id: *pack_id,
                    pack_pk: *pack_pk,
                    chunk_index: index as u16,
                    chunk_count,
                    data: piece.to_vec(),
                }),
                None,
                false,
            )
            .await?;
        }
        Ok(())
    }

    /// Answer WANT_THUMBS with the unsigned preview doc (media-prepared
    /// 96px thumbnails), chunked as THUMBS_BODY.
    pub(crate) async fn answer_want_thumbs(
        &mut self,
        rel_id: &str,
        pack_id: &[u8; 16],
        pack_pk: &[u8; 32],
    ) -> Result<(), EngineError> {
        // Anti-flood: thumbs serving re-encodes every item's thumbnail —
        // the CPU-heaviest sticker path; throttle per peer.
        if !self.rate_allow(crate::ratelimit::Surface::StickerServe, rel_id) {
            return Ok(());
        }
        let Some(info) = packs::pack_info(&self.db, pack_id)? else {
            return Ok(());
        };
        if info.pack_pk != *pack_pk || info.visibility == limits::VISIBILITY_PRIVATE {
            return Ok(());
        }
        let mut thumbs = Vec::new();
        for item in self.db.items_for(pack_id)? {
            if let Ok(t) = crate::media::image::make_thumbnail(&item.bytes) {
                thumbs.push(Thumb {
                    item_id: item.item_id,
                    bytes: t,
                });
            }
        }
        if thumbs.is_empty() {
            return Ok(());
        }
        let doc = StickerThumbsDoc {
            title: info.title,
            kind: info.kind,
            icon_item_id: info.icon_item_id,
            thumbs,
        };
        let blob = doc.encode()?;
        let chunk_count = (blob.len().div_ceil(limits::PACK_CHUNK_MAX)).max(1) as u16;
        for (index, piece) in blob.chunks(limits::PACK_CHUNK_MAX).enumerate() {
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::StickerCtrl(StickerCtrl::ThumbsBody {
                    pack_id: *pack_id,
                    pack_pk: *pack_pk,
                    chunk_index: index as u16,
                    chunk_count,
                    data: piece.to_vec(),
                }),
                None,
                false,
            )
            .await?;
        }
        Ok(())
    }

    /// Ask a peer for a pack (user-driven clone, or auto-cache of a
    /// public pack seen in an ITEM_BODY trailer).
    pub async fn fetch_pack(
        &mut self,
        rel_id: &str,
        pack_id: &[u8; 16],
        pack_pk: &[u8; 32],
    ) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::StickerCtrl(StickerCtrl::WantPack {
                pack_id: *pack_id,
                pack_pk: *pack_pk,
            }),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Ask for a pack's preview thumbnails.
    pub async fn fetch_thumbs(
        &mut self,
        rel_id: &str,
        pack_id: &[u8; 16],
        pack_pk: &[u8; 32],
    ) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::StickerCtrl(StickerCtrl::WantThumbs {
                pack_id: *pack_id,
                pack_pk: *pack_pk,
            }),
            None,
            false,
        )
        .await?;
        Ok(())
    }
}
