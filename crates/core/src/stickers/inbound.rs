//! Inbound sticker paths: STICKER items (inline or fetch-on-miss) and
//! the STICKER_CTRL state machine (ACK / WANT_ITEM / ITEM_BODY /
//! WANT_PACK / PACK_BODY / PACK_REFUSED / WANT_THUMBS / THUMBS_BODY).

use rusqlite::params;
use schat_wire_types::envelope::{Envelope, Payload};
use schat_wire_types::sticker::limits;
use schat_wire_types::sticker::{StickerCtrl, StickerItem, StickerThumbsDoc};

use crate::engine::send::send_envelope;
use crate::engine::{Engine, EngineError, EngineEvent};
use crate::store::sticker_cache::{NewCachedItem, StickerCacheRepository};
use crate::store::sticker_items::StickerItemsRepository;
use crate::store::{hex_encode, Db, StoreError};
use crate::util::sha256;

use super::{packs, tokens};

/// Do we hold an item with this hash (installed pack or loose cache)?
fn have_item(db: &Db, sha: &[u8; 32]) -> Result<bool, StoreError> {
    if db.item_by_sha(sha)?.is_some() {
        return Ok(true);
    }
    Ok(db.cache_get(sha)?.is_some())
}

/// Cache-prefix lookup for `:e:` tokens (do we already hold it?).
fn have_item_prefix(db: &Db, prefix: &[u8; 8]) -> Result<bool, StoreError> {
    let like = format!("{}%", hex_encode(prefix));
    let n: i64 = db.conn().query_row(
        "SELECT (
            SELECT COUNT(*) FROM sticker_items WHERE hex(sha256) LIKE ?1
         ) + (
            SELECT COUNT(*) FROM sticker_cache WHERE hex(sha256) LIKE ?1
         )",
        params![like],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

impl Engine {
    /// Inbound STICKER: inline bytes are
    /// hash-checked and cached; references we lack trigger WANT_ITEM.
    pub(crate) async fn on_sticker(
        &mut self,
        rel_id: &str,
        env: &Envelope,
        item: &StickerItem,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        let ready = match &item.bytes {
            Some(bytes) => {
                if sha256(bytes) != item.content_sha256 {
                    return Ok(()); // hash mismatch: drop (fail closed)
                }
                if !have_item(&self.db, &item.content_sha256)? {
                    self.db.cache_put(&NewCachedItem {
                        sha256: &item.content_sha256,
                        bytes,
                        w: item.w,
                        h: item.h,
                        kind: item.kind,
                        pack_id: Some(&item.pack_id),
                        from_rel: Some(rel_id),
                    })?;
                    self.ack_sticker(rel_id, &item.content_sha256).await?;
                }
                true
            }
            None => {
                if have_item(&self.db, &item.content_sha256)? {
                    true
                } else {
                    // Fetch the missing item (bounded: one WANT per
                    // unknown item per message).
                    send_envelope(
                        &self.db,
                        &self.transport,
                        rel_id,
                        Payload::StickerCtrl(StickerCtrl::WantItem(item.content_sha256.to_vec())),
                        None,
                        false,
                    )
                    .await?;
                    false
                }
            }
        };
        events.push(EngineEvent::Sticker {
            rel_id: rel_id.into(),
            msg_id: env.msg_id,
            ready,
        });
        Ok(())
    }

    /// ACK: the peer holds this hash (lets us omit bytes later).
    async fn ack_sticker(&mut self, rel_id: &str, sha: &[u8; 32]) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::StickerCtrl(StickerCtrl::Ack(*sha)),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Inbound STICKER_CTRL dispatch.
    pub(crate) async fn on_sticker_ctrl(
        &mut self,
        rel_id: &str,
        ctrl: &StickerCtrl,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        let now = self.now();
        match ctrl {
            StickerCtrl::Ack(_) => Ok(()), // informational; we don't track
            StickerCtrl::WantItem(sha) => self.answer_want_item(rel_id, sha).await,
            StickerCtrl::ItemBody {
                sha,
                chunk_index,
                chunk_count,
                data,
                pack,
            } => {
                let key = hex_encode(sha);
                let Some(blob) =
                    self.sticker_pending
                        .feed_item(&key, *chunk_index, *chunk_count, data, now)
                else {
                    return Ok(());
                };
                if sha256(&blob) != *sha {
                    return Ok(()); // hash mismatch: drop
                }
                let (w, h, kind, pack_id) = match pack {
                    Some(p) => (p.w, p.h, p.kind, Some(p.pack_id)),
                    None => (0, 0, limits::KIND_STICKER, None),
                };
                if !have_item(&self.db, sha)? {
                    self.db.cache_put(&NewCachedItem {
                        sha256: sha,
                        bytes: &blob,
                        w,
                        h,
                        kind,
                        pack_id: pack_id.as_ref(),
                        from_rel: Some(rel_id),
                    })?;
                    self.ack_sticker(rel_id, sha).await?;
                }
                // Public pack we don't know: auto-cache it,
                // quota-bounded.
                if let Some(p) = pack {
                    if p.visibility == limits::VISIBILITY_PUBLIC
                        && packs::pack_info(&self.db, &p.pack_id)?.is_none()
                    {
                        self.fetch_pack(rel_id, &p.pack_id, &p.pack_pk).await?;
                    }
                }
                Ok(())
            }
            StickerCtrl::WantPack { pack_id, pack_pk } => {
                self.answer_want_pack(rel_id, pack_id, pack_pk).await
            }
            StickerCtrl::PackBody {
                pack_id,
                pack_pk,
                chunk_index,
                chunk_count,
                data,
            } => {
                let key = hex_encode(pack_id);
                let Some(blob) =
                    self.sticker_pending
                        .feed_pack(&key, *chunk_index, *chunk_count, data, now)
                else {
                    return Ok(());
                };
                // Verify + install as an auto-cached pack.
                match self.install_pack_blob(&blob, pack_pk, Some(rel_id), true) {
                    Ok(id) => {
                        events.push(EngineEvent::StickerPackInstalled { pack_id: id });
                    }
                    Err(e) => {
                        tracing::warn!(rel_id, "pack install failed: {e}");
                    }
                }
                Ok(())
            }
            StickerCtrl::PackRefused {
                pack_id, reason, ..
            } => {
                events.push(EngineEvent::StickerPackRefused {
                    pack_id: *pack_id,
                    reason: *reason,
                });
                Ok(())
            }
            StickerCtrl::WantThumbs { pack_id, pack_pk } => {
                self.answer_want_thumbs(rel_id, pack_id, pack_pk).await
            }
            StickerCtrl::ThumbsBody {
                pack_id,
                chunk_index,
                chunk_count,
                data,
                ..
            } => {
                let key = format!("thumbs:{}", hex_encode(pack_id));
                let Some(blob) =
                    self.sticker_pending
                        .feed_thumbs(&key, *chunk_index, *chunk_count, data, now)
                else {
                    return Ok(());
                };
                match StickerThumbsDoc::decode(&blob) {
                    Ok(doc) => events.push(EngineEvent::StickerThumbs {
                        pack_id: *pack_id,
                        doc,
                    }),
                    Err(e) => tracing::debug!(rel_id, "thumbs doc dropped: {e}"),
                }
                Ok(())
            }
        }
    }

    /// After an inbound MSG: fetch any `:e:` items we don't hold.
    pub(crate) async fn fetch_missing_emoji(
        &mut self,
        rel_id: &str,
        body: &str,
    ) -> Result<(), EngineError> {
        for prefix in tokens::extract(body) {
            if have_item_prefix(&self.db, &prefix)? {
                continue;
            }
            // Anti-flood: inbound content triggers *outbound* fetches — a
            // peer stuffing messages with unknown `:tokens:` must not
            // turn us into a WANT_ITEM fountain.
            if !self.rate_allow(crate::ratelimit::Surface::StickerFetch, rel_id) {
                continue;
            }
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::StickerCtrl(StickerCtrl::WantItem(prefix.to_vec())),
                None,
                false,
            )
            .await?;
        }
        Ok(())
    }
}
