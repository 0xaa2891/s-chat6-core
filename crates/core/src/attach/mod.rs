//! `attach/` — the ATTACH_HEAD / ATTACH_CHUNK pipeline:
//! outbound chunk planning (with bucket padding), inbound reassembly
//! with hash verification, orphan-chunk tolerance (chunks may land
//! before their head), and view-once erasure.
//!
//! The head's `msg_id` IS the transfer's `head_id` — chunks name it in
//! `head_id`. Outbound chunk payloads are not stored: every chunk is
//! its own envelope with its own I11 frame, so resync retransmits from
//! the ciphertext cache.

use schat_wire_types::attach::{
    AttachChunk, AttachHead, AttachHeadPayload, CHUNK_DATA_MAX, CLASS_IMAGE, FLAG_VIEW_ONCE,
    MAX_ATTACH,
};
use schat_wire_types::envelope::{Envelope, Payload};

use crate::engine::send::send_envelope;
use crate::engine::{Engine, EngineError, EngineEvent};
use crate::policy;
use crate::store::attachments::{AttachmentsRepository, NewAttachment};
use crate::store::chunks::ChunksRepository;
use crate::store::messages::Direction;

// Send-side bounds declared in the bounds catalog.
pub use crate::limits::attach::{BUCKET_GRANULARITY, INLINE_MAX};

use crate::util::sha256;

/// One planned outbound chunk: real data or a bucket-filling pad.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkOut {
    Data(Vec<u8>),
    Pad,
}

#[derive(Clone, Debug)]
pub struct AttachPlan {
    pub head: AttachHead,
    pub chunks: Vec<ChunkOut>,
}

/// Everything needed to send one attachment, grouped so the send call
/// stays two parameters.
#[derive(Clone, Debug)]
pub struct AttachmentSpec {
    pub media_class: u8,
    pub mime_hint: String,
    pub orig_ext: String,
    pub bytes: Vec<u8>,
    pub caption: String,
    pub view_once: bool,
}

/// Split `bytes` into the chunk plan: data chunks of `CHUNK_DATA_MAX`,
/// the count rounded up to the bucket granularity, pads filling the rest.
pub fn plan_transfer(
    media_class: u8,
    mime_hint: &str,
    orig_ext: &str,
    bytes: &[u8],
    caption: &str,
    view_once: bool,
) -> Result<AttachPlan, EngineError> {
    if bytes.is_empty() || bytes.len() > MAX_ATTACH as usize {
        return Err(EngineError::EditDenied("attachment size out of range"));
    }
    let inline = bytes.len() <= INLINE_MAX;
    let chunk_count = if inline {
        0
    } else {
        (bytes.len() as u32).div_ceil(CHUNK_DATA_MAX as u32) as u16
    };
    let chunk_bucket = if inline {
        0
    } else {
        chunk_count.div_ceil(BUCKET_GRANULARITY) * BUCKET_GRANULARITY
    };
    let mut chunks = Vec::new();
    if !inline {
        for piece in bytes.chunks(CHUNK_DATA_MAX) {
            chunks.push(ChunkOut::Data(piece.to_vec()));
        }
        while chunks.len() < chunk_bucket as usize {
            chunks.push(ChunkOut::Pad);
        }
    }
    Ok(AttachPlan {
        head: AttachHead {
            media_class,
            mime_hint: mime_hint.to_string(),
            orig_ext: orig_ext.to_string(),
            uncompressed_n: bytes.len() as u32,
            chunk_count,
            chunk_bucket,
            content_sha256: sha256(bytes),
            caption: caption.to_string(),
            flags: if view_once { FLAG_VIEW_ONCE } else { 0 },
        },
        chunks,
    })
}

/// Media hygiene gate: every outbound still image goes
/// through the strip/re-encode pipeline — there is no bypass. The wire
/// carries a generic extension derived from the prepared bytes, never
/// the client's claimed `orig_ext` (the prepared bytes decide: the wire
/// extension is "jpg" / "mp4").
///
/// Pass-throughs, accepted and documented: animated GIF (the core has
/// an encoder but no frame decoder — flattening would destroy content;
/// metadata-free re-encode is the client's frames → `media::encode_gif`
/// flow) and video (hardware transcode is client-side by design). A
/// claimed image that sniffs as neither still image nor GIF is refused,
/// never sent raw.
fn prepare_spec(spec: &AttachmentSpec) -> Result<AttachmentSpec, EngineError> {
    use crate::media::sniff::{self, MediaKind};
    use schat_wire_types::attach::{CLASS_IMAGE, CLASS_VIDEO};

    match spec.media_class {
        CLASS_IMAGE => match sniff::sniff(&spec.bytes) {
            MediaKind::Jpeg | MediaKind::Png | MediaKind::Webp => {
                let bytes = crate::media::strip_and_reencode_image(&spec.bytes)?;
                // The pipeline emits JPEG (no alpha) or PNG (alpha).
                let (mime_hint, orig_ext) = if bytes.starts_with(&[0xff, 0xd8]) {
                    ("image/jpeg".to_string(), "jpg".to_string())
                } else {
                    ("image/png".to_string(), "png".to_string())
                };
                Ok(AttachmentSpec {
                    media_class: spec.media_class,
                    mime_hint,
                    orig_ext,
                    bytes,
                    caption: spec.caption.clone(),
                    view_once: spec.view_once,
                })
            }
            MediaKind::Gif => Ok(AttachmentSpec {
                mime_hint: "image/gif".to_string(),
                orig_ext: "gif".to_string(),
                ..spec.clone()
            }),
            other => Err(crate::media::MediaError::Unsupported(other.as_str()).into()),
        },
        CLASS_VIDEO => Ok(AttachmentSpec {
            orig_ext: "mp4".to_string(),
            ..spec.clone()
        }),
        _ => Ok(spec.clone()),
    }
}

impl Engine {
    /// Send media: one inline head, or head + chunk envelopes. Still
    /// images are stripped/re-encoded first (see `prepare_spec`).
    /// Returns the head's msg_id (the transfer id).
    pub async fn send_attachment(
        &mut self,
        rel_id: &str,
        spec: &AttachmentSpec,
    ) -> Result<[u8; 16], EngineError> {
        let spec = &prepare_spec(spec)?;
        let plan = plan_transfer(
            spec.media_class,
            &spec.mime_hint,
            &spec.orig_ext,
            &spec.bytes,
            &spec.caption,
            spec.view_once,
        )?;
        let inline = (spec.bytes.len() <= INLINE_MAX).then(|| spec.bytes.clone());
        let head_payload = AttachHeadPayload {
            head: plan.head.clone(),
            inline,
        };
        let sent = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::AttachHead(head_payload),
            None,
            true,
        )
        .await?;
        let head_id = sent.msg_id;

        // Outbound tracking row (we hold the bytes; nothing to fetch).
        let expiry = policy::store::message_expiry(self.db.conn(), rel_id, self.now())?;
        self.db.insert_head(&NewAttachment {
            head_id,
            rel_id: rel_id.into(),
            msg_id: head_id,
            direction: Direction::Out,
            media_class: plan.head.media_class,
            mime_hint: plan.head.mime_hint.clone(),
            uncompressed_n: plan.head.uncompressed_n,
            chunk_count: plan.head.chunk_count,
            chunk_bucket: plan.head.chunk_bucket,
            content_sha256: plan.head.content_sha256,
            caption: plan.head.caption.clone(),
            flags: plan.head.flags,
            orig_ext: plan.head.orig_ext.clone(),
            expires_at: expiry,
        })?;
        if plan.head.chunk_count == 0 {
            // Inline: stash the bytes as chunk 0 so retrieval is uniform.
            self.db
                .put_chunk(&head_id, 0, &spec.bytes, rel_id, self.now() as i64)?;
            self.db.conn().execute(
                "UPDATE attachments SET complete = 1 WHERE head_id = ?1",
                [crate::store::hex_encode(&head_id)],
            )?;
        }

        for (index, chunk) in plan.chunks.iter().enumerate() {
            let (pad, data) = match chunk {
                ChunkOut::Data(d) => (false, d.clone()),
                ChunkOut::Pad => (true, Vec::new()),
            };
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::AttachChunk(AttachChunk {
                    head_id,
                    index: index as u16,
                    pad,
                    data,
                }),
                None,
                false,
            )
            .await?;
        }
        Ok(head_id)
    }

    /// Inbound ATTACH_HEAD (dispatched from the engine). Inline heads
    /// complete immediately; chunked heads start the reassembly.
    pub(crate) fn on_attach_head(
        &mut self,
        rel_id: &str,
        env: &Envelope,
        payload: &AttachHeadPayload,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        if !policy::store::attachments_allowed(self.db.conn(), rel_id)? {
            return Ok(()); // policy off: drop (the ledger row stays)
        }
        if self.db.attachment(&env.msg_id)?.is_some() {
            return Ok(()); // head replay
        }
        let head = &payload.head;
        let expiry = policy::store::message_expiry(self.db.conn(), rel_id, self.now())?;
        self.db.insert_head(&NewAttachment {
            head_id: env.msg_id,
            rel_id: rel_id.into(),
            msg_id: env.msg_id,
            direction: Direction::In,
            media_class: head.media_class,
            mime_hint: head.mime_hint.clone(),
            uncompressed_n: head.uncompressed_n,
            chunk_count: head.chunk_count,
            chunk_bucket: head.chunk_bucket,
            content_sha256: head.content_sha256,
            caption: head.caption.clone(),
            flags: head.flags,
            orig_ext: head.orig_ext.clone(),
            expires_at: expiry,
        })?;
        if let Some(bytes) = &payload.inline {
            // v2 inline: verify and complete in one step.
            if sha256(bytes) != head.content_sha256 {
                self.db.delete_attachment(&env.msg_id)?;
                events.push(EngineEvent::AttachmentFailed {
                    rel_id: rel_id.into(),
                    head_id: env.msg_id,
                });
                return Ok(());
            }
            self.db
                .put_chunk(&env.msg_id, 0, bytes, rel_id, self.now() as i64)?;
            self.db.conn().execute(
                "UPDATE attachments SET complete = 1 WHERE head_id = ?1",
                [crate::store::hex_encode(&env.msg_id)],
            )?;
            events.push(EngineEvent::AttachmentComplete {
                rel_id: rel_id.into(),
                head_id: env.msg_id,
                msg_id: env.msg_id,
            });
            return Ok(());
        }
        // Chunks may have landed first (orphan path).
        self.try_complete(rel_id, &env.msg_id, events)
    }

    /// Inbound ATTACH_CHUNK. Orphans (head not yet seen) are stored —
    /// the head's arrival completes them.
    pub(crate) fn on_attach_chunk(
        &mut self,
        rel_id: &str,
        chunk: &AttachChunk,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        if chunk.pad {
            return Ok(()); // bucket filler; the bitmap tracks real chunks
        }
        // Orphan caps (RAM caps, adapted because chunks are
        // stored durably here): while the head is unknown, stored chunks
        // are bounded per head and per
        // relationship. Once the ATTACH_HEAD lands its own
        // chunk_count/uncompressed_n govern. Fail toward loss, loudly.
        match self.db.attachment(&chunk.head_id)? {
            None => {
                use crate::limits::orphan::*;
                let data_len = chunk.data.len() as u64;
                let (count, bytes) = self.db.orphan_head_stats(&chunk.head_id)?;
                let (rel_count, rel_bytes) = self.db.orphan_rel_stats(rel_id)?;
                if count >= MAX_ORPHAN_CHUNKS_PER_HEAD
                    || bytes + data_len > MAX_ORPHAN_BYTES_PER_HEAD
                    || rel_count >= MAX_ORPHAN_CHUNKS_PER_REL
                    || rel_bytes + data_len > MAX_ORPHAN_BYTES_PER_REL
                {
                    tracing::warn!(
                        rel_id,
                        head_id = %crate::store::hex_encode(&chunk.head_id),
                        "orphan chunk cap reached; chunk dropped"
                    );
                    events.push(EngineEvent::AttachmentChunkDropped {
                        rel_id: rel_id.into(),
                        head_id: chunk.head_id,
                    });
                    return Ok(());
                }
            }
            Some(head_row) if chunk.index >= head_row.chunk_count => {
                // Can never belong to this transfer; without this gate an
                // evil peer could store 2^16 max-size chunks per head,
                // bypassing the orphan caps (found by the adversarial harness).
                tracing::warn!(
                    rel_id,
                    head_id = %crate::store::hex_encode(&chunk.head_id),
                    index = chunk.index,
                    "chunk index out of range; dropped"
                );
                events.push(EngineEvent::AttachmentChunkDropped {
                    rel_id: rel_id.into(),
                    head_id: chunk.head_id,
                });
                return Ok(());
            }
            Some(_) => {}
        }
        self.db.put_chunk(
            &chunk.head_id,
            chunk.index,
            &chunk.data,
            rel_id,
            self.now() as i64,
        )?;
        match self.db.note_chunk(&chunk.head_id, chunk.index)? {
            None => Ok(()), // orphan: stored, waiting for the head
            Some(false) => {
                let row = self.db.attachment(&chunk.head_id)?;
                let received = row
                    .as_ref()
                    .map(|r| r.chunks.iter().map(|b| b.count_ones()).sum::<u32>())
                    .unwrap_or(0);
                events.push(EngineEvent::AttachmentProgress {
                    rel_id: rel_id.into(),
                    head_id: chunk.head_id,
                    received,
                    total: row.map(|r| u32::from(r.chunk_count)).unwrap_or(0),
                });
                Ok(())
            }
            Some(true) => self.try_complete(rel_id, &chunk.head_id, events),
        }
    }

    /// Reassemble + verify once every chunk is in. Orphan chunks that
    /// landed before the head never touched the bitmap, so completion
    /// is judged by stored count here, and the bitmap is filled on
    /// success. Hash failure erases the transfer (fail closed).
    fn try_complete(
        &mut self,
        rel_id: &str,
        head_id: &[u8; 16],
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        let Some(row) = self.db.attachment(head_id)? else {
            return Ok(());
        };
        if row.complete {
            return Ok(());
        }
        let stored = self.db.chunks_for(head_id)?;
        if stored.len() < row.chunk_count as usize {
            return Ok(()); // still missing pieces
        }
        let mut bytes = Vec::with_capacity(row.uncompressed_n as usize);
        for piece in &stored {
            bytes.extend_from_slice(piece);
        }
        if bytes.len() != row.uncompressed_n as usize || sha256(&bytes) != row.content_sha256 {
            self.db.delete_chunks(head_id)?;
            self.db.delete_attachment(head_id)?;
            events.push(EngineEvent::AttachmentFailed {
                rel_id: rel_id.into(),
                head_id: *head_id,
            });
            return Ok(());
        }
        let need = (row.chunk_count as usize).div_ceil(8);
        let mut bitmap = vec![0xffu8; need];
        if row.chunk_count % 8 != 0 {
            let last = need - 1;
            bitmap[last] = (1u8 << (row.chunk_count % 8)) - 1;
        }
        self.db.conn().execute(
            "UPDATE attachments SET chunks = ?2, complete = 1 WHERE head_id = ?1",
            rusqlite::params![crate::store::hex_encode(head_id), bitmap],
        )?;
        events.push(EngineEvent::AttachmentComplete {
            rel_id: rel_id.into(),
            head_id: *head_id,
            msg_id: row.msg_id,
        });
        Ok(())
    }

    /// DELETE targeting an attachment message: erase payloads too.
    pub(crate) fn on_delete_target(
        &mut self,
        rel_id: &str,
        target: &[u8; 16],
    ) -> Result<(), EngineError> {
        let _ = rel_id;
        for att in self.db.for_message(target)? {
            self.db.delete_chunks(&att.head_id)?;
            self.db.delete_attachment(&att.head_id)?;
        }
        Ok(())
    }

    /// Reassembled bytes for the client. `None` unless complete and
    /// (for view-once) not yet consumed.
    pub fn attachment_bytes(&self, head_id: &[u8; 16]) -> Result<Option<Vec<u8>>, EngineError> {
        let Some(row) = self.db.attachment(head_id)? else {
            return Ok(None);
        };
        if !row.complete || row.consumed {
            return Ok(None);
        }
        let stored = self.db.chunks_for(head_id)?;
        if stored.is_empty() {
            return Ok(None); // inline heads store no chunks; see below
        }
        let mut bytes = Vec::with_capacity(row.uncompressed_n as usize);
        for piece in &stored {
            bytes.extend_from_slice(piece);
        }
        Ok(Some(bytes))
    }

    /// View-once: the client rendered it — erase the payloads.
    pub fn attachment_viewed(&mut self, head_id: &[u8; 16]) -> Result<(), EngineError> {
        if let Some(row) = self.db.attachment(head_id)? {
            if row.flags & FLAG_VIEW_ONCE != 0 && !row.consumed {
                self.db.delete_chunks(head_id)?;
                self.db.mark_consumed(head_id)?;
            }
        }
        Ok(())
    }
}

/// Sniffed media class for the send path (image vs video).
pub fn class_for_mime(mime: &str) -> u8 {
    if mime.starts_with("video/") {
        schat_wire_types::attach::CLASS_VIDEO
    } else {
        CLASS_IMAGE
    }
}
