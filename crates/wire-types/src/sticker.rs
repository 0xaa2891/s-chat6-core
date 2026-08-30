//! `STICKER` / `STICKER_CTRL` payloads plus
//! the pack-document formats that ride inside STICKER_CTRL chunks.
//!
//! `STICKER` carries one item reference (optionally with inline bytes).
//! `STICKER_CTRL` carries ACKs and the WANT_ITEM / ITEM_BODY / WANT_PACK /
//! PACK_BODY fetch dance. All decode paths are bounded and fail closed.
//!
//! Pack-document *signature* verification is not in this crate: the
//! core-side sticker module picks the primitive and passes it in as a
//! closure, keeping `wire-types` crypto-free.

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

// ---------------------------------------------------------------------------
// Limits: per-item bytes/pixels/aspect,
// per-pack item counts, and device quotas so a peer cannot fill the device.
// Everything fails closed: an over-cap item or pack is refused, not
// truncated.

// The limits module is declared in the bounds catalog;
// re-exported so `sticker::limits::…` keeps working.
pub use crate::limits::sticker as limits;

use limits::{aspect_ok, item_ok, max_bytes, max_edge, max_items, valid_kind, valid_visibility};

// ---------------------------------------------------------------------------
// STICKER: one item send. Bytes are present only when `has_bytes`.

pub const ITEM_VERSION: u8 = 1;
const ITEM_HEAD_LEN: usize = 1 + 1 + 1 + 16 + 32 + 2 + 2 + 2 + 32 + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerItem {
    pub kind: u8,
    pub visibility: u8,
    pub pack_id: [u8; 16],
    pub pack_pk: [u8; 32],
    pub item_id: u16,
    pub w: u16,
    pub h: u16,
    pub content_sha256: [u8; 32],
    /// Inline item bytes; `None` = reference only (peer fetches via
    /// WANT_ITEM).
    pub bytes: Option<Vec<u8>>,
}

fn bad(at: &'static str, detail: impl Into<String>) -> WireError {
    WireError::BadField {
        at,
        detail: detail.into(),
    }
}

impl StickerItem {
    fn validate(&self) -> Result<(), WireError> {
        if !valid_kind(self.kind) || !valid_visibility(self.visibility) {
            return Err(bad("sticker.kind", "unknown kind/visibility"));
        }
        if !aspect_ok(self.kind, self.w as u32, self.h as u32) {
            return Err(bad("sticker.dims", "aspect out of range"));
        }
        if (self.w.max(self.h) as u32) > max_edge(self.kind) {
            return Err(bad("sticker.dims", "edge over cap"));
        }
        if let Some(b) = &self.bytes {
            if b.is_empty() || b.len() > max_bytes(self.kind) {
                return Err(bad("sticker.bytes", "inline bytes out of range"));
            }
        }
        Ok(())
    }
}

impl WirePayload for StickerItem {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut w = Writer::with_capacity(ITEM_HEAD_LEN);
        w.u8(ITEM_VERSION);
        w.u8(self.kind);
        w.u8(self.visibility);
        w.raw(&self.pack_id);
        w.raw(&self.pack_pk);
        w.u16be(self.item_id);
        w.u16be(self.w);
        w.u16be(self.h);
        w.raw(&self.content_sha256);
        match &self.bytes {
            None => w.u8(0),
            Some(b) => {
                w.u8(1);
                w.lp(b);
            }
        }
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("sticker.version")?;
        if version != ITEM_VERSION {
            return Err(WireError::BadVersion {
                at: "sticker",
                version,
            });
        }
        let kind = r.u8("sticker.kind")?;
        let visibility = r.u8("sticker.visibility")?;
        if !valid_kind(kind) || !valid_visibility(visibility) {
            return Err(bad("sticker.kind", "unknown kind/visibility"));
        }
        let pack_id: [u8; 16] =
            r.take(16, "sticker.pack_id")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "sticker.pack_id",
                })?;
        let pack_pk: [u8; 32] =
            r.take(32, "sticker.pack_pk")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "sticker.pack_pk",
                })?;
        let item_id = r.u16be("sticker.item_id")?;
        let w = r.u16be("sticker.w")?;
        let h = r.u16be("sticker.h")?;
        if !aspect_ok(kind, w as u32, h as u32) {
            return Err(bad("sticker.dims", "aspect out of range"));
        }
        if (w.max(h) as u32) > max_edge(kind) {
            return Err(bad("sticker.dims", "edge over cap"));
        }
        let content_sha256: [u8; 32] =
            r.take(32, "sticker.sha256")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "sticker.sha256",
                })?;
        let has_bytes = r.u8("sticker.has_bytes")?;
        let inline = match has_bytes {
            0 => {
                r.expect_end("sticker")?;
                None
            }
            1 => {
                let b = r
                    .lp(limits::MAX_BYTES_STICKER as u64, "sticker.bytes")?
                    .to_vec();
                r.expect_end("sticker")?;
                if b.is_empty() || b.len() > max_bytes(kind) {
                    return Err(bad("sticker.bytes", "inline bytes out of range"));
                }
                Some(b)
            }
            other => return Err(bad("sticker.has_bytes", format!("{other}"))),
        };
        Ok(Self {
            kind,
            visibility,
            pack_id,
            pack_pk,
            item_id,
            w,
            h,
            content_sha256,
            bytes: inline,
        })
    }
}

// ---------------------------------------------------------------------------
// STICKER_CTRL operations.

pub const CTRL_VERSION: u8 = 1;
pub const OP_ACK: u8 = 1;
pub const OP_WANT_ITEM: u8 = 2;
pub const OP_ITEM_BODY: u8 = 3;
pub const OP_WANT_PACK: u8 = 4;
pub const OP_PACK_BODY: u8 = 5;
pub const OP_PACK_REFUSED: u8 = 6;
pub const OP_WANT_THUMBS: u8 = 7;
pub const OP_THUMBS_BODY: u8 = 8;

pub const REFUSED_PRIVATE: u8 = 1;
pub const REFUSED_UNKNOWN: u8 = 2;
pub const REFUSED_RATE_LIMITED: u8 = 3;

/// Pack context attached to ITEM_BODY so the receiver can auto-cache
/// public packs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackRef {
    pub pack_id: [u8; 16],
    pub pack_pk: [u8; 32],
    pub kind: u8,
    pub visibility: u8,
    pub item_id: u16,
    pub w: u16,
    pub h: u16,
}

pub const PACK_REF_LEN: usize = 16 + 32 + 1 + 1 + 2 + 2 + 2;

impl PackRef {
    fn encode_to(&self, w: &mut Writer) {
        w.raw(&self.pack_id);
        w.raw(&self.pack_pk);
        w.u8(self.kind);
        w.u8(self.visibility);
        w.u16be(self.item_id);
        w.u16be(self.w);
        w.u16be(self.h);
    }

    fn decode_from(r: &mut Reader) -> Result<Self, WireError> {
        let pack_id: [u8; 16] =
            r.take(16, "pack_ref.pack_id")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "pack_ref.pack_id",
                })?;
        let pack_pk: [u8; 32] =
            r.take(32, "pack_ref.pack_pk")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "pack_ref.pack_pk",
                })?;
        let kind = r.u8("pack_ref.kind")?;
        let visibility = r.u8("pack_ref.visibility")?;
        if !valid_kind(kind) || !valid_visibility(visibility) {
            return Err(bad("pack_ref.kind", "unknown kind/visibility"));
        }
        let item_id = r.u16be("pack_ref.item_id")?;
        let w = r.u16be("pack_ref.w")?;
        let h = r.u16be("pack_ref.h")?;
        if !aspect_ok(kind, w as u32, h as u32) {
            return Err(bad("pack_ref.dims", "aspect out of range"));
        }
        Ok(Self {
            pack_id,
            pack_pk,
            kind,
            visibility,
            item_id,
            w,
            h,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StickerCtrl {
    /// Receiver confirms it holds `sha`; sender may omit bytes for it later.
    Ack([u8; 32]),
    /// Hash the receiver is missing. Full 32 bytes when known (sticker
    /// bubble), or an 8-byte prefix from an inline `:e:` token — the sender
    /// resolves the prefix against its own packs.
    WantItem(Vec<u8>),
    ItemBody {
        sha: [u8; 32],
        chunk_index: u16,
        chunk_count: u16,
        data: Vec<u8>,
        pack: Option<PackRef>,
    },
    WantPack {
        pack_id: [u8; 16],
        pack_pk: [u8; 32],
    },
    PackBody {
        pack_id: [u8; 16],
        pack_pk: [u8; 32],
        chunk_index: u16,
        chunk_count: u16,
        data: Vec<u8>,
    },
    /// Typed refusal (never a hang): 1=private, 2=unknown pack,
    /// 3=rate limited.
    PackRefused {
        pack_id: [u8; 16],
        pack_pk: [u8; 32],
        reason: u8,
    },
    /// Ask for a pack's preview thumbnails (small unsigned doc, no item
    /// bytes).
    WantThumbs {
        pack_id: [u8; 16],
        pack_pk: [u8; 32],
    },
    /// One chunk of a [`StickerThumbsDoc`] blob; reassembled like
    /// PACK_BODY.
    ThumbsBody {
        pack_id: [u8; 16],
        pack_pk: [u8; 32],
        chunk_index: u16,
        chunk_count: u16,
        data: Vec<u8>,
    },
}

fn take16(r: &mut Reader, at: &'static str) -> Result<[u8; 16], WireError> {
    r.take(16, at)?
        .try_into()
        .map_err(|_| WireError::Truncated { at })
}

fn take32(r: &mut Reader, at: &'static str) -> Result<[u8; 32], WireError> {
    r.take(32, at)?
        .try_into()
        .map_err(|_| WireError::Truncated { at })
}

fn check_chunk_plan(
    index: u16,
    count: u16,
    max_chunks: u16,
    at: &'static str,
) -> Result<(), WireError> {
    if count < 1 || count > max_chunks || index >= count {
        return Err(bad(at, format!("chunk {index}/{count} (max {max_chunks})")));
    }
    Ok(())
}

impl WirePayload for StickerCtrl {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::new();
        w.u8(CTRL_VERSION);
        match self {
            StickerCtrl::Ack(sha) => {
                w.u8(OP_ACK);
                w.raw(sha);
            }
            StickerCtrl::WantItem(sha) => {
                if !(4..=32).contains(&sha.len()) {
                    return Err(bad("sticker_ctrl.want_item", "sha len 4..=32"));
                }
                w.u8(OP_WANT_ITEM);
                w.u8(sha.len() as u8);
                w.raw(sha);
            }
            StickerCtrl::ItemBody {
                sha,
                chunk_index,
                chunk_count,
                data,
                pack,
            } => {
                check_chunk_plan(
                    *chunk_index,
                    *chunk_count,
                    limits::MAX_ITEM_CHUNKS,
                    "sticker_ctrl.item_body",
                )?;
                if data.len() > limits::ITEM_CHUNK_MAX {
                    return Err(WireError::TooLarge {
                        at: "sticker_ctrl.item_body",
                        size: data.len(),
                        max: limits::ITEM_CHUNK_MAX,
                    });
                }
                w.u8(OP_ITEM_BODY);
                w.raw(sha);
                w.u16be(*chunk_index);
                w.u16be(*chunk_count);
                w.lp(data);
                if let Some(p) = pack {
                    p.encode_to(&mut w);
                }
            }
            StickerCtrl::WantPack { pack_id, pack_pk } => {
                w.u8(OP_WANT_PACK);
                w.raw(pack_id);
                w.raw(pack_pk);
            }
            StickerCtrl::PackBody {
                pack_id,
                pack_pk,
                chunk_index,
                chunk_count,
                data,
            } => {
                check_chunk_plan(
                    *chunk_index,
                    *chunk_count,
                    limits::MAX_PACK_CHUNKS,
                    "sticker_ctrl.pack_body",
                )?;
                if data.len() > limits::PACK_CHUNK_MAX {
                    return Err(WireError::TooLarge {
                        at: "sticker_ctrl.pack_body",
                        size: data.len(),
                        max: limits::PACK_CHUNK_MAX,
                    });
                }
                w.u8(OP_PACK_BODY);
                w.raw(pack_id);
                w.raw(pack_pk);
                w.u16be(*chunk_index);
                w.u16be(*chunk_count);
                w.lp(data);
            }
            StickerCtrl::PackRefused {
                pack_id,
                pack_pk,
                reason,
            } => {
                if !(REFUSED_PRIVATE..=REFUSED_RATE_LIMITED).contains(reason) {
                    return Err(bad("sticker_ctrl.refused", format!("reason {reason}")));
                }
                w.u8(OP_PACK_REFUSED);
                w.raw(pack_id);
                w.raw(pack_pk);
                w.u8(*reason);
            }
            StickerCtrl::WantThumbs { pack_id, pack_pk } => {
                w.u8(OP_WANT_THUMBS);
                w.raw(pack_id);
                w.raw(pack_pk);
            }
            StickerCtrl::ThumbsBody {
                pack_id,
                pack_pk,
                chunk_index,
                chunk_count,
                data,
            } => {
                check_chunk_plan(
                    *chunk_index,
                    *chunk_count,
                    limits::MAX_THUMBS_CHUNKS,
                    "sticker_ctrl.thumbs_body",
                )?;
                if data.len() > limits::PACK_CHUNK_MAX {
                    return Err(WireError::TooLarge {
                        at: "sticker_ctrl.thumbs_body",
                        size: data.len(),
                        max: limits::PACK_CHUNK_MAX,
                    });
                }
                w.u8(OP_THUMBS_BODY);
                w.raw(pack_id);
                w.raw(pack_pk);
                w.u16be(*chunk_index);
                w.u16be(*chunk_count);
                w.lp(data);
            }
        }
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("sticker_ctrl.version")?;
        if version != CTRL_VERSION {
            return Err(WireError::BadVersion {
                at: "sticker_ctrl",
                version,
            });
        }
        let op = r.u8("sticker_ctrl.op")?;
        match op {
            OP_ACK => {
                let sha = take32(&mut r, "sticker_ctrl.ack")?;
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::Ack(sha))
            }
            OP_WANT_ITEM => {
                let n = r.u8("sticker_ctrl.want_item.len")? as usize;
                if !(4..=32).contains(&n) {
                    return Err(bad("sticker_ctrl.want_item", "sha len 4..=32"));
                }
                let sha = r.take(n, "sticker_ctrl.want_item")?.to_vec();
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::WantItem(sha))
            }
            OP_ITEM_BODY => {
                let sha = take32(&mut r, "sticker_ctrl.item_body.sha")?;
                let idx = r.u16be("sticker_ctrl.item_body.idx")?;
                let count = r.u16be("sticker_ctrl.item_body.count")?;
                check_chunk_plan(
                    idx,
                    count,
                    limits::MAX_ITEM_CHUNKS,
                    "sticker_ctrl.item_body",
                )?;
                let data = r
                    .lp(limits::ITEM_CHUNK_MAX as u64, "sticker_ctrl.item_body.data")?
                    .to_vec();
                // Keep the image bytes even if pack metadata is picky
                // (non-square emoji dims, etc.): a bad trailer drops the
                // PackRef, not the chunk. Parse from a sub-reader so a
                // failed trailer cannot leave the main cursor advanced.
                let pack = match r.remaining() {
                    0 => None,
                    PACK_REF_LEN => {
                        let trailer = r.take(PACK_REF_LEN, "sticker_ctrl.item_body.pack")?;
                        PackRef::decode_from(&mut Reader::new(trailer)).ok()
                    }
                    _ => {
                        return Err(WireError::Trailing {
                            at: "sticker_ctrl.item_body",
                            extra: r.remaining(),
                        })
                    }
                };
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::ItemBody {
                    sha,
                    chunk_index: idx,
                    chunk_count: count,
                    data,
                    pack,
                })
            }
            OP_WANT_PACK => {
                let pack_id = take16(&mut r, "sticker_ctrl.want_pack.id")?;
                let pack_pk = take32(&mut r, "sticker_ctrl.want_pack.pk")?;
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::WantPack { pack_id, pack_pk })
            }
            OP_PACK_BODY => {
                let pack_id = take16(&mut r, "sticker_ctrl.pack_body.id")?;
                let pack_pk = take32(&mut r, "sticker_ctrl.pack_body.pk")?;
                let idx = r.u16be("sticker_ctrl.pack_body.idx")?;
                let count = r.u16be("sticker_ctrl.pack_body.count")?;
                check_chunk_plan(
                    idx,
                    count,
                    limits::MAX_PACK_CHUNKS,
                    "sticker_ctrl.pack_body",
                )?;
                let data = r
                    .lp(limits::PACK_CHUNK_MAX as u64, "sticker_ctrl.pack_body.data")?
                    .to_vec();
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::PackBody {
                    pack_id,
                    pack_pk,
                    chunk_index: idx,
                    chunk_count: count,
                    data,
                })
            }
            OP_PACK_REFUSED => {
                let pack_id = take16(&mut r, "sticker_ctrl.refused.id")?;
                let pack_pk = take32(&mut r, "sticker_ctrl.refused.pk")?;
                let reason = r.u8("sticker_ctrl.refused.reason")?;
                r.expect_end("sticker_ctrl")?;
                if !(REFUSED_PRIVATE..=REFUSED_RATE_LIMITED).contains(&reason) {
                    return Err(bad("sticker_ctrl.refused", format!("reason {reason}")));
                }
                Ok(StickerCtrl::PackRefused {
                    pack_id,
                    pack_pk,
                    reason,
                })
            }
            OP_WANT_THUMBS => {
                let pack_id = take16(&mut r, "sticker_ctrl.want_thumbs.id")?;
                let pack_pk = take32(&mut r, "sticker_ctrl.want_thumbs.pk")?;
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::WantThumbs { pack_id, pack_pk })
            }
            OP_THUMBS_BODY => {
                let pack_id = take16(&mut r, "sticker_ctrl.thumbs_body.id")?;
                let pack_pk = take32(&mut r, "sticker_ctrl.thumbs_body.pk")?;
                let idx = r.u16be("sticker_ctrl.thumbs_body.idx")?;
                let count = r.u16be("sticker_ctrl.thumbs_body.count")?;
                check_chunk_plan(
                    idx,
                    count,
                    limits::MAX_THUMBS_CHUNKS,
                    "sticker_ctrl.thumbs_body",
                )?;
                let data = r
                    .lp(
                        limits::PACK_CHUNK_MAX as u64,
                        "sticker_ctrl.thumbs_body.data",
                    )?
                    .to_vec();
                r.expect_end("sticker_ctrl")?;
                Ok(StickerCtrl::ThumbsBody {
                    pack_id,
                    pack_pk,
                    chunk_index: idx,
                    chunk_count: count,
                    data,
                })
            }
            other => Err(bad("sticker_ctrl.op", format!("{other}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Signed pack document — the exact byte string a recipient installs, so a
// downloaded pack renders identically to the creator's (title, order,
// icon). The signature covers the doc; every item hash is verified against
// its bytes. Signature *verification* is injected (the caller picks the
// primitive); structure, caps, and hashes are checked here.

pub const PACK_DOC_DOMAIN: &[u8] = b"s//chat6-v7 Pack";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackDocItem {
    pub item_id: u16,
    pub w: u16,
    pub h: u16,
    pub sha256: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerPackDoc {
    pub pack_id: [u8; 16],
    pub kind: u8,
    pub visibility: u8,
    pub title: String,
    pub icon_item_id: u16,
    pub items: Vec<PackDocItem>,
}

impl StickerPackDoc {
    /// Canonical unsigned body; this is what gets signed.
    pub fn body_bytes(&self) -> Result<Vec<u8>, WireError> {
        if !valid_kind(self.kind) || !valid_visibility(self.visibility) {
            return Err(bad("pack_doc.kind", "unknown kind/visibility"));
        }
        let title = self.title.as_bytes();
        if title.len() > limits::MAX_TITLE_CHARS * 4 {
            return Err(WireError::TooLarge {
                at: "pack_doc.title",
                size: title.len(),
                max: limits::MAX_TITLE_CHARS * 4,
            });
        }
        if self.items.is_empty() || self.items.len() > max_items(self.kind) {
            return Err(bad("pack_doc.items", "item count out of range"));
        }
        let mut seen = std::collections::HashSet::with_capacity(self.items.len() * 2);
        let mut w = Writer::new();
        w.raw(PACK_DOC_DOMAIN);
        w.raw(&self.pack_id);
        w.u8(self.kind);
        w.u8(self.visibility);
        w.lp(title);
        w.u16be(self.icon_item_id);
        w.u16be(self.items.len() as u16);
        for it in &self.items {
            if !seen.insert(it.item_id) {
                return Err(bad("pack_doc.items", "duplicate item id"));
            }
            if !item_ok(self.kind, it.w as u32, it.h as u32, it.bytes.len()) {
                return Err(bad("pack_doc.item", "item fails caps"));
            }
            w.u16be(it.item_id);
            w.u16be(it.w);
            w.u16be(it.h);
            w.raw(&it.sha256);
            w.lp(&it.bytes);
        }
        Ok(w.finish())
    }

    /// Parse + verify a reassembled `doc ‖ sig`. `verify(pack_pk, body,
    /// sig)` and `sha256(bytes)` are injected by the caller. Returns the
    /// doc on success; error on any truncation, cap violation, hash
    /// mismatch, or bad signature. Item bytes are hash-checked here, so
    /// callers never see unverified content.
    pub fn decode_signed(
        blob: &[u8],
        pack_pk: &[u8; 32],
        verify: impl Fn(&[u8; 32], &[u8], &[u8]) -> bool,
        sha256: impl Fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, WireError> {
        if blob.len() > limits::MAX_PACK_DOC_BYTES {
            return Err(WireError::TooLarge {
                at: "pack_doc",
                size: blob.len(),
                max: limits::MAX_PACK_DOC_BYTES,
            });
        }
        let min = 64 + PACK_DOC_DOMAIN.len() + 16 + 1 + 1 + 4 + 2 + 2;
        if blob.len() < min {
            return Err(WireError::Truncated { at: "pack_doc" });
        }
        let body = &blob[..blob.len() - 64];
        let sig = &blob[blob.len() - 64..];
        if !verify(pack_pk, body, sig) {
            return Err(bad("pack_doc.sig", "signature invalid"));
        }
        Self::decode_body(body, &sha256)
    }

    /// Structural decode of the unsigned body with per-item hash checks.
    fn decode_body(body: &[u8], sha256: &impl Fn(&[u8]) -> [u8; 32]) -> Result<Self, WireError> {
        let mut r = Reader::new(body);
        let domain = r.take(PACK_DOC_DOMAIN.len(), "pack_doc.domain")?;
        if domain != PACK_DOC_DOMAIN {
            return Err(bad("pack_doc.domain", "mismatch"));
        }
        let pack_id = take16(&mut r, "pack_doc.pack_id")?;
        let kind = r.u8("pack_doc.kind")?;
        let visibility = r.u8("pack_doc.visibility")?;
        if !valid_kind(kind) || !valid_visibility(visibility) {
            return Err(bad("pack_doc.kind", "unknown kind/visibility"));
        }
        let title_bytes = r.lp((limits::MAX_TITLE_CHARS * 4) as u64, "pack_doc.title")?;
        let title =
            String::from_utf8(title_bytes.to_vec()).map_err(|_| bad("pack_doc.title", "utf-8"))?;
        if title.chars().count() > limits::MAX_TITLE_CHARS {
            return Err(WireError::TooLarge {
                at: "pack_doc.title",
                size: title.chars().count(),
                max: limits::MAX_TITLE_CHARS,
            });
        }
        let icon_item_id = r.u16be("pack_doc.icon")?;
        let count = r.u16be("pack_doc.count")? as usize;
        if count < 1 || count > max_items(kind) {
            return Err(bad("pack_doc.items", "item count out of range"));
        }
        let mut items = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::with_capacity(count * 2);
        for _ in 0..count {
            let item_id = r.u16be("pack_doc.item.id")?;
            let w = r.u16be("pack_doc.item.w")?;
            let h = r.u16be("pack_doc.item.h")?;
            let sha = take32(&mut r, "pack_doc.item.sha")?;
            let bytes = r
                .lp(max_bytes(kind) as u64, "pack_doc.item.bytes")?
                .to_vec();
            if bytes.is_empty() {
                return Err(bad("pack_doc.item.bytes", "empty"));
            }
            if !seen.insert(item_id) {
                return Err(bad("pack_doc.items", "duplicate item id"));
            }
            if sha256(&bytes) != sha {
                return Err(bad("pack_doc.item.sha", "hash mismatch"));
            }
            if !item_ok(kind, w as u32, h as u32, bytes.len()) {
                return Err(bad("pack_doc.item", "item fails caps"));
            }
            items.push(PackDocItem {
                item_id,
                w,
                h,
                sha256: sha,
                bytes,
            });
        }
        r.expect_end("pack_doc")?;
        if !items.iter().any(|it| it.item_id == icon_item_id) {
            return Err(bad("pack_doc.icon", "icon item missing"));
        }
        Ok(Self {
            pack_id,
            kind,
            visibility,
            title,
            icon_item_id,
            items,
        })
    }

    /// Progress scan over a partially reassembled `doc ‖ sig` prefix:
    /// walks the item table without hashing or signature checks and
    /// returns (complete items, total items), or `None` while the fixed
    /// header has not fully arrived. Verification still happens on the
    /// complete blob via [`Self::decode_signed`].
    pub fn scan_partial(partial: &[u8]) -> Option<(usize, usize)> {
        if partial.len() > limits::MAX_PACK_DOC_BYTES {
            return None;
        }
        let mut r = Reader::new(partial);
        let domain = r.take(PACK_DOC_DOMAIN.len(), "pack_doc.domain").ok()?;
        if domain != PACK_DOC_DOMAIN {
            return None;
        }
        r.take(16, "pack_doc.pack_id").ok()?;
        let kind = r.u8("pack_doc.kind").ok()?;
        r.u8("pack_doc.visibility").ok()?;
        if !valid_kind(kind) {
            return None;
        }
        r.lp((limits::MAX_TITLE_CHARS * 4) as u64, "pack_doc.title")
            .ok()?;
        r.u16be("pack_doc.icon").ok()?;
        let count = r.u16be("pack_doc.count").ok()? as usize;
        if count < 1 || count > max_items(kind) {
            return None;
        }
        let mut complete = 0usize;
        let mut seen = std::collections::HashSet::with_capacity(count * 2);
        while complete < count {
            // Length-only walk: copying each item's bytes per progress
            // scan would turn a big-pack download quadratic. Truncation
            // mid-table means "still downloading" — report progress, not
            // failure.
            let Some(item_id) = r.u16be("pack_doc.item.id").ok() else {
                break;
            };
            if r.take(2 + 2 + 32, "pack_doc.item.head").is_err() {
                break;
            }
            let Ok(n) = r.u32be("pack_doc.item.len") else {
                break;
            };
            let n = n as usize;
            if n == 0 || n > max_bytes(kind) {
                break;
            }
            if r.remaining() < n {
                break;
            }
            if r.take(n, "pack_doc.item.bytes").is_err() {
                break;
            }
            if !seen.insert(item_id) {
                break;
            }
            complete += 1;
        }
        Some((complete, count))
    }
}

// ---------------------------------------------------------------------------
// Unsigned pack-preview document: title + icon + one small thumbnail per
// item, answered to WANT_THUMBS so a peer can render the pack grid before
// deciding to clone. Not signed and never installed — a preview only.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thumb {
    pub item_id: u16,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StickerThumbsDoc {
    pub title: String,
    pub kind: u8,
    pub icon_item_id: u16,
    pub thumbs: Vec<Thumb>,
}

impl StickerThumbsDoc {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if !valid_kind(self.kind) {
            return Err(bad("thumbs_doc.kind", "unknown kind"));
        }
        let title = self.title.as_bytes();
        if title.len() > limits::MAX_TITLE_CHARS * 4 {
            return Err(WireError::TooLarge {
                at: "thumbs_doc.title",
                size: title.len(),
                max: limits::MAX_TITLE_CHARS * 4,
            });
        }
        if self.thumbs.is_empty() || self.thumbs.len() > max_items(self.kind) {
            return Err(bad("thumbs_doc.thumbs", "count out of range"));
        }
        let mut seen = std::collections::HashSet::with_capacity(self.thumbs.len() * 2);
        let mut w = Writer::new();
        w.lp(title);
        w.u8(self.kind);
        w.u16be(self.icon_item_id);
        w.u16be(self.thumbs.len() as u16);
        for t in &self.thumbs {
            if !seen.insert(t.item_id) {
                return Err(bad("thumbs_doc.thumbs", "duplicate item id"));
            }
            if t.bytes.is_empty() || t.bytes.len() > limits::MAX_THUMB_BYTES {
                return Err(bad("thumbs_doc.thumb", "bytes out of range"));
            }
            w.u16be(t.item_id);
            w.lp(&t.bytes);
        }
        let out = w.finish();
        if out.len() > limits::MAX_THUMBS_DOC_BYTES {
            return Err(WireError::TooLarge {
                at: "thumbs_doc",
                size: out.len(),
                max: limits::MAX_THUMBS_DOC_BYTES,
            });
        }
        Ok(out)
    }

    pub fn decode(blob: &[u8]) -> Result<Self, WireError> {
        if blob.len() > limits::MAX_THUMBS_DOC_BYTES {
            return Err(WireError::TooLarge {
                at: "thumbs_doc",
                size: blob.len(),
                max: limits::MAX_THUMBS_DOC_BYTES,
            });
        }
        let mut r = Reader::new(blob);
        let title_bytes = r.lp((limits::MAX_TITLE_CHARS * 4) as u64, "thumbs_doc.title")?;
        let title = String::from_utf8(title_bytes.to_vec())
            .map_err(|_| bad("thumbs_doc.title", "utf-8"))?;
        if title.chars().count() > limits::MAX_TITLE_CHARS {
            return Err(WireError::TooLarge {
                at: "thumbs_doc.title",
                size: title.chars().count(),
                max: limits::MAX_TITLE_CHARS,
            });
        }
        let kind = r.u8("thumbs_doc.kind")?;
        if !valid_kind(kind) {
            return Err(bad("thumbs_doc.kind", "unknown kind"));
        }
        let icon_item_id = r.u16be("thumbs_doc.icon")?;
        let count = r.u16be("thumbs_doc.count")? as usize;
        if count < 1 || count > max_items(kind) {
            return Err(bad("thumbs_doc.thumbs", "count out of range"));
        }
        let mut thumbs = Vec::with_capacity(count);
        let mut seen = std::collections::HashSet::with_capacity(count * 2);
        for _ in 0..count {
            let item_id = r.u16be("thumbs_doc.thumb.id")?;
            let bytes = r
                .lp(limits::MAX_THUMB_BYTES as u64, "thumbs_doc.thumb.bytes")?
                .to_vec();
            if bytes.is_empty() {
                return Err(bad("thumbs_doc.thumb", "empty"));
            }
            if !seen.insert(item_id) {
                return Err(bad("thumbs_doc.thumbs", "duplicate item id"));
            }
            thumbs.push(Thumb { item_id, bytes });
        }
        r.expect_end("thumbs_doc")?;
        Ok(Self {
            title,
            kind,
            icon_item_id,
            thumbs,
        })
    }
}
