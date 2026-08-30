//! `ATTACH_HEAD` / `ATTACH_CHUNK` payloads.
//!
//! Heads come in two versions: v1 chunked (metadata + chunk plan; bytes
//! follow as ATTACH_CHUNK envelopes) and v2 inline (whole file in the head
//! payload, for small media). The caption tail is `CAP_V16`, the trailing
//! flags byte `CAP_V17` — on this wire both are baseline (CAP_V15 subsumes
//! them; there are no pre-V16 peers).
//!
//! The jumbo-frame layer was cut; one chunk must fit one envelope, so
//! the chunk data ceiling is 27 900 bytes.

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

pub const CLASS_IMAGE: u8 = 1;
pub const CLASS_VIDEO: u8 = 2;

// Caps declared in the bounds catalog.
pub use crate::limits::attach::{
    CHUNK_DATA_MAX, MAX_ATTACH, MAX_CAPTION, MAX_CHUNKS, MAX_EXT, MAX_MIME,
};

pub const FLAG_VIEW_ONCE: u8 = 1;

pub const VERSION: u8 = 1;
pub const VERSION_INLINE: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachHead {
    pub media_class: u8,
    pub mime_hint: String,
    pub orig_ext: String,
    pub uncompressed_n: u32,
    pub chunk_count: u16,
    pub chunk_bucket: u16,
    pub content_sha256: [u8; 32],
    pub caption: String,
    pub flags: u8,
}

impl AttachHead {
    pub fn view_once(&self) -> bool {
        self.flags & FLAG_VIEW_ONCE != 0
    }

    fn validate_common(&self) -> Result<(), WireError> {
        if self.media_class != CLASS_IMAGE && self.media_class != CLASS_VIDEO {
            return Err(WireError::BadField {
                at: "attach_head.media_class",
                detail: format!("class {}", self.media_class),
            });
        }
        if self.mime_hint.len() > MAX_MIME {
            return Err(WireError::TooLarge {
                at: "attach_head.mime",
                size: self.mime_hint.len(),
                max: MAX_MIME,
            });
        }
        if self.orig_ext.len() > MAX_EXT {
            return Err(WireError::TooLarge {
                at: "attach_head.ext",
                size: self.orig_ext.len(),
                max: MAX_EXT,
            });
        }
        if self.uncompressed_n < 1 || self.uncompressed_n > MAX_ATTACH {
            return Err(WireError::BadField {
                at: "attach_head.uncompressed_n",
                detail: format!("n {}", self.uncompressed_n),
            });
        }
        if self.caption.len() > MAX_CAPTION {
            return Err(WireError::TooLarge {
                at: "attach_head.caption",
                size: self.caption.len(),
                max: MAX_CAPTION,
            });
        }
        Ok(())
    }

    /// Chunked head (v1): metadata + chunk plan, bytes ride as chunks.
    pub fn encode_chunked(&self) -> Result<Vec<u8>, WireError> {
        self.validate_common()?;
        if self.chunk_count < 1
            || self.chunk_count > MAX_CHUNKS
            || self.chunk_bucket < self.chunk_count
            || self.chunk_bucket > MAX_CHUNKS
        {
            return Err(WireError::BadField {
                at: "attach_head.chunks",
                detail: format!("count {} bucket {}", self.chunk_count, self.chunk_bucket),
            });
        }
        let mut w = Writer::new();
        w.u8(VERSION);
        w.u8(self.media_class);
        w.lp(self.mime_hint.as_bytes());
        w.lp(self.orig_ext.as_bytes());
        w.u32be(self.uncompressed_n);
        w.u16be(self.chunk_count);
        w.u16be(self.chunk_bucket);
        w.raw(&self.content_sha256);
        encode_caption_tail(&mut w, &self.caption, self.flags)?;
        Ok(w.finish())
    }

    /// Inline head (v2): the whole file in the head payload.
    pub fn encode_inline(&self, inline_bytes: &[u8]) -> Result<Vec<u8>, WireError> {
        self.validate_common()?;
        if self.chunk_count != 0 || self.chunk_bucket != 0 {
            return Err(WireError::BadField {
                at: "attach_head.chunks",
                detail: "inline head must have zero chunk plan".into(),
            });
        }
        if inline_bytes.len() != self.uncompressed_n as usize {
            return Err(WireError::BadLength {
                at: "attach_head.inline",
                len: inline_bytes.len() as u64,
                max: self.uncompressed_n as u64,
            });
        }
        let mut w = Writer::new();
        w.u8(VERSION_INLINE);
        w.u8(self.media_class);
        w.lp(self.mime_hint.as_bytes());
        w.lp(self.orig_ext.as_bytes());
        w.u32be(self.uncompressed_n);
        w.raw(&self.content_sha256);
        encode_caption_tail(&mut w, &self.caption, self.flags)?;
        w.lp(inline_bytes);
        Ok(w.finish())
    }

    /// Decode either version. Inline heads return their bytes in the
    /// second tuple element.
    pub fn decode_with_inline(bytes: &[u8]) -> Result<(Self, Option<Vec<u8>>), WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("attach_head.version")?;
        match version {
            VERSION => Ok((decode_chunked(bytes)?, None)),
            VERSION_INLINE => decode_inline(bytes),
            other => Err(WireError::BadVersion {
                at: "attach_head",
                version: other,
            }),
        }
    }
}

/// The caption/flags tail shared by both head versions. An empty caption
/// with no flags is omitted entirely; a caption-only tail is the CAP_V16
/// shape; a trailing flags byte makes it CAP_V17.
fn encode_caption_tail(w: &mut Writer, caption: &str, flags: u8) -> Result<(), WireError> {
    if caption.is_empty() && flags == 0 {
        return Ok(());
    }
    let cap = caption.as_bytes();
    if cap.len() > MAX_CAPTION {
        return Err(WireError::TooLarge {
            at: "attach_head.caption",
            size: cap.len(),
            max: MAX_CAPTION,
        });
    }
    w.lp(cap);
    if flags != 0 {
        w.u8(flags);
    }
    Ok(())
}

/// Read the optional caption/flags tail, then require `end` to equal the
/// payload size. Returns (caption, flags).
fn decode_caption_tail(r: &mut Reader, total: usize) -> Result<(String, u8), WireError> {
    if r.remaining() == 0 {
        return Ok((String::new(), 0));
    }
    let cap_len = r.u32be("attach_head.caption")? as usize;
    if cap_len > MAX_CAPTION {
        return Err(WireError::BadLength {
            at: "attach_head.caption",
            len: cap_len as u64,
            max: MAX_CAPTION as u64,
        });
    }
    let cap_bytes = r.take(cap_len, "attach_head.caption")?;
    let cap_end = r.position();
    if cap_end == total {
        // CAP_V16: caption consumes the rest. Empty captions are omitted
        // entirely, so a zero-length caption here is malformed.
        if cap_len < 1 {
            return Err(WireError::BadLength {
                at: "attach_head.caption",
                len: 0,
                max: MAX_CAPTION as u64,
            });
        }
        let caption = String::from_utf8(cap_bytes.to_vec()).map_err(|_| WireError::BadField {
            at: "attach_head.caption",
            detail: "invalid utf-8".into(),
        })?;
        return Ok((caption, 0));
    }
    if cap_end + 1 == total {
        let caption = if cap_len == 0 {
            String::new()
        } else {
            String::from_utf8(cap_bytes.to_vec()).map_err(|_| WireError::BadField {
                at: "attach_head.caption",
                detail: "invalid utf-8".into(),
            })?
        };
        let flags = r.u8("attach_head.flags")?;
        return Ok((caption, flags));
    }
    Err(WireError::Trailing {
        at: "attach_head",
        extra: total - cap_end,
    })
}

fn read_ascii(r: &mut Reader, max: u64, at: &'static str) -> Result<String, WireError> {
    let bytes = r.lp(max, at)?;
    if bytes.iter().any(|b| !b.is_ascii()) {
        return Err(WireError::BadField {
            at,
            detail: "not ascii".into(),
        });
    }
    // ASCII is always valid UTF-8.
    Ok(String::from_utf8(bytes.to_vec()).expect("ascii"))
}

fn decode_chunked(bytes: &[u8]) -> Result<AttachHead, WireError> {
    let mut r = Reader::new(bytes);
    let version = r.u8("attach_head.version")?;
    debug_assert_eq!(version, VERSION);
    let media_class = r.u8("attach_head.class")?;
    let mime_hint = read_ascii(&mut r, MAX_MIME as u64, "attach_head.mime")?;
    let orig_ext = read_ascii(&mut r, MAX_EXT as u64, "attach_head.ext")?;
    let uncompressed_n = r.u32be("attach_head.n")?;
    let chunk_count = r.u16be("attach_head.count")?;
    let chunk_bucket = r.u16be("attach_head.bucket")?;
    let content_sha256: [u8; 32] =
        r.take(32, "attach_head.sha256")?
            .try_into()
            .map_err(|_| WireError::Truncated {
                at: "attach_head.sha256",
            })?;
    let (caption, flags) = decode_caption_tail(&mut r, bytes.len())?;
    let head = AttachHead {
        media_class,
        mime_hint,
        orig_ext,
        uncompressed_n,
        chunk_count,
        chunk_bucket,
        content_sha256,
        caption,
        flags,
    };
    head.validate_common()?;
    if head.chunk_count < 1
        || head.chunk_count > MAX_CHUNKS
        || head.chunk_bucket < head.chunk_count
        || head.chunk_bucket > MAX_CHUNKS
    {
        return Err(WireError::BadField {
            at: "attach_head.chunks",
            detail: format!("count {} bucket {}", head.chunk_count, head.chunk_bucket),
        });
    }
    Ok(head)
}

fn decode_inline(bytes: &[u8]) -> Result<(AttachHead, Option<Vec<u8>>), WireError> {
    let mut r = Reader::new(bytes);
    let version = r.u8("attach_head.version")?;
    debug_assert_eq!(version, VERSION_INLINE);
    let media_class = r.u8("attach_head.class")?;
    let mime_hint = read_ascii(&mut r, MAX_MIME as u64, "attach_head.mime")?;
    let orig_ext = read_ascii(&mut r, MAX_EXT as u64, "attach_head.ext")?;
    let uncompressed_n = r.u32be("attach_head.n")?;
    let content_sha256: [u8; 32] =
        r.take(32, "attach_head.sha256")?
            .try_into()
            .map_err(|_| WireError::Truncated {
                at: "attach_head.sha256",
            })?;
    // The caption tail and the inline blob are both lp-prefixed; the tail
    // is present only when the next length prefix does not itself consume
    // the rest as the inline blob (peek-based disambiguation).
    let n = uncompressed_n as usize;
    let mut caption = String::new();
    let mut flags = 0u8;
    let inline = {
        let peek = r.peek_u32be("attach_head.inline")? as usize;
        if peek == n && r.remaining() == 4 + peek {
            r.u32be("attach_head.inline")?;
            r.take(peek, "attach_head.inline")?.to_vec()
        } else {
            // It was the caption length.
            let cap_len = r.u32be("attach_head.caption")? as usize;
            if cap_len > MAX_CAPTION {
                return Err(WireError::BadLength {
                    at: "attach_head.caption",
                    len: cap_len as u64,
                    max: MAX_CAPTION as u64,
                });
            }
            let cap_bytes = r.take(cap_len, "attach_head.caption")?;
            caption = String::from_utf8(cap_bytes.to_vec()).map_err(|_| WireError::BadField {
                at: "attach_head.caption",
                detail: "invalid utf-8".into(),
            })?;
            let peek2 = r.peek_u32be("attach_head.inline")? as usize;
            if peek2 == n && r.remaining() == 4 + peek2 {
                r.u32be("attach_head.inline")?;
                r.take(peek2, "attach_head.inline")?.to_vec()
            } else {
                // lp caption, u8 flags, lp inline.
                flags = r.u8("attach_head.flags")?;
                let inline_len = r.u32be("attach_head.inline")? as usize;
                if inline_len != n || r.remaining() != inline_len {
                    return Err(WireError::BadLength {
                        at: "attach_head.inline",
                        len: inline_len as u64,
                        max: n as u64,
                    });
                }
                r.take(inline_len, "attach_head.inline")?.to_vec()
            }
        }
    };
    let head = AttachHead {
        media_class,
        mime_hint,
        orig_ext,
        uncompressed_n,
        chunk_count: 0,
        chunk_bucket: 0,
        caption,
        flags,
        content_sha256,
    };
    head.validate_common()?;
    Ok((head, Some(inline)))
}

/// The envelope-level ATTACH_HEAD body: the head plus its inline bytes
/// when the v2 (whole-file) form is used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachHeadPayload {
    pub head: AttachHead,
    pub inline: Option<Vec<u8>>,
}

impl WirePayload for AttachHeadPayload {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        match &self.inline {
            Some(bytes) => self.head.encode_inline(bytes),
            None => self.head.encode_chunked(),
        }
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let (head, inline) = AttachHead::decode_with_inline(bytes)?;
        Ok(Self { head, inline })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachChunk {
    pub head_id: [u8; 16],
    pub index: u16,
    /// Padding chunk: carries no data, exists only to fill the bucket plan.
    pub pad: bool,
    pub data: Vec<u8>,
}

impl WirePayload for AttachChunk {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        if self.data.len() > CHUNK_DATA_MAX {
            return Err(WireError::TooLarge {
                at: "attach_chunk.data",
                size: self.data.len(),
                max: CHUNK_DATA_MAX,
            });
        }
        if self.pad && !self.data.is_empty() {
            return Err(WireError::BadField {
                at: "attach_chunk.pad",
                detail: "pad chunk carries data".into(),
            });
        }
        let mut w = Writer::new();
        w.raw(&self.head_id);
        w.u16be(self.index);
        w.u8(u8::from(self.pad));
        w.lp(&self.data);
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let head_id: [u8; 16] =
            r.take(16, "attach_chunk.head")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "attach_chunk.head",
                })?;
        let index = r.u16be("attach_chunk.index")?;
        let pad = match r.u8("attach_chunk.pad")? {
            0 => false,
            1 => true,
            other => {
                return Err(WireError::BadField {
                    at: "attach_chunk.pad",
                    detail: format!("{other}"),
                })
            }
        };
        let data = r.lp(CHUNK_DATA_MAX as u64, "attach_chunk.data")?.to_vec();
        r.expect_end("attach_chunk")?;
        if pad && !data.is_empty() {
            return Err(WireError::BadField {
                at: "attach_chunk.pad",
                detail: "pad chunk carries data".into(),
            });
        }
        Ok(Self {
            head_id,
            index,
            pad,
            data,
        })
    }
}
