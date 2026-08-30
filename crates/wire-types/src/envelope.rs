//! The inner envelope: one
//! application message inside the libsignal ciphertext.
//!
//! Layout (all integers big-endian, `lp` = u32be length prefix):
//!
//! ```text
//! u8   type
//! 16B  msg_id
//! u64  app_seq
//! u64  sent_at
//! u8   ref_len (0 or 16)  ‖ ref bytes
//! lp   payload
//! ```
//!
//! The 17 types. Codes 12/13 are unassigned; the gap is preserved.
//! Unknown type codes decode to [`WireError::UnknownType`] — the sync
//! layer drops the envelope, increments a counter, and leaves the session
//! untouched (I7).

use crate::attach::{AttachChunk, AttachHeadPayload};
use crate::bin::{Reader, Writer};
use crate::contact::ContactClose;
use crate::delete::{Delete, DeleteAll};
use crate::edit::Edit;
use crate::error::WireError;
use crate::msg::Msg;
use crate::policy::ChatPolicy;
use crate::pref::Pref;
use crate::presence::Presence;
use crate::profile::{Profile, ProfileReq};
use crate::read::Read;
use crate::resync::ResyncReq;
use crate::sticker::{StickerCtrl, StickerItem};
use crate::typing::Typing;
use crate::WirePayload;

// Cap declared in the bounds catalog.
pub use crate::limits::envelope::MAX_ENVELOPE_BYTES;

pub const MSG_ID_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EnvelopeType {
    Msg,
    Edit,
    Delete,
    DeleteAll,
    ResyncReq,
    AttachHead,
    AttachChunk,
    ContactClose,
    Profile,
    Pref,
    ProfileReq,
    Sticker,
    StickerCtrl,
    Presence,
    ChatPolicy,
    Typing,
    Read,
}

impl EnvelopeType {
    /// Wire code. 12/13 are unassigned.
    pub fn code(self) -> u8 {
        match self {
            EnvelopeType::Msg => 1,
            EnvelopeType::Edit => 2,
            EnvelopeType::Delete => 3,
            EnvelopeType::DeleteAll => 4,
            EnvelopeType::ResyncReq => 5,
            EnvelopeType::AttachHead => 6,
            EnvelopeType::AttachChunk => 7,
            EnvelopeType::ContactClose => 8,
            EnvelopeType::Profile => 9,
            EnvelopeType::Pref => 10,
            EnvelopeType::ProfileReq => 11,
            EnvelopeType::Sticker => 14,
            EnvelopeType::StickerCtrl => 15,
            EnvelopeType::Presence => 16,
            EnvelopeType::ChatPolicy => 17,
            EnvelopeType::Typing => 18,
            EnvelopeType::Read => 19,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => EnvelopeType::Msg,
            2 => EnvelopeType::Edit,
            3 => EnvelopeType::Delete,
            4 => EnvelopeType::DeleteAll,
            5 => EnvelopeType::ResyncReq,
            6 => EnvelopeType::AttachHead,
            7 => EnvelopeType::AttachChunk,
            8 => EnvelopeType::ContactClose,
            9 => EnvelopeType::Profile,
            10 => EnvelopeType::Pref,
            11 => EnvelopeType::ProfileReq,
            14 => EnvelopeType::Sticker,
            15 => EnvelopeType::StickerCtrl,
            16 => EnvelopeType::Presence,
            17 => EnvelopeType::ChatPolicy,
            18 => EnvelopeType::Typing,
            19 => EnvelopeType::Read,
            _ => return None,
        })
    }
}

/// The typed payload union — one variant per kept envelope type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Msg(Msg),
    Edit(Edit),
    Delete(Delete),
    DeleteAll(DeleteAll),
    ResyncReq(ResyncReq),
    AttachHead(AttachHeadPayload),
    AttachChunk(AttachChunk),
    ContactClose(ContactClose),
    Profile(Profile),
    Pref(Pref),
    ProfileReq(ProfileReq),
    Sticker(StickerItem),
    StickerCtrl(StickerCtrl),
    Presence(Presence),
    ChatPolicy(ChatPolicy),
    Typing(Typing),
    Read(Read),
}

impl Payload {
    pub fn envelope_type(&self) -> EnvelopeType {
        match self {
            Payload::Msg(_) => EnvelopeType::Msg,
            Payload::Edit(_) => EnvelopeType::Edit,
            Payload::Delete(_) => EnvelopeType::Delete,
            Payload::DeleteAll(_) => EnvelopeType::DeleteAll,
            Payload::ResyncReq(_) => EnvelopeType::ResyncReq,
            Payload::AttachHead(_) => EnvelopeType::AttachHead,
            Payload::AttachChunk(_) => EnvelopeType::AttachChunk,
            Payload::ContactClose(_) => EnvelopeType::ContactClose,
            Payload::Profile(_) => EnvelopeType::Profile,
            Payload::Pref(_) => EnvelopeType::Pref,
            Payload::ProfileReq(_) => EnvelopeType::ProfileReq,
            Payload::Sticker(_) => EnvelopeType::Sticker,
            Payload::StickerCtrl(_) => EnvelopeType::StickerCtrl,
            Payload::Presence(_) => EnvelopeType::Presence,
            Payload::ChatPolicy(_) => EnvelopeType::ChatPolicy,
            Payload::Typing(_) => EnvelopeType::Typing,
            Payload::Read(_) => EnvelopeType::Read,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        match self {
            Payload::Msg(p) => p.encode_payload(),
            Payload::Edit(p) => p.encode_payload(),
            Payload::Delete(p) => p.encode_payload(),
            Payload::DeleteAll(p) => p.encode_payload(),
            Payload::ResyncReq(p) => p.encode_payload(),
            Payload::AttachHead(p) => p.encode_payload(),
            Payload::AttachChunk(p) => p.encode_payload(),
            Payload::ContactClose(p) => p.encode_payload(),
            Payload::Profile(p) => p.encode_payload(),
            Payload::Pref(p) => p.encode_payload(),
            Payload::ProfileReq(p) => p.encode_payload(),
            Payload::Sticker(p) => p.encode_payload(),
            Payload::StickerCtrl(p) => p.encode_payload(),
            Payload::Presence(p) => p.encode_payload(),
            Payload::ChatPolicy(p) => p.encode_payload(),
            Payload::Typing(p) => p.encode_payload(),
            Payload::Read(p) => p.encode_payload(),
        }
    }

    fn decode(t: EnvelopeType, bytes: &[u8]) -> Result<Self, WireError> {
        Ok(match t {
            EnvelopeType::Msg => Payload::Msg(Msg::decode_payload(bytes)?),
            EnvelopeType::Edit => Payload::Edit(Edit::decode_payload(bytes)?),
            EnvelopeType::Delete => Payload::Delete(Delete::decode_payload(bytes)?),
            EnvelopeType::DeleteAll => Payload::DeleteAll(DeleteAll::decode_payload(bytes)?),
            EnvelopeType::ResyncReq => Payload::ResyncReq(ResyncReq::decode_payload(bytes)?),
            EnvelopeType::AttachHead => {
                Payload::AttachHead(AttachHeadPayload::decode_payload(bytes)?)
            }
            EnvelopeType::AttachChunk => Payload::AttachChunk(AttachChunk::decode_payload(bytes)?),
            EnvelopeType::ContactClose => {
                Payload::ContactClose(ContactClose::decode_payload(bytes)?)
            }
            EnvelopeType::Profile => Payload::Profile(Profile::decode_payload(bytes)?),
            EnvelopeType::Pref => Payload::Pref(Pref::decode_payload(bytes)?),
            EnvelopeType::ProfileReq => Payload::ProfileReq(ProfileReq::decode_payload(bytes)?),
            EnvelopeType::Sticker => Payload::Sticker(StickerItem::decode_payload(bytes)?),
            EnvelopeType::StickerCtrl => Payload::StickerCtrl(StickerCtrl::decode_payload(bytes)?),
            EnvelopeType::Presence => Payload::Presence(Presence::decode_payload(bytes)?),
            EnvelopeType::ChatPolicy => Payload::ChatPolicy(ChatPolicy::decode_payload(bytes)?),
            EnvelopeType::Typing => Payload::Typing(Typing::decode_payload(bytes)?),
            EnvelopeType::Read => Payload::Read(Read::decode_payload(bytes)?),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub msg_id: [u8; MSG_ID_BYTES],
    pub app_seq: u64,
    /// Peer-controlled display metadata. The sync layer clamps it against
    /// the local time floor on ingest; never trust it for retention.
    pub sent_at: u64,
    pub ref_id: Option<[u8; MSG_ID_BYTES]>,
    pub payload: Payload,
}

impl Envelope {
    pub fn envelope_type(&self) -> EnvelopeType {
        self.payload.envelope_type()
    }

    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let payload = self.payload.encode()?;
        let mut w = Writer::with_capacity(1 + 16 + 8 + 8 + 1 + 4 + payload.len());
        w.u8(self.envelope_type().code());
        w.raw(&self.msg_id);
        w.u64be(self.app_seq);
        w.u64be(self.sent_at);
        match &self.ref_id {
            Some(r) => {
                w.u8(MSG_ID_BYTES as u8);
                w.raw(r);
            }
            None => w.u8(0),
        }
        w.lp(&payload);
        let out = w.finish();
        if out.len() > MAX_ENVELOPE_BYTES {
            return Err(WireError::TooLarge {
                at: "envelope",
                size: out.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(out)
    }

    /// Strict decode. Unknown type codes are [`WireError::UnknownType`]
    /// (I7 drop); every other deviation is a hard error.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(WireError::TooLarge {
                at: "envelope",
                size: bytes.len(),
                max: MAX_ENVELOPE_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let code = r.u8("envelope.type")?;
        let msg_id: [u8; MSG_ID_BYTES] = r
            .take(MSG_ID_BYTES, "envelope.msg_id")?
            .try_into()
            .map_err(|_| WireError::Truncated {
                at: "envelope.msg_id",
            })?;
        let app_seq = r.u64be("envelope.app_seq")?;
        let sent_at = r.u64be("envelope.sent_at")?;
        let ref_len = r.u8("envelope.ref_len")? as usize;
        let ref_id = match ref_len {
            0 => None,
            MSG_ID_BYTES => Some(
                r.take(MSG_ID_BYTES, "envelope.ref")?
                    .try_into()
                    .map_err(|_| WireError::Truncated { at: "envelope.ref" })?,
            ),
            other => {
                return Err(WireError::BadLength {
                    at: "envelope.ref",
                    len: other as u64,
                    max: MSG_ID_BYTES as u64,
                })
            }
        };
        let payload_bytes = r.lp(MAX_ENVELOPE_BYTES as u64, "envelope.payload")?;
        r.expect_end("envelope")?;
        let Some(t) = EnvelopeType::from_code(code) else {
            return Err(WireError::UnknownType {
                code,
                msg_id,
                app_seq,
            });
        };
        let payload = Payload::decode(t, payload_bytes)?;
        Ok(Self {
            msg_id,
            app_seq,
            sent_at,
            ref_id,
            payload,
        })
    }
}
