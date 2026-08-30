//! `CHAT_POLICY` payload. Fixed 28-byte payload.
//!
//! Per-chat rules change only via PROPOSE + ACCEPT; capability wants are
//! one-to-disable, two-to-enable. Flag bits and cap ids are numbered
//! densely.
//!
//! This module is the codec only; the mutual-accept state machine lives
//! core-side.

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

pub const VERSION: u8 = 1;

pub const OP_RULE_PROPOSE: u8 = 1;
pub const OP_RULE_ACCEPT: u8 = 2;
pub const OP_CAP_SET: u8 = 3;
pub const OP_SYNC: u8 = 4;

pub const FLAG_SCREENSHOT: u32 = 1 << 0;
pub const FLAG_ATTACH_DL: u32 = 1 << 1;
pub const FLAG_WANT_ATTACH: u32 = 1 << 2;
pub const FLAG_WANT_EMOJI: u32 = 1 << 3;
pub const FLAG_WANT_PRESENCE: u32 = 1 << 4;
pub const FLAG_WANT_TYPING: u32 = 1 << 5;
pub const FLAG_WANT_RECEIPTS: u32 = 1 << 6;

/// Cap ids for `OP_CAP_SET`.
pub const CAP_ID_ATTACH: u8 = 0;
pub const CAP_ID_EMOJI: u8 = 1;
pub const CAP_ID_PRESENCE: u8 = 2;
pub const CAP_ID_TYPING: u8 = 3;
pub const CAP_ID_RECEIPTS: u8 = 4;
pub const CAP_ID_MAX: u8 = CAP_ID_RECEIPTS;

/// Message TTL options: the wire/storage
/// sentinel `TTL_NEVER` means messages do not expire.
pub const TTL_1H: u32 = 3_600;
pub const TTL_6H: u32 = 21_600;
pub const TTL_12H: u32 = 43_200;
pub const TTL_24H: u32 = 86_400;
pub const TTL_3D: u32 = 259_200;
pub const TTL_7D: u32 = 604_800;
pub const TTL_14D: u32 = 1_209_600;
pub const TTL_NEVER: u32 = 0;

pub const TTL_OPTIONS: [u32; 8] = [
    TTL_1H, TTL_6H, TTL_12H, TTL_24H, TTL_3D, TTL_7D, TTL_14D, TTL_NEVER,
];

pub fn is_allowed_ttl(ttl: u32) -> bool {
    TTL_OPTIONS.contains(&ttl)
}

pub fn cap_bit(cap_id: u8) -> u32 {
    match cap_id {
        CAP_ID_ATTACH => FLAG_WANT_ATTACH,
        CAP_ID_EMOJI => FLAG_WANT_EMOJI,
        CAP_ID_PRESENCE => FLAG_WANT_PRESENCE,
        CAP_ID_TYPING => FLAG_WANT_TYPING,
        CAP_ID_RECEIPTS => FLAG_WANT_RECEIPTS,
        _ => 0,
    }
}

pub fn cap_id_of(bit: u32) -> Option<u8> {
    match bit {
        FLAG_WANT_ATTACH => Some(CAP_ID_ATTACH),
        FLAG_WANT_EMOJI => Some(CAP_ID_EMOJI),
        FLAG_WANT_PRESENCE => Some(CAP_ID_PRESENCE),
        FLAG_WANT_TYPING => Some(CAP_ID_TYPING),
        FLAG_WANT_RECEIPTS => Some(CAP_ID_RECEIPTS),
        _ => None,
    }
}

pub const SIZE: usize = 1 + 1 + 4 + 4 + 1 + 1 + 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatPolicy {
    pub op: u8,
    pub ttl_sec: u32,
    pub screenshot: bool,
    pub attach_download: bool,
    pub want_attach: bool,
    pub want_emoji: bool,
    pub want_presence: bool,
    pub want_typing: bool,
    pub want_receipts: bool,
    pub cap_id: u8,
    pub cap_on: bool,
    pub propose_id: [u8; 16],
}

impl ChatPolicy {
    fn flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.screenshot {
            flags |= FLAG_SCREENSHOT;
        }
        if self.attach_download {
            flags |= FLAG_ATTACH_DL;
        }
        if self.want_attach {
            flags |= FLAG_WANT_ATTACH;
        }
        if self.want_emoji {
            flags |= FLAG_WANT_EMOJI;
        }
        if self.want_presence {
            flags |= FLAG_WANT_PRESENCE;
        }
        if self.want_typing {
            flags |= FLAG_WANT_TYPING;
        }
        if self.want_receipts {
            flags |= FLAG_WANT_RECEIPTS;
        }
        flags
    }

    fn validate(&self) -> Result<(), WireError> {
        if !(OP_RULE_PROPOSE..=OP_SYNC).contains(&self.op) {
            return Err(WireError::BadField {
                at: "policy.op",
                detail: format!("op {}", self.op),
            });
        }
        if self.op != OP_CAP_SET && !is_allowed_ttl(self.ttl_sec) {
            return Err(WireError::BadField {
                at: "policy.ttl_sec",
                detail: format!("ttl {} not in options", self.ttl_sec),
            });
        }
        if self.op == OP_CAP_SET && self.cap_id > CAP_ID_MAX {
            return Err(WireError::BadField {
                at: "policy.cap_id",
                detail: format!("cap id {}", self.cap_id),
            });
        }
        Ok(())
    }
}

impl WirePayload for ChatPolicy {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        let mut w = Writer::with_capacity(SIZE);
        w.u8(VERSION);
        w.u8(self.op);
        w.u32be(self.ttl_sec);
        w.u32be(self.flags());
        w.u8(self.cap_id);
        w.u8(u8::from(self.cap_on));
        w.raw(&self.propose_id);
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != SIZE {
            return Err(WireError::BadLength {
                at: "policy",
                len: bytes.len() as u64,
                max: SIZE as u64,
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u8("policy.version")?;
        if version != VERSION {
            return Err(WireError::BadVersion {
                at: "policy",
                version,
            });
        }
        let op = r.u8("policy.op")?;
        let ttl_sec = r.u32be("policy.ttl")?;
        let flags = r.u32be("policy.flags")?;
        let cap_id = r.u8("policy.cap_id")?;
        let cap_on = r.u8("policy.cap_on")?;
        if cap_on > 1 {
            return Err(WireError::BadField {
                at: "policy.cap_on",
                detail: format!("{cap_on}"),
            });
        }
        let propose_id: [u8; 16] =
            r.take(16, "policy.propose_id")?
                .try_into()
                .map_err(|_| WireError::Truncated {
                    at: "policy.propose_id",
                })?;
        r.expect_end("policy")?;
        let out = Self {
            op,
            ttl_sec,
            screenshot: flags & FLAG_SCREENSHOT != 0,
            attach_download: flags & FLAG_ATTACH_DL != 0,
            want_attach: flags & FLAG_WANT_ATTACH != 0,
            want_emoji: flags & FLAG_WANT_EMOJI != 0,
            want_presence: flags & FLAG_WANT_PRESENCE != 0,
            want_typing: flags & FLAG_WANT_TYPING != 0,
            want_receipts: flags & FLAG_WANT_RECEIPTS != 0,
            cap_id,
            cap_on: cap_on == 1,
            propose_id,
        };
        out.validate()?;
        Ok(out)
    }
}
