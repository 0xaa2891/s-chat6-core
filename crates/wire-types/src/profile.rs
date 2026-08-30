//! `PROFILE` / `PROFILE_REQ` payloads.
//!
//! PROFILE carries a display name + an already-compressed JPEG (media
//! preparation happens core-side). PROFILE_REQ is
//! empty — the opt-in share/request/accept flow lives core-side.

use unicode_normalization::UnicodeNormalization;

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

pub const VERSION: u8 = 1;

// Caps declared in the bounds catalog.
pub use crate::limits::profile::{MAX_JPEG, MAX_NAME_BYTES};

/// NFC-normalized, 1..=32 UTF-8 bytes, no ISO control
/// characters.
pub fn name_ok(raw: &str) -> bool {
    let nfc: String = raw.nfc().collect();
    if nfc != raw {
        return false;
    }
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NAME_BYTES {
        return false;
    }
    !raw.chars().any(|c| c.is_control())
}

/// Trim, NFC, validate. `None` when unusable.
pub fn normalize_name(raw: &str) -> Option<String> {
    let nfc: String = raw.trim().nfc().collect();
    name_ok(&nfc).then_some(nfc)
}

fn jpeg_ok(jpeg: &[u8]) -> bool {
    jpeg.is_empty() || (jpeg.len() >= 3 && jpeg[0] == 0xff && jpeg[1] == 0xd8)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Profile {
    pub name: String,
    pub jpeg: Vec<u8>,
}

impl WirePayload for Profile {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        if !name_ok(&self.name) {
            return Err(WireError::BadField {
                at: "profile.name",
                detail: "name fails nfc/length/control rules".into(),
            });
        }
        if self.jpeg.len() > MAX_JPEG {
            return Err(WireError::TooLarge {
                at: "profile.jpeg",
                size: self.jpeg.len(),
                max: MAX_JPEG,
            });
        }
        if !jpeg_ok(&self.jpeg) {
            return Err(WireError::BadField {
                at: "profile.jpeg",
                detail: "bad jpeg magic".into(),
            });
        }
        let mut w = Writer::new();
        w.u8(VERSION);
        w.lp(self.name.as_bytes());
        w.lp(&self.jpeg);
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("profile.version")?;
        if version != VERSION {
            return Err(WireError::BadVersion {
                at: "profile",
                version,
            });
        }
        let name_bytes = r.lp(MAX_NAME_BYTES as u64, "profile.name")?;
        let name = String::from_utf8(name_bytes.to_vec()).map_err(|_| WireError::BadField {
            at: "profile.name",
            detail: "invalid utf-8".into(),
        })?;
        if !name_ok(&name) {
            return Err(WireError::BadField {
                at: "profile.name",
                detail: "name fails nfc/length/control rules".into(),
            });
        }
        let jpeg = r.lp(MAX_JPEG as u64, "profile.jpeg")?.to_vec();
        r.expect_end("profile")?;
        if !jpeg_ok(&jpeg) {
            return Err(WireError::BadField {
                at: "profile.jpeg",
                detail: "bad jpeg magic".into(),
            });
        }
        Ok(Self { name, jpeg })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProfileReq;

impl WirePayload for ProfileReq {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        Ok(Vec::new())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        super::delete::decode_empty(bytes, "profile_req")?;
        Ok(Self)
    }
}
