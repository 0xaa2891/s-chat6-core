//! `EDIT` payload: the replacement body as raw UTF-8. The edit target is
//! the envelope's `ref_id`; the 1-hour edit window is a feature-layer
//! rule, not a wire property.

use crate::error::WireError;
use crate::msg::MAX_BODY_BYTES;
use crate::WirePayload;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    pub body: String,
}

impl Edit {
    pub fn new(body: String) -> Result<Self, WireError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(WireError::TooLarge {
                at: "edit.body",
                size: body.len(),
                max: MAX_BODY_BYTES,
            });
        }
        Ok(Self { body })
    }
}

impl WirePayload for Edit {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        if self.body.len() > MAX_BODY_BYTES {
            return Err(WireError::TooLarge {
                at: "edit.body",
                size: self.body.len(),
                max: MAX_BODY_BYTES,
            });
        }
        Ok(self.body.as_bytes().to_vec())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err(WireError::TooLarge {
                at: "edit.body",
                size: bytes.len(),
                max: MAX_BODY_BYTES,
            });
        }
        let body = String::from_utf8(bytes.to_vec()).map_err(|_| WireError::BadField {
            at: "edit.body",
            detail: "invalid utf-8".into(),
        })?;
        Ok(Self { body })
    }
}
