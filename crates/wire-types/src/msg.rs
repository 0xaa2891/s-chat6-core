//! `MSG` payload: the message body as raw UTF-8, nothing else. Reply
//! targets ride in the envelope's `ref_id`, not here.

use crate::error::WireError;
use crate::WirePayload;

// Cap declared in the bounds catalog; re-exported so
// `msg::MAX_BODY_BYTES` keeps working.
pub use crate::limits::msg::MAX_BODY_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Msg {
    pub body: String,
}

impl Msg {
    pub fn new(body: String) -> Result<Self, WireError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(WireError::TooLarge {
                at: "msg.body",
                size: body.len(),
                max: MAX_BODY_BYTES,
            });
        }
        Ok(Self { body })
    }
}

impl WirePayload for Msg {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        if self.body.len() > MAX_BODY_BYTES {
            return Err(WireError::TooLarge {
                at: "msg.body",
                size: self.body.len(),
                max: MAX_BODY_BYTES,
            });
        }
        Ok(self.body.as_bytes().to_vec())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_BODY_BYTES {
            return Err(WireError::TooLarge {
                at: "msg.body",
                size: bytes.len(),
                max: MAX_BODY_BYTES,
            });
        }
        // Strict UTF-8: invalid sequences fail closed (no lossy
        // replacement).
        let body = String::from_utf8(bytes.to_vec()).map_err(|_| WireError::BadField {
            at: "msg.body",
            detail: "invalid utf-8".into(),
        })?;
        Ok(Self { body })
    }
}
