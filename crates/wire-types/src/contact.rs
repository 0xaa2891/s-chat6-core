//! `CONTACT_CLOSE` payload: empty. The closing-state machine (honest
//! closing states, burn behavior) lives core-side; the wire carries only the
//! signal itself.

use crate::error::WireError;
use crate::WirePayload;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContactClose;

impl WirePayload for ContactClose {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        Ok(Vec::new())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        super::delete::decode_empty(bytes, "contact_close")?;
        Ok(Self)
    }
}
