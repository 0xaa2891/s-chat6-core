//! `READ` payload: empty. The receipt target rides in the envelope's
//! `ref_id`. Opt-in via chat policy; the wire type
//! exists so the envelope round-trips.

use crate::error::WireError;
use crate::WirePayload;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Read;

impl WirePayload for Read {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        Ok(Vec::new())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        super::delete::decode_empty(bytes, "read")?;
        Ok(Self)
    }
}
