//! `DELETE` / `DELETE_ALL` payloads: both are empty. DELETE's target rides
//! in the envelope's `ref_id`; DELETE_ALL scopes to the whole relationship.
//! Both are best-effort requests with honest copy semantics; tombstone
//! behavior is owned core-side.

use crate::error::WireError;
use crate::WirePayload;

/// Every payload-less envelope body decodes through this gate: any byte at
/// all is a protocol violation (fail closed).
pub(crate) fn decode_empty(bytes: &[u8], at: &'static str) -> Result<(), WireError> {
    if !bytes.is_empty() {
        return Err(WireError::TooLarge {
            at,
            size: bytes.len(),
            max: 0,
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Delete;

impl WirePayload for Delete {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        Ok(Vec::new())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        decode_empty(bytes, "delete")?;
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeleteAll;

impl WirePayload for DeleteAll {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        Ok(Vec::new())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        decode_empty(bytes, "delete_all")?;
        Ok(Self)
    }
}
