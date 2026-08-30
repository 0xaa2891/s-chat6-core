//! `schat-wire-types` — the shared inner payload structs and their
//! hand-rolled codecs. Feature modules import payload types
//! from here only; nothing else defines wire shapes.
//!
//! Rules:
//!
//! - Hand-rolled codecs (u8/u16be/u32be/u64be, `lp` = u32be length
//!   prefix). **No serde on the wire.**
//! - No compression of ciphertext. Compress plaintext, then encrypt, then
//!   pad.
//! - Fail-closed decode: unknown version, wrong size, trailing bytes, or a
//!   field outside its allowed set is an error, never a guess.
//! - Unknown envelope *type codes* decode to [`WireError::UnknownType`] so
//!   the sync layer can drop-and-count without touching the session (I7).

pub mod attach;
pub mod bin;
pub mod caps;
pub mod contact;
pub mod delete;
pub mod edit;
pub mod envelope;
pub mod error;
pub mod limits;
pub mod msg;
pub mod policy;
pub mod pref;
pub mod presence;
pub mod profile;
pub mod read;
pub mod resync;
pub mod sticker;
pub mod typing;

pub use envelope::{Envelope, EnvelopeType, Payload, MAX_ENVELOPE_BYTES, MSG_ID_BYTES};
pub use error::WireError;

/// One typed envelope payload. `encode_payload` validates before writing
/// (fail closed on construction-time violations); `decode_payload` is
/// strict and bounded.
pub trait WirePayload: Sized {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError>;
    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError>;
}

/// Wire protocol version of this build (the inner-envelope layer; the
/// outer record version lives in `schat_core::wire::frame`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireVersion {
    pub major: u8,
    pub minor: u8,
}

pub const WIRE_VERSION: WireVersion = WireVersion { major: 7, minor: 0 };
