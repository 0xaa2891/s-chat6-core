//! Wire decode error taxonomy. Every decode fails closed: any deviation
//! from the expected layout is an error, never a guess.

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Fewer bytes than the field requires.
    #[error("truncated {at}")]
    Truncated { at: &'static str },
    /// A length prefix is out of its allowed range.
    #[error("bad length for {at}: {len} (max {max})")]
    BadLength {
        at: &'static str,
        len: u64,
        max: u64,
    },
    /// A version byte this build does not speak.
    #[error("bad version for {at}: {version}")]
    BadVersion { at: &'static str, version: u8 },
    /// A field value outside its allowed set (flag, op, enum discriminant).
    #[error("bad field {at}: {detail}")]
    BadField { at: &'static str, detail: String },
    /// Bytes left over after the last field.
    #[error("trailing bytes in {at}: {extra}")]
    Trailing { at: &'static str, extra: usize },
    /// The whole payload exceeds its ceiling.
    #[error("oversize {at}: {size} (max {max})")]
    TooLarge {
        at: &'static str,
        size: usize,
        max: usize,
    },
    /// I7: an envelope type code this build does not know. Carries the
    /// envelope identity so the sync layer can log-and-count the drop
    /// without touching the session.
    #[error("unknown envelope type {code} (msg {msg_id:?} seq {app_seq})")]
    UnknownType {
        code: u8,
        msg_id: [u8; 16],
        app_seq: u64,
    },
}
