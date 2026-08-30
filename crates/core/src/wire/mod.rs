//! `wire/` — frame encode/decode, padding, alert flags, inner payload
//! codecs.
//!
//! - [`frame`]: the outer record — fixed buckets, CSPRNG padding, version
//!   byte + u16 length. Fail closed before crypto.
//! - [`envelope`]: the inner payload enum (17 kept types) plus the I7
//!   unknown-type drop counter. The typed structs themselves live in the
//!   platform-agnostic `schat-wire-types` crate; feature modules import
//!   from there only.
//!
//! No serde. No compression of ciphertext.

pub mod envelope;
pub mod frame;
