//! s//chat6 core: protocol, transport, store, media. Not an app.
//!
//! This crate is a **platformless library**. Clients bind it (UniFFI / `cdylib`)
//! from any supported language and OS. No `cfg(target_os)` here may change
//! protocol, crypto, or store behavior.

pub mod attach;
pub mod caps;
pub mod close;
pub mod engine;
mod ffi;
pub mod limits;
pub mod media;
pub mod messages;
pub mod pairing;
pub mod policy;
pub mod presence;
pub mod profile;
pub mod ratelimit;
pub mod session;
pub mod stickers;
pub mod store;
pub mod sync;
pub mod transport;
pub mod typing;
pub mod util;
pub mod vault;
pub mod wire;

/// The platform-agnostic wire payload structs (envelope types, sticker
/// docs, policy ops, limits). Clients use these; the core's `wire/`
/// module is only the frame/envelope codec.
pub use schat_wire_types as wire_types;

// The UniFFI surface (`SchatCore`, `SchatEvent`, `CoreError`, the FFI
// records) lives in `ffi/`, split by domain; re-exported flat so the
// bound API is `schat_core::*` either way.
pub use ffi::*;

uniffi::setup_scaffolding!();

/// Headless health check for the UniFFI boundary.
#[uniffi::export]
pub fn ping() -> String {
    "pong".to_string()
}

/// The pinned libsignal tag — clients check this against their build
/// config (surfaced over FFI so clients can check their build against it).
#[uniffi::export]
pub fn crypto_version() -> String {
    session::CRYPTO_VERSION.to_string()
}

#[cfg(test)]
mod tests {
    use super::ping;

    #[test]
    fn ping_returns_pong() {
        assert_eq!(ping(), "pong");
    }
}
