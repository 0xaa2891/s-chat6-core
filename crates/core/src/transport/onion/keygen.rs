//! Local v3 service keygen.
//!
//! Tor's `ED25519-V3` key blob is base64 of the 64-byte *expanded* secret
//! key: `SHA512(seed)` with the first half clamped per RFC 8032 (verified
//! against tor 0.4.9 on Chutney). Generating locally means the onion
//! address is known synchronously and `ADD_ONION` can wait until tor is
//! online — adding a service before tor has directory info gives it a
//! broken descriptor upload schedule (first upload deferred ~90 min).

use crate::transport::error::TransportError;

use super::address::hostname_from_pubkey;

/// Generate a fresh v3 service key. Returns `(blob_b64, hostname)` where
/// the blob is the base64 body persisted in the [`KeyStore`](super::KeyStore)
/// (the `ED25519-V3:` prefix is added at `ADD_ONION` time).
pub fn generate_v3_key_blob() -> (String, String) {
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
    key_blob_from_seed(&seed)
}

/// Deterministic keygen from a 32-byte seed (tests, future seed-backed
/// identity recovery).
pub fn key_blob_from_seed(seed: &[u8; 32]) -> (String, String) {
    use sha2::Digest as _;
    let h = sha2::Sha512::digest(seed);
    let mut expanded = [0u8; 64];
    expanded.copy_from_slice(&h);
    // RFC 8032 §5.1.5 clamping.
    expanded[0] &= 248;
    expanded[31] &= 63;
    expanded[31] |= 64;
    let hostname = hostname_from_expanded(&expanded);
    (data_encoding::BASE64.encode(&expanded), hostname)
}

/// Derive the bare hostname (no `.onion`) from a persisted key blob.
pub fn hostname_from_key_blob(blob_b64: &str) -> Result<String, TransportError> {
    let raw = data_encoding::BASE64
        .decode(blob_b64.as_bytes())
        .map_err(|e| TransportError::KeyStore(format!("bad v3 key blob: {e}")))?;
    let expanded: &[u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::KeyStore("v3 key blob must be 64 bytes".into()))?;
    Ok(hostname_from_expanded(expanded))
}

fn hostname_from_expanded(expanded: &[u8; 64]) -> String {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    let scalar_bytes: [u8; 32] = expanded[..32].try_into().expect("half of 64");
    // from_bytes_mod_order is exact here: the basepoint has order L, so
    // (a mod L)·B == a·B for the clamped scalar a.
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let pubkey = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    hostname_from_pubkey(&pubkey)
}
