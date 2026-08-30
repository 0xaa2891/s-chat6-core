//! v3 onion address codec, per rend-spec-v3:
//! `raw = pubkey ‖ checksum[2] ‖ 0x03`, base32-encoded.

use sha3::{Digest, Sha3_256};

use crate::transport::error::TransportError;

pub const ONION_RAW_BYTES: usize = 35;
pub const ONION_VERSION: u8 = 3;
pub const ONION_HOSTNAME_LEN: usize = 56;

pub(crate) fn base32_lower(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD
        .encode(bytes)
        .to_ascii_lowercase()
}

pub(crate) fn base32_decode(s: &str) -> Result<Vec<u8>, TransportError> {
    data_encoding::BASE32_NOPAD
        .decode(s.to_ascii_uppercase().as_bytes())
        .map_err(|e| TransportError::InvalidOnion(format!("base32: {e}")))
}

/// `pubkey[32] → 56-char hostname` (without `.onion`).
pub fn hostname_from_pubkey(pubkey: &[u8; 32]) -> String {
    let checksum = onion_checksum(pubkey);
    let mut raw = [0u8; ONION_RAW_BYTES];
    raw[..32].copy_from_slice(pubkey);
    raw[32] = checksum[0];
    raw[33] = checksum[1];
    raw[34] = ONION_VERSION;
    base32_lower(&raw)
}

fn onion_checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([ONION_VERSION]);
    let digest = h.finalize();
    [digest[0], digest[1]]
}

/// Validate and decode a v3 hostname (with or without `.onion`).
pub fn pubkey_from_hostname(hostname: &str) -> Result<[u8; 32], TransportError> {
    let host = hostname
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches(".onion")
        .to_string();
    if host.len() != ONION_HOSTNAME_LEN {
        return Err(TransportError::InvalidOnion(format!(
            "hostname length {} != {ONION_HOSTNAME_LEN}",
            host.len()
        )));
    }
    let raw = base32_decode(&host)?;
    if raw.len() != ONION_RAW_BYTES {
        return Err(TransportError::InvalidOnion(format!(
            "decoded length {} != {ONION_RAW_BYTES}",
            raw.len()
        )));
    }
    if raw[34] != ONION_VERSION {
        return Err(TransportError::InvalidOnion("bad version byte".into()));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[..32]);
    let checksum = onion_checksum(&pubkey);
    if checksum[0] != raw[32] || checksum[1] != raw[33] {
        return Err(TransportError::InvalidOnion("checksum mismatch".into()));
    }
    Ok(pubkey)
}

/// Normalize a hostname: trim, lowercase, ensure `.onion` suffix.
pub fn normalize_hostname(hostname: &str) -> Result<String, TransportError> {
    let host = hostname.trim().to_ascii_lowercase();
    let bare = host.trim_end_matches(".onion");
    pubkey_from_hostname(bare)?; // validate
    Ok(format!("{bare}.onion"))
}

/// Decode a hostname to the raw 35-byte v3 address (pairing payloads carry
/// the raw form).
pub fn raw_from_hostname(hostname: &str) -> Result<[u8; ONION_RAW_BYTES], TransportError> {
    let pubkey = pubkey_from_hostname(hostname)?;
    let checksum = onion_checksum(&pubkey);
    let mut raw = [0u8; ONION_RAW_BYTES];
    raw[..32].copy_from_slice(&pubkey);
    raw[32] = checksum[0];
    raw[33] = checksum[1];
    raw[34] = ONION_VERSION;
    Ok(raw)
}

/// Checked raw → hostname conversion (ports `OnionV3.toAddress`): the
/// checksum and version byte are verified, fail closed.
pub fn hostname_from_raw(raw: &[u8; ONION_RAW_BYTES]) -> Result<String, TransportError> {
    if raw[34] != ONION_VERSION {
        return Err(TransportError::InvalidOnion(
            "raw address: bad version".into(),
        ));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[..32]);
    let checksum = onion_checksum(&pubkey);
    if checksum[0] != raw[32] || checksum[1] != raw[33] {
        return Err(TransportError::InvalidOnion(
            "raw address: checksum mismatch".into(),
        ));
    }
    Ok(hostname_from_pubkey(&pubkey))
}
