//! v3 client authorization keys (x25519, rend-spec-v3 §G.1.2).

use std::path::{Path, PathBuf};

use crate::transport::error::TransportError;

use super::address::{base32_decode, base32_lower, ONION_HOSTNAME_LEN};

/// A client-auth keypair. The **public** half goes to the service operator
/// (`ClientAuthV3=` on `ADD_ONION`); the **private** half is written into the
/// client's `ClientOnionAuthDir` as a `.auth_private` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAuthKeys {
    /// base32 (lower, no pad) of the 32-byte x25519 public key.
    pub public_b32: String,
    /// base32 (lower, no pad) of the 32-byte x25519 private key.
    pub private_b32: String,
}

impl ClientAuthKeys {
    pub fn generate() -> Self {
        // x25519-dalek 2.x keys off rand_core 0.6; sample bytes with the
        // workspace rand (0.9) and import them instead of mixing rng traits.
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_bytes);
        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self {
            public_b32: base32_lower(public.as_bytes()),
            private_b32: base32_lower(secret.as_bytes()),
        }
    }

    pub fn public_bytes(&self) -> Result<[u8; 32], TransportError> {
        decode_client_auth_key(&self.public_b32)
    }
}

/// Decode a base32 client-auth key (either half) to its 32 raw bytes.
pub fn decode_client_auth_key(b32: &str) -> Result<[u8; 32], TransportError> {
    base32_decode(b32)?
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::KeyStore("client-auth key must be 32 bytes".into()))
}

/// Write `$host.auth_private` into `dir` (ports `writeClientAuth`).
/// Contents: `$host:descriptor:x25519:<base32 private>\n`.
pub fn write_client_auth_file(
    dir: &Path,
    hostname: &str,
    private_b32: &str,
) -> Result<PathBuf, TransportError> {
    let host = hostname
        .trim()
        .to_ascii_lowercase()
        .trim_end_matches(".onion")
        .to_string();
    if host.len() != ONION_HOSTNAME_LEN {
        return Err(TransportError::InvalidOnion(format!(
            "client-auth hostname length {} != {ONION_HOSTNAME_LEN}",
            host.len()
        )));
    }
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{host}.auth_private"));
    std::fs::write(&path, format!("{host}:descriptor:x25519:{private_b32}\n"))?;
    Ok(path)
}
