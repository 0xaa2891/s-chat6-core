//! Onion service hosting via `ADD_ONION` (ephemeral control-port
//! services, no torrc `HiddenServiceDir` model).
//!
//! Services are ephemeral control-port services with **persisted key blobs**:
//! the `ED25519-V3:<base64>` blob tor returns on first creation is stored in
//! the [`KeyStore`] and re-added on every boot. The control-port reply *is*
//! the hostname — no `hostname` file, no `FileObserver` races.
//!
//! Restricted discovery uses v3 client authorization: `ClientAuthV3=<base32
//! x25519 public key>` on `ADD_ONION` (service side), and
//! `$host.auth_private` files in a managed `ClientOnionAuthDir` plus
//! `SIGNAL RELOAD` on the client side.

mod address;
mod client_auth;
mod keygen;
mod keystore;
mod manager;
mod torrc;

pub use address::{
    hostname_from_pubkey, hostname_from_raw, normalize_hostname, pubkey_from_hostname,
    raw_from_hostname, ONION_HOSTNAME_LEN, ONION_RAW_BYTES, ONION_VERSION,
};
pub use client_auth::{decode_client_auth_key, write_client_auth_file, ClientAuthKeys};
pub use keygen::{generate_v3_key_blob, hostname_from_key_blob, key_blob_from_seed};
pub use keystore::{FileKeyStore, KeyStore};
pub use manager::{HostedService, OnionServiceManager, ONION_KEY_PREFIX};
pub use torrc::{base_torrc, TorrcParams};

#[cfg(test)]
mod tests;

/// Tor's hidden-service virtual port.
pub const VIRTUAL_PORT: u16 = 80;
