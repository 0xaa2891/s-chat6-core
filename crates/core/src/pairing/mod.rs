//! `pairing/` — the one-way invitation ceremony.
//!
//! One side offers: a signed pairing payload (libsignal pre-key bundle +
//! onion + restricted-discovery key + nonce + 5-minute expiry) rendered as
//! a QR matrix or copied as a Base58 one-time code. The other side
//! accepts — scans or pastes — and becomes the PQXDH initiator: it
//! processes the inviter's bundle, hosts its own restricted service, and
//! its first outbound frames carry the payload as a transport-level intro.
//! The inviter's instance
//! decrypts the intro frame, lands the relationship in the **requests**
//! bucket, and accepts it there — only one side ever scans or pastes.
//!
//! Fail closed: invalid fields, bad signatures, expired offers, and
//! self-pairing all abort with no partial state written.
//!
//! Submodule map: `relationship` (table rows), `offer` (inviter side),
//! `accept` (accepter side), `requests` (request bucket + safety codes), `ingest`
//! (inbound routing), `messaging` (outbound + service restore).

pub mod qr;
pub mod sas;

mod accept;
mod ingest;
mod messaging;
mod offer;
pub mod relationship;
mod requests;

pub use accept::{accept, accept_code, Accepted};
pub use ingest::{ingest_frame, Ingest};
pub use messaging::{restore_services, send_message};
#[cfg(test)]
pub(crate) use offer::load_pending;
pub use offer::{abort_offer, offer, sweep_expired, Offer};
pub use relationship::{load_relationship, Relationship};
pub use requests::{accept_request, pending_requests, sas_for, RequestInfo};

#[cfg(test)]
mod tests;

use std::time::SystemTime;

use rusqlite::params;
use thiserror::Error;

use crate::session::SessionError;
use crate::store::{hex_encode, StoreError};
use crate::transport::error::TransportError;

pub const ROLE_INVITER: &str = "inviter";
pub const ROLE_ACCEPTER: &str = "accepter";
pub const STATE_REQUEST: &str = "request";
pub const STATE_ACTIVE: &str = "active";

#[derive(Debug, Error)]
pub enum PairingFailure {
    #[error("{0}")]
    Payload(#[from] qr::PairingError),
    #[error("{0}")]
    Session(#[from] SessionError),
    #[error("{0}")]
    Transport(#[from] TransportError),
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("wire: {0}")]
    Wire(#[from] schat_wire_types::WireError),
    #[error("contact already exists")]
    ContactExists,
    #[error("cannot pair with our own offer")]
    SelfPairing,
    #[error("relationship not found")]
    NotFound,
    #[error("no pending request for this relationship")]
    NotARequest,
    /// A static bound from `limits::pairing` was hit.
    #[error("pairing cap reached: {0}")]
    CapReached(String),
}

pub(crate) fn now_secs(now: SystemTime) -> u64 {
    now.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn service_id_for(identity: &libsignal_protocol::IdentityKey) -> String {
    hex_encode(&identity.serialize())
}

pub(crate) fn fresh_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut nonce);
    nonce
}

pub(crate) fn b32(raw: &[u8; 32]) -> String {
    data_encoding::BASE32_NOPAD.encode(raw).to_ascii_lowercase()
}

pub(crate) fn our_identity_key(
    db: &rusqlite::Connection,
    namespace: &str,
) -> Result<Vec<u8>, PairingFailure> {
    let blob: Vec<u8> = db.query_row(
        "SELECT identity_keypair FROM signal_locals WHERE namespace = ?1",
        params![namespace],
        |r| r.get(0),
    )?;
    let keypair = libsignal_protocol::IdentityKeyPair::try_from(blob.as_slice())
        .map_err(|e| StoreError::Corrupt(format!("identity keypair: {e}")))?;
    Ok(keypair.identity_key().serialize().to_vec())
}
