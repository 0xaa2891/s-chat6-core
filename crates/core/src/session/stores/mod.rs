//! libsignal store traits over SQLCipher.
//!
//! Every relationship is its own persona: identity key pair, registration
//! id, pre-keys, session, and the peer's pinned identity all live under a
//! per-relationship `namespace` (the relationship id hex; `"pending"` for
//! the single outstanding invitation). There is no global identity.
//!
//! The traits are `async_trait(?Send)` over a synchronous rusqlite
//! connection, so each trait gets its own lightweight handle struct —
//! `message_encrypt` takes `&mut dyn SessionStore` and `&mut dyn
//! IdentityKeyStore` in the same call, which rules out one struct
//! implementing both behind a single `&mut`.

mod identity;
mod prekey;
mod session;

pub use identity::SqliteIdentityStore;
pub use prekey::{SqliteKyberPreKeyStore, SqlitePreKeyStore, SqliteSignedPreKeyStore};
pub use session::SqliteSessionStore;

#[cfg(test)]
mod tests;

use libsignal_protocol::IdentityKeyPair;
use libsignal_protocol::SignalProtocolError;
use rusqlite::{params, Connection};

/// Namespace of the single outstanding invitation persona.
pub const PENDING_NAMESPACE: &str = "pending";

/// Every table keyed by `namespace` (the persona's state spread).
const NAMESPACED_TABLES: [&str; 6] = [
    "signal_locals",
    "signal_identities",
    "signal_sessions",
    "signal_prekeys",
    "signal_signed_prekeys",
    "signal_kyber_prekeys",
];

pub(crate) fn store_err(context: &'static str) -> impl Fn(rusqlite::Error) -> SignalProtocolError {
    move |e| SignalProtocolError::InvalidState(context, format!("sqlite: {e}"))
}

pub(crate) fn corrupt(
    context: &'static str,
    detail: impl std::fmt::Display,
) -> SignalProtocolError {
    SignalProtocolError::InvalidState(context, format!("corrupt row: {detail}"))
}

// ---------------------------------------------------------------------------
// Local persona (identity key pair + registration id) — not a libsignal
// trait, but the backing for IdentityKeyStore's own-identity methods.

pub fn create_local(
    db: &Connection,
    namespace: &str,
    registration_id: u32,
    keypair: &IdentityKeyPair,
) -> Result<(), SignalProtocolError> {
    db.execute(
        "INSERT INTO signal_locals (namespace, registration_id, identity_keypair)
         VALUES (?1, ?2, ?3)",
        params![namespace, registration_id, keypair.serialize().as_ref()],
    )
    .map_err(store_err("create_local"))?;
    Ok(())
}

/// Move every namespaced row (persona, pre-keys, sessions, identities)
/// to a new namespace. Used when the pending invitation becomes a real
/// relationship on intro arrival.
pub fn migrate_namespace(db: &Connection, from: &str, to: &str) -> Result<(), SignalProtocolError> {
    for table in NAMESPACED_TABLES {
        db.execute(
            &format!("UPDATE {table} SET namespace = ?1 WHERE namespace = ?2"),
            params![to, from],
        )
        .map_err(store_err("migrate_namespace"))?;
    }
    Ok(())
}

pub fn delete_namespace(db: &Connection, namespace: &str) -> Result<(), SignalProtocolError> {
    for table in NAMESPACED_TABLES {
        db.execute(
            &format!("DELETE FROM {table} WHERE namespace = ?1"),
            params![namespace],
        )
        .map_err(store_err("delete_namespace"))?;
    }
    Ok(())
}
