//! Inviter request bucket and safety-code lookup.
//!
//! Accepting a request is the protocol action (restrict the invitation
//! service to the peer, mark the relationship active). Safety codes are
//! computed for display; they are not a pairing gate.

use std::sync::Arc;

use rusqlite::{params, Connection};
use tracing::info;

use crate::transport::Transport;

use super::relationship::{load_relationship, row_to_relationship, RELATIONSHIP_COLS};
use super::{our_identity_key, sas, PairingFailure, STATE_ACTIVE, STATE_REQUEST};

/// The 8-digit safety code for a relationship, recomputed from the stored
/// pairing payloads. Display-only — pairing does not wait on a compare.
pub fn sas_for(db: &Connection, rel_id: &str) -> Result<String, PairingFailure> {
    let row = load_relationship(db, rel_id)?.ok_or(PairingFailure::NotFound)?;
    let our_ik = our_identity_key(db, &row.rel_id)?;
    Ok(sas::sas(
        &our_ik,
        &row.our_nonce,
        &row.peer_identity_key,
        &row.peer_nonce,
    ))
}

/// Inviter accepts a relationship in `request` state: our service becomes
/// restricted to the peer's client-auth key and the row goes active.
pub async fn accept_request(
    db: &Connection,
    transport: &Arc<Transport>,
    rel_id: &str,
) -> Result<(), PairingFailure> {
    let row = load_relationship(db, rel_id)?.ok_or(PairingFailure::NotFound)?;
    if row.state != STATE_REQUEST {
        return Err(PairingFailure::NotARequest);
    }
    transport
        .host_service_with_auth(
            &row.service_id,
            std::slice::from_ref(&row.peer_client_auth_public),
        )
        .await?;
    db.execute(
        "UPDATE relationships SET state = ?2 WHERE rel_id = ?1",
        params![rel_id, STATE_ACTIVE],
    )?;
    info!(rel_id, "request accepted; service restricted to peer");
    Ok(())
}

pub struct RequestInfo {
    pub rel_id: String,
    pub sas: String,
    pub peer_onion: String,
    pub created_at: u64,
}

/// Incoming message requests awaiting acceptance (the inviter's bucket).
pub fn pending_requests(db: &Connection) -> Result<Vec<RequestInfo>, PairingFailure> {
    let mut stmt = db.prepare(&format!(
        "SELECT {RELATIONSHIP_COLS} FROM relationships WHERE state = ?1 ORDER BY created_at"
    ))?;
    let rows = stmt.query_map(params![STATE_REQUEST], row_to_relationship)?;
    let mut out = Vec::new();
    for row in rows {
        let row = row?;
        out.push(RequestInfo {
            sas: sas_for(db, &row.rel_id)?,
            rel_id: row.rel_id,
            peer_onion: row.peer_onion,
            created_at: row.created_at,
        });
    }
    Ok(out)
}
