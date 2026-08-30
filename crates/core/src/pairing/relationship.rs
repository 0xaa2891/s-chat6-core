//! Relationship rows: the `relationships` table shape and its helpers.

use rusqlite::{params, Connection};

use super::PairingFailure;

pub struct Relationship {
    pub rel_id: String,
    pub role: String,
    pub state: String,
    pub service_id: String,
    pub onion: String,
    pub peer_onion: String,
    pub peer_identity_key: Vec<u8>,
    pub peer_client_auth_public: String,
    pub our_client_auth_private: String,
    pub our_nonce: [u8; 32],
    pub peer_nonce: [u8; 32],
    pub our_qr_bytes: Vec<u8>,
    pub intro_pending: bool,
    pub session_state: String,
    pub created_at: u64,
}

pub(crate) fn row_to_relationship(row: &rusqlite::Row) -> rusqlite::Result<Relationship> {
    let our_nonce: Vec<u8> = row.get("our_nonce")?;
    let peer_nonce: Vec<u8> = row.get("peer_nonce")?;
    Ok(Relationship {
        rel_id: row.get("rel_id")?,
        role: row.get("role")?,
        state: row.get("state")?,
        service_id: row.get("service_id")?,
        onion: row.get("onion")?,
        peer_onion: row.get("peer_onion")?,
        peer_identity_key: row.get("peer_identity_key")?,
        peer_client_auth_public: row.get("peer_client_auth_public")?,
        our_client_auth_private: row.get("our_client_auth_private")?,
        our_nonce: our_nonce.try_into().unwrap_or([0u8; 32]),
        peer_nonce: peer_nonce.try_into().unwrap_or([0u8; 32]),
        our_qr_bytes: row.get("our_qr_bytes")?,
        intro_pending: row.get::<_, i64>("intro_pending")? != 0,
        session_state: row.get("session_state")?,
        created_at: row.get::<_, i64>("created_at")? as u64,
    })
}

pub(crate) const RELATIONSHIP_COLS: &str = "rel_id, role, state, service_id, onion, peer_onion,
    peer_identity_key, peer_client_auth_public, our_client_auth_private,
    our_nonce, peer_nonce, our_qr_bytes, intro_pending,
    session_state, created_at";

pub fn load_relationship(
    db: &Connection,
    rel_id: &str,
) -> Result<Option<Relationship>, PairingFailure> {
    let mut stmt = db.prepare(&format!(
        "SELECT {RELATIONSHIP_COLS} FROM relationships WHERE rel_id = ?1"
    ))?;
    let mut rows = stmt.query_map(params![rel_id], row_to_relationship)?;
    Ok(rows.next().transpose()?)
}

pub(crate) fn load_relationship_by_service(
    db: &Connection,
    service_id: &str,
) -> Result<Option<Relationship>, PairingFailure> {
    let mut stmt = db.prepare(&format!(
        "SELECT {RELATIONSHIP_COLS} FROM relationships WHERE service_id = ?1"
    ))?;
    let mut rows = stmt.query_map(params![service_id], row_to_relationship)?;
    Ok(rows.next().transpose()?)
}

/// Every relationship, oldest first (contact list, broadcast loops).
pub fn list_relationships(db: &Connection) -> Result<Vec<Relationship>, PairingFailure> {
    let mut stmt = db.prepare(&format!(
        "SELECT {RELATIONSHIP_COLS} FROM relationships ORDER BY created_at ASC"
    ))?;
    let rows = stmt.query_map([], row_to_relationship)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// The accepter's intro rides outbound frames until the inviter's
/// first frame lands; call when that happens.
pub fn clear_intro_pending(db: &Connection, rel_id: &str) -> Result<(), PairingFailure> {
    db.execute(
        "UPDATE relationships SET intro_pending = 0 WHERE rel_id = ?1",
        params![rel_id],
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn insert_relationship(
    db: &Connection,
    rel_id: &str,
    role: &str,
    state: &str,
    service_id: &str,
    onion: &str,
    peer_onion: &str,
    peer_identity_key: &[u8],
    peer_client_auth_public: &str,
    our_client_auth_private: &str,
    our_nonce: &[u8; 32],
    peer_nonce: &[u8; 32],
    our_qr_bytes: &[u8],
    intro_pending: bool,
    now: u64,
) -> Result<(), PairingFailure> {
    // Bounds gate: total relationships are bounded. The
    // peer-driven path (request ingest) is additionally capped by
    // `MAX_PENDING_REQUESTS` before it gets here.
    let total = db.query_row("SELECT COUNT(*) FROM relationships", [], |r| {
        r.get::<_, u32>(0)
    })?;
    if total >= crate::limits::pairing::MAX_RELATIONSHIPS {
        return Err(PairingFailure::CapReached(format!(
            "relationships ({})",
            crate::limits::pairing::MAX_RELATIONSHIPS
        )));
    }
    db.execute(
        "INSERT INTO relationships (
            rel_id, role, state, service_id, onion, peer_onion,
            peer_identity_key, peer_client_auth_public, our_client_auth_private,
            our_nonce, peer_nonce, our_qr_bytes, intro_pending,
            session_state, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'active', ?14)",
        params![
            rel_id,
            role,
            state,
            service_id,
            onion,
            peer_onion,
            peer_identity_key,
            peer_client_auth_public,
            our_client_auth_private,
            our_nonce.as_slice(),
            peer_nonce.as_slice(),
            our_qr_bytes,
            intro_pending as i64,
            now as i64,
        ],
    )?;
    Ok(())
}
