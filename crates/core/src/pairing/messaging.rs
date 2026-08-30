//! Outbound messaging and service restore after a restart.

use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::Connection;

use crate::session::{self, SessionError};
use crate::transport::{framing, Transport};

use super::offer::load_pending;
use super::relationship::{load_relationship, row_to_relationship, RELATIONSHIP_COLS};
use super::{PairingFailure, ROLE_INVITER, STATE_REQUEST};

/// Encrypt and send one application payload to a relationship. While
/// `intro_pending` our signed pairing payload rides as the transport intro
/// (cleared once the peer answers — see `session::decrypt`).
pub async fn send_message(
    db: &Connection,
    transport: &Arc<Transport>,
    rel_id: &str,
    msg_id: &str,
    plaintext: &[u8],
    alert: bool,
    now: SystemTime,
) -> Result<(), PairingFailure> {
    let row = load_relationship(db, rel_id)?.ok_or(PairingFailure::NotFound)?;
    if row.session_state == "broken" {
        return Err(PairingFailure::Session(SessionError::Broken(
            "relationship is broken".into(),
        )));
    }
    // Gate: the inviter cannot send until the request is accepted.
    if row.role == ROLE_INVITER && row.state == STATE_REQUEST {
        return Err(PairingFailure::NotARequest);
    }
    let frame = session::encrypt(db, rel_id, msg_id, plaintext, now).await?;
    let record = framing::build_record(&frame)?;
    let intro = row.intro_pending.then_some(row.our_qr_bytes);
    transport
        .send_record(&row.peer_onion, intro.as_deref(), &record, alert)
        .await?;
    Ok(())
}

/// Re-host every relationship service (plus a live pending offer) after a
/// restart. The CLI daemon and clients call this at boot.
pub async fn restore_services(
    db: &Connection,
    transport: &Arc<Transport>,
) -> Result<(), PairingFailure> {
    let mut stmt = db.prepare(&format!("SELECT {RELATIONSHIP_COLS} FROM relationships"))?;
    let rows = stmt.query_map([], row_to_relationship)?;
    for row in rows {
        let row = row?;
        // Inviter-side services are open until the request is accepted;
        // everything else is restricted to the peer.
        let auth = if row.state == STATE_REQUEST && row.role == ROLE_INVITER {
            Vec::new()
        } else {
            vec![row.peer_client_auth_public.clone()]
        };
        transport
            .host_service_with_auth(&row.service_id, &auth)
            .await?;
        transport
            .install_client_auth(&row.peer_onion, &row.our_client_auth_private)
            .await?;
    }
    if let Some(pending) = load_pending(db)? {
        transport.host_service(&pending.service_id, false).await?;
    }
    Ok(())
}
