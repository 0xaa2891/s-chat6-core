//! Offer (inviter side): the pending invitation lifecycle — create, sweep,
//! abort. The 5-minute window is the access control: the invitation
//! service has no client auth until the request is accepted.

use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::{params, Connection};
use tracing::info;

use crate::session::{self, stores};
use crate::store::StoreError;
use crate::transport::onion::{self, ClientAuthKeys};
use crate::transport::Transport;

use super::qr::{self, PairingPayload};
use super::{fresh_nonce, now_secs, service_id_for, PairingFailure};

pub struct Offer {
    pub qr_bytes: Vec<u8>,
    /// The same payload as a Base58 one-time code (5-minute expiry).
    pub code: String,
    pub onion: String,
    pub expires_at: u64,
    /// The open invitation service id (derivable from the QR identity
    /// key; exposed so harnesses can address frames at the offer).
    pub service_id: String,
}

pub(crate) struct PendingRow {
    pub service_id: String,
    pub onion: String,
    pub qr_bytes: Vec<u8>,
    pub client_auth_private: String,
    pub expires_at: u64,
}

pub(crate) fn load_pending(db: &Connection) -> Result<Option<PendingRow>, PairingFailure> {
    let row = db
        .query_row(
            "SELECT service_id, onion, qr_bytes, client_auth_private, expires_at
             FROM pending_pairing WHERE id = 1",
            [],
            |r| {
                Ok(PendingRow {
                    service_id: r.get(0)?,
                    onion: r.get(1)?,
                    qr_bytes: r.get(2)?,
                    client_auth_private: r.get(3)?,
                    expires_at: r.get::<_, i64>(4)? as u64,
                })
            },
        )
        .ok();
    Ok(row)
}

async fn clear_pending(
    db: &Connection,
    transport: &Arc<Transport>,
    reason: &str,
) -> Result<(), PairingFailure> {
    if let Some(pending) = load_pending(db)? {
        info!(service_id = %pending.service_id, %reason, "clearing pending pairing");
        let _ = transport.remove_service(&pending.service_id).await;
        db.execute("DELETE FROM pending_pairing WHERE id = 1", [])?;
        stores::delete_namespace(db, stores::PENDING_NAMESPACE)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    }
    Ok(())
}

/// Sweep an expired offer: service removed, persona destroyed.
pub async fn sweep_expired(
    db: &Connection,
    transport: &Arc<Transport>,
    now: SystemTime,
) -> Result<(), PairingFailure> {
    let expired = load_pending(db)?
        .map(|p| p.expires_at <= now_secs(now))
        .unwrap_or(false);
    if expired {
        clear_pending(db, transport, "offer expired").await?;
    }
    Ok(())
}

/// Abort the outstanding offer (user cancelled).
pub async fn abort_offer(
    db: &Connection,
    transport: &Arc<Transport>,
) -> Result<(), PairingFailure> {
    clear_pending(db, transport, "offer aborted").await
}

/// Create a pairing offer: fresh persona, open invitation service, signed
/// payload.
pub async fn offer(
    db: &Connection,
    transport: &Arc<Transport>,
    now: SystemTime,
) -> Result<Offer, PairingFailure> {
    sweep_expired(db, transport, now).await?;
    clear_pending(db, transport, "replaced by new offer").await?;

    let persona = session::generate_persona()?;
    let client_auth = ClientAuthKeys::generate();
    let nonce = fresh_nonce();
    let service_id = service_id_for(persona.identity.identity_key());
    let onion = transport.host_service(&service_id, false).await?;
    let onion_raw = onion::raw_from_hostname(&onion)?;
    let expires_at = now_secs(now) + qr::OFFER_TTL_SECONDS;

    let payload = PairingPayload::from_bundle(
        &session::persona_bundle(&persona)?,
        onion_raw,
        client_auth.public_bytes()?,
        nonce,
        expires_at,
    )?
    .sign(persona.identity.private_key())?;
    let qr_bytes = payload.encode();

    session::store_persona(db, stores::PENDING_NAMESPACE, &persona).await?;
    db.execute(
        "INSERT INTO pending_pairing (id, service_id, onion, qr_bytes, client_auth_private, expires_at)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            service_id,
            onion,
            qr_bytes,
            client_auth.private_b32,
            expires_at as i64
        ],
    )?;
    info!(onion, expires_at, "pairing offer created");
    Ok(Offer {
        code: qr::encode_code(&qr_bytes),
        qr_bytes,
        onion,
        expires_at,
        service_id,
    })
}
