//! Accept (accepter side — the only side that scans/pastes). Fail closed:
//! decode + full verification (expiry enforced) happen before anything is
//! written; any failure after resources are held cleans them up.

use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::Connection;
use tracing::info;

use crate::session::{self, stores};
use crate::store::hex_encode;
use crate::transport::onion::{self, ClientAuthKeys};
use crate::transport::Transport;

use super::offer::load_pending;
use super::qr::{self, PairingPayload};
use super::relationship::{insert_relationship, load_relationship};
use super::{
    b32, fresh_nonce, now_secs, sas, service_id_for, PairingFailure, ROLE_ACCEPTER, STATE_ACTIVE,
};

pub struct Accepted {
    pub rel_id: String,
    pub sas: String,
    pub peer_onion: String,
    pub onion: String,
}

pub async fn accept_code(
    db: &Connection,
    transport: &Arc<Transport>,
    code: &str,
    now: SystemTime,
) -> Result<Accepted, PairingFailure> {
    accept(db, transport, &qr::decode_code(code)?, now).await
}

/// Accept an offer. Fail closed: decode + full verification (expiry
/// enforced) happen before anything is written.
pub async fn accept(
    db: &Connection,
    transport: &Arc<Transport>,
    qr_bytes: &[u8],
    now: SystemTime,
) -> Result<Accepted, PairingFailure> {
    let payload = PairingPayload::decode(qr_bytes)?;
    payload.verify(now_secs(now), true)?;

    // Accepting our own outstanding offer is self-pairing: the accepter
    // persona is always fresh, so the give-away is the offer's identity
    // matching our pending invitation's (both would collide on rel_id in
    // one store). Fail closed.
    if let Some(pending) = load_pending(db)? {
        if let Ok(our_offer) = PairingPayload::decode(&pending.qr_bytes) {
            if our_offer.identity_key == payload.identity_key {
                return Err(PairingFailure::SelfPairing);
            }
        }
    }

    let persona = session::generate_persona()?;
    let our_ik = persona.identity.identity_key().serialize().to_vec();
    let rel_id = hex_encode(&sas::relationship_id(&our_ik, &payload.identity_key));
    if load_relationship(db, &rel_id)?.is_some() {
        return Err(PairingFailure::ContactExists);
    }

    let our_client_auth = ClientAuthKeys::generate();
    let our_nonce = fresh_nonce();
    let service_id = service_id_for(persona.identity.identity_key());
    let peer_onion = format!(
        "{}.onion",
        onion::hostname_from_raw(&payload.onion)
            .map_err(|e| qr::PairingError::Invalid(format!("onion: {e}")))?
    );

    // From here on we hold resources; any failure cleans up.
    let result = accept_inner(
        db,
        transport,
        &payload,
        &persona,
        &rel_id,
        &service_id,
        &peer_onion,
        &our_client_auth,
        our_nonce,
        now,
    )
    .await;
    if result.is_err() {
        let _ = transport.remove_service(&service_id).await;
        let _ = stores::delete_namespace(db, &rel_id);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn accept_inner(
    db: &Connection,
    transport: &Arc<Transport>,
    payload: &PairingPayload,
    persona: &session::Persona,
    rel_id: &str,
    service_id: &str,
    peer_onion: &str,
    our_client_auth: &ClientAuthKeys,
    our_nonce: [u8; 32],
    now: SystemTime,
) -> Result<Accepted, PairingFailure> {
    // Our service is restricted to the inviter's client-auth key from the
    // moment it exists (ports `authorizeClient` at accept time).
    let our_onion = transport
        .host_service_with_auth(service_id, &[b32(&payload.client_auth_public)])
        .await?;
    // Authenticate to the inviter's (currently open) service with our own
    // client-auth keypair; the inviter restricts to its public half when
    // accepting the request (ports `setClientAuth`).
    transport
        .install_client_auth(peer_onion, &our_client_auth.private_b32)
        .await?;

    session::store_persona(db, rel_id, persona).await?;
    session::process_bundle(db, rel_id, &payload.to_bundle()?, now).await?;

    let our_payload = PairingPayload::from_bundle(
        &session::persona_bundle(persona)?,
        onion::raw_from_hostname(&our_onion)?,
        our_client_auth.public_bytes()?,
        our_nonce,
        now_secs(now) + qr::OFFER_TTL_SECONDS,
    )?
    .sign(persona.identity.private_key())?;
    let our_qr_bytes = our_payload.encode();

    insert_relationship(
        db,
        rel_id,
        ROLE_ACCEPTER,
        STATE_ACTIVE,
        service_id,
        &our_onion,
        peer_onion,
        &payload.identity_key,
        &b32(&payload.client_auth_public),
        &our_client_auth.private_b32,
        &our_nonce,
        &payload.nonce,
        &our_qr_bytes,
        true, // intro rides on outbound frames until the inviter answers
        now_secs(now),
    )?;

    let sas = sas::sas(
        &persona.identity.identity_key().serialize(),
        &our_nonce,
        &payload.identity_key,
        &payload.nonce,
    );
    info!(rel_id, "pairing accepted");
    Ok(Accepted {
        rel_id: rel_id.to_string(),
        sas,
        peer_onion: peer_onion.to_string(),
        onion: our_onion,
    })
}
