//! Inbound routing: one transport frame → relationship message, pairing
//! request, duplicate, or drop. This is the pairing inbound path; the
//! sync layer takes over routing (outbox ACKs, resync).

use std::sync::Arc;
use std::time::SystemTime;

use rusqlite::Connection;
use tracing::{info, warn};

use crate::session::{self, stores, SessionError};
use crate::store::{hex_encode, StoreError};
use crate::transport::onion;
use crate::transport::{framing, Transport};

use super::offer::{load_pending, PendingRow};
use super::qr::{self, PairingPayload};
use super::relationship::{insert_relationship, load_relationship, load_relationship_by_service};
use super::{b32, now_secs, our_identity_key, sas, PairingFailure, ROLE_INVITER, STATE_REQUEST};

#[derive(Debug)]
pub enum Ingest {
    /// A pairing intro arrived at our invitation service: new relationship
    /// in the requests bucket, first plaintext already decrypted.
    RequestReceived {
        rel_id: String,
        sas: String,
        plaintext: Vec<u8>,
    },
    Message {
        rel_id: String,
        plaintext: Vec<u8>,
    },
    /// Retransmission of an already-processed frame.
    Duplicate,
    /// The session broke on this frame (marked broken; re-pair required).
    SessionBroken {
        rel_id: String,
        reason: String,
    },
    /// Unknown service, missing intro, or malformed bytes. Logged, dropped.
    Dropped,
}

/// Route one inbound transport frame.
pub async fn ingest_frame(
    db: &Connection,
    transport: &Arc<Transport>,
    service_id: &str,
    intro: Option<&[u8]>,
    record: &[u8],
    now: SystemTime,
) -> Result<Ingest, PairingFailure> {
    if let Some(pending) = load_pending(db)? {
        if pending.service_id == service_id {
            return ingest_intro(db, transport, pending, intro, record, now).await;
        }
    }
    let Some(row) = load_relationship_by_service(db, service_id)? else {
        warn!(service_id, "drop for unknown service");
        return Ok(Ingest::Dropped);
    };
    let frame = match framing::parse_record(record) {
        Ok(f) => f,
        Err(e) => {
            warn!(service_id, error = %e, "malformed record dropped");
            return Ok(Ingest::Dropped);
        }
    };
    match session::decrypt(db, &row.rel_id, frame, now).await {
        Ok(plaintext) => Ok(Ingest::Message {
            rel_id: row.rel_id,
            plaintext,
        }),
        Err(SessionError::Duplicate) => Ok(Ingest::Duplicate),
        Err(SessionError::Broken(reason)) => Ok(Ingest::SessionBroken {
            rel_id: row.rel_id,
            reason,
        }),
        Err(e) => {
            warn!(service_id, error = %e, "inbound frame dropped");
            Ok(Ingest::Dropped)
        }
    }
}

async fn ingest_intro(
    db: &Connection,
    transport: &Arc<Transport>,
    pending: PendingRow,
    intro: Option<&[u8]>,
    record: &[u8],
    now: SystemTime,
) -> Result<Ingest, PairingFailure> {
    let Some(intro_bytes) = intro else {
        warn!("frame at invitation service without intro; dropped");
        return Ok(Ingest::Dropped);
    };
    let payload = match PairingPayload::decode(intro_bytes)
        .and_then(|p| p.verify(now_secs(now), false).map(|_| p))
    {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "intro payload invalid; dropped");
            return Ok(Ingest::Dropped);
        }
    };
    let frame = match framing::parse_record(record) {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, "intro frame malformed; dropped");
            return Ok(Ingest::Dropped);
        }
    };
    let prekey = match session::parse_prekey_frame(frame) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "intro frame is not a pre-key message; dropped");
            return Ok(Ingest::Dropped);
        }
    };
    // Bind the intro to the ciphertext: the identity key inside the
    // PreKeySignalMessage (covered by the message MAC) must equal the
    // intro's claimed identity.
    let their_ik = prekey.identity_key().serialize().to_vec();
    if their_ik != payload.identity_key {
        warn!("intro identity does not match pre-key message; dropped");
        return Ok(Ingest::Dropped);
    }
    let our_ik = our_identity_key(db, stores::PENDING_NAMESPACE)?;
    if their_ik == our_ik {
        warn!("intro from our own identity; dropped");
        return Ok(Ingest::Dropped);
    }

    // Anti-flood: each intro costs a PQXDH decrypt; an open invitation
    // service is reachable by anyone who saw the (off-band) QR, so
    // throttle processing to a min interval. Honest pacing is one
    // intro per 5-minute offer window; redelivery rides the accepter's
    // outbox backoff (≥5 s), which clears the interval.
    if intro_throttled(db, &pending.service_id, now_secs(now))? {
        crate::ratelimit::note_limited(crate::ratelimit::Surface::Intro, &pending.service_id);
        return Ok(Ingest::Dropped);
    }

    let rel_id = hex_encode(&sas::relationship_id(&our_ik, &their_ik));

    // Bounds gate: one open offer can attract unbounded
    // intros; cap the pending-request bucket. Fail toward loss, loudly.
    if request_bucket_full(db, &rel_id)? {
        warn!(rel_id, "pending-request bucket full; intro dropped");
        return Ok(Ingest::Dropped);
    }

    // The pending persona becomes the relationship persona.
    stores::migrate_namespace(db, stores::PENDING_NAMESPACE, &rel_id)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let plaintext = match session::decrypt_prekey_message(db, &rel_id, &prekey).await {
        Ok(pt) => pt,
        Err(e) => {
            // Fail closed AND leave the offer intact: restore the
            // pending persona so one crafted intro (valid signature,
            // broken ciphertext) cannot brick the open offer for the
            // honest accepter. Found by the adversarial
            // suite (intro_flood_throttled).
            warn!(rel_id, error = %e, "intro decrypt failed; no state kept");
            let _ = stores::migrate_namespace(db, &rel_id, stores::PENDING_NAMESPACE);
            let _ = stores::delete_namespace(db, &rel_id);
            return Ok(Ingest::Dropped);
        }
    };

    let peer_onion = format!(
        "{}.onion",
        onion::hostname_from_raw(&payload.onion)
            .map_err(|e| qr::PairingError::Invalid(format!("onion: {e}")))?
    );
    let our_offer = PairingPayload::decode(&pending.qr_bytes)?;
    insert_relationship(
        db,
        &rel_id,
        ROLE_INVITER,
        STATE_REQUEST,
        &pending.service_id,
        &pending.onion,
        &peer_onion,
        &their_ik,
        &b32(&payload.client_auth_public),
        &pending.client_auth_private,
        &our_offer.nonce,
        &payload.nonce,
        &pending.qr_bytes,
        false,
        now_secs(now),
    )?;
    db.execute("DELETE FROM pending_pairing WHERE id = 1", [])?;
    // Authenticate to the accepter's restricted service (ports
    // `setClientAuth` at responder open).
    transport
        .install_client_auth(&peer_onion, &pending.client_auth_private)
        .await?;

    let sas = sas::sas(&our_ik, &our_offer.nonce, &their_ik, &payload.nonce);
    info!(rel_id, "pairing request received");
    Ok(Ingest::RequestReceived {
        rel_id,
        sas,
        plaintext,
    })
}

/// Intro flood guard: `true` when an intro was already processed
/// at this invitation service within the min interval. The timestamp is
/// persisted so a restart mid-flood doesn't reset the budget. Only
/// intros that passed signature + identity checks reach here, so the
/// throttle bounds the expensive PQXDH decrypt attempts an attacker can
/// force while the offer is open (failed decrypts keep the offer open).
pub(crate) fn intro_throttled(
    db: &Connection,
    service_id: &str,
    now_s: u64,
) -> Result<bool, PairingFailure> {
    use crate::store::settings::{keys, SettingsRepository};
    let key = keys::intro_at(service_id);
    let last = db
        .setting(&key)?
        .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
        .unwrap_or(0);
    if now_s.saturating_sub(last) < crate::limits::rate::INTRO_MIN_INTERVAL_SECS {
        return Ok(true);
    }
    db.set_setting(&key, &now_s.to_be_bytes())?;
    Ok(false)
}

/// Is the inviter's pending-request bucket full for a *new* relationship?
/// Re-intros for an existing relationship always pass (they are
/// re-deliveries, not bucket growth).
pub(crate) fn request_bucket_full(
    db: &rusqlite::Connection,
    rel_id: &str,
) -> Result<bool, PairingFailure> {
    let pending_count = db.query_row(
        "SELECT COUNT(*) FROM relationships WHERE state = ?1 AND role = ?2",
        rusqlite::params![STATE_REQUEST, ROLE_INVITER],
        |r| r.get::<_, u32>(0),
    )?;
    Ok(
        pending_count >= crate::limits::pairing::MAX_PENDING_REQUESTS
            && load_relationship(db, rel_id)?.is_none(),
    )
}
