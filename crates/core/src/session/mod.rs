//! `session/` — libsignal session lifecycle. PQXDH + Double Ratchet +
//! SPQR (Triple Ratchet)
//! via the pinned `libsignal-protocol` crate; no self-implemented crypto.
//!
//! One `ProtocolAddress` per relationship: `ProtocolAddress::new(rel_id_hex,
//! 1)`. Per-relationship identity keys — no global identity, no master seed.
//!
//! I11: one `msg_id` → one ciphertext. `encrypt` stores the produced frame
//! and returns the stored bytes on any re-encrypt request for the same
//! `msg_id`; retransmission never produces a new ciphertext.

mod error;
mod persona;
pub mod stores;

pub use error::SessionError;
pub use persona::{generate_persona, persona_bundle, store_persona, Persona};

use std::time::SystemTime;

use libsignal_protocol::{
    message_decrypt_prekey, message_decrypt_signal, message_encrypt, process_prekey_bundle,
    CiphertextMessage, PreKeyBundle, PreKeySignalMessage, ProtocolAddress, SignalMessage,
    SignalProtocolError,
};
use rusqlite::{params, Connection, OptionalExtension};
use schat_wire_types::limits::envelope::MAX_ENVELOPE_BYTES;
use sha2::{Digest, Sha256};

use crate::store::StoreError;

use error::{classify_signal_error, map_store_err};

/// The CSPRNG handed to libsignal. rand_core 0.9's `OsRng` only implements
/// `TryCryptoRng`; `UnwrapErr` lifts it to `RngCore + CryptoRng` (OsRng
/// never actually fails). Send + Sync, stateless.
pub type CsRng = rand_core::UnwrapErr<rand::rngs::OsRng>;

pub fn csprng() -> CsRng {
    rand_core::UnwrapErr(rand::rngs::OsRng)
}

/// The pinned libsignal tag — surfaced to clients for BuildConfig checks
/// (surfaced over FFI so clients can check their build against it).
pub const CRYPTO_VERSION: &str = "libsignal-v0.99.4";

/// Frame tags: 1 byte prefix on the serialized libsignal ciphertext so the
/// receiver knows which parser to use (both message types share a version
/// byte scheme, so the wire must carry the type). Values match
/// `CiphertextMessageType` discriminants.
pub const TAG_SIGNAL: u8 = 0x02;
pub const TAG_PREKEY: u8 = 0x03;

/// Fixed pre-key ids within a relationship namespace (one of each per
/// pairing; the namespace isolates them from other relationships).
pub const SIGNED_PREKEY_ID: u32 = 1;
pub const KYBER_PREKEY_ID: u32 = 1;
pub const ONE_TIME_PREKEY_ID: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionState {
    /// No relationship / no session.
    None,
    Active,
    Broken,
}

// ---------------------------------------------------------------------------
// Addresses

/// The peer's protocol address — identical on both sides (both derive the
/// relationship id from both identity keys).
pub fn remote_address(rel_id: &str) -> Result<ProtocolAddress, SessionError> {
    Ok(ProtocolAddress::new(
        rel_id.to_string(),
        1u32.try_into().map_err(|_| SessionError::NoSession)?,
    ))
}

/// Our own address. Never on the wire (non-ServiceId names serialize to
/// no address binding); used for store keying and self-send detection only.
fn local_address(rel_id: &str) -> ProtocolAddress {
    ProtocolAddress::new(
        format!("self.{rel_id}"),
        1u32.try_into().expect("device id 1"),
    )
}

// ---------------------------------------------------------------------------
// Session establishment

/// Accepter side (PQXDH initiator): process the inviter's bundle from
/// their pairing QR. After this, `encrypt` produces a PreKeySignalMessage
/// that carries our identity to the inviter.
pub async fn process_bundle(
    db: &Connection,
    rel_id: &str,
    bundle: &PreKeyBundle,
    now: SystemTime,
) -> Result<(), SessionError> {
    let mut session_store = stores::SqliteSessionStore {
        db,
        namespace: rel_id.into(),
    };
    let mut identity_store = stores::SqliteIdentityStore {
        db,
        namespace: rel_id.into(),
    };
    let mut rng = csprng();
    process_prekey_bundle(
        &remote_address(rel_id)?,
        &local_address(rel_id),
        &mut session_store,
        &mut identity_store,
        bundle,
        now,
        &mut rng,
    )
    .await
    .map_err(|e| {
        classify_signal_error(&e).unwrap_or_else(|| SessionError::Malformed(e.to_string()))
    })
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt

fn relationship_session_state(db: &Connection, rel_id: &str) -> Result<SessionState, SessionError> {
    let state: Option<String> = match db.query_row(
        "SELECT session_state FROM relationships WHERE rel_id = ?1",
        params![rel_id],
        |r| r.get(0),
    ) {
        Ok(s) => Some(s),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        // A store failure is not "no session" — propagate, never improvise.
        Err(e) => return Err(map_store_err(e)),
    };
    Ok(match state.as_deref() {
        None => SessionState::None,
        Some("broken") => SessionState::Broken,
        Some(_) => SessionState::Active,
    })
}

pub fn session_state(db: &Connection, rel_id: &str) -> Result<SessionState, SessionError> {
    relationship_session_state(db, rel_id)
}

/// I11 cache read for the sync layer: the stored frame for immutable
/// retransmission, scoped to the relationship (a msg_id minted under a
/// different relationship is not yours to retransmit).
pub fn stored_ciphertext(
    db: &Connection,
    rel_id: &str,
    msg_id_hex: &str,
) -> Result<Option<Vec<u8>>, SessionError> {
    db.query_row(
        "SELECT frame_bytes FROM message_ciphertexts WHERE msg_id = ?1 AND rel_id = ?2",
        params![msg_id_hex, rel_id],
        |r| r.get(0),
    )
    .optional()
    .map_err(map_store_err)
}

fn mark_broken(db: &Connection, rel_id: &str, reason: &str) {
    tracing::warn!(rel_id, %reason, "session marked broken");
    let _ = db.execute(
        "UPDATE relationships SET session_state = 'broken' WHERE rel_id = ?1",
        params![rel_id],
    );
    // Case B: a broken session can never deliver its
    // queue — fail every queued/transmitted outbound row at break time
    // instead of letting it sit until the 24 h TTL.
    if let Err(e) = crate::store::outbox::fail_relationship_outbound(db, rel_id) {
        tracing::warn!(rel_id, error = %e, "outbound rows not failed on session break");
    }
}

// ---------------------------------------------------------------------------
// Inbound replay cache (I7 hardening)
//
// libsignal retains only a bounded window of receiver chains; past it, a
// replayed ciphertext is indistinguishable from a session break, so a
// captured-and-replayed frame would be a one-packet DoS. Every
// successfully decrypted frame's hash is remembered for the message-TTL
// horizon: a byte-identical replay drops as a duplicate before crypto.
// The sweep (store::messages::sweep_expired) expires rows with the
// ledger; beyond the horizon a replay fails closed (Broken) as before.

fn inbound_frame_hash(frame: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(frame);
    h.finalize().into()
}

fn is_known_inbound_frame(
    db: &Connection,
    rel_id: &str,
    frame: &[u8],
) -> Result<bool, SessionError> {
    db.query_row(
        "SELECT 1 FROM inbound_frames WHERE rel_id = ?1 AND frame_hash = ?2",
        params![rel_id, inbound_frame_hash(frame).as_slice()],
        |_| Ok(()),
    )
    .optional()
    .map(|o| o.is_some())
    .map_err(map_store_err)
}

fn note_inbound_frame(
    db: &Connection,
    rel_id: &str,
    frame: &[u8],
    now: SystemTime,
) -> Result<(), SessionError> {
    let now_s = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    db.execute(
        "INSERT OR IGNORE INTO inbound_frames (rel_id, frame_hash, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?3)",
        params![
            rel_id,
            inbound_frame_hash(frame).as_slice(),
            now_s + crate::limits::store::INBOUND_FRAME_TTL_SECS
        ],
    )
    .map_err(map_store_err)?;
    Ok(())
}

/// Encrypt `plaintext` for `rel_id`. I11: a second call with the same
/// `msg_id` returns the stored frame bytes — never a fresh ciphertext.
pub async fn encrypt(
    db: &Connection,
    rel_id: &str,
    msg_id: &str,
    plaintext: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, SessionError> {
    // Bounds gate: a plaintext that can never fit a record
    // bucket is refused before any crypto runs and before the I11 row is
    // written — otherwise `build_record` would fail *after* the
    // ciphertext was stored, leaving an orphan row.
    if plaintext.len() > MAX_ENVELOPE_BYTES {
        return Err(SessionError::TooLarge {
            size: plaintext.len(),
            max: MAX_ENVELOPE_BYTES,
        });
    }
    match relationship_session_state(db, rel_id)? {
        SessionState::Broken => return Err(SessionError::Broken("relationship is broken".into())),
        SessionState::None => return Err(SessionError::NoSession),
        SessionState::Active => {}
    }
    // I11, scoped: a msg_id belongs to exactly one relationship. Returning
    // ciphertext encrypted under a *different* relationship's session would
    // be undecryptable at the peer (bad MAC → broken session), so cross-
    // relationship reuse refuses instead of improvising.
    match db.query_row(
        "SELECT rel_id, frame_bytes FROM message_ciphertexts WHERE msg_id = ?1",
        params![msg_id],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
    ) {
        Ok((stored_rel, frame)) => {
            if stored_rel != rel_id {
                return Err(SessionError::MsgIdConflict);
            }
            return Ok(frame);
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(e) => return Err(map_store_err(e)),
    }

    let mut session_store = stores::SqliteSessionStore {
        db,
        namespace: rel_id.into(),
    };
    let mut identity_store = stores::SqliteIdentityStore {
        db,
        namespace: rel_id.into(),
    };
    let mut rng = csprng();
    let message = message_encrypt(
        plaintext,
        &remote_address(rel_id)?,
        &local_address(rel_id),
        &mut session_store,
        &mut identity_store,
        now,
        &mut rng,
    )
    .await
    .map_err(|e| match classify_signal_error(&e) {
        Some(SessionError::Broken(reason)) => {
            mark_broken(db, rel_id, &reason);
            SessionError::Broken(reason)
        }
        Some(other) => other,
        None => SessionError::Malformed(e.to_string()),
    })?;

    let tag = match &message {
        CiphertextMessage::SignalMessage(_) => TAG_SIGNAL,
        CiphertextMessage::PreKeySignalMessage(_) => TAG_PREKEY,
        other => {
            return Err(SessionError::Malformed(format!(
                "unexpected ciphertext type {:?}",
                other.message_type()
            )))
        }
    };
    let mut frame = Vec::with_capacity(1 + message.serialize().len());
    frame.push(tag);
    frame.extend_from_slice(message.serialize());

    let created_at = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    db.execute(
        "INSERT INTO message_ciphertexts (msg_id, rel_id, frame_bytes, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![msg_id, rel_id, frame, created_at],
    )
    .map_err(map_store_err)?;
    Ok(frame)
}

/// Split a stored frame into (tag, ciphertext). Fail closed on unknown
/// tags and short buffers — before any crypto runs.
fn parse_frame(frame: &[u8]) -> Result<(u8, &[u8]), SessionError> {
    let (tag, rest) = frame
        .split_first()
        .ok_or_else(|| SessionError::Malformed("empty frame".into()))?;
    match *tag {
        TAG_SIGNAL | TAG_PREKEY => Ok((*tag, rest)),
        other => Err(SessionError::Malformed(format!(
            "unknown ciphertext tag 0x{other:02x}"
        ))),
    }
}

/// Parse the pre-key message out of a frame (responder path: the pairing
/// module needs the sender's identity key before it knows the rel_id).
pub fn parse_prekey_frame(frame: &[u8]) -> Result<PreKeySignalMessage, SessionError> {
    let (tag, rest) = parse_frame(frame)?;
    if tag != TAG_PREKEY {
        return Err(SessionError::Malformed("not a pre-key frame".into()));
    }
    PreKeySignalMessage::try_from(rest).map_err(|e| SessionError::Malformed(e.to_string()))
}

/// Decrypt a frame from an established relationship.
pub async fn decrypt(
    db: &Connection,
    rel_id: &str,
    frame: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, SessionError> {
    if relationship_session_state(db, rel_id)? == SessionState::Broken {
        return Err(SessionError::Broken("relationship is broken".into()));
    }
    // A byte-identical frame we already decrypted is a retransmission —
    // drop it without touching the session (see the replay-cache note
    // above). This check must come AFTER the Broken gate: a broken
    // relationship fails closed even for replayed bytes.
    if is_known_inbound_frame(db, rel_id, frame)? {
        return Err(SessionError::Duplicate);
    }
    let (tag, rest) = parse_frame(frame)?;
    let result = match tag {
        TAG_SIGNAL => {
            let message = SignalMessage::try_from(rest)
                .map_err(|e| SessionError::Malformed(e.to_string()))?;
            let mut session_store = stores::SqliteSessionStore {
                db,
                namespace: rel_id.into(),
            };
            let mut identity_store = stores::SqliteIdentityStore {
                db,
                namespace: rel_id.into(),
            };
            let mut rng = csprng();
            message_decrypt_signal(
                &message,
                &remote_address(rel_id)?,
                &local_address(rel_id),
                &mut session_store,
                &mut identity_store,
                &mut rng,
            )
            .await
        }
        TAG_PREKEY => {
            let message = parse_prekey_frame(frame)?;
            decrypt_prekey_message(db, rel_id, &message).await
        }
        _ => unreachable!("parse_frame gates tags"),
    };
    let plaintext = finish_decrypt(db, rel_id, result, now)?;
    note_inbound_frame(db, rel_id, frame, now)?;
    Ok(plaintext)
}

/// Responder half of the first frame: the relationship row and the
/// migrated namespace must already exist (pairing module sets them up).
pub async fn decrypt_prekey_message(
    db: &Connection,
    rel_id: &str,
    message: &PreKeySignalMessage,
) -> Result<Vec<u8>, SignalProtocolError> {
    let mut session_store = stores::SqliteSessionStore {
        db,
        namespace: rel_id.into(),
    };
    let mut identity_store = stores::SqliteIdentityStore {
        db,
        namespace: rel_id.into(),
    };
    let mut pre_key_store = stores::SqlitePreKeyStore {
        db,
        namespace: rel_id.into(),
    };
    let signed_pre_key_store = stores::SqliteSignedPreKeyStore {
        db,
        namespace: rel_id.into(),
    };
    let mut kyber_store = stores::SqliteKyberPreKeyStore {
        db,
        namespace: rel_id.into(),
    };
    let mut rng = csprng();
    message_decrypt_prekey(
        message,
        &remote_address(rel_id)
            .map_err(|_| SignalProtocolError::InvalidArgument("bad rel_id".into()))?,
        &local_address(rel_id),
        &mut session_store,
        &mut identity_store,
        &mut pre_key_store,
        &signed_pre_key_store,
        &mut kyber_store,
        &mut rng,
    )
    .await
}

fn finish_decrypt(
    db: &Connection,
    rel_id: &str,
    result: Result<Vec<u8>, SignalProtocolError>,
    _now: SystemTime,
) -> Result<Vec<u8>, SessionError> {
    match result {
        Ok(plaintext) => {
            // Any valid inbound message proves our intro arrived (the peer
            // could not have answered otherwise). Stop attaching it.
            let _ = db.execute(
                "UPDATE relationships SET intro_pending = 0 WHERE rel_id = ?1",
                params![rel_id],
            );
            Ok(plaintext)
        }
        Err(e) => Err(match classify_signal_error(&e) {
            Some(SessionError::Broken(reason)) => {
                mark_broken(db, rel_id, &reason);
                SessionError::Broken(reason)
            }
            Some(other) => other,
            None => SessionError::Store(StoreError::Corrupt(e.to_string())),
        }),
    }
}
