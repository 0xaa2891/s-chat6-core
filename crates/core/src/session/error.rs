//! Session error taxonomy and decrypt-failure classification (session
//! broken / duplicate message / authentication failure split).

use libsignal_protocol::SignalProtocolError;
use thiserror::Error;

use crate::store::StoreError;

#[derive(Debug, Error)]
pub enum SessionError {
    /// Ratchet desync beyond recovery, identity change, or peer state
    /// loss. The relationship is marked `broken`; no auto-reset — the
    /// peers must re-pair.
    #[error("session broken: {0}")]
    Broken(String),
    /// Retransmission of an already-processed message. Drop silently;
    /// the session is fine.
    #[error("duplicate message")]
    Duplicate,
    /// Garbage on the wire. Dropped before crypto state is touched; the
    /// session is unaffected.
    #[error("malformed ciphertext: {0}")]
    Malformed(String),
    /// No session exists for this relationship (yet).
    #[error("no session")]
    NoSession,
    /// Plaintext exceeds the wire envelope ceiling; refused before any
    /// crypto or store write.
    #[error("plaintext too large: {size} > {max}")]
    TooLarge { size: usize, max: usize },
    /// I11 violation: the caller reused a `msg_id` under a different
    /// relationship. Refused (fail closed) — never re-encrypt, never
    /// return another relationship's ciphertext.
    #[error("msg_id already used under a different relationship")]
    MsgIdConflict,
    #[error("store: {0}")]
    Store(#[from] StoreError),
}

pub(crate) fn map_store_err(e: rusqlite::Error) -> SessionError {
    SessionError::Store(StoreError::Sqlite(e))
}

/// Classify a libsignal failure: `Some(Broken)` for unrecoverable
/// classes, `Some(Duplicate)` for retransmissions, `Some(Malformed)` for
/// wire garbage, `None` for store/internal errors that say nothing about
/// the session.
pub(crate) fn classify_signal_error(e: &SignalProtocolError) -> Option<SessionError> {
    use SignalProtocolError as E;
    Some(match e {
        E::DuplicatedMessage(..) => SessionError::Duplicate,
        E::InvalidMessage(t, d) => SessionError::Broken(format!("invalid {t:?} message: {d}")),
        E::InvalidSessionStructure(d) => SessionError::Broken(format!("invalid session: {d}")),
        E::UntrustedIdentity(addr) => SessionError::Broken(format!("untrusted identity {addr}")),
        E::InvalidKeyAgreement => SessionError::Broken("invalid key agreement".into()),
        E::SignatureValidationFailed => SessionError::Broken("signature validation failed".into()),
        E::SessionNotFound(s) => SessionError::Broken(format!("peer has session, we don't: {s}")),
        E::InvalidRegistrationId(addr, id) => {
            SessionError::Broken(format!("invalid registration id {id:X} for {addr}"))
        }
        E::InvalidPreKeyId | E::InvalidSignedPreKeyId | E::InvalidKyberPreKeyId => {
            SessionError::Broken(format!("pre-key id unknown: {e}"))
        }
        E::InvalidProtobufEncoding
        | E::CiphertextMessageTooShort(_)
        | E::LegacyCiphertextVersion(_)
        | E::UnrecognizedCiphertextVersion(_)
        | E::UnrecognizedMessageVersion(_)
        | E::NoKeyTypeIdentifier
        | E::BadKeyType(_)
        | E::BadKeyLength(..) => SessionError::Malformed(e.to_string()),
        // Conservative default: an unclassified crypto-layer failure
        // breaks the session rather than improvising (fail closed).
        other => SessionError::Broken(other.to_string()),
    })
}
