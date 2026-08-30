//! `caps/` — capability advertisement and gating.
//!
//! Caps live inside the encrypted channel only: they ride in
//! `RESYNC_REQ` (`wire_types::caps`), so advertising on session start
//! means sending a resync request — the engine does that when a
//! relationship activates. There is no cleartext capability leak and no
//! downgrade path: a peer that never advertises a bit is treated as not
//! speaking the feature, full stop.
//!
//! Gating is symmetric:
//! - **Inbound:** an envelope whose type needs a bit the peer never
//!   advertised is dropped + counted + logged; the session is
//!   unaffected (same posture as I7's unknown-type drop).
//! - **Outbound:** the engine refuses to encrypt a gated type for a
//!   peer without the bit (need-to-send: don't emit what the peer will
//!   drop).
//!
//! Baseline types (MSG, EDIT, DELETE, DELETE_ALL, RESYNC_REQ,
//! ATTACH_HEAD, ATTACH_CHUNK, CONTACT_CLOSE, PROFILE, PREF,
//! PROFILE_REQ) need no bit — `CAP_V15`/`CAP_V19` describe the baseline
//! itself, and a peer that stripped them is not this build.

use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{params, Connection, OptionalExtension};
use schat_wire_types::caps;
use schat_wire_types::envelope::EnvelopeType;

use crate::store::StoreError;

/// Everything this build speaks (`wire_types::caps::LOCAL`).
pub fn local_caps() -> u32 {
    caps::LOCAL
}

/// The cap bit a type needs before either side may speak it. `None` =
/// baseline, always allowed.
pub fn required_cap(t: EnvelopeType) -> Option<u32> {
    match t {
        EnvelopeType::Sticker | EnvelopeType::StickerCtrl => Some(caps::CAP_STICKER),
        EnvelopeType::Presence => Some(caps::CAP_PRESENCE),
        EnvelopeType::Typing => Some(caps::CAP_TYPING),
        EnvelopeType::Read => Some(caps::CAP_READ),
        EnvelopeType::ChatPolicy => Some(caps::CAP_POLICY),
        _ => None,
    }
}

/// Record the peer's advertised caps (from their `RESYNC_REQ`).
pub fn note_peer_caps(db: &Connection, rel_id: &str, peer_caps: u32) -> Result<(), StoreError> {
    db.execute(
        "UPDATE relationships SET peer_caps = ?2 WHERE rel_id = ?1",
        params![rel_id, peer_caps as i64],
    )?;
    Ok(())
}

/// The peer's advertised caps. `0` = nothing advertised yet (baseline
/// only — no stickers, presence, typing, receipts, or policy).
pub fn peer_caps(db: &Connection, rel_id: &str) -> Result<u32, StoreError> {
    let caps: Option<i64> = db
        .query_row(
            "SELECT peer_caps FROM relationships WHERE rel_id = ?1",
            params![rel_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(caps.unwrap_or(0) as u32)
}

/// May this type cross the channel to/from a peer with `peer_caps`?
pub fn allows(peer_caps: u32, t: EnvelopeType) -> bool {
    match required_cap(t) {
        None => true,
        Some(bit) => caps::has(peer_caps, bit),
    }
}

static GATED_DROPS: AtomicU64 = AtomicU64::new(0);

/// Inbound gate. On refusal: drop + count + log, session untouched.
pub fn check_inbound(db: &Connection, rel_id: &str, t: EnvelopeType) -> Result<bool, StoreError> {
    let caps = peer_caps(db, rel_id)?;
    if allows(caps, t) {
        return Ok(true);
    }
    let n = GATED_DROPS.fetch_add(1, Ordering::Relaxed) + 1;
    tracing::warn!(
        rel_id,
        r#type = ?t,
        peer_caps = caps,
        total = n,
        "caps gate: unadvertised type dropped; session unaffected"
    );
    Ok(false)
}

/// Outbound gate (pure): the engine checks before encrypting.
pub fn check_outbound(peer_caps: u32, t: EnvelopeType) -> bool {
    allows(peer_caps, t)
}

/// Total unadvertised-type envelopes dropped since process start.
pub fn gated_drops() -> u64 {
    GATED_DROPS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    fn db_with_rel(caps: u32) -> (Db, String) {
        let db = Db::open_in_memory().unwrap();
        db.conn()
            .execute(
                "INSERT INTO relationships (
                    rel_id, role, state, service_id, onion, peer_onion,
                    peer_identity_key, peer_client_auth_public,
                    our_client_auth_private, our_nonce, peer_nonce,
                    our_qr_bytes, intro_pending,
                    session_state, created_at, peer_caps
                 ) VALUES (
                    'rel', 'inviter', 'active', 'svc', 'a.onion', 'b.onion',
                    X'00', 'ca', 'cb', X'00', X'00', X'00', 0,
                    'active', 0, ?1
                 )",
                params![caps as i64],
            )
            .unwrap();
        (db, "rel".to_string())
    }

    #[test]
    fn baseline_always_allowed_gated_needs_bit() {
        assert!(allows(0, EnvelopeType::Msg));
        assert!(allows(0, EnvelopeType::AttachHead));
        assert!(!allows(0, EnvelopeType::Typing));
        assert!(!allows(0, EnvelopeType::Sticker));
        assert!(allows(caps::CAP_TYPING, EnvelopeType::Typing));
        assert!(allows(caps::LOCAL, EnvelopeType::Read));
        // No downgrade: a stripped bit stays off.
        assert!(!allows(
            caps::LOCAL & !caps::CAP_PRESENCE,
            EnvelopeType::Presence
        ));
    }

    #[test]
    fn inbound_gate_drops_and_counts() {
        let (db, rel) = db_with_rel(0);
        let before = gated_drops();
        assert!(check_inbound(db.conn(), &rel, EnvelopeType::Msg).unwrap());
        assert!(!check_inbound(db.conn(), &rel, EnvelopeType::Typing).unwrap());
        assert_eq!(gated_drops(), before + 1);

        note_peer_caps(db.conn(), &rel, caps::CAP_TYPING).unwrap();
        assert!(check_inbound(db.conn(), &rel, EnvelopeType::Typing).unwrap());
        assert_eq!(gated_drops(), before + 1);
    }

    #[test]
    fn unknown_relationship_has_no_caps() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(peer_caps(db.conn(), "nobody").unwrap(), 0);
    }
}
