//! Inbound ingress: a decrypted envelope lands in the ledger.
//!
//! Order of gates (fail closed at each):
//! 1. **Skew** — `sent_at` is clamped or rejected (`skew.rs`).
//! 2. **Dedupe** — a repeat `msg_id` is a duplicate delivery (Tor
//!    retransmits happen); it's acknowledged and dropped, never
//!    double-stored.
//! 3. **Gap detection** — an `app_seq` above the contiguous horizon + 1
//!    flags `opens_gap` so the caller fires a `RESYNC_REQ`.
//!
//! Per-type handling (edit windows, tombstones, policies) is the
//! feature layer's job; ingress stores the decoded payload and lets it
//! react.

use schat_wire_types::envelope::Envelope;

use crate::store::inbound_seqs::InboundSeqsRepository;
use crate::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use crate::store::Db;

use super::{resync, skew, SyncError, MESSAGE_TTL_SECS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    /// New ledger row. `opens_gap` requests an immediate resync.
    Stored { opens_gap: bool },
    /// Repeat delivery of a known msg_id — dropped, session unaffected.
    Duplicate,
}

/// Skew gate + seq tracking for EVERY inbound envelope, ledgered or
/// not. Returns false on redelivery (the seq is already known).
/// Ephemeral envelopes (typing/presence) run only this; ledgered types
/// continue to `ingest_envelope`.
pub fn track_inbound(db: &Db, rel_id: &str, env: &Envelope) -> Result<bool, SyncError> {
    let now = db.clock().now_secs();
    skew::clamp_sent_at(env.sent_at, now)?;
    db.note_inbound_seq(rel_id, env.app_seq).map_err(Into::into)
}

pub fn ingest_envelope(db: &Db, rel_id: &str, env: &Envelope) -> Result<IngestOutcome, SyncError> {
    let now = db.clock().now_secs();
    let sent_at = skew::clamp_sent_at(env.sent_at, now)?;

    if db.message(&env.msg_id)?.is_some() {
        return Ok(IngestOutcome::Duplicate);
    }
    let opens_gap = resync::opens_gap(db, rel_id, env.app_seq)?;
    db.note_inbound_seq(rel_id, env.app_seq)?;
    let payload = env.payload.encode()?;
    db.insert_message(&NewMessage {
        msg_id: env.msg_id,
        rel_id: rel_id.into(),
        direction: Direction::In,
        app_seq: env.app_seq,
        sent_at,
        received_at: Some(now),
        env_type: env.envelope_type().code(),
        ref_id: env.ref_id,
        payload,
        state: DeliveryState::Received,
        expires_at: Some(now + MESSAGE_TTL_SECS),
    })?;
    Ok(IngestOutcome::Stored { opens_gap })
}
