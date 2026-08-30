//! Outbox drain + delivery-state transitions (plan 3.3.12/14).
//!
//! Lifecycle: `queued → transmitted → acknowledged | failed`. A socket
//! write completion moves the message to `transmitted` (never "sent" —
//! clients see nothing until the peer's sync view covers it, which moves
//! it to `acknowledged`; see `resync::handle_request`). Send failure
//! re-queues with capped exponential backoff until the 24h delivery
//! horizon, then `failed`.

use crate::store::messages::{DeliveryState, MessagesRepository};
use crate::store::outbox::OutboxRepository;
use crate::store::Db;

use super::SyncError;

/// First retry delay; each subsequent attempt triples it.
pub const BACKOFF_BASE_SECS: u64 = 5;
/// Backoff cap: after this the schedule flattens until the TTL horizon.
pub const BACKOFF_CAP_SECS: u64 = 900;

/// Capped exponential backoff: 5s, 15s, 45s, … ≤ 15min.
pub fn backoff(attempts: u32) -> u64 {
    BACKOFF_BASE_SECS
        .saturating_mul(3u64.saturating_pow(attempts.min(10)))
        .min(BACKOFF_CAP_SECS)
}

/// What one drain pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrainOutcome {
    /// Successfully written to the transport (now `transmitted`).
    pub transmitted: Vec<[u8; 16]>,
    /// Send failed; re-queued with backoff.
    pub deferred: Vec<[u8; 16]>,
}

/// Drain due outbox entries through `send` (a socket write to the
/// peer's onion). Sync owns no transport — the caller supplies the sink,
/// which is what makes the whole pipeline headless-testable.
pub fn drain(
    db: &Db,
    limit: u32,
    mut send: impl FnMut(&str, &[u8]) -> Result<(), SyncError>,
) -> Result<DrainOutcome, SyncError> {
    let mut outcome = DrainOutcome::default();
    for row in db.due(limit)? {
        match send(&row.rel_id, &row.record) {
            Ok(()) => {
                db.dequeue(&row.msg_id)?;
                db.set_delivery(&row.msg_id, DeliveryState::Transmitted)?;
                outcome.transmitted.push(row.msg_id);
            }
            Err(e) => {
                tracing::debug!(
                    rel_id = row.rel_id,
                    msg_id = %crate::store::hex_encode(&row.msg_id),
                    attempts = row.attempts,
                    "outbox send failed: {e}; backing off"
                );
                db.note_attempt(&row.msg_id, backoff(row.attempts))?;
                outcome.deferred.push(row.msg_id);
            }
        }
    }
    Ok(outcome)
}

/// Socket write completed: `queued → transmitted`. Any other source
/// state is a lifecycle bug — fail closed.
pub fn mark_transmitted(db: &Db, msg_id: &[u8; 16]) -> Result<(), SyncError> {
    transition(db, msg_id, DeliveryState::Transmitted)
}

/// Peer's sync view covers the message: `transmitted → acknowledged`.
pub fn mark_acknowledged(db: &Db, msg_id: &[u8; 16]) -> Result<(), SyncError> {
    transition(db, msg_id, DeliveryState::Acknowledged)
}

fn transition(db: &Db, msg_id: &[u8; 16], to: DeliveryState) -> Result<(), SyncError> {
    let row = db
        .message(msg_id)?
        .ok_or(StoreError::Corrupt("transition on unknown msg_id".into()))?;
    let from = row.state;
    let legal = matches!(
        (from, to),
        (DeliveryState::Queued, DeliveryState::Transmitted)
            // The peer's sync view is ground truth: it can ack a message
            // our socket layer never confirmed (write errored after the
            // peer already stored the frame).
            | (DeliveryState::Queued, DeliveryState::Acknowledged)
            | (DeliveryState::Transmitted, DeliveryState::Acknowledged)
            // A resync retransmission requeues an already-transmitted
            // frame; draining it re-marks the same state. Idempotent.
            | (DeliveryState::Transmitted, DeliveryState::Transmitted)
            | (DeliveryState::Queued, DeliveryState::Failed)
            | (DeliveryState::Transmitted, DeliveryState::Failed)
    );
    if !legal {
        return Err(SyncError::BadTransition { from, to });
    }
    db.set_delivery(msg_id, to)?;
    Ok(())
}

use crate::store::StoreError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_schedule_is_capped_exponential() {
        assert_eq!(backoff(0), 5);
        assert_eq!(backoff(1), 15);
        assert_eq!(backoff(2), 45);
        assert_eq!(backoff(5), 900);
        assert_eq!(backoff(100), 900);
    }
}
