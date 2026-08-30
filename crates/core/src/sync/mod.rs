//! `sync/` — resync protocol, outbox management, delivery tracking,
//! history repair.
//!
//! The sync layer is transport-free: it moves wire *records* between the
//! store and a caller-supplied send closure, so the whole protocol runs
//! headless in tests. Session crypto stays in `session/`; sync only ever
//! retransmits the I11 cache's stored bytes (immutable — never
//! re-encrypted).
//!
//! Case A (resync: peer's ledger has gaps, session healthy) and Case B
//! (session broken) are separate paths: a broken session refuses here and
//! is surfaced by `session/` — sync never silently merges the two.
//!
//! Submodule map: `resync` (RESYNC_REQ build/handle, gap detection),
//! `outbox` (delivery queue drain, backoff, delivery-state transitions),
//! `skew` (malicious `sent_at` handling), `ingress` (decrypted envelope →
//! ledger).

pub mod ingress;
pub mod outbox;
pub mod resync;
pub mod skew;

pub use ingress::{ingest_envelope, IngestOutcome};
pub use outbox::{backoff, drain, mark_acknowledged, mark_transmitted, DrainOutcome};
pub use resync::{build_request, handle_request, is_missing, opens_gap, Retransmit};

use thiserror::Error;

use crate::session::SessionError;
use crate::store::messages::DeliveryState;
use crate::store::{Db, StoreError};

/// A message lives 24h, then the sweeper
/// erases it (SQLCipher `secure_delete` zeroes the pages).
pub const MESSAGE_TTL_SECS: u64 = 86_400;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("{0}")]
    Store(#[from] StoreError),
    #[error("{0}")]
    Session(#[from] SessionError),
    #[error("{0}")]
    Wire(#[from] schat_wire_types::WireError),
    /// `sent_at` too far in the future: the sender is malicious or its
    /// clock is hopelessly wrong. Fail closed — drop the envelope.
    #[error("sent_at {sent_at} is too far ahead of local time {now}")]
    FutureTimestamp { sent_at: u64, now: u64 },
    /// A delivery-state transition the lifecycle does not allow.
    #[error("bad delivery transition: {from:?} → {to:?}")]
    BadTransition {
        from: DeliveryState,
        to: DeliveryState,
    },
    #[error("send failed: {0}")]
    Send(String),
}

/// Counts from one `sweep_expired` pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub messages_erased: u64,
    pub attachments_erased: u64,
    pub outbox_failed: u64,
    /// Orphan attachment chunks (head never arrived) past their TTL.
    pub orphan_chunks_erased: u64,
}

/// Thin entry point over the submodules. Stateless beyond the store
/// handle — all logic lives in the submodules.
pub struct Sync<'a> {
    db: &'a Db,
}

impl<'a> Sync<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// TTL sweeper: erase expired messages + attachments,
    /// fail outbox entries past their delivery horizon (their message
    /// rows move to `failed` — never silently dropped), and reclaim
    /// orphan attachment chunks whose head never arrived.
    pub fn sweep_expired(&self) -> Result<SweepReport, SyncError> {
        use crate::store::attachments::AttachmentsRepository;
        use crate::store::chunks::ChunksRepository;
        use crate::store::messages::MessagesRepository;
        use crate::store::outbox::OutboxRepository;

        let mut report = SweepReport::default();
        for row in self.db.fail_expired()? {
            self.db.set_delivery(&row.msg_id, DeliveryState::Failed)?;
            report.outbox_failed += 1;
        }
        report.messages_erased = MessagesRepository::sweep_expired(self.db)?;
        report.attachments_erased = AttachmentsRepository::sweep_expired(self.db)?;
        let cutoff = self.db.clock().now_secs() as i64 - crate::limits::orphan::ORPHAN_TTL_SECS;
        report.orphan_chunks_erased = self.db.sweep_orphans(cutoff)?;
        Ok(report)
    }
}

#[cfg(test)]
mod tests;
