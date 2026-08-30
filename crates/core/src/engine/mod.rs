//! `engine/` — the application glue: envelope-shaped send and
//! ingest pipelines on top of `session` (I11 encryption), `sync`
//! (ledger, outbox, resync), and the feature modules (`messages`,
//! `attach`, `profile`, `stickers`, `policy`, `presence`, `typing`,
//! `close`). The engine owns no sockets of its own; it drives
//! `Transport`, and it owns the RAM-only feature state (presence and
//! typing tables, sticker chunk buffers).
//!
//! Submodule map: `send` (outbound pipeline + gates), `inbound`
//! (decrypted-envelope dispatch), `drain` (outbox drain, retransmit,
//! sweeps), `burn` (relationship erasure).
//!
//! Sequencing rule that shapes everything: **every** envelope consumes
//! an `app_seq`, is ledgered, and rides the outbox — typing and
//! presence included. That keeps the resync receive-view contiguous
//! (a dropped ephemeral beat would otherwise wedge the peer's
//! contiguous horizon forever). "RAM-only" for presence/typing refers
//! to *rendered state* (no persisted dots); the ledger
//! rows are swept by the ordinary TTL.

pub mod burn;
pub mod drain;
pub mod inbound;
pub mod lifecycle;
pub mod send;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_rate;

use std::sync::Arc;

use schat_wire_types::envelope::EnvelopeType;
use schat_wire_types::error::WireError;
use thiserror::Error;

use crate::media::MediaError;
use crate::pairing::PairingFailure;
use crate::presence::PresenceTable;
use crate::session::SessionError;
use crate::store::{Db, StoreError};
use crate::sync::SyncError;
use crate::transport::error::TransportError;
use crate::transport::Transport;
use crate::typing::TypingTable;

/// One engine instance per app runtime (CLI daemon, Android client).
/// Single-threaded driver: the libsignal session chain is `!Send`, so
/// callers must not invoke engine methods concurrently.
pub struct Engine {
    pub db: Db,
    pub transport: Arc<Transport>,
    /// RAM-only presence dots (never persisted).
    pub presence: PresenceTable,
    /// RAM-only typing indicators (never persisted).
    pub typing: TypingTable,
    /// RAM-only sticker chunk reassembly buffers.
    pub sticker_pending: crate::stickers::PendingBuffers,
    /// Per-relationship temporal anti-flood buckets.
    rate: crate::ratelimit::RateTables,
}

impl Engine {
    pub fn new(db: Db, transport: Arc<Transport>) -> Self {
        Self {
            db,
            transport,
            presence: PresenceTable::new(),
            typing: TypingTable::new(),
            sticker_pending: crate::stickers::PendingBuffers::new(),
            rate: crate::ratelimit::RateTables::new(),
        }
    }

    /// Consume one anti-flood token for `(surface, rel_id)`; `false`
    /// means the inbound work is dropped (counted + logged, session
    /// unaffected). Engine clock driven — `FakeClock` in tests.
    pub(crate) fn rate_allow(&mut self, surface: crate::ratelimit::Surface, rel_id: &str) -> bool {
        self.rate.check(surface, rel_id, self.now())
    }

    pub fn now(&self) -> u64 {
        self.db.clock().now_secs()
    }
}

/// What happened inside the engine, for the client event stream.
/// Ids are hex strings at the FFI boundary; raw bytes inside.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EngineEvent {
    /// New inbound ledger message (MSG).
    Message {
        rel_id: String,
        msg_id: [u8; 16],
    },
    Edited {
        rel_id: String,
        msg_id: [u8; 16],
    },
    Deleted {
        rel_id: String,
        msg_id: [u8; 16],
    },
    /// DELETE_ALL landed: the thread was wiped.
    HistoryCleared {
        rel_id: String,
    },
    /// Peer's READ receipt landed on our outbound row.
    Read {
        rel_id: String,
        msg_id: [u8; 16],
    },
    Typing {
        rel_id: String,
        typing: bool,
    },
    Presence {
        rel_id: String,
        in_app: bool,
        do_not_disturb: bool,
    },
    ProfileUpdated {
        rel_id: String,
    },
    /// Peer asked for our profile (PROFILE_REQ).
    ProfileRequested {
        rel_id: String,
    },
    /// Peer's receive preferences changed (PREF).
    PeerPrefs {
        rel_id: String,
    },
    /// Inbound sticker; `ready` = bytes held locally.
    Sticker {
        rel_id: String,
        msg_id: [u8; 16],
        ready: bool,
    },
    StickerPackInstalled {
        pack_id: [u8; 16],
    },
    StickerPackRefused {
        pack_id: [u8; 16],
        reason: u8,
    },
    /// A reassembled pack-preview doc (answer to our WANT_THUMBS).
    StickerThumbs {
        pack_id: [u8; 16],
        doc: schat_wire_types::sticker::StickerThumbsDoc,
    },
    AttachmentProgress {
        rel_id: String,
        head_id: [u8; 16],
        received: u32,
        total: u32,
    },
    AttachmentComplete {
        rel_id: String,
        head_id: [u8; 16],
        msg_id: [u8; 16],
    },
    AttachmentFailed {
        rel_id: String,
        head_id: [u8; 16],
    },
    /// An orphan chunk (head not yet seen) was refused by the storage
    /// caps. Loss is loud, never silent.
    AttachmentChunkDropped {
        rel_id: String,
        head_id: [u8; 16],
    },
    PolicyChanged {
        rel_id: String,
    },
    /// Peer's CONTACT_CLOSE landed; the relationship was burned.
    ContactClosed {
        rel_id: String,
    },
    /// Inbound seq gap: a resync request went out.
    GapDetected {
        rel_id: String,
    },
}

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("unknown relationship")]
    UnknownRelationship,
    #[error("relationship not active (request pending or closed)")]
    NotActive,
    #[error("close in flight; the relationship is settling")]
    Closing,
    #[error("session broken; re-pair required")]
    SessionBroken,
    #[error("peer never advertised the capability for {0:?}")]
    CapGated(EnvelopeType),
    #[error("chat policy denies {0:?}")]
    PolicyDenied(EnvelopeType),
    #[error("target message not found")]
    NotFound,
    #[error("edit window closed or edit cap reached")]
    EditDenied(&'static str),
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("session: {0}")]
    Session(#[from] SessionError),
    #[error("transport: {0}")]
    Transport(#[from] TransportError),
    #[error("pairing: {0}")]
    Pairing(#[from] PairingFailure),
    #[error("sync: {0}")]
    Sync(#[from] SyncError),
    #[error("media: {0}")]
    Media(#[from] MediaError),
}

/// Fresh random msg_id.
pub(crate) fn random_msg_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id
}
