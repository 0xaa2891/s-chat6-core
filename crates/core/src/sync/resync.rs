//! `RESYNC_REQ` build + handle (plan 3.3.11/13): the receive view rides
//! out, stored frames come back. Retransmission is immutable — the I11
//! cache's `frame_bytes` go out as-is, never re-encrypted (a fresh
//! ciphertext would desync the ratchet the peer already advanced).
//!
//! This is Case A only: the session is healthy and the peer's ledger has
//! gaps. Case B (session broken) is refused twice over — `session::
//! encrypt`/`decrypt` reject every frame on a Broken relationship, and
//! the entry points here check `session_state` themselves (defense in
//! depth: the sync layer must not ack/retransmit for a dead session even
//! when a caller reaches it directly).

use schat_wire_types::caps;
use schat_wire_types::resync::{self, ResyncReq};

use crate::session::{self, SessionError, SessionState};
use crate::store::messages::{DeliveryState, MessagesRepository};
use crate::store::{hex_encode, Db};

use super::SyncError;

/// The v2 repair window (`CAP_V19`-gated on the wire).
pub const BITMAP_BITS: u32 = resync::BITMAP_BITS as u32;

/// Case B guard: a broken relationship is re-pair-only.
fn refuse_if_broken(db: &Db, rel_id: &str) -> Result<(), SyncError> {
    if session::session_state(db.conn(), rel_id)? == SessionState::Broken {
        return Err(SessionError::Broken("relationship is broken".into()).into());
    }
    Ok(())
}

/// Build our `RESYNC_REQ` for a relationship: receive view + history
/// hash over the deep window.
pub fn build_request(db: &Db, rel_id: &str) -> Result<ResyncReq, SyncError> {
    refuse_if_broken(db, rel_id)?;
    let view = db.receive_view(rel_id, BITMAP_BITS)?;
    let base = resync::deep_base(view.max_contiguous_seq);
    let deep = db.deep_seqs(rel_id, base, view.max_contiguous_seq)?;
    let history_hash = resync::history_hash(view.max_contiguous_seq, &view.bitmap, &deep);
    Ok(ResyncReq {
        max_contiguous_seq: view.max_contiguous_seq,
        received_seq_bitmap: view.bitmap,
        caps: caps::LOCAL,
        history_hash,
    })
}

/// Does the peer's view lack `app_seq`?
pub fn is_missing(max_contiguous_seq: u64, bitmap: &[u8], app_seq: u64) -> bool {
    if app_seq == 0 || app_seq <= max_contiguous_seq {
        return app_seq == 0;
    }
    let offset = app_seq - max_contiguous_seq - 1;
    if offset >= u64::from(BITMAP_BITS) {
        return true;
    }
    let i = offset as usize;
    match bitmap.get(i / 8) {
        Some(byte) => byte & (1 << (i % 8)) == 0,
        None => true,
    }
}

/// An inbound `app_seq` above the
/// contiguous horizon + 1 means we missed something — trigger an
/// immediate (throttled) resync rather than waiting for the cadence.
pub fn opens_gap(db: &Db, rel_id: &str, app_seq: u64) -> Result<bool, SyncError> {
    if app_seq <= 1 {
        return Ok(false);
    }
    let view = db.receive_view(rel_id, BITMAP_BITS)?;
    Ok(app_seq > view.max_contiguous_seq + 1)
}

/// One frame to retransmit, exactly as first encrypted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retransmit {
    pub msg_id: [u8; 16],
    pub app_seq: u64,
    pub frame: Vec<u8>,
}

/// Handle the peer's `RESYNC_REQ` (Case A):
///
/// 1. Every outbound row the peer's view **covers** (not missing) moves
///    to `acknowledged` — the sync-view ACK, replacing any explicit
///    receipt envelope.
/// 2. Every outbound row the peer is **missing** (and whose local TTL
///    hasn't expired) is returned with its stored I11 frame for
///    immutable retransmission. A row with no cached frame is logged and
///    skipped — we cannot retransmit what we no longer hold.
pub fn handle_request(
    db: &Db,
    rel_id: &str,
    req: &ResyncReq,
) -> Result<Vec<Retransmit>, SyncError> {
    refuse_if_broken(db, rel_id)?;
    let now = db.clock().now_secs();
    // Every unsettled outbound row up to the peer's window edge gets a
    // verdict: covered → acked (including rows at/below the contiguous
    // horizon), missing → retransmitted.
    let through = req.max_contiguous_seq + u64::from(BITMAP_BITS);
    let candidates = db.unacked_outbound(rel_id, through)?;
    let mut out = Vec::new();
    let mut acked = Vec::new();
    for row in candidates {
        if !is_missing(
            req.max_contiguous_seq,
            &req.received_seq_bitmap,
            row.app_seq,
        ) {
            // Covered by the peer's view → acknowledged (sync-hash ACK).
            if row.state == DeliveryState::Transmitted || row.state == DeliveryState::Queued {
                super::outbox::mark_acknowledged(db, &row.msg_id)?;
                acked.push(row.app_seq);
            }
            continue;
        }
        if row.expires_at.is_some_and(|exp| exp <= now) {
            continue; // past the delivery horizon; the sweeper fails it
        }
        match session::stored_ciphertext(db.conn(), rel_id, &hex_encode(&row.msg_id))? {
            Some(frame) => {
                tracing::info!(rel_id, app_seq = row.app_seq, "resync retransmit queued");
                out.push(Retransmit {
                    msg_id: row.msg_id,
                    app_seq: row.app_seq,
                    frame,
                });
            }
            None => {
                tracing::warn!(
                    rel_id,
                    msg_id = %hex_encode(&row.msg_id),
                    app_seq = row.app_seq,
                    "peer missing message but no I11 frame cached; skipping"
                );
            }
        }
    }
    tracing::info!(rel_id, acked = ?acked, "resync covered rows acked");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_missing_matches_spec_semantics() {
        // max=3, bitmap bit1 (seq 5) and bit4 (seq 8) set.
        let bitmap = [0b0001_0010u8];
        assert!(is_missing(3, &bitmap, 0)); // seq 0 is invalid
        assert!(!is_missing(3, &bitmap, 2)); // below horizon
        assert!(is_missing(3, &bitmap, 4)); // gap
        assert!(!is_missing(3, &bitmap, 5)); // covered
        assert!(is_missing(3, &bitmap, 6));
        assert!(!is_missing(3, &bitmap, 8));
        assert!(is_missing(3, &bitmap, 9)); // beyond last set byte
        assert!(is_missing(3, &bitmap, 3 + BITMAP_BITS as u64 + 1)); // beyond window
    }
}
