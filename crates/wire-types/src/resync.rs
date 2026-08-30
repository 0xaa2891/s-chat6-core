//! `RESYNC_REQ` payload: the receive view (max contiguous seq + repair
//! bitmap) plus a history hash — a compact fingerprint of the receiver's
//! inbound ledger. Ports `ResyncReqV1` semantics at the v2 window
//! (`HistorySyncV1`): the old 1024-bit v1 window is not carried over —
//! this wire speaks only the 4096-bit layout, gated by `CAP_V19`.
//!
//! Layout (all integers big-endian):
//!
//! ```text
//! u64  max_contiguous_seq
//! lp   received_seq_bitmap (<= MAX_BITMAP_BYTES)
//! u32  caps
//! 32B  history_hash
//! ```
//!
//! The hash lets the sender prove sync state in one compare instead of
//! inferring it from retransmit behaviour: the receive view below
//! `max_contiguous_seq` is contiguous by construction, so both sides
//! compute the identical fingerprint — the receiver from its seq ledger,
//! the sender from the fact that its own outbound seqs are gap-free
//! (1..next_seq-1). Equal hashes = provably in sync; unequal = keep
//! repairing via the bitmap. The receive view doubles as the delivery
//! ACK: covered outbound seqs are acknowledged.

use sha2::{Digest, Sha256};

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

// Caps declared in the bounds catalog.
pub use crate::limits::resync::{BITMAP_BITS, DEEP_WINDOW, MAX_BITMAP_BYTES};

pub const HASH_BYTES: usize = 32;

/// Domain separator for the history hash (`S6HIST2` on the old wire).
const HASH_DOMAIN: &[u8] = b"S7HIST1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResyncReq {
    pub max_contiguous_seq: u64,
    pub received_seq_bitmap: Vec<u8>,
    pub caps: u32,
    pub history_hash: [u8; HASH_BYTES],
}

/// First seq of the deep window folded into the history hash.
pub fn deep_base(max_contiguous_seq: u64) -> u64 {
    max_contiguous_seq
        .saturating_sub(DEEP_WINDOW)
        .saturating_add(1)
        .max(1)
}

/// Fingerprint of a receive view. `deep_seqs` are the known seqs in
/// `[deep_base, max_contiguous_seq]`, sorted ascending. For a complete
/// history that is every seq in the range; [`hash_contiguous`] encodes
/// that case without materialising the list.
pub fn history_hash(max_contiguous_seq: u64, bitmap: &[u8], deep_seqs: &[u64]) -> [u8; HASH_BYTES] {
    let mut deep = Sha256::new();
    for seq in deep_seqs {
        deep.update(seq.to_be_bytes());
    }
    let deep_digest = deep.finalize();

    let mut md = Sha256::new();
    md.update(HASH_DOMAIN);
    md.update(max_contiguous_seq.to_be_bytes());
    md.update((bitmap.len() as u32).to_be_bytes());
    md.update(bitmap);
    md.update(deep_digest);
    md.finalize().into()
}

/// Hash for the hole-free case: every seq in the deep window present.
pub fn hash_contiguous(max_contiguous_seq: u64, bitmap: &[u8]) -> [u8; HASH_BYTES] {
    let base = deep_base(max_contiguous_seq);
    let mut deep = Sha256::new();
    let mut seq = base;
    while seq <= max_contiguous_seq {
        deep.update(seq.to_be_bytes());
        seq += 1;
    }
    let deep_digest = deep.finalize();

    let mut md = Sha256::new();
    md.update(HASH_DOMAIN);
    md.update(max_contiguous_seq.to_be_bytes());
    md.update((bitmap.len() as u32).to_be_bytes());
    md.update(bitmap);
    md.update(deep_digest);
    md.finalize().into()
}

impl WirePayload for ResyncReq {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        if self.received_seq_bitmap.len() > MAX_BITMAP_BYTES {
            return Err(WireError::TooLarge {
                at: "resync.bitmap",
                size: self.received_seq_bitmap.len(),
                max: MAX_BITMAP_BYTES,
            });
        }
        let mut w = Writer::new();
        w.u64be(self.max_contiguous_seq);
        w.lp(&self.received_seq_bitmap);
        w.u32be(self.caps);
        w.raw(&self.history_hash);
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let max_contiguous_seq = r.u64be("resync.max_seq")?;
        let bitmap = r.lp(MAX_BITMAP_BYTES as u64, "resync.bitmap")?.to_vec();
        let caps = r.u32be("resync.caps")?;
        let hash: [u8; HASH_BYTES] = r
            .take(HASH_BYTES, "resync.history_hash")?
            .try_into()
            .map_err(|_| WireError::Truncated {
                at: "resync.history_hash",
            })?;
        r.expect_end("resync")?;
        Ok(Self {
            max_contiguous_seq,
            received_seq_bitmap: bitmap,
            caps,
            history_hash: hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_base_clamps_to_one() {
        assert_eq!(deep_base(0), 1);
        assert_eq!(deep_base(1), 1);
        assert_eq!(deep_base(DEEP_WINDOW), 1);
        assert_eq!(deep_base(DEEP_WINDOW + 1), 2);
        assert_eq!(deep_base(10_000), 10_000 - DEEP_WINDOW + 1);
    }

    #[test]
    fn contiguous_hash_matches_materialised() {
        let max = 100u64;
        let bitmap = vec![0b1010_0001u8];
        let deep: Vec<u64> = (deep_base(max)..=max).collect();
        assert_eq!(
            history_hash(max, &bitmap, &deep),
            hash_contiguous(max, &bitmap)
        );
    }

    #[test]
    fn hash_changes_with_view() {
        let a = hash_contiguous(100, &[]);
        let b = hash_contiguous(101, &[]);
        let c = hash_contiguous(100, &[1u8]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
