//! Safety code + relationship id derivation.
//!
//! Safety code (SAS digits): `SHA-256("s//chat6-v7 SAS" ‖ min(ik_A, ik_B) ‖
//! max(ik_A, ik_B) ‖ nonce_A ‖ nonce_B)` → 8 decimal digits, where A/B
//! are ordered by the identity-key bytes (so the nonces line up on both
//! sides). Both sides compute independently over the two pairing
//! payloads. The number is for optional out-of-band comparison; pairing
//! does not wait on a confirm step.
//!
//! Relationship id: `SHA-256("s//chat6-v7 REL" ‖ min(ik) ‖ max(ik))`. Both
//! sides derive it independently; it keys the session stores and the
//! `ProtocolAddress`.

use sha2::{Digest, Sha256};

const SAS_LABEL: &[u8] = b"s//chat6-v7 SAS";
const RELATIONSHIP_LABEL: &[u8] = b"s//chat6-v7 REL";

fn ordered<'a>(a: &'a [u8], b: &'a [u8]) -> (&'a [u8], &'a [u8]) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

pub fn relationship_id(identity_a: &[u8], identity_b: &[u8]) -> [u8; 32] {
    let (min, max) = ordered(identity_a, identity_b);
    let mut h = Sha256::new();
    h.update(RELATIONSHIP_LABEL);
    h.update(min);
    h.update(max);
    h.finalize().into()
}

/// 8 decimal digits, zero-padded (mod-10^8 reduction of the first 8
/// digest bytes).
/// Display-only safety code — not a pairing gate.
pub fn sas(identity_a: &[u8], nonce_a: &[u8; 32], identity_b: &[u8], nonce_b: &[u8; 32]) -> String {
    // Callers reject self-pairing (identical identity keys), so the
    // ordering is never ambiguous in practice.
    let (min_ik, max_ik, min_nonce, max_nonce) = if identity_a <= identity_b {
        (identity_a, identity_b, nonce_a, nonce_b)
    } else {
        (identity_b, identity_a, nonce_b, nonce_a)
    };
    let mut h = Sha256::new();
    h.update(SAS_LABEL);
    h.update(min_ik);
    h.update(max_ik);
    h.update(min_nonce);
    h.update(max_nonce);
    let digest = h.finalize();
    let n = u64::from_be_bytes(digest[..8].try_into().expect("8 of 32")) % 100_000_000;
    format!("{n:08}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_id_is_order_independent() {
        let a = [1u8; 33];
        let b = [2u8; 33];
        assert_eq!(relationship_id(&a, &b), relationship_id(&b, &a));
        assert_ne!(relationship_id(&a, &b), relationship_id(&a, &a));
    }

    #[test]
    fn sas_is_symmetric_and_8_digits() {
        let a = [3u8; 33];
        let b = [4u8; 33];
        let na = [5u8; 32];
        let nb = [6u8; 32];
        let forward = sas(&a, &na, &b, &nb);
        let reverse = sas(&b, &nb, &a, &na);
        assert_eq!(forward, reverse);
        assert_eq!(forward.len(), 8);
        assert!(forward.chars().all(|c| c.is_ascii_digit()));
        // Different nonces → different SAS.
        assert_ne!(forward, sas(&a, &na, &b, &[9u8; 32]));
    }
}
