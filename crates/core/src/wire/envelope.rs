//! Inner envelope glue: the typed payloads live in `schat-wire-types`
//! (shared, serde-free); this module adds the core-side I7 drop counter.
//!
//! I7: an envelope whose type code this build does not know (codes
//! 12/13 are unassigned) is dropped, counted, and logged — the session
//! is never affected.

use std::sync::atomic::{AtomicU64, Ordering};

use schat_wire_types::WireError;

pub use schat_wire_types::envelope::{
    Envelope, EnvelopeType, Payload, MAX_ENVELOPE_BYTES, MSG_ID_BYTES,
};
pub use schat_wire_types::{caps, WirePayload};

static UNKNOWN_TYPE_DROPS: AtomicU64 = AtomicU64::new(0);

/// Decode an envelope from decrypted plaintext. Unknown type codes are
/// counted + logged here so every caller gets the I7 behavior for free;
/// the error still propagates (the caller drops the envelope).
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, WireError> {
    Envelope::decode(bytes).inspect_err(|e| {
        if let WireError::UnknownType {
            code,
            msg_id,
            app_seq,
        } = e
        {
            let n = UNKNOWN_TYPE_DROPS.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                code,
                msg_id = %crate::store::hex_encode(msg_id),
                app_seq,
                total = n,
                "I7: unknown envelope type dropped; session unaffected"
            );
        }
    })
}

/// Total unknown-type envelopes dropped since process start (I7 counter).
pub fn unknown_type_drops() -> u64 {
    UNKNOWN_TYPE_DROPS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_type_counted_and_session_safe() {
        let before = unknown_type_drops();
        // Type code 12 (unassigned) with an otherwise valid header.
        let mut bytes = vec![12u8];
        bytes.extend_from_slice(&[1u8; 16]);
        bytes.extend_from_slice(&3u64.to_be_bytes());
        bytes.extend_from_slice(&4u64.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        let err = decode_envelope(&bytes).unwrap_err();
        assert!(matches!(err, WireError::UnknownType { code: 12, .. }));
        assert_eq!(unknown_type_drops(), before + 1);
    }

    #[test]
    fn known_type_not_counted() {
        let before = unknown_type_drops();
        let env = Envelope {
            msg_id: [9u8; 16],
            app_seq: 1,
            sent_at: 1,
            ref_id: None,
            payload: Payload::Typing(schat_wire_types::typing::Typing { typing: true }),
        };
        let bytes = env.encode().unwrap();
        decode_envelope(&bytes).unwrap();
        assert_eq!(unknown_type_drops(), before);
    }
}
