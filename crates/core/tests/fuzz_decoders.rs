//! Proptest fuzzing of every decoder
//! that touches peer-supplied bytes (the plan's "proptest corpus"
//! alternative to cargo-fuzz).
//!
//! Invariants under test:
//! - No decoder ever panics, on any input.
//! - Decoders fail closed: malformed input is an error, never a
//!   best-effort parse.
//! - `parse_record` returns `Ok` only for well-formed v2 records
//!   (bucket size, version byte, in-bounds length prefix).
//! - `wire::envelope::decode_envelope` increments the I7
//!   `unknown_type_drops()` counter exactly when it returns
//!   `WireError::UnknownType`.
//! - `PairingPayload::decode`+`verify` are fail-closed: arbitrary bytes
//!   never yield a verifiable payload.
//!
//! Any crash found here must be added to `tests/fuzz_corpus/` as a
//! regression entry together with its structural fix (see
//! `fuzz_corpus.rs`).

use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use schat_core::pairing::qr::PairingPayload;
use schat_core::transport::control::ReplyParser;
use schat_core::transport::framing::{self, MAX_INTRO_BYTES};
use schat_core::wire::envelope::{decode_envelope, unknown_type_drops};
use schat_core::wire::frame::{
    self as wire_frame, bucket_for, is_bucket, RECORD_BUCKETS, RECORD_HEADER_BYTES, VERSION_V2,
};
use schat_wire_types::WireError;

/// Largest payload that fits the largest record bucket.
const MAX_PAYLOAD: usize = wire_frame::MAX_RECORD_BYTES - RECORD_HEADER_BYTES;

// ---------------------------------------------------------------------------
// Outer record: parse_record on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn parse_record_never_panics_and_is_strict(
        bytes in prop::collection::vec(any::<u8>(), 0..40 * 1024),
    ) {
        // Err is always fine; Ok only for well-formed records: bucket
        // size, v2 version byte, in-bounds u16be length prefix.
        if let Ok(payload) = wire_frame::parse_record(&bytes) {
            prop_assert!(is_bucket(bytes.len()), "Ok on non-bucket len {:?}", bytes.len());
            prop_assert_eq!(bytes[0], VERSION_V2);
            let declared = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
            prop_assert!(RECORD_HEADER_BYTES + declared <= bytes.len());
            prop_assert_eq!(payload, &bytes[RECORD_HEADER_BYTES..RECORD_HEADER_BYTES + declared]);
        }
    }

    #[test]
    fn build_parse_round_trip(payload in prop::collection::vec(any::<u8>(), 0..=MAX_PAYLOAD)) {
        let rec = wire_frame::build_record(&payload).unwrap();
        prop_assert_eq!(rec.len(), bucket_for(payload.len()).unwrap());
        prop_assert_eq!(rec[0], VERSION_V2);
        prop_assert_eq!(wire_frame::parse_record(&rec).unwrap(), payload.as_slice());
    }

    #[test]
    fn build_record_rejects_oversize(len in (MAX_PAYLOAD + 1)..(MAX_PAYLOAD + 8192)) {
        let payload = vec![0u8; len];
        let too_large = matches!(wire_frame::build_record(&payload), Err(WireError::TooLarge { .. }));
        prop_assert!(too_large);
    }
}

// ---------------------------------------------------------------------------
// Stream framing: read_frame over arbitrary byte streams
// ---------------------------------------------------------------------------

/// A well-formed packed frame (random bucket, optional intro).
fn packed_frame() -> impl Strategy<Value = Vec<u8>> {
    (
        prop::option::of(prop::collection::vec(any::<u8>(), 1..64)),
        prop::sample::select(RECORD_BUCKETS.to_vec()),
        any::<bool>(),
    )
        .prop_map(|(intro, bucket, alert)| {
            let mut rec = vec![0u8; bucket];
            rec[0] = VERSION_V2;
            framing::pack(intro.as_deref(), &rec, alert).unwrap()
        })
}

fn stream_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        // Pure garbage.
        prop::collection::vec(any::<u8>(), 0..=4096),
        // One valid frame, possibly with a junk tail.
        (packed_frame(), prop::collection::vec(any::<u8>(), 0..64)).prop_map(|(mut f, tail)| {
            f.extend_from_slice(&tail);
            f
        }),
        // Several valid frames concatenated.
        prop::collection::vec(packed_frame(), 1..4).prop_map(|fs| fs.concat()),
        // A valid frame with one byte flipped.
        (packed_frame(), any::<prop::sample::Index>(), any::<u8>()).prop_map(|(mut f, i, b)| {
            let n = f.len();
            f[i.index(n)] ^= b;
            f
        }),
        // A valid frame truncated anywhere (incl. mid-header).
        (packed_frame(), any::<prop::sample::Index>())
            .prop_map(|(f, i)| { f[..i.index(f.len())].to_vec() }),
        // A valid frame with an oversized intro (near the cap).
        (
            prop::collection::vec(any::<u8>(), 8000..=8300),
            any::<bool>(),
        )
            .prop_map(|(intro, alert)| {
                let mut rec = vec![0u8; 256];
                rec[0] = VERSION_V2;
                // pack() refuses out-of-range intros; build the bytes by
                // hand so the decoder sees them.
                let mut out = vec![if alert { 0xFD } else { 0xFC }];
                out.extend_from_slice(&(intro.len() as u16).to_be_bytes());
                out.extend_from_slice(&intro);
                out.extend_from_slice(&256u16.to_be_bytes());
                out.extend_from_slice(&rec);
                out
            }),
    ]
}

/// Pump frames until EOF or error; every yielded frame must be
/// well-formed and the reader must make progress (no past-bounds reads,
/// no infinite loop).
async fn check_stream(bytes: &[u8]) {
    let mut cur: &[u8] = bytes;
    for _ in 0..16 {
        let before = cur.len();
        match framing::read_frame(&mut cur).await {
            Ok(Some(f)) => {
                assert!(is_bucket(f.frame.len()), "non-bucket frame yielded");
                assert_eq!(f.frame[0], VERSION_V2, "bad version yielded");
                if let Some(intro) = &f.intro {
                    assert!(!intro.is_empty() && intro.len() <= MAX_INTRO_BYTES);
                }
                assert!(cur.len() < before, "no progress made");
            }
            Ok(None) => {
                assert!(cur.is_empty(), "clean EOF only at end of input");
                break;
            }
            Err(_) => break, // fail closed: caller drops the connection
        }
    }
}

#[test]
fn read_frame_never_panics_on_arbitrary_streams() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mut runner = TestRunner::new(ProptestConfig::with_cases(2048));
    runner
        .run(&stream_strategy(), |bytes| {
            rt.block_on(check_stream(&bytes));
            Ok(())
        })
        .unwrap();
}

// ---------------------------------------------------------------------------
// Inner envelope: decode_envelope + the I7 unknown-type counter
// ---------------------------------------------------------------------------

/// Valid envelope header with an arbitrary type code and empty payload.
fn envelope_with_code(code: u8) -> Vec<u8> {
    let mut bytes = vec![code];
    bytes.extend_from_slice(&[1u8; 16]); // msg_id
    bytes.extend_from_slice(&3u64.to_be_bytes()); // app_seq
    bytes.extend_from_slice(&4u64.to_be_bytes()); // sent_at
    bytes.push(0); // no ref_id
    bytes.extend_from_slice(&0u32.to_be_bytes()); // lp payload (empty)
    bytes
}

fn envelope_strategy() -> impl Strategy<Value = Vec<u8>> {
    use schat_core::wire::envelope::{Envelope, Payload};
    let valid = any::<u64>().prop_map(|seq| {
        Envelope {
            msg_id: [7u8; 16],
            app_seq: seq,
            sent_at: 1_700_000_000,
            ref_id: None,
            payload: Payload::Typing(schat_wire_types::typing::Typing { typing: true }),
        }
        .encode()
        .unwrap()
    });
    prop_oneof![
        prop::collection::vec(any::<u8>(), 0..=4200),
        any::<u8>().prop_map(envelope_with_code),
        // Valid envelope with one byte mutated anywhere.
        (valid, any::<prop::sample::Index>(), any::<u8>()).prop_map(|(mut e, i, b)| {
            let n = e.len();
            e[i.index(n)] ^= b;
            e
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn decode_envelope_never_panics_and_counts_unknown_types(bytes in envelope_strategy()) {
        let before = unknown_type_drops();
        let result = decode_envelope(&bytes);
        let after = unknown_type_drops();
        match result {
            Err(WireError::UnknownType { .. }) => {
                prop_assert_eq!(after, before + 1, "I7 drop not counted");
            }
            other => {
                prop_assert_eq!(after, before, "counter moved without UnknownType: {:?}", other);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Control-port reply parser
// ---------------------------------------------------------------------------

fn control_input_strategy() -> impl Strategy<Value = Vec<String>> {
    let arbitrary_lines = prop::collection::vec(any::<u8>(), 0..=2048)
        .prop_map(|b| String::from_utf8_lossy(&b).into_owned());
    let protocolish_line = (
        prop::num::u16::ANY,
        prop::sample::select(vec![' ', '-', '+', '=', '\t']),
        prop::collection::vec(any::<char>(), 0..40),
    )
        .prop_map(|(code, sep, tail)| {
            format!("{code:03}{sep}{}", tail.into_iter().collect::<String>())
        });
    prop_oneof![
        arbitrary_lines.prop_map(|s| s.split('\n').map(str::to_string).collect::<Vec<_>>()),
        prop::collection::vec(protocolish_line, 0..16),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn control_reply_parser_never_panics(lines in control_input_strategy()) {
        let mut parser = ReplyParser::new();
        for line in &lines {
            match parser.feed(line) {
                Ok(Some(reply)) => {
                    // A completed reply always carries the 3-digit code
                    // that opened it.
                    prop_assert!(reply.code <= 999);
                }
                Ok(None) => {}
                Err(_) => break, // fail closed: caller closes the connection
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pairing QR payload
// ---------------------------------------------------------------------------

fn qr_strategy() -> impl Strategy<Value = Vec<u8>> {
    let labelled = prop::collection::vec(any::<u8>(), 0..=2048).prop_map(|mut tail| {
        let mut v = b"SPAIR7\x01".to_vec();
        v.append(&mut tail);
        v
    });
    prop_oneof![prop::collection::vec(any::<u8>(), 0..=8300), labelled,]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn pairing_payload_decode_is_fail_closed(bytes in qr_strategy()) {
        // Never panics; arbitrary bytes may at most decode
        // *structurally* — cryptographic verification must still fail.
        if let Ok(payload) = PairingPayload::decode(&bytes) {
            prop_assert!(payload.verify(1_800_000_000, true).is_err());
            prop_assert!(payload.verify(1_800_000_000, false).is_err());
        }
    }
}
