//! Checked-in fuzz regression corpus.
//!
//! Every file in `tests/fuzz_corpus/` is replayed through ALL decoders
//! that touch peer-supplied bytes (outer record, stream frame, inner
//! envelope, control-port reply, pairing QR) asserting:
//!
//! - no decoder ever panics;
//! - fail-closed behavior: malformed inputs error out, and no corpus
//!   input produces a *verifiable* pairing payload;
//! - per-file expectations pin the intended accept/reject behavior of
//!   the decoder each entry targets.
//!
//! REGRESSION POLICY: any future fuzz crash (from `fuzz_decoders.rs`,
//! cargo-fuzz, or the wild) MUST be minimized, added to
//! `tests/fuzz_corpus/` as a new entry, and listed in `expectations`
//! below — together with the structural (root-cause) fix that makes it
//! pass. Never fix a crash by special-casing the input.

use std::path::PathBuf;

use schat_core::pairing::qr::PairingPayload;
use schat_core::transport::control::ReplyParser;
use schat_core::transport::framing;
use schat_core::wire::envelope::{decode_envelope, unknown_type_drops};
use schat_core::wire::frame as wire_frame;
use schat_wire_types::WireError;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fuzz_corpus")
}

/// What the entry's *target* decoder must do with it.
#[derive(Clone, Copy, Debug)]
enum Expect {
    /// `parse_record` succeeds.
    RecordOk,
    /// `parse_record` fails closed.
    RecordErr,
    /// `read_frame` yields exactly this many frames, then clean EOF.
    FramesOk(usize),
    /// `read_frame` fails closed (never yields a frame).
    FrameErr,
    /// `decode_envelope` succeeds.
    EnvelopeOk,
    /// `decode_envelope` fails with `UnknownType` (and counts it, I7).
    EnvelopeUnknown(u8),
    /// `decode_envelope` fails closed with any other error.
    EnvelopeErr,
    /// `PairingPayload::decode`+`verify` never both succeed.
    QrReject,
    /// The control parser completes a 250 reply carrying one data block.
    ControlDataReply,
    /// The control parser must not panic; any outcome is acceptable.
    ControlAny,
}

fn expectations(name: &str) -> Expect {
    match name {
        "record_valid_256.bin" | "record_bucket_max_valid.bin" => Expect::RecordOk,
        "record_bad_version.bin"
        | "record_len_overrun.bin"
        | "record_header_only.bin"
        | "record_len_255.bin"
        | "record_len_257.bin"
        | "record_len_32769.bin" => Expect::RecordErr,
        "frame_intro_max_valid.bin" => Expect::FramesOk(1),
        "frame_two_records.bin" => Expect::FramesOk(2),
        "frame_sized_truncated.bin" | "frame_intro_oversize.bin" | "frame_legacy_flag.bin" => {
            Expect::FrameErr
        }
        "envelope_msg_valid.bin" => Expect::EnvelopeOk,
        "envelope_unknown_12.bin" => Expect::EnvelopeUnknown(12),
        "envelope_unknown_13.bin" => Expect::EnvelopeUnknown(13),
        "envelope_unknown_255.bin" => Expect::EnvelopeUnknown(255),
        "envelope_msg_truncated.bin" => Expect::EnvelopeErr,
        "qr_flipped_signature.bin" | "qr_flipped_body.bin" | "qr_truncated.bin" => Expect::QrReject,
        "control_multiline_data.bin" => Expect::ControlDataReply,
        "control_garbage.bin" => Expect::ControlAny,
        other => panic!("corpus entry {other:?} has no registered expectation — add it"),
    }
}

/// Run every decoder over `bytes`; assert no panics and fail-closed
/// behavior that holds for *every* corpus entry regardless of target.
async fn replay_all(name: &str, bytes: &[u8]) {
    // 1. Outer record.
    let _ = wire_frame::parse_record(bytes);

    // 2. Stream framing.
    let mut cur: &[u8] = bytes;
    for _ in 0..8 {
        match framing::read_frame(&mut cur).await {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }

    // 3. Inner envelope.
    let _ = decode_envelope(bytes);

    // 4. Control-port reply parser (line-oriented; feed lossy lines).
    let mut parser = ReplyParser::new();
    for line in String::from_utf8_lossy(bytes).split('\n') {
        if parser.feed(line.trim_end_matches('\r')).is_err() {
            break;
        }
    }

    // 5. Pairing QR: no corpus input may ever verify.
    if let Ok(payload) = PairingPayload::decode(bytes) {
        assert!(
            payload.verify(1_800_000_000, true).is_err(),
            "{name}: corpus input verified as a pairing payload"
        );
        assert!(payload.verify(1_800_000_000, false).is_err());
    }
}

fn check_expectation(name: &str, expect: Expect, bytes: &[u8]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    match expect {
        Expect::RecordOk => {
            wire_frame::parse_record(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        Expect::RecordErr => {
            assert!(wire_frame::parse_record(bytes).is_err(), "{name}: parsed");
        }
        Expect::FramesOk(want) => rt.block_on(async {
            let mut cur: &[u8] = bytes;
            let mut got = 0;
            loop {
                match framing::read_frame(&mut cur).await {
                    Ok(Some(_)) => got += 1,
                    Ok(None) => break,
                    Err(e) => panic!("{name}: stream errored after {got} frames: {e}"),
                }
            }
            assert_eq!(got, want, "{name}: frame count");
        }),
        Expect::FrameErr => rt.block_on(async {
            let mut cur: &[u8] = bytes;
            match framing::read_frame(&mut cur).await {
                Err(_) => {}
                other => panic!("{name}: expected stream error, got {other:?}"),
            }
        }),
        Expect::EnvelopeOk => {
            decode_envelope(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        }
        Expect::EnvelopeUnknown(code) => {
            let before = unknown_type_drops();
            match decode_envelope(bytes) {
                Err(WireError::UnknownType { code: got, .. }) => {
                    assert_eq!(got, code, "{name}: wrong unknown code");
                }
                other => panic!("{name}: expected UnknownType({code}), got {other:?}"),
            }
            assert_eq!(unknown_type_drops(), before + 1, "{name}: I7 not counted");
        }
        Expect::EnvelopeErr => match decode_envelope(bytes) {
            Err(WireError::UnknownType { .. }) => panic!("{name}: unexpected UnknownType"),
            Err(_) => {}
            Ok(_) => panic!("{name}: envelope decoded"),
        },
        Expect::QrReject => {
            // Structural decode may succeed (flipped body); verify must not.
            if let Ok(p) = PairingPayload::decode(bytes) {
                assert!(p.verify(1_800_000_000, true).is_err(), "{name}: verified");
            }
        }
        Expect::ControlDataReply => {
            let mut parser = ReplyParser::new();
            let mut reply = None;
            for line in String::from_utf8_lossy(bytes).split('\n') {
                if let Ok(Some(r)) = parser.feed(line.trim_end_matches('\r')) {
                    reply = Some(r);
                    break;
                }
            }
            let reply = reply.unwrap_or_else(|| panic!("{name}: no completed reply"));
            assert_eq!(reply.code, 250, "{name}");
            assert_eq!(reply.data.len(), 1, "{name}: data block lost");
            assert_eq!(reply.get("KEY"), Some("line1\nline2"), "{name}");
        }
        Expect::ControlAny => {}
    }
}

#[test]
fn corpus_replays_through_all_decoders_without_panic() {
    let dir = corpus_dir();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("corpus dir {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    entries.sort();
    assert!(
        entries.len() >= 10,
        "corpus must hold at least 10 entries, found {}",
        entries.len()
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for path in entries {
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let bytes = std::fs::read(&path).unwrap();
        rt.block_on(replay_all(&name, &bytes));
        check_expectation(&name, expectations(&name), &bytes);
    }
}
