//! Outer wire record: the fixed-bucket, CSPRNG-padded record
//! every frame on the wire is built from.
//!
//! ```text
//! u8 version (=2) ‖ u16be payload_len ‖ payload ‖ CSPRNG padding
//! ```
//!
//! The record length is always exactly one of [`RECORD_BUCKETS`]. Fail
//! closed: unknown version, wrong size, or a length prefix that overruns
//! the record is an error **before any crypto is touched**. Padding bytes
//! are random on build and intentionally *not* inspected on parse — a
//! zero-check would hand a traffic-shaping adversary a distinguishing
//! oracle.

use rand::RngCore;
use schat_wire_types::WireError;

pub const VERSION_V2: u8 = 2;

/// Wire record size buckets.
pub const RECORD_BUCKETS: [usize; 6] = [256, 512, 1024, 4096, 16384, 32768];
pub const MAX_RECORD_BYTES: usize = 32768;

/// Record header: version byte + u16be length.
pub const RECORD_HEADER_BYTES: usize = 3;

pub fn is_bucket(len: usize) -> bool {
    RECORD_BUCKETS.contains(&len)
}

/// Smallest bucket that fits a payload, if any.
pub fn bucket_for(payload_len: usize) -> Option<usize> {
    let inner = RECORD_HEADER_BYTES + payload_len;
    RECORD_BUCKETS.into_iter().find(|b| inner <= *b)
}

/// Build a bucket-sized v2 record around `payload`: version byte, u16be
/// length, payload, CSPRNG padding to the smallest fitting bucket.
pub fn build_record(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    let bucket = bucket_for(payload.len()).ok_or(WireError::TooLarge {
        at: "record",
        size: payload.len(),
        max: MAX_RECORD_BYTES - RECORD_HEADER_BYTES,
    })?;
    let mut rec = vec![0u8; bucket];
    rec[0] = VERSION_V2;
    rec[1..3].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    rec[3..3 + payload.len()].copy_from_slice(payload);
    rand::rng().fill_bytes(&mut rec[3 + payload.len()..]);
    Ok(rec)
}

/// Parse a v2 record back into its payload. Fail closed: bad version,
/// non-bucket size, or an overrunning length prefix is an error.
pub fn parse_record(record: &[u8]) -> Result<&[u8], WireError> {
    if record.first().copied() != Some(VERSION_V2) {
        return Err(WireError::BadVersion {
            at: "record",
            version: record.first().copied().unwrap_or(0),
        });
    }
    if !is_bucket(record.len()) {
        return Err(WireError::BadLength {
            at: "record",
            len: record.len() as u64,
            max: MAX_RECORD_BYTES as u64,
        });
    }
    let len = u16::from_be_bytes([record[1], record[2]]) as usize;
    if RECORD_HEADER_BYTES + len > record.len() {
        return Err(WireError::BadLength {
            at: "record.payload",
            len: len as u64,
            max: (record.len() - RECORD_HEADER_BYTES) as u64,
        });
    }
    Ok(&record[3..3 + len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_bucket() {
        for (i, bucket) in RECORD_BUCKETS.into_iter().enumerate() {
            // Largest payload that fits this bucket.
            let payload = vec![0xabu8; bucket - RECORD_HEADER_BYTES];
            let rec = build_record(&payload).unwrap();
            assert_eq!(rec.len(), bucket);
            assert_eq!(rec[0], VERSION_V2);
            assert_eq!(parse_record(&rec).unwrap(), payload.as_slice());

            // Smallest payload that lands in this bucket (one over the
            // previous bucket's capacity).
            let small = if i == 0 {
                Vec::new()
            } else {
                vec![7u8; RECORD_BUCKETS[i - 1] - RECORD_HEADER_BYTES + 1]
            };
            let rec = build_record(&small).unwrap();
            assert_eq!(rec.len(), bucket);
            assert_eq!(parse_record(&rec).unwrap(), small.as_slice());
        }
    }

    #[test]
    fn padding_is_random_not_zero() {
        let rec = build_record(b"x").unwrap();
        // CSPRNG padding: all-zero padding would be a (vanishingly
        // unlikely) fluke — the zero-padded shape must be gone.
        assert!(rec[3 + 1..].iter().any(|b| *b != 0));
        // Two builds of the same payload differ in the padding region.
        let rec2 = build_record(b"x").unwrap();
        assert_ne!(rec[4..], rec2[4..]);
    }

    #[test]
    fn fail_closed_on_bad_input() {
        // Unknown version.
        let mut rec = build_record(b"abc").unwrap();
        rec[0] = 1;
        assert!(matches!(
            parse_record(&rec),
            Err(WireError::BadVersion { version: 1, .. })
        ));
        // Non-bucket size.
        let fresh = build_record(b"abc").unwrap();
        assert!(matches!(
            parse_record(&fresh[..100]),
            Err(WireError::BadLength { .. })
        ));
        // Overrunning length prefix.
        let mut rec = build_record(b"abc").unwrap();
        rec[1..3].copy_from_slice(&(300u16).to_be_bytes());
        assert!(matches!(
            parse_record(&rec),
            Err(WireError::BadLength { .. })
        ));
        // Empty input.
        assert!(parse_record(&[]).is_err());
        // Oversize payload.
        assert!(matches!(
            build_record(&vec![0u8; MAX_RECORD_BYTES]),
            Err(WireError::TooLarge { .. })
        ));
    }

    #[test]
    fn parse_never_panics_on_arbitrary_bytes() {
        // Poor man's fuzz over structured garbage: every prefix of a valid
        // record plus random tails.
        let rec = build_record(b"hello").unwrap();
        for cut in 0..rec.len() {
            let _ = parse_record(&rec[..cut]);
        }
        let mut rng = rand::rng();
        for _ in 0..256 {
            let n = (rand::Rng::random_range(&mut rng, 0..=2 * MAX_RECORD_BYTES)) as usize;
            let mut buf = vec![0u8; n];
            rng.fill_bytes(&mut buf);
            let _ = parse_record(&buf);
        }
    }
}
