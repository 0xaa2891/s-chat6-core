//! Outer wire record framing (current flags only).
//!
//! Layout on the wire:
//!
//! ```text
//! [0x05|0x06] ‖ u16be(record_len) ‖ record                  (sized quiet/alert)
//! [0xFC|0xFD] ‖ u16be(intro_len) ‖ intro ‖ u16be(record_len) ‖ record
//! ```
//!
//! `record_len` must be exactly one of [`RECORD_BUCKETS`] and `record[0]` must
//! be [`VERSION_V2`]. Legacy decode-only flags
//! (`0x00/0x01/0x02/0x03/0x04/0xFE/0xFF`, `'S'` magic) are **dropped** — the
//! rebuild breaks wire compatibility on purpose. Fail closed: anything unknown
//! or malformed terminates the connection before any crypto is touched.

use tokio::io::{AsyncRead, AsyncReadExt};

use super::error::TransportError;

// The record layer (buckets, version byte, CSPRNG padding) lives in
// `wire::frame`; re-exported here so transport call sites
// keep one import path.
pub use crate::wire::frame::{
    build_record, is_bucket, parse_record, MAX_RECORD_BYTES, RECORD_BUCKETS, VERSION_V2,
};

pub const FLAG_SIZED_QUIET: u8 = 0x05;
pub const FLAG_SIZED_ALERT: u8 = 0x06;
pub const INTRO_SIZED_QUIET: u8 = 0xFC;
pub const INTRO_SIZED_ALERT: u8 = 0xFD;

// Caps declared in the bounds catalog.
pub use crate::limits::transport::{MAX_CONN_BYTES, MAX_CONN_PACKETS, MAX_INTRO_BYTES};

/// One decoded inbound record. Transport never sees plaintext: the `frame`
/// here is still the (later, libsignal) ciphertext record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueFrame {
    pub intro: Option<Vec<u8>>,
    pub frame: Vec<u8>,
    /// Alert flag: surfaces to the client as an "arrival" (notification
    /// decision) without decrypting anything.
    pub alert: bool,
}

/// Encode one record with the current sized flags.
pub fn pack(intro: Option<&[u8]>, frame: &[u8], alert: bool) -> Result<Vec<u8>, TransportError> {
    if !is_bucket(frame.len()) {
        return Err(TransportError::MalformedFrame(format!(
            "frame length {} is not a record bucket",
            frame.len()
        )));
    }
    if frame.first().copied() != Some(VERSION_V2) {
        return Err(TransportError::MalformedFrame(
            "frame does not start with VERSION_V2".into(),
        ));
    }
    let mut out = match intro {
        None => {
            let mut out = Vec::with_capacity(3 + frame.len());
            out.push(if alert {
                FLAG_SIZED_ALERT
            } else {
                FLAG_SIZED_QUIET
            });
            out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
            out
        }
        Some(intro) => {
            if intro.is_empty() || intro.len() > MAX_INTRO_BYTES {
                return Err(TransportError::MalformedFrame(format!(
                    "intro length {} out of range",
                    intro.len()
                )));
            }
            let mut out = Vec::with_capacity(5 + intro.len() + frame.len());
            out.push(if alert {
                INTRO_SIZED_ALERT
            } else {
                INTRO_SIZED_QUIET
            });
            out.extend_from_slice(&(intro.len() as u16).to_be_bytes());
            out.extend_from_slice(intro);
            out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
            out
        }
    };
    out.extend_from_slice(frame);
    Ok(out)
}

/// Read one frame from a stream. Returns `Ok(None)` on clean EOF before any
/// byte of a next frame. Malformed input is an error — the caller drops the
/// connection (fail closed).
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<OpaqueFrame>, TransportError> {
    let mut flag = [0u8; 1];
    match reader.read_exact(&mut flag).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let flag = flag[0];
    let (alert, has_intro) = match flag {
        FLAG_SIZED_QUIET => (false, false),
        FLAG_SIZED_ALERT => (true, false),
        INTRO_SIZED_QUIET => (false, true),
        INTRO_SIZED_ALERT => (true, true),
        other => {
            return Err(TransportError::MalformedFrame(format!(
                "unknown frame flag 0x{other:02x} (legacy flags are dropped)"
            )));
        }
    };

    let intro = if has_intro {
        let intro_len = read_u16(reader).await? as usize;
        if intro_len == 0 || intro_len > MAX_INTRO_BYTES {
            return Err(TransportError::MalformedFrame(format!(
                "intro length {intro_len} out of range"
            )));
        }
        let mut intro = vec![0u8; intro_len];
        reader.read_exact(&mut intro).await?;
        Some(intro)
    } else {
        None
    };

    let frame_len = read_u16(reader).await? as usize;
    if !is_bucket(frame_len) {
        return Err(TransportError::MalformedFrame(format!(
            "record length {frame_len} is not a bucket"
        )));
    }
    let mut frame = vec![0u8; frame_len];
    reader.read_exact(&mut frame).await?;
    if frame.first().copied() != Some(VERSION_V2) {
        return Err(TransportError::MalformedFrame(
            "record version byte is not VERSION_V2".into(),
        ));
    }

    Ok(Some(OpaqueFrame {
        intro,
        frame,
        alert,
    }))
}

async fn read_u16<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u16, TransportError> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(bucket: usize) -> Vec<u8> {
        let mut r = vec![0u8; bucket];
        r[0] = VERSION_V2;
        r
    }

    #[tokio::test]
    async fn roundtrip_quiet_and_alert() {
        for alert in [false, true] {
            let packed = pack(None, &record(256), alert).unwrap();
            let mut slice: &[u8] = &packed;
            let got = read_frame(&mut slice).await.unwrap().unwrap();
            assert_eq!(got.alert, alert);
            assert_eq!(got.intro, None);
            assert_eq!(got.frame, record(256));
        }
    }

    #[tokio::test]
    async fn roundtrip_with_intro() {
        let intro = b"hello-intro";
        let packed = pack(Some(intro), &record(1024), true).unwrap();
        let mut slice: &[u8] = &packed;
        let got = read_frame(&mut slice).await.unwrap().unwrap();
        assert!(got.alert);
        assert_eq!(got.intro.as_deref(), Some(intro.as_slice()));
        assert_eq!(got.frame.len(), 1024);
    }

    #[tokio::test]
    async fn legacy_flags_are_dropped() {
        for flag in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0xFE, 0xFF, b'S'] {
            let bytes = vec![flag; 1];
            let mut slice: &[u8] = &bytes;
            let err = read_frame(&mut slice).await;
            assert!(err.is_err(), "flag 0x{flag:02x} must be rejected");
        }
    }

    #[tokio::test]
    async fn bad_bucket_rejected() {
        let mut bytes = vec![FLAG_SIZED_QUIET];
        bytes.extend_from_slice(&300u16.to_be_bytes()); // not a bucket
        bytes.extend_from_slice(&[0u8; 300]);
        let mut slice: &[u8] = &bytes;
        assert!(read_frame(&mut slice).await.is_err());
    }

    #[tokio::test]
    async fn bad_version_byte_rejected() {
        let mut rec = record(256);
        rec[0] = 1; // legacy version
        let mut bytes = vec![FLAG_SIZED_QUIET];
        bytes.extend_from_slice(&256u16.to_be_bytes());
        bytes.extend_from_slice(&rec);
        let mut slice: &[u8] = &bytes;
        assert!(read_frame(&mut slice).await.is_err());
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let mut slice: &[u8] = &[];
        assert!(read_frame(&mut slice).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn pack_rejects_non_bucket() {
        assert!(pack(None, &[VERSION_V2; 300], false).is_err());
        assert!(pack(None, &[VERSION_V2; 256], false).is_ok());
    }
}
