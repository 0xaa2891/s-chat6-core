//! Hand-rolled binary codec primitives.
//!
//! All multi-byte integers are big-endian. `lp` is a u32be length prefix.
//! No serde on the wire — these two types are the only way payloads are
//! written or read.

use crate::error::WireError;

/// Append-only big-endian writer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16be(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u32be(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64be(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// u32be length prefix + bytes.
    pub fn lp(&mut self, v: &[u8]) {
        self.u32be(v.len() as u32);
        self.raw(v);
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Cursor reader. Every method is bounds-checked; `lp` takes an explicit
/// per-field ceiling so a hostile length prefix cannot force an oversized
/// allocation.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    /// Invariant: returns exactly `n` bytes on success, which is what
    /// makes the fixed-width integer readers' `try_into().unwrap()`
    /// infallible.
    pub fn take(&mut self, n: usize, at: &'static str) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated { at });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self, at: &'static str) -> Result<u8, WireError> {
        Ok(self.take(1, at)?[0])
    }

    pub fn u16be(&mut self, at: &'static str) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.take(2, at)?.try_into().unwrap()))
    }

    pub fn u32be(&mut self, at: &'static str) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.take(4, at)?.try_into().unwrap()))
    }

    pub fn u64be(&mut self, at: &'static str) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.take(8, at)?.try_into().unwrap()))
    }

    /// u32be-prefixed blob, bounded by `max`.
    pub fn lp(&mut self, max: u64, at: &'static str) -> Result<&'a [u8], WireError> {
        let len = u64::from(self.u32be(at)?);
        if len > max {
            return Err(WireError::BadLength { at, len, max });
        }
        self.take(len as usize, at)
    }

    /// Read the next u32be without advancing (the attach-head inline
    /// disambiguation peeks the length prefix to tell caption from blob).
    pub fn peek_u32be(&self, at: &'static str) -> Result<u32, WireError> {
        if self.remaining() < 4 {
            return Err(WireError::Truncated { at });
        }
        Ok(u32::from_be_bytes(
            self.buf[self.pos..self.pos + 4].try_into().unwrap(),
        ))
    }

    pub fn expect_end(&self, at: &'static str) -> Result<(), WireError> {
        if self.remaining() != 0 {
            return Err(WireError::Trailing {
                at,
                extra: self.remaining(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_big_endian() {
        let mut w = Writer::new();
        w.u8(0x01);
        w.u16be(0x0203);
        w.u32be(0x04050607);
        w.u64be(0x08090a0b0c0d0e0f);
        let bytes = w.finish();
        assert_eq!(
            bytes,
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f
            ]
        );
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8("t").unwrap(), 0x01);
        assert_eq!(r.u16be("t").unwrap(), 0x0203);
        assert_eq!(r.u32be("t").unwrap(), 0x04050607);
        assert_eq!(r.u64be("t").unwrap(), 0x08090a0b0c0d0e0f);
        r.expect_end("t").unwrap();
    }

    #[test]
    fn lp_round_trip_and_bounds() {
        let mut w = Writer::new();
        w.lp(b"abc");
        w.lp(b"");
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.lp(10, "a").unwrap(), b"abc");
        assert_eq!(r.lp(10, "b").unwrap(), b"");
        r.expect_end("t").unwrap();

        // Over-ceiling prefix is rejected before any allocation.
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.lp(2, "a"),
            Err(WireError::BadLength { len: 3, max: 2, .. })
        ));
    }

    #[test]
    fn truncation_and_trailing_detected() {
        let mut r = Reader::new(&[0x01]);
        assert!(matches!(
            r.u32be("t"),
            Err(WireError::Truncated { at: "t" })
        ));
        let mut r = Reader::new(&[0x01, 0x02]);
        r.u8("t").unwrap();
        assert!(matches!(
            r.expect_end("t"),
            Err(WireError::Trailing { extra: 1, .. })
        ));
    }
}
