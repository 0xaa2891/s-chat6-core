//! `TYPING` payload: one flag byte, no
//! timestamp. ~5 s RAM TTL, ≥3 s send interval, quiet frames, send on
//! start/stop transitions only — those rules live in the core-side typing
//! module; the wire carries only the flag.

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

pub const VERSION: u8 = 1;
pub const FLAG_TYPING: u8 = 1 << 0;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Typing {
    pub typing: bool,
}

impl WirePayload for Typing {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        let mut w = Writer::with_capacity(2);
        w.u8(VERSION);
        w.u8(if self.typing { FLAG_TYPING } else { 0 });
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("typing.version")?;
        if version != VERSION {
            return Err(WireError::BadVersion {
                at: "typing",
                version,
            });
        }
        let flags = r.u8("typing.flags")?;
        r.expect_end("typing")?;
        Ok(Self {
            typing: flags & FLAG_TYPING != 0,
        })
    }
}
