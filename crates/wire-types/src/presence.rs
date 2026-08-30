//! `PRESENCE` payload: one flag byte, no
//! timestamp. The receiver anchors TTLs to its own clock so a peer cannot
//! extend or backdate their "in app" state, and there is nothing to
//! persist. RAM-only on receipt; send only on an opted-in
//! transition (need-to-send).

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

pub const VERSION: u8 = 1;
pub const FLAG_IN_APP: u8 = 1 << 0;
pub const FLAG_DND: u8 = 1 << 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Presence {
    pub in_app: bool,
    pub do_not_disturb: bool,
}

impl WirePayload for Presence {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        let mut flags = 0u8;
        if self.in_app {
            flags |= FLAG_IN_APP;
        }
        if self.do_not_disturb {
            flags |= FLAG_DND;
        }
        let mut w = Writer::with_capacity(2);
        w.u8(VERSION);
        w.u8(flags);
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("presence.version")?;
        if version != VERSION {
            return Err(WireError::BadVersion {
                at: "presence",
                version,
            });
        }
        let flags = r.u8("presence.flags")?;
        r.expect_end("presence")?;
        Ok(Self {
            in_app: flags & FLAG_IN_APP != 0,
            do_not_disturb: flags & FLAG_DND != 0,
        })
    }
}
