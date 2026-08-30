//! `PREF` payload: the sender's receive
//! preferences — media auto-download, listen-saver (longer catch-up
//! retention), and the inactivity-erase horizon.

use crate::bin::{Reader, Writer};
use crate::error::WireError;
use crate::WirePayload;

pub const VERSION: u8 = 1;
pub const FLAG_RECEIVE_MEDIA: u32 = 1 << 0;
pub const FLAG_LISTEN_SAVER: u32 = 1 << 1;

// Cap declared in the bounds catalog.
pub use crate::limits::pref::MAX_ERASE_HOURS;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pref {
    pub receive_media: bool,
    pub listen_saver: bool,
    pub inactivity_erase_hours: u32,
}

impl WirePayload for Pref {
    fn encode_payload(&self) -> Result<Vec<u8>, WireError> {
        if self.inactivity_erase_hours > MAX_ERASE_HOURS {
            return Err(WireError::BadField {
                at: "pref.inactivity_erase_hours",
                detail: format!("{} exceeds {MAX_ERASE_HOURS}", self.inactivity_erase_hours),
            });
        }
        let mut flags = 0u32;
        if self.receive_media {
            flags |= FLAG_RECEIVE_MEDIA;
        }
        if self.listen_saver {
            flags |= FLAG_LISTEN_SAVER;
        }
        let mut w = Writer::with_capacity(9);
        w.u8(VERSION);
        w.u32be(flags);
        w.u32be(self.inactivity_erase_hours);
        Ok(w.finish())
    }

    fn decode_payload(bytes: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(bytes);
        let version = r.u8("pref.version")?;
        if version != VERSION {
            return Err(WireError::BadVersion {
                at: "pref",
                version,
            });
        }
        let flags = r.u32be("pref.flags")?;
        let hours = r.u32be("pref.erase_hours")?;
        r.expect_end("pref")?;
        if hours > MAX_ERASE_HOURS {
            return Err(WireError::BadField {
                at: "pref.inactivity_erase_hours",
                detail: format!("{hours} exceeds {MAX_ERASE_HOURS}"),
            });
        }
        Ok(Self {
            receive_media: flags & FLAG_RECEIVE_MEDIA != 0,
            listen_saver: flags & FLAG_LISTEN_SAVER != 0,
            inactivity_erase_hours: hours,
        })
    }
}
