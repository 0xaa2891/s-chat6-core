//! Messaging at the boundary: envelope ingest, outbox drain, sweep,
//! text/edit/delete/read, typing, presence, caps, and thread paging.

use crate::store::messages::MessagesRepository;
use crate::{caps, engine, pairing, store};

use super::{hex_id16, CoreError, SchatCore};

#[derive(uniffi::Record, Clone, Debug)]
pub struct MessageRowFfi {
    pub msg_id: String,
    pub rel_id: String,
    pub outgoing: bool,
    pub app_seq: u64,
    pub sent_at: u64,
    pub env_type: u8,
    pub payload: Vec<u8>,
    /// queued | transmitted | acknowledged | failed | received
    pub delivery: String,
    pub edited: bool,
    pub read_at: Option<u64>,
    pub expires_at: Option<u64>,
}

#[derive(uniffi::Record, Clone, Copy, Debug)]
pub struct PresenceFfi {
    pub in_app: bool,
    pub do_not_disturb: bool,
}

/// `EngineEvent` at the boundary: ids hex-encoded, docs as wire bytes.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum EngineEventFfi {
    Message {
        rel_id: String,
        msg_id: String,
    },
    Edited {
        rel_id: String,
        msg_id: String,
    },
    Deleted {
        rel_id: String,
        msg_id: String,
    },
    HistoryCleared {
        rel_id: String,
    },
    Read {
        rel_id: String,
        msg_id: String,
    },
    Typing {
        rel_id: String,
        typing: bool,
    },
    Presence {
        rel_id: String,
        in_app: bool,
        do_not_disturb: bool,
    },
    ProfileUpdated {
        rel_id: String,
    },
    ProfileRequested {
        rel_id: String,
    },
    PeerPrefs {
        rel_id: String,
    },
    Sticker {
        rel_id: String,
        msg_id: String,
        ready: bool,
    },
    StickerPackInstalled {
        pack_id: String,
    },
    StickerPackRefused {
        pack_id: String,
        reason: u8,
    },
    StickerThumbs {
        pack_id: String,
        doc_bytes: Vec<u8>,
    },
    AttachmentProgress {
        rel_id: String,
        head_id: String,
        received: u32,
        total: u32,
    },
    AttachmentComplete {
        rel_id: String,
        head_id: String,
        msg_id: String,
    },
    AttachmentFailed {
        rel_id: String,
        head_id: String,
    },
    AttachmentChunkDropped {
        rel_id: String,
        head_id: String,
    },
    PolicyChanged {
        rel_id: String,
    },
    ContactClosed {
        rel_id: String,
    },
    GapDetected {
        rel_id: String,
    },
}

fn engine_event_ffi(e: &engine::EngineEvent) -> EngineEventFfi {
    use engine::EngineEvent as E;
    let hex = store::hex_encode;
    match e {
        E::Message { rel_id, msg_id } => EngineEventFfi::Message {
            rel_id: rel_id.clone(),
            msg_id: hex(msg_id),
        },
        E::Edited { rel_id, msg_id } => EngineEventFfi::Edited {
            rel_id: rel_id.clone(),
            msg_id: hex(msg_id),
        },
        E::Deleted { rel_id, msg_id } => EngineEventFfi::Deleted {
            rel_id: rel_id.clone(),
            msg_id: hex(msg_id),
        },
        E::HistoryCleared { rel_id } => EngineEventFfi::HistoryCleared {
            rel_id: rel_id.clone(),
        },
        E::Read { rel_id, msg_id } => EngineEventFfi::Read {
            rel_id: rel_id.clone(),
            msg_id: hex(msg_id),
        },
        E::Typing { rel_id, typing } => EngineEventFfi::Typing {
            rel_id: rel_id.clone(),
            typing: *typing,
        },
        E::Presence {
            rel_id,
            in_app,
            do_not_disturb,
        } => EngineEventFfi::Presence {
            rel_id: rel_id.clone(),
            in_app: *in_app,
            do_not_disturb: *do_not_disturb,
        },
        E::ProfileUpdated { rel_id } => EngineEventFfi::ProfileUpdated {
            rel_id: rel_id.clone(),
        },
        E::ProfileRequested { rel_id } => EngineEventFfi::ProfileRequested {
            rel_id: rel_id.clone(),
        },
        E::PeerPrefs { rel_id } => EngineEventFfi::PeerPrefs {
            rel_id: rel_id.clone(),
        },
        E::Sticker {
            rel_id,
            msg_id,
            ready,
        } => EngineEventFfi::Sticker {
            rel_id: rel_id.clone(),
            msg_id: hex(msg_id),
            ready: *ready,
        },
        E::StickerPackInstalled { pack_id } => EngineEventFfi::StickerPackInstalled {
            pack_id: hex(pack_id),
        },
        E::StickerPackRefused { pack_id, reason } => EngineEventFfi::StickerPackRefused {
            pack_id: hex(pack_id),
            reason: *reason,
        },
        E::StickerThumbs { pack_id, doc } => EngineEventFfi::StickerThumbs {
            pack_id: hex(pack_id),
            doc_bytes: doc.encode().unwrap_or_default(),
        },
        E::AttachmentProgress {
            rel_id,
            head_id,
            received,
            total,
        } => EngineEventFfi::AttachmentProgress {
            rel_id: rel_id.clone(),
            head_id: hex(head_id),
            received: *received,
            total: *total,
        },
        E::AttachmentComplete {
            rel_id,
            head_id,
            msg_id,
        } => EngineEventFfi::AttachmentComplete {
            rel_id: rel_id.clone(),
            head_id: hex(head_id),
            msg_id: hex(msg_id),
        },
        E::AttachmentFailed { rel_id, head_id } => EngineEventFfi::AttachmentFailed {
            rel_id: rel_id.clone(),
            head_id: hex(head_id),
        },
        E::AttachmentChunkDropped { rel_id, head_id } => EngineEventFfi::AttachmentChunkDropped {
            rel_id: rel_id.clone(),
            head_id: hex(head_id),
        },
        E::PolicyChanged { rel_id } => EngineEventFfi::PolicyChanged {
            rel_id: rel_id.clone(),
        },
        E::ContactClosed { rel_id } => EngineEventFfi::ContactClosed {
            rel_id: rel_id.clone(),
        },
        E::GapDetected { rel_id } => EngineEventFfi::GapDetected {
            rel_id: rel_id.clone(),
        },
    }
}

#[uniffi::export]
impl SchatCore {
    /// Feed one decrypted envelope (from `ingest_frame`) to the engine.
    /// Returns what happened, for the client event stream.
    pub fn handle_plaintext(
        &self,
        rel_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<EngineEventFfi>, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let events = self
            .rt
            .block_on(eng.handle_plaintext(&rel_id, &plaintext))?;
        Ok(events.iter().map(engine_event_ffi).collect())
    }

    /// Flush due outbox rows (call on a timer, e.g. every few seconds).
    /// Returns how many frames went out.
    pub fn drain_outbox(&self) -> Result<u32, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(self.rt.block_on(eng.drain_outbox())?)
    }

    /// Periodic upkeep: expiry sweeps, presence/typing TTLs, closing
    /// finalization. Returns events worth telling the client about.
    pub fn sweep(&self) -> Result<Vec<EngineEventFfi>, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let events = self.rt.block_on(eng.sweep())?;
        Ok(events.iter().map(engine_event_ffi).collect())
    }

    /// Send a text message. `reply_to` is a hex msg_id. Returns the
    /// new message's hex id.
    pub fn send_text(
        &self,
        rel_id: String,
        body: String,
        reply_to: Option<String>,
    ) -> Result<String, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let reply_to = reply_to.map(|s| hex_id16(&s)).transpose()?;
        let id = self.rt.block_on(eng.send_text(&rel_id, &body, reply_to))?;
        Ok(store::hex_encode(&id))
    }

    /// Edit our own outbound text (window + cap gated).
    pub fn edit_message(
        &self,
        rel_id: String,
        target_id: String,
        new_body: String,
    ) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let target = hex_id16(&target_id)?;
        self.rt
            .block_on(eng.send_edit(&rel_id, &target, &new_body))?;
        Ok(())
    }

    /// Delete a message for everyone (tombstones locally too).
    pub fn delete_message(&self, rel_id: String, target_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let target = hex_id16(&target_id)?;
        self.rt.block_on(eng.send_delete(&rel_id, &target))?;
        Ok(())
    }

    /// Wipe the whole thread for everyone (DELETE_ALL).
    pub fn delete_all(&self, rel_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        self.rt.block_on(eng.send_delete_all(&rel_id))?;
        Ok(())
    }

    /// Read receipt for an inbound message (hex msg_id).
    pub fn mark_read(&self, rel_id: String, target_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let target = hex_id16(&target_id)?;
        Ok(self.rt.block_on(eng.send_read(&rel_id, &target))?)
    }

    /// Typing indicator (throttled while on; stops always go out).
    pub fn set_typing(&self, rel_id: String, typing: bool) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(self.rt.block_on(eng.send_typing(&rel_id, typing))?)
    }

    /// Presence beat to every active relationship. Send on transitions
    /// only (need-to-send); the client lifecycle decides when.
    pub fn send_presence(&self, in_app: bool, do_not_disturb: bool) -> Result<u32, CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        let rels = pairing::relationship::list_relationships(eng.db.conn())?;
        let mut sent = 0u32;
        for rel in rels.iter().filter(|r| r.state == "active") {
            self.rt
                .block_on(eng.send_presence(&rel.rel_id, in_app, do_not_disturb))?;
            sent += 1;
        }
        Ok(sent)
    }

    /// Peer's current presence (RAM-only; `None` if never seen or locked).
    pub fn presence_state(&self, rel_id: String) -> Option<PresenceFfi> {
        let v = self.unlocked().ok()?;
        let eng = v.engine().ok()?;
        let now = eng.now();
        let p = eng.presence.state(&rel_id, now);
        Some(PresenceFfi {
            in_app: p.in_app,
            do_not_disturb: p.do_not_disturb,
        })
    }

    /// Is the peer typing right now (RAM-only)?
    pub fn typing_state(&self, rel_id: String) -> bool {
        let Ok(v) = self.unlocked() else {
            return false;
        };
        let Ok(eng) = v.engine() else {
            return false;
        };
        let now = eng.now();
        eng.typing.is_typing(&rel_id, now)
    }

    /// Peer's advertised capability bitmask (0 until their first
    /// RESYNC_REQ arrives).
    pub fn peer_caps(&self, rel_id: String) -> Result<u32, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(caps::peer_caps(eng.db.conn(), &rel_id)?)
    }

    /// The renderable thread: control frames and tombstones filtered
    /// out, newest-first, `before_seq` for paging.
    pub fn thread(
        &self,
        rel_id: String,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<MessageRowFfi>, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        // UniFFI ingress bound: the client pages; it cannot
        // pull the whole ledger in one call.
        let limit = crate::limits::ffi::clamp_thread_page(limit);
        Ok(eng
            .db
            .thread_visible(&rel_id, limit, before_seq)?
            .into_iter()
            .map(|r| MessageRowFfi {
                msg_id: store::hex_encode(&r.msg_id),
                rel_id: r.rel_id,
                outgoing: r.direction == store::messages::Direction::Out,
                app_seq: r.app_seq,
                sent_at: r.sent_at,
                env_type: r.env_type,
                payload: r.payload,
                delivery: r.state.as_str().to_string(),
                edited: r.edited,
                read_at: r.read_at,
                expires_at: r.expires_at,
            })
            .collect())
    }
}
