//! Outbound envelope pipeline: gate → sequence → encrypt (I11) →
//! ledger → outbox → immediate send attempt. Every feature's send
//! helper funnels through `send_envelope`; there is no other way out.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rusqlite::{params, OptionalExtension};
use schat_wire_types::envelope::{Envelope, EnvelopeType, Payload};

use crate::caps;
use crate::messages::{self, MAX_BODY_BYTES};
use crate::pairing::relationship::{load_relationship, Relationship};
use crate::pairing::{ROLE_INVITER, STATE_REQUEST};
use crate::policy;
use crate::session;
use crate::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use crate::store::outbox::OutboxRepository;
use crate::store::{hex_encode, Db};
use crate::sync::{self, outbox::mark_transmitted};
use crate::transport::{framing, Transport};

use super::{random_msg_id, Engine, EngineError};

/// The relationship's close state (NULL = open).
pub(crate) fn close_state(db: &Db, rel_id: &str) -> Result<Option<String>, EngineError> {
    let state: Option<String> = db
        .conn()
        .query_row(
            "SELECT close_state FROM relationships WHERE rel_id = ?1",
            params![rel_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    Ok(state)
}

/// Gates every outbound envelope. Pure checks; no mutation.
pub(crate) fn gate_outbound(
    db: &Db,
    row: &Relationship,
    t: EnvelopeType,
) -> Result<(), EngineError> {
    if row.session_state == "broken" {
        return Err(EngineError::SessionBroken);
    }
    // Gate: the inviter cannot send until the request is accepted.
    if row.role == ROLE_INVITER && row.state == STATE_REQUEST {
        return Err(EngineError::NotActive);
    }
    if row.state != "active" && row.state != STATE_REQUEST {
        return Err(EngineError::NotActive);
    }
    // A closing relationship settles its control frames; nothing new.
    // (DELETE_ALL / CONTACT_CLOSE / RESYNC_REQ are the close flow's own
    // frames and must pass.)
    if close_state(db, &row.rel_id)?.is_some()
        && !matches!(
            t,
            EnvelopeType::DeleteAll | EnvelopeType::ContactClose | EnvelopeType::ResyncReq
        )
    {
        return Err(EngineError::Closing);
    }
    // Caps gate (need-to-send: don't emit what the peer will drop).
    let peer_caps = caps::peer_caps(db.conn(), &row.rel_id)?;
    if !caps::check_outbound(peer_caps, t) {
        return Err(EngineError::CapGated(t));
    }
    // Policy gate (two-to-enable enforced wants).
    let policy = policy::load_policy(db.conn(), &row.rel_id)?;
    let denied = match t {
        EnvelopeType::Typing => !policy.typing(),
        EnvelopeType::Presence => !policy.presence(),
        EnvelopeType::Read => !policy.receipts(),
        EnvelopeType::Sticker | EnvelopeType::StickerCtrl => !policy.emoji(),
        EnvelopeType::AttachHead | EnvelopeType::AttachChunk => !policy.attachments(),
        _ => false,
    };
    if denied {
        return Err(EngineError::PolicyDenied(t));
    }
    Ok(())
}

/// What `send_envelope` minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sent {
    pub msg_id: [u8; 16],
    pub app_seq: u64,
}

/// Build, gate, encrypt, ledger, queue, and attempt one envelope.
/// On transport failure the row stays queued for the drain loop — the
/// send is not lost.
pub async fn send_envelope(
    db: &Db,
    transport: &Arc<Transport>,
    rel_id: &str,
    payload: Payload,
    ref_id: Option<[u8; 16]>,
    alert: bool,
) -> Result<Sent, EngineError> {
    let row = load_relationship(db.conn(), rel_id)?.ok_or(EngineError::UnknownRelationship)?;
    let t = payload.envelope_type();
    gate_outbound(db, &row, t)?;

    let now = db.clock().now_secs();
    let seq = db.next_out_seq(rel_id)?;
    let msg_id = random_msg_id();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at: now,
        ref_id,
        payload,
    };
    // Zeroizing: the encoded envelope is plaintext; the locked-state
    // memory audit scans for exactly these bytes.
    let plaintext = zeroize::Zeroizing::new(env.encode()?);
    let msg_id_hex = hex_encode(&msg_id);
    let frame = session::encrypt(
        db.conn(),
        rel_id,
        &msg_id_hex,
        &plaintext,
        SystemTime::UNIX_EPOCH + Duration::from_secs(now),
    )
    .await?;
    let record = framing::build_record(&frame)?;

    let expiry = policy::store::message_expiry(db.conn(), rel_id, now)?;
    db.insert_message(&NewMessage {
        msg_id,
        rel_id: rel_id.into(),
        direction: Direction::Out,
        app_seq: seq,
        sent_at: now,
        received_at: None,
        env_type: t.code(),
        ref_id,
        payload: env.payload.encode()?,
        state: DeliveryState::Queued,
        expires_at: expiry,
    })?;
    db.enqueue(&msg_id, rel_id, &record, sync::MESSAGE_TTL_SECS)?;

    let intro = row.intro_pending.then_some(row.our_qr_bytes);
    match transport
        .send_record(&row.peer_onion, intro.as_deref(), &record, alert)
        .await
    {
        Ok(()) => {
            db.dequeue(&msg_id)?;
            mark_transmitted(db, &msg_id)?;
        }
        Err(e) => {
            tracing::debug!(rel_id, msg_id = %msg_id_hex, "immediate send failed; queued: {e}");
        }
    }
    Ok(Sent {
        msg_id,
        app_seq: seq,
    })
}

// ---- typed send helpers (thin; features with real logic live in their
// own modules) ----

impl Engine {
    /// Plain text message. `reply_to` rides as the envelope `ref_id`.
    pub async fn send_text(
        &mut self,
        rel_id: &str,
        body: &str,
        reply_to: Option<[u8; 16]>,
    ) -> Result<[u8; 16], EngineError> {
        if body.len() > MAX_BODY_BYTES {
            return Err(EngineError::EditDenied("body too large"));
        }
        let sent = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Msg(schat_wire_types::msg::Msg::new(body.to_string())?),
            reply_to,
            true,
        )
        .await?;
        // Inline `:e:` tokens: push the item bytes so the peer renders
        // immediately (WANT_ITEM is the miss fallback).
        self.push_inline_emoji(rel_id, body).await?;
        Ok(sent.msg_id)
    }

    /// Edit our own outbound text message (window + cap gated).
    pub async fn send_edit(
        &mut self,
        rel_id: &str,
        target: &[u8; 16],
        new_body: &str,
    ) -> Result<[u8; 16], EngineError> {
        let row = self.db.message(target)?.ok_or(EngineError::NotFound)?;
        if row.rel_id != rel_id {
            return Err(EngineError::NotFound);
        }
        let now = self.now();
        if !messages::can_offer_edit(&row, now) {
            return Err(EngineError::EditDenied(
                "window closed, cap reached, or not our text",
            ));
        }
        let sent = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Edit(schat_wire_types::edit::Edit::new(new_body.to_string())?),
            Some(*target),
            false,
        )
        .await?;
        // Local echo: our own ledger row reflects the edit immediately.
        self.db
            .mark_edited(target, new_body.as_bytes(), sent.app_seq)?;
        Ok(sent.msg_id)
    }

    /// Delete a message for everyone (tombstones locally too).
    pub async fn send_delete(
        &mut self,
        rel_id: &str,
        target: &[u8; 16],
    ) -> Result<[u8; 16], EngineError> {
        let sent = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Delete(schat_wire_types::delete::Delete),
            Some(*target),
            false,
        )
        .await?;
        self.db.mark_tombstoned(target)?;
        crate::store::tombstones::TombstonesRepository::add_tombstone(&self.db, rel_id, target)?;
        Ok(sent.msg_id)
    }

    /// Wipe the thread for everyone (DELETE_ALL + local erase + cut).
    pub async fn send_delete_all(&mut self, rel_id: &str) -> Result<[u8; 16], EngineError> {
        let sent = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::DeleteAll(schat_wire_types::delete::DeleteAll),
            None,
            false,
        )
        .await?;
        crate::store::relationships::raise_history_cut(self.db.conn(), rel_id, sent.app_seq)?;
        self.db.erase_history(rel_id, &[sent.msg_id])?;
        Ok(sent.msg_id)
    }

    /// Typing indicator (throttled to one per `TYPING_SEND_INTERVAL_SECS`
    /// while typing; stops always go out).
    pub async fn send_typing(&mut self, rel_id: &str, typing: bool) -> Result<(), EngineError> {
        let now = self.now();
        if typing {
            if !self.typing.should_send(rel_id, now) {
                return Ok(());
            }
            self.typing.note_sent(rel_id, now);
        }
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Typing(schat_wire_types::typing::Typing { typing }),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Presence beat. Send only on transitions (need-to-send): the
    /// caller (client lifecycle) decides when in_app/dnd changed.
    pub async fn send_presence(
        &mut self,
        rel_id: &str,
        in_app: bool,
        do_not_disturb: bool,
    ) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Presence(schat_wire_types::presence::Presence {
                in_app,
                do_not_disturb,
            }),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Read receipt for an inbound message.
    pub async fn send_read(&mut self, rel_id: &str, target: &[u8; 16]) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Read(schat_wire_types::read::Read),
            Some(*target),
            false,
        )
        .await?;
        Ok(())
    }
}
