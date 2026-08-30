//! Inbound dispatch: one decrypted envelope → ledger + feature
//! handling + events. Gate order (fail closed at each):
//!
//! 1. **I7 decode** — unknown types never reach here.
//! 2. **Caps** — unadvertised gated types drop (session untouched);
//!    a received type also *implies* the peer holds its cap.
//! 3. **Closing** — a settling relationship accepts only RESYNC_REQ.
//! 4. **Skew** — far-future `sent_at` rejects; near-future clamps.
//! 5. **Dedupe** — by msg_id (ledger) then by app_seq (covers
//!    retransmits of cut/tombstoned rows, which have no ledger row).
//! 6. **Gap** — computed *before* the seq is noted.
//! 7. **History cut / tombstone** — history types drop without a
//!    ledger row; the seq is still noted (continuity).
//! 8. **Ledger** — everything except typing/presence is stored.
//! 9. **Feature dispatch** — per-type handlers.

use crate::caps;
use crate::messages::{self, MAX_BODY_BYTES};
use crate::pairing::relationship::load_relationship;
use crate::policy;
use crate::store::inbound_seqs::InboundSeqsRepository;
use crate::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use crate::store::outbox::OutboxRepository;
use crate::store::settings::SettingsRepository;
use crate::store::tombstones::TombstonesRepository;
use crate::sync::{resync, skew};
use schat_wire_types::envelope::{Envelope, EnvelopeType, Payload};
use schat_wire_types::policy as wire_policy;

use super::send::{close_state, send_envelope};
use super::{Engine, EngineError, EngineEvent};

/// Minimum interval between gap-triggered RESYNC_REQs per peer.
const RESYNC_REQ_MIN_SECS: u64 = 10;

impl Engine {
    /// Process one decrypted envelope plaintext (from the transport
    /// inbound loop, after `pairing::ingest::ingest_frame`).
    pub async fn handle_plaintext(
        &mut self,
        rel_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let mut events = Vec::new();
        // I7: decode via the counting wrapper — unknown type codes are
        // dropped, counted, and logged; the session is never affected.
        let env = crate::wire::envelope::decode_envelope(plaintext)?;
        let t = env.envelope_type();
        let row =
            load_relationship(self.db.conn(), rel_id)?.ok_or(EngineError::UnknownRelationship)?;
        // The peer answered: our intro no longer rides outbound frames,
        // and (accepter side) the relationship is now active — reply
        // with our own activation burst.
        // (2) caps gate + implied caps from observed types.
        if !caps::check_inbound(self.db.conn(), rel_id, t)? {
            return Ok(events);
        }
        if let Some(bit) = caps::required_cap(t) {
            let known = caps::peer_caps(self.db.conn(), rel_id)?;
            if known & bit == 0 {
                caps::note_peer_caps(self.db.conn(), rel_id, known | bit)?;
            }
        }

        // (3) a closing relationship only settles control frames.
        if close_state(&self.db, rel_id)?.is_some() && t != EnvelopeType::ResyncReq {
            return Ok(events);
        }

        // (4) skew.
        let now = self.now();
        let sent_at = skew::clamp_sent_at(env.sent_at, now)?;

        // (5) dedupe.
        if self.db.message(&env.msg_id)?.is_some()
            || self.db.has_inbound_seq(rel_id, env.app_seq)?
        {
            return Ok(events);
        }
        // (6) gap BEFORE noting the seq.
        let opens_gap = resync::opens_gap(&self.db, rel_id, env.app_seq)?;
        self.db.note_inbound_seq(rel_id, env.app_seq)?;

        // Accepter-side activation: the first valid inbound frame proves
        // the relationship live (the session layer has already retired
        // our intro by the time we see plaintext). Fire our activation
        // burst exactly once — AFTER noting the seq, so the burst's
        // receive view covers this very frame. The inviter's burst fires
        // in `accept_request` instead.
        if row.role == crate::pairing::ROLE_ACCEPTER {
            let key = crate::store::settings::keys::activation_sent(rel_id);
            if self.db.setting(&key)?.is_none() {
                self.db.set_setting(&key, &[1])?;
                self.on_relationship_active(rel_id).await?;
            }
        }

        // (7) history cut / tombstone drops (history types only).
        let cut = crate::store::relationships::history_cut(self.db.conn(), rel_id)?;
        let tombstoned = self.db.is_tombstoned(rel_id, &env.msg_id)?;
        if messages::should_drop_inbound(t, env.app_seq, cut, tombstoned) {
            if opens_gap {
                self.maybe_request_resync(rel_id, &mut events).await?;
            }
            return Ok(events);
        }

        // (8) ledger (typing/presence are seq-tracked but not stored).
        let ephemeral = matches!(t, EnvelopeType::Typing | EnvelopeType::Presence);
        if !ephemeral {
            let expiry = policy::store::message_expiry(self.db.conn(), rel_id, now)?;
            self.db.insert_message(&NewMessage {
                msg_id: env.msg_id,
                rel_id: rel_id.into(),
                direction: Direction::In,
                app_seq: env.app_seq,
                sent_at,
                received_at: Some(now),
                env_type: t.code(),
                ref_id: env.ref_id,
                payload: env.payload.encode()?,
                state: DeliveryState::Received,
                expires_at: expiry,
            })?;
        }

        // (9) feature dispatch.
        match env.payload.clone() {
            Payload::Msg(m) => {
                events.push(EngineEvent::Message {
                    rel_id: rel_id.into(),
                    msg_id: env.msg_id,
                });
                self.fetch_missing_emoji(rel_id, &m.body).await?;
            }
            Payload::Edit(e) => self.apply_edit(rel_id, &env, &e.body, &mut events)?,
            Payload::Delete(_) => self.apply_delete(rel_id, &env, &mut events)?,
            Payload::DeleteAll(_) => {
                crate::store::relationships::raise_history_cut(
                    self.db.conn(),
                    rel_id,
                    env.app_seq,
                )?;
                self.db.erase_history(rel_id, &[env.msg_id])?;
                events.push(EngineEvent::HistoryCleared {
                    rel_id: rel_id.into(),
                });
            }
            Payload::ContactClose(_) => {
                self.burn_relationship(rel_id).await?;
                events.push(EngineEvent::ContactClosed {
                    rel_id: rel_id.into(),
                });
                return Ok(events); // the relationship is gone
            }
            Payload::ResyncReq(req) => {
                // Handling a request costs a receive-view scan +
                // retransmits; throttle per peer so a RESYNC_REQ storm
                // (buggy or evil client) cannot run the CPU/outbox.
                // Honest catch-up is one request per reconnect — the
                // burst covers it with 10× headroom.
                if self.rate_allow(crate::ratelimit::Surface::ResyncReq, rel_id) {
                    self.apply_resync_req(rel_id, &req, &mut events).await?;
                }
            }
            Payload::AttachHead(p) => self.on_attach_head(rel_id, &env, &p, &mut events)?,
            Payload::AttachChunk(c) => self.on_attach_chunk(rel_id, &c, &mut events)?,
            Payload::Profile(p) => {
                if crate::profile::apply_inbound(&self.db, rel_id, &p)? {
                    events.push(EngineEvent::ProfileUpdated {
                        rel_id: rel_id.into(),
                    });
                }
            }
            Payload::ProfileReq(_) => {
                events.push(EngineEvent::ProfileRequested {
                    rel_id: rel_id.into(),
                });
            }
            Payload::Pref(p) => {
                crate::profile::note_peer_prefs(&self.db, rel_id, &p)?;
                events.push(EngineEvent::PeerPrefs {
                    rel_id: rel_id.into(),
                });
            }
            Payload::Sticker(item) => {
                self.on_sticker(rel_id, &env, &item, &mut events).await?;
            }
            Payload::StickerCtrl(ctrl) => {
                self.on_sticker_ctrl(rel_id, &ctrl, &mut events).await?;
            }
            Payload::Presence(p) => {
                let policy = policy::load_policy(self.db.conn(), rel_id)?;
                // Presence floods drop before touching RAM state.
                if policy.presence()
                    && self.rate_allow(crate::ratelimit::Surface::Ephemeral, rel_id)
                {
                    if let Some(state) = self.presence.note(rel_id, p, now) {
                        events.push(EngineEvent::Presence {
                            rel_id: rel_id.into(),
                            in_app: state.in_app,
                            do_not_disturb: state.do_not_disturb,
                        });
                    }
                }
            }
            Payload::Typing(tp) => {
                let policy = policy::load_policy(self.db.conn(), rel_id)?;
                // Typing floods drop before touching RAM state.
                if policy.typing() && self.rate_allow(crate::ratelimit::Surface::Ephemeral, rel_id)
                {
                    if let Some(lit) = self.typing.note(rel_id, tp.typing, now) {
                        events.push(EngineEvent::Typing {
                            rel_id: rel_id.into(),
                            typing: lit,
                        });
                    }
                }
            }
            Payload::Read(_) => {
                let policy = policy::load_policy(self.db.conn(), rel_id)?;
                if policy.receipts() {
                    if let Some(target) = env.ref_id {
                        if self.db.mark_read(&target, now)? {
                            events.push(EngineEvent::Read {
                                rel_id: rel_id.into(),
                                msg_id: target,
                            });
                        }
                    }
                }
            }
            Payload::ChatPolicy(cp) => {
                self.apply_chat_policy(rel_id, &env, &cp, &mut events)
                    .await?;
            }
        }

        if opens_gap {
            self.maybe_request_resync(rel_id, &mut events).await?;
        }
        Ok(events)
    }

    /// EDIT decision → apply or drop.
    fn apply_edit(
        &mut self,
        rel_id: &str,
        env: &Envelope,
        body: &str,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        let Some(target_id) = env.ref_id else {
            return Ok(()); // EDIT without a target is malformed; dropped
        };
        let target = self.db.message(&target_id)?;
        let now = self.now();
        let cut = crate::store::relationships::history_cut(self.db.conn(), rel_id)?;
        let tombstoned = self.db.is_tombstoned(rel_id, &env.msg_id)?;
        let decision = messages::edit_decision(
            target.as_ref(),
            now,
            env.app_seq,
            body.len(),
            MAX_BODY_BYTES,
            tombstoned,
            cut,
        );
        match decision {
            messages::EditDecision::Apply => {
                self.db
                    .mark_edited(&target_id, body.as_bytes(), env.app_seq)?;
                events.push(EngineEvent::Edited {
                    rel_id: rel_id.into(),
                    msg_id: target_id,
                });
            }
            other => {
                tracing::debug!(rel_id, ?other, "inbound edit dropped");
            }
        }
        Ok(())
    }

    /// DELETE: tombstone the target. Attachment
    /// payloads die with the row.
    fn apply_delete(
        &mut self,
        rel_id: &str,
        env: &Envelope,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        let Some(target_id) = env.ref_id else {
            return Ok(());
        };
        self.on_delete_target(rel_id, &target_id)?;
        // The tombstone is recorded even when the target never arrived
        // (out-of-order delete): its whole job is dropping the late copy.
        self.db.add_tombstone(rel_id, &target_id)?;
        if self.db.mark_tombstoned(&target_id)? {
            events.push(EngineEvent::Deleted {
                rel_id: rel_id.into(),
                msg_id: target_id,
            });
        }
        Ok(())
    }

    /// Peer's RESYNC_REQ: note their caps, ack covered rows, retransmit
    /// missing frames immutably (I11), and answer with a policy SYNC
    /// (throttled).
    async fn apply_resync_req(
        &mut self,
        rel_id: &str,
        req: &schat_wire_types::resync::ResyncReq,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        caps::note_peer_caps(self.db.conn(), rel_id, req.caps)?;
        let retransmits = resync::handle_request(&self.db, rel_id, req)?;
        tracing::info!(
            rel_id,
            peer_max_contiguous = req.max_contiguous_seq,
            retransmits = retransmits.len(),
            "resync request handled"
        );
        for rt in retransmits {
            // Retransmissions ride the outbox like first sends: an
            // immediate-send failure must not lose the frame.
            let record = crate::transport::framing::build_record(&rt.frame)?;
            self.db
                .requeue(&rt.msg_id, rel_id, &record, crate::sync::MESSAGE_TTL_SECS)?;
        }
        // Policy SYNC reply, throttled (30s min interval).
        let state = policy::load_policy(self.db.conn(), rel_id)?;
        let now = self.now();
        if now >= state.last_sync_at + policy::SYNC_REPLY_MIN_SEC {
            let (next, sync_payload) = policy::machine::build_sync(state, now);
            policy::save_policy(self.db.conn(), rel_id, &next)?;
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::ChatPolicy(sync_payload),
                None,
                false,
            )
            .await?;
        }
        let _ = events;
        Ok(())
    }

    /// CHAT_POLICY ops through the state machine; effects applied here.
    async fn apply_chat_policy(
        &mut self,
        rel_id: &str,
        env: &Envelope,
        cp: &wire_policy::ChatPolicy,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        let state = policy::load_policy(self.db.conn(), rel_id)?;
        let now = self.now();
        let (next, outcome, respond) = match cp.op {
            wire_policy::OP_RULE_PROPOSE => {
                // A fresh inbound proposal is always client-visible
                // (the rules sheet lights up).
                let next = policy::machine::apply_propose(state, cp, env.msg_id);
                let outcome = policy::ApplyOutcome {
                    changed: true,
                    ..Default::default()
                };
                (next, outcome, false)
            }
            wire_policy::OP_RULE_ACCEPT => {
                match policy::machine::apply_accept(state, cp, now) {
                    Some((s, o)) => (s, o, false),
                    None => return Ok(()), // stale/forged accept
                }
            }
            wire_policy::OP_CAP_SET => {
                let (s, o) = policy::machine::apply_cap_set(&state, cp.cap_id, cp.cap_on);
                (s, o, false)
            }
            wire_policy::OP_SYNC => {
                let (s, o) = policy::machine::apply_sync(&state, cp);
                // SYNC begets SYNC (throttled) so both sides converge.
                (s, o, true)
            }
            _ => return Ok(()),
        };
        policy::save_policy(self.db.conn(), rel_id, &next)?;
        if let Some(clamp_to) = outcome.clamp_expiry_to {
            policy::store::clamp_message_expiry(self.db.conn(), rel_id, clamp_to)?;
        }
        if outcome.erase_attachments {
            policy::store::erase_attach_messages(&self.db, rel_id)?;
        }
        if outcome.changed {
            events.push(EngineEvent::PolicyChanged {
                rel_id: rel_id.into(),
            });
        }
        if respond && now >= next.last_sync_at + policy::SYNC_REPLY_MIN_SEC {
            let (s2, sync_payload) = policy::machine::build_sync(next, now);
            policy::save_policy(self.db.conn(), rel_id, &s2)?;
            send_envelope(
                &self.db,
                &self.transport,
                rel_id,
                Payload::ChatPolicy(sync_payload),
                None,
                false,
            )
            .await?;
        }
        Ok(())
    }

    /// Gap-triggered RESYNC_REQ, throttled per peer.
    async fn maybe_request_resync(
        &mut self,
        rel_id: &str,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        use crate::store::settings::{keys, SettingsRepository};
        let now = self.now();
        let key = keys::resync_req_at(rel_id);
        let last = self
            .db
            .setting(&key)?
            .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);
        if now < last + RESYNC_REQ_MIN_SECS {
            return Ok(());
        }
        self.db.set_setting(&key, &now.to_be_bytes())?;
        let req = resync::build_request(&self.db, rel_id)?;
        let set_bits: Vec<u64> = (1..=schat_wire_types::resync::BITMAP_BITS as u64)
            .filter(|off| {
                // off ∈ 1..=BITMAP_BITS, so the byte offset fits a usize
                // and the bit offset a u8 on any supported platform.
                let byte = usize::try_from((off - 1) / 8).expect("bitmap byte fits usize");
                let bit = u8::try_from((off - 1) % 8).expect("bitmap bit fits u8");
                req.received_seq_bitmap
                    .get(byte)
                    .is_some_and(|b| b & (1 << bit) != 0)
            })
            .map(|off| req.max_contiguous_seq + off)
            .collect();
        tracing::info!(
            rel_id,
            max_contiguous = req.max_contiguous_seq,
            bitmap_set = ?set_bits,
            "gap detected; requesting resync"
        );
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ResyncReq(req),
            None,
            false,
        )
        .await?;
        events.push(EngineEvent::GapDetected {
            rel_id: rel_id.into(),
        });
        Ok(())
    }
}
