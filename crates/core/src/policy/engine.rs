//! Engine glue for the policy machine: the client-facing operations
//! (propose rules, accept a proposal, set a capability want) and their
//! side effects (clamp, erase).

use schat_wire_types::envelope::Payload;

use crate::engine::send::send_envelope;
use crate::engine::{random_msg_id, Engine, EngineError, EngineEvent};

use super::machine::{self, ApplyOutcome};
use super::{load_policy, save_policy};

impl Engine {
    /// Apply an outcome's side effects.
    fn apply_outcome(
        &self,
        rel_id: &str,
        outcome: &ApplyOutcome,
        events: &mut Vec<EngineEvent>,
    ) -> Result<(), EngineError> {
        if let Some(clamp_to) = outcome.clamp_expiry_to {
            super::store::clamp_message_expiry(self.db.conn(), rel_id, clamp_to)?;
        }
        if outcome.erase_attachments {
            super::store::erase_attach_messages(&self.db, rel_id)?;
        }
        if outcome.changed {
            events.push(EngineEvent::PolicyChanged {
                rel_id: rel_id.into(),
            });
        }
        Ok(())
    }

    /// Propose new chat rules (TTL / screenshot / attach-download).
    pub async fn propose_rules(
        &mut self,
        rel_id: &str,
        ttl_sec: u32,
        screenshot: bool,
        attach_download: bool,
    ) -> Result<(), EngineError> {
        let state = load_policy(self.db.conn(), rel_id)?;
        let propose_id = random_msg_id();
        let Some((next, payload)) =
            machine::build_propose(state, ttl_sec, screenshot, attach_download, propose_id)
        else {
            return Err(EngineError::EditDenied("disallowed TTL"));
        };
        save_policy(self.db.conn(), rel_id, &next)?;
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ChatPolicy(payload),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Accept the peer's pending proposal: rules apply locally first,
    /// then the ACCEPT goes out.
    pub async fn accept_rules(&mut self, rel_id: &str) -> Result<Vec<EngineEvent>, EngineError> {
        let mut events = Vec::new();
        let state = load_policy(self.db.conn(), rel_id)?;
        let now = self.now();
        let Some((next, payload, outcome)) = machine::build_accept(state, now) else {
            return Err(EngineError::EditDenied("no inbound proposal pending"));
        };
        save_policy(self.db.conn(), rel_id, &next)?;
        self.apply_outcome(rel_id, &outcome, &mut events)?;
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ChatPolicy(payload),
            None,
            false,
        )
        .await?;
        Ok(events)
    }

    /// Decline the peer's pending proposal (local only — the proposer's
    /// pending state expires by being overwritten or ignored).
    pub fn decline_rules(&mut self, rel_id: &str) -> Result<(), EngineError> {
        let mut state = load_policy(self.db.conn(), rel_id)?;
        state.pending = None;
        save_policy(self.db.conn(), rel_id, &state)?;
        Ok(())
    }

    /// Set a capability want (two-to-enable, one-to-disable).
    pub async fn set_capability(
        &mut self,
        rel_id: &str,
        cap_id: u8,
        on: bool,
    ) -> Result<Vec<EngineEvent>, EngineError> {
        let mut events = Vec::new();
        let state = load_policy(self.db.conn(), rel_id)?;
        let Some((next, payload, outcome)) = machine::build_cap_set(&state, cap_id, on) else {
            return Ok(events); // already in the desired local state
        };
        save_policy(self.db.conn(), rel_id, &next)?;
        self.apply_outcome(rel_id, &outcome, &mut events)?;
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ChatPolicy(payload),
            None,
            false,
        )
        .await?;
        Ok(events)
    }

    /// The relationship's current policy state (client rendering).
    pub fn chat_policy(&self, rel_id: &str) -> Result<super::PolicyState, EngineError> {
        Ok(load_policy(self.db.conn(), rel_id)?)
    }
}
