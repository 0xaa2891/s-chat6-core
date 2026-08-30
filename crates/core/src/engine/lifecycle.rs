//! Relationship lifecycle glue: request acceptance and the
//! activation burst (caps advertisement + profile + policy sync).

use schat_wire_types::envelope::Payload;

use crate::pairing;
use crate::policy;
use crate::sync::resync;

use super::send::send_envelope;
use super::{Engine, EngineError};

impl Engine {
    /// Inviter accepts a pending request: the service becomes restricted
    /// to the peer, then the activation burst.
    pub async fn accept_request(&mut self, rel_id: &str) -> Result<(), EngineError> {
        pairing::accept_request(self.db.conn(), &self.transport, rel_id).await?;
        self.on_relationship_active(rel_id).await
    }

    /// A relationship just became active (either side): advertise caps
    /// (the RESYNC_REQ carries them), share our profile, sync policy
    /// wants.
    pub async fn on_relationship_active(&mut self, rel_id: &str) -> Result<(), EngineError> {
        let req = resync::build_request(&self.db, rel_id)?;
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ResyncReq(req),
            None,
            false,
        )
        .await?;
        self.send_profile(rel_id).await?;
        // Policy sync — but only if the peer has advertised CAP_POLICY.
        // At activation they haven't yet; their RESYNC_REQ (which carries
        // their caps) arrives next and triggers the throttled sync reply.
        let state = policy::load_policy(self.db.conn(), rel_id)?;
        let (next, sync) = policy::machine::build_sync(state, self.now());
        match send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ChatPolicy(sync),
            None,
            false,
        )
        .await
        {
            Ok(_) => policy::save_policy(self.db.conn(), rel_id, &next)?,
            Err(EngineError::CapGated(_)) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    }
}
