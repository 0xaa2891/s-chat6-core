//! `close/` — the contact-close flow.
//!
//! We close: enter `closing`, send DELETE_ALL then CONTACT_CLOSE,
//! erase the local ledger keeping the two control frames, and let the
//! sweeper burn the relationship once the outbox settles (or the
//! settle window passes). Peer closes: burn immediately — their
//! CONTACT_CLOSE is the last word; nothing we could send would be
//! read.

use schat_wire_types::delete::DeleteAll;
use schat_wire_types::envelope::Payload;

use crate::engine::drain::enter_closing;
use crate::engine::send::{close_state, send_envelope};
use crate::engine::{Engine, EngineError};
use crate::store::messages::MessagesRepository;
use crate::store::relationships::raise_history_cut;

impl Engine {
    /// Close the contact. Idempotent.
    pub async fn close_contact(&mut self, rel_id: &str) -> Result<(), EngineError> {
        if close_state(&self.db, rel_id)?.is_some() {
            return Ok(());
        }
        enter_closing(self, rel_id)?;
        // Control frames are exempt from the closing gate.
        let da = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::DeleteAll(DeleteAll),
            None,
            false,
        )
        .await?;
        let cc = send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ContactClose(schat_wire_types::contact::ContactClose),
            None,
            false,
        )
        .await?;
        let cut = da.app_seq.max(cc.app_seq);
        raise_history_cut(self.db.conn(), rel_id, cut)?;
        self.db.erase_history(rel_id, &[da.msg_id, cc.msg_id])?;
        Ok(())
    }
}
