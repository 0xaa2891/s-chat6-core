//! Relationship burn: the point of no return. Every byte of the
//! relationship — ledger, outbox, attachments, chunks, profile,
//! tombstones, seqs, session keys, the onion service — is erased.
//! Used by both close paths (we close → settle → burn; peer closes →
//! burn immediately) and by panic-wipe style flows.

use crate::pairing::relationship::load_relationship;
use crate::store::settings::{keys, SettingsRepository};

use super::drain::wipe_session;
use super::{Engine, EngineError};

impl Engine {
    /// Erase the relationship entirely. Idempotent.
    pub async fn burn_relationship(&mut self, rel_id: &str) -> Result<(), EngineError> {
        let Some(row) = load_relationship(self.db.conn(), rel_id)? else {
            return Ok(());
        };
        // The onion service dies first: nothing new can arrive.
        if let Err(e) = self.transport.remove_service(&row.service_id).await {
            tracing::warn!(rel_id, "service removal during burn failed: {e}");
        }
        wipe_session(&self.db, rel_id);

        let db = self.db.conn();
        // Chunks are keyed by head_id; clear them via the attachments
        // join before the attachment rows themselves go.
        db.execute(
            "DELETE FROM attachment_chunks WHERE head_id IN (
                SELECT head_id FROM attachments WHERE rel_id = ?1
            )",
            [rel_id],
        )?;
        for table in [
            "messages",
            "outbox",
            "attachments",
            "profiles",
            "tombstones",
            "inbound_seqs",
            "sticker_serves",
        ] {
            db.execute(&format!("DELETE FROM {table} WHERE rel_id = ?1"), [rel_id])?;
        }
        db.execute("DELETE FROM relationships WHERE rel_id = ?1", [rel_id])?;
        self.db.delete_setting(&keys::close_started_at(rel_id))?;
        self.db.delete_setting(&keys::resync_req_at(rel_id))?;

        // RAM state.
        self.presence.forget(rel_id);
        self.typing.forget(rel_id);
        self.sticker_pending.forget(rel_id);
        tracing::info!(rel_id, "relationship burned");
        Ok(())
    }
}
