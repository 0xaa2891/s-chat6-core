//! Outbox drain + periodic sweeps. The client (or CLI daemon) calls
//! `drain_outbox` on connectivity changes and `sweep` on a timer.

use crate::pairing::relationship::load_relationship;
use crate::session::stores;
use crate::store::messages::{DeliveryState, MessagesRepository};
use crate::store::outbox::OutboxRepository;
use crate::store::settings::{keys, SettingsRepository};
use crate::sync::outbox::mark_transmitted;
use crate::sync::MESSAGE_TTL_SECS;

use super::send::close_state;
use super::{Engine, EngineError, EngineEvent};

// Max records per drain pass (one pass per connectivity event);
// declared in the bounds catalog.
use crate::limits::drain::DRAIN_BATCH;
/// A closing relationship burns once its outbox settles or this much
/// time passes, whichever comes first.
pub const CLOSE_SETTLE_SECS: u64 = 60;

fn backoff_secs(attempts: u32) -> u64 {
    // 5s, 10s, 20s, … capped at 5 minutes.
    (5u64 << attempts.min(6)).min(300)
}

impl Engine {
    /// Send every due outbox record. Returns how many went out.
    pub async fn drain_outbox(&mut self) -> Result<u32, EngineError> {
        let due = self.db.due(DRAIN_BATCH)?;
        let mut sent = 0u32;
        // Per-peer fail-fast: once a send to an onion fails this pass,
        // its remaining rows are backed off without another connect
        // attempt — one dead peer must not stall the whole drain behind
        // repeated circuit-build timeouts.
        let mut failed_onions: std::collections::HashSet<String> = std::collections::HashSet::new();
        for row in due {
            let Some(rel) = load_relationship(self.db.conn(), &row.rel_id)? else {
                // Relationship burned while queued: drop the record.
                self.db.dequeue(&row.msg_id)?;
                continue;
            };
            if failed_onions.contains(&rel.peer_onion) {
                self.db
                    .note_attempt(&row.msg_id, backoff_secs(row.attempts))?;
                continue;
            }
            let intro = rel.intro_pending.then_some(rel.our_qr_bytes);
            match self
                .transport
                .send_record(&rel.peer_onion, intro.as_deref(), &row.record, false)
                .await
            {
                Ok(()) => {
                    self.db.dequeue(&row.msg_id)?;
                    mark_transmitted(&self.db, &row.msg_id)?;
                    sent += 1;
                }
                Err(e) => {
                    tracing::debug!(rel_id = %row.rel_id, attempts = row.attempts, "drain send failed: {e}");
                    failed_onions.insert(rel.peer_onion.clone());
                    self.db
                        .note_attempt(&row.msg_id, backoff_secs(row.attempts))?;
                }
            }
        }
        // Delivery horizon passed: fail loudly, never silently drop.
        for expired in self.db.fail_expired()? {
            self.db
                .set_delivery(&expired.msg_id, DeliveryState::Failed)?;
        }
        Ok(sent)
    }

    /// Periodic maintenance: TTL sweep, closing-relationship burns,
    /// RAM indicator sweeps, tombstone/sticker-cache pruning. Returns
    /// events for state transitions the client should render.
    pub async fn sweep(&mut self) -> Result<Vec<EngineEvent>, EngineError> {
        let mut events = Vec::new();
        let now = self.now();

        // Cryptographic erasure of expired rows (message TTL).
        self.db.sweep_expired()?;

        // Closing relationships: burn once settled.
        let mut closing: Vec<(String, i64)> = Vec::new();
        {
            let mut stmt = self.db.conn().prepare(
                "SELECT rel_id, created_at FROM relationships WHERE close_state IS NOT NULL",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            for r in rows {
                closing.push(r?);
            }
        }
        for (rel_id, created_at) in closing {
            let key = keys::close_started_at(&rel_id);
            let started = self
                .db
                .setting(&key)?
                .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
                .unwrap_or(created_at as u64);
            let settled = self.db.conn().query_row(
                "SELECT COUNT(*) FROM outbox WHERE rel_id = ?1",
                [&rel_id],
                |r| r.get::<_, i64>(0),
            )? == 0;
            if settled || now >= started + CLOSE_SETTLE_SECS {
                self.burn_relationship(&rel_id).await?;
                events.push(EngineEvent::ContactClosed { rel_id });
            }
        }

        // RAM indicator sweeps (transition-only events).
        for rel_id in self.presence.sweep(now) {
            events.push(EngineEvent::Presence {
                rel_id,
                in_app: false,
                do_not_disturb: false,
            });
        }
        for rel_id in self.typing.sweep(now) {
            events.push(EngineEvent::Typing {
                rel_id,
                typing: false,
            });
        }

        // Tombstone + sticker cache hygiene.
        use crate::store::tombstones::TombstonesRepository;
        for rel in crate::pairing::relationship::list_relationships(self.db.conn())? {
            self.db.prune_tombstones(&rel.rel_id)?;
        }
        self.sticker_pending.sweep(now);
        crate::stickers::sweep_cache(&self.db)?;
        Ok(events)
    }

    /// Fail every queued row for a relationship (session broken path).
    /// The break path calls this automatically via `session::mark_broken`;
    /// this stays public for explicit client-driven teardown.
    pub fn fail_outbound(&self, rel_id: &str) -> Result<u64, EngineError> {
        Ok(crate::store::outbox::fail_relationship_outbound(
            self.db.conn(),
            rel_id,
        )?)
    }

    /// Delivery horizon for new outbound rows (exposed for tests).
    pub fn delivery_ttl(&self) -> u64 {
        MESSAGE_TTL_SECS
    }
}

/// Enter the closing state:
/// mark the relationship, remember when, so the sweeper burns it.
pub fn enter_closing(engine: &Engine, rel_id: &str) -> Result<(), EngineError> {
    if close_state(&engine.db, rel_id)?.is_some() {
        return Ok(());
    }
    engine.db.conn().execute(
        "UPDATE relationships SET close_state = 'closing' WHERE rel_id = ?1",
        [rel_id],
    )?;
    engine
        .db
        .set_setting(&keys::close_started_at(rel_id), &engine.now().to_be_bytes())?;
    Ok(())
}

/// Session teardown shared by burn paths.
pub(crate) fn wipe_session(db: &crate::store::Db, rel_id: &str) {
    if let Err(e) = stores::delete_namespace(db.conn(), rel_id) {
        tracing::warn!(rel_id, "session namespace wipe failed: {e}");
    }
}
