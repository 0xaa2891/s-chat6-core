//! Queries on the `relationships` row that are not pairing-owned:
//! the per-relationship history cut (DELETE_ALL / contact-close burn).

use rusqlite::{params, Connection, OptionalExtension};

use crate::store::StoreError;

/// The relationship's history cut (0 = none).
pub fn history_cut(db: &Connection, rel_id: &str) -> Result<u64, StoreError> {
    let cut: Option<i64> = db
        .query_row(
            "SELECT history_cut_seq FROM relationships WHERE rel_id = ?1",
            params![rel_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(cut.unwrap_or(0) as u64)
}

/// Raise the history cut (DELETE_ALL). Monotonic: a late-arriving
/// DELETE_ALL with an older seq must not lower it.
pub fn raise_history_cut(db: &Connection, rel_id: &str, seq: u64) -> Result<(), StoreError> {
    db.execute(
        "UPDATE relationships SET history_cut_seq = MAX(history_cut_seq, ?2)
         WHERE rel_id = ?1",
        params![rel_id, seq as i64],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_is_monotonic() {
        let db = crate::store::Db::open_in_memory().unwrap();
        db.conn()
            .execute(
                "INSERT INTO relationships (
                    rel_id, role, state, service_id, onion, peer_onion,
                    peer_identity_key, peer_client_auth_public,
                    our_client_auth_private, our_nonce, peer_nonce,
                    our_qr_bytes, intro_pending,
                    session_state, created_at
                 ) VALUES (
                    'rel', 'inviter', 'active', 'svc', 'a.onion', 'b.onion',
                    X'00', 'ca', 'cb', X'00', X'00', X'00', 0, 'active', 0
                 )",
                [],
            )
            .unwrap();
        assert_eq!(history_cut(db.conn(), "rel").unwrap(), 0);
        raise_history_cut(db.conn(), "rel", 10).unwrap();
        raise_history_cut(db.conn(), "rel", 5).unwrap();
        assert_eq!(history_cut(db.conn(), "rel").unwrap(), 10, "never lowered");
    }
}
