//! Policy persistence on the `relationships` row, plus the two store
//! side effects the machine can request: expiry clamping (TTL shrank)
//! and attachment erasure (capability turned off).

use rusqlite::{params, Connection, OptionalExtension};

use schat_wire_types::envelope::EnvelopeType;

use crate::store::messages::MessagesRepository;
use crate::store::{hex_decode, Db, StoreError};

use super::{PendingProposal, PolicyState};

/// Pending proposal blob: ttl(4 BE) + flags(1: bit0 screenshot, bit1
/// download, bit2 inbound) + propose msg_id(16).
const PENDING_LEN: usize = 4 + 1 + 16;

fn encode_pending(p: &PendingProposal) -> Vec<u8> {
    let mut out = Vec::with_capacity(PENDING_LEN);
    out.extend_from_slice(&p.ttl_sec.to_be_bytes());
    out.push((p.screenshot as u8) | ((p.attach_download as u8) << 1) | ((p.inbound as u8) << 2));
    out.extend_from_slice(&p.propose_id);
    out
}

fn decode_pending(bytes: &[u8]) -> Result<PendingProposal, StoreError> {
    if bytes.len() != PENDING_LEN {
        return Err(StoreError::Corrupt(format!(
            "policy_pending: {} bytes, want {PENDING_LEN}",
            bytes.len()
        )));
    }
    // Length is pinned to PENDING_LEN above, so the slice conversions hold.
    let ttl_sec = u32::from_be_bytes(bytes[..4].try_into().expect("len checked"));
    let flags = bytes[4];
    let propose_id: [u8; 16] = bytes[5..21]
        .try_into()
        .map_err(|_| StoreError::Corrupt("policy_pending.propose_id".into()))?;
    Ok(PendingProposal {
        ttl_sec,
        screenshot: flags & 1 != 0,
        attach_download: flags & 2 != 0,
        inbound: flags & 4 != 0,
        propose_id,
    })
}

/// Load the policy state; a relationship with no v3 columns touched
/// reads as the default (24h TTL, everything on).
pub fn load_policy(db: &Connection, rel_id: &str) -> Result<PolicyState, StoreError> {
    let row = db
        .query_row(
            "SELECT policy_ttl_sec, policy_flags, policy_wants, policy_pending,
                    policy_last_sync_at
             FROM relationships WHERE rel_id = ?1",
            params![rel_id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, Option<Vec<u8>>>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((ttl, flags, wants, pending, last_sync)) = row else {
        return Err(StoreError::Corrupt(format!(
            "policy for unknown rel {rel_id}"
        )));
    };
    let pending = pending.map(|b| decode_pending(&b)).transpose()?;
    Ok(PolicyState {
        ttl_sec: ttl as u32,
        screenshot: flags & 1 != 0,
        attach_download: flags & 2 != 0,
        local_want: (wants as u32) & 0xff,
        peer_want: ((wants as u32) >> 8) & 0xff,
        pending,
        last_sync_at: last_sync as u64,
    })
}

pub fn save_policy(db: &Connection, rel_id: &str, state: &PolicyState) -> Result<(), StoreError> {
    let flags = (state.screenshot as i64) | ((state.attach_download as i64) << 1);
    let wants = ((state.peer_want & 0xff) << 8) | (state.local_want & 0xff);
    let pending = state.pending.as_ref().map(encode_pending);
    db.execute(
        "UPDATE relationships SET policy_ttl_sec = ?2, policy_flags = ?3, policy_wants = ?4,
                policy_pending = ?5, policy_last_sync_at = ?6
         WHERE rel_id = ?1",
        params![
            rel_id,
            state.ttl_sec as i64,
            flags,
            wants as i64,
            pending,
            state.last_sync_at as i64,
        ],
    )?;
    Ok(())
}

/// Clamp every live message's expiry to `before` (TTL shrank).
/// Messages with no expiry (TTL_NEVER era) get the new horizon.
pub fn clamp_message_expiry(db: &Connection, rel_id: &str, before: u64) -> Result<u64, StoreError> {
    let n = db.execute(
        "UPDATE messages SET expires_at = ?2
         WHERE rel_id = ?1 AND (expires_at IS NULL OR expires_at > ?2)",
        params![rel_id, before as i64],
    )?;
    Ok(n as u64)
}

/// Erase this relationship's attachment messages: tombstone the
/// ATTACH_HEAD ledger rows and drop their chunk payloads + transfer
/// rows.
pub fn erase_attach_messages(db: &Db, rel_id: &str) -> Result<u64, StoreError> {
    let heads: Vec<String> = {
        let mut stmt = db.conn().prepare(
            "SELECT msg_id FROM messages WHERE rel_id = ?1 AND env_type = ?2 AND tombstone = 0",
        )?;
        let rows = stmt.query_map(params![rel_id, EnvelopeType::AttachHead.code()], |r| {
            r.get::<_, String>(0)
        })?;
        rows.collect::<Result<Vec<_>, _>>()?
    };
    let mut erased = 0u64;
    for head_hex in heads {
        let head_id: [u8; 16] = hex_decode(&head_hex)?
            .try_into()
            .map_err(|_| StoreError::Corrupt("messages.msg_id".into()))?;
        crate::store::chunks::ChunksRepository::delete_chunks(db, &head_id)?;
        crate::store::attachments::AttachmentsRepository::delete_attachment(db, &head_id)?;
        db.mark_tombstoned(&head_id)?;
        erased += 1;
    }
    Ok(erased)
}

/// Compute the expiry for a new message under this relationship's
/// agreed TTL.
pub fn message_expiry(
    db: &Connection,
    rel_id: &str,
    floor: u64,
) -> Result<Option<u64>, StoreError> {
    Ok(load_policy(db, rel_id)?.expiry_at(floor))
}

/// Attachments currently enforceable? (Both sides want them.)
pub fn attachments_allowed(db: &Connection, rel_id: &str) -> Result<bool, StoreError> {
    Ok(load_policy(db, rel_id)?.attachments())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::messages::{DeliveryState, Direction, NewMessage};

    fn db_with_rel() -> (Db, String) {
        let db = Db::open_in_memory().unwrap();
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
                    X'00', 'ca', 'cb', X'00', X'00', X'00', 0,
                    'active', 0
                 )",
                [],
            )
            .unwrap();
        (db, "rel".to_string())
    }

    #[test]
    fn policy_roundtrip_with_pending() {
        let (db, rel) = db_with_rel();
        let def = load_policy(db.conn(), &rel).unwrap();
        assert_eq!(def, PolicyState::default());

        let mut state = def;
        state.ttl_sec = schat_wire_types::policy::TTL_7D;
        state.screenshot = false;
        state.local_want &= !crate::policy::FLAG_WANT_TYPING;
        state.pending = Some(PendingProposal {
            ttl_sec: schat_wire_types::policy::TTL_1H,
            screenshot: true,
            attach_download: false,
            inbound: true,
            propose_id: [3u8; 16],
        });
        save_policy(db.conn(), &rel, &state).unwrap();
        assert_eq!(load_policy(db.conn(), &rel).unwrap(), state);
    }

    #[test]
    fn clamp_only_shrinks() {
        let (db, rel) = db_with_rel();
        let msg = |id: u8, exp: Option<u64>| NewMessage {
            msg_id: [id; 16],
            rel_id: rel.clone(),
            direction: Direction::In,
            app_seq: u64::from(id),
            sent_at: 1,
            received_at: Some(1),
            env_type: 1,
            ref_id: None,
            payload: vec![],
            state: DeliveryState::Received,
            expires_at: exp,
        };
        db.insert_message(&msg(1, Some(10_000))).unwrap();
        db.insert_message(&msg(2, None)).unwrap();
        db.insert_message(&msg(3, Some(5_000))).unwrap();

        let n = clamp_message_expiry(db.conn(), &rel, 8_000).unwrap();
        assert_eq!(n, 2, "10k clamped, NULL clamped, 5k untouched");
        assert_eq!(
            db.message(&[1u8; 16]).unwrap().unwrap().expires_at,
            Some(8_000)
        );
        assert_eq!(
            db.message(&[2u8; 16]).unwrap().unwrap().expires_at,
            Some(8_000)
        );
        assert_eq!(
            db.message(&[3u8; 16]).unwrap().unwrap().expires_at,
            Some(5_000)
        );
    }
}
