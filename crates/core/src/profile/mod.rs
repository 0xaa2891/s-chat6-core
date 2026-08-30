//! `profile/` — PROFILE / PROFILE_REQ / PREF flows.
//!
//! Deliberately simple (no trade-awaiting state machine, no
//! receive-disabled flag): an inbound PROFILE upserts the `profiles`
//! row and updates the display name unless the user set a custom one;
//! PROFILE_REQ is surfaced as an event (the client decides to share);
//! PREF is stored raw on the relationship.

use rusqlite::params;
use schat_wire_types::envelope::Payload;
use schat_wire_types::pref::Pref;
use schat_wire_types::profile::Profile;
use schat_wire_types::WirePayload;

use crate::engine::send::send_envelope;
use crate::engine::{Engine, EngineError};
use crate::store::profiles::ProfilesRepository;
use crate::store::settings::{keys, SettingsRepository};
use crate::store::{Db, StoreError};

const SETTING_NAME: &str = keys::PROFILE_NAME;
const SETTING_JPEG: &str = keys::PROFILE_AVATAR;

/// Apply an inbound PROFILE: upsert the peer's profile row. Returns
/// true when anything changed (→ `ProfileUpdated` event). The display
/// name the client renders is `custom_name ?? profile.name` — this
/// layer never overwrites a user's custom contact name.
pub fn apply_inbound(db: &Db, rel_id: &str, p: &Profile) -> Result<bool, StoreError> {
    let prev = db.profile(rel_id)?;
    let changed = prev
        .as_ref()
        .map(|old| old.name != p.name || old.jpeg != p.jpeg)
        .unwrap_or(true);
    if changed {
        db.put_profile(rel_id, &p.name, &p.jpeg)?;
    }
    Ok(changed)
}

/// Store the peer's receive preferences (raw PREF bytes).
pub fn note_peer_prefs(db: &Db, rel_id: &str, p: &Pref) -> Result<(), StoreError> {
    let bytes = p
        .encode_payload()
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    db.conn().execute(
        "UPDATE relationships SET peer_prefs = ?2 WHERE rel_id = ?1",
        params![rel_id, bytes],
    )?;
    Ok(())
}

/// The peer's receive preferences, if a PREF ever landed.
pub fn peer_prefs(db: &Db, rel_id: &str) -> Result<Option<Pref>, StoreError> {
    use rusqlite::OptionalExtension;
    let raw: Option<Vec<u8>> = db
        .conn()
        .query_row(
            "SELECT peer_prefs FROM relationships WHERE rel_id = ?1",
            params![rel_id],
            |r| r.get(0),
        )
        .optional()?
        .flatten();
    raw.map(|b| Pref::decode_payload(&b).map_err(|e| StoreError::Corrupt(e.to_string())))
        .transpose()
}

/// Our own profile (settings-backed).
pub fn our_profile(db: &Db) -> Result<Profile, StoreError> {
    let name = db
        .setting(SETTING_NAME)?
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_default();
    let jpeg = db.setting(SETTING_JPEG)?.unwrap_or_default();
    Ok(Profile { name, jpeg })
}

/// Set our profile. The name must pass the wire rules; the JPEG must
/// be a media-prepared `profile/jpeg` (≤ 24 KiB, JFIF magic).
pub fn set_our_profile(db: &Db, name: &str, jpeg: &[u8]) -> Result<(), EngineError> {
    let normalized = schat_wire_types::profile::normalize_name(name).ok_or(
        EngineError::EditDenied("profile name fails nfc/length/control rules"),
    )?;
    if jpeg.len() > schat_wire_types::profile::MAX_JPEG {
        return Err(EngineError::EditDenied("profile jpeg over 24 KiB"));
    }
    db.set_setting(SETTING_NAME, normalized.as_bytes())?;
    db.set_setting(SETTING_JPEG, jpeg)?;
    Ok(())
}

impl Engine {
    /// Share our profile with one peer.
    pub async fn send_profile(&mut self, rel_id: &str) -> Result<(), EngineError> {
        let p = our_profile(&self.db)?;
        if p.name.is_empty() {
            return Ok(()); // no profile set: nothing to share
        }
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Profile(p),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Ask a peer for their profile.
    pub async fn send_profile_req(&mut self, rel_id: &str) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::ProfileReq(schat_wire_types::profile::ProfileReq),
            None,
            false,
        )
        .await?;
        Ok(())
    }

    /// Share our profile with every active relationship (after the
    /// user edits it).
    pub async fn broadcast_profile(&mut self) -> Result<u32, EngineError> {
        let rels = crate::pairing::relationship::list_relationships(self.db.conn())?;
        let mut sent = 0;
        for rel in rels {
            if rel.state == "active" {
                self.send_profile(&rel.rel_id).await?;
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Advertise our receive preferences to one peer.
    pub async fn send_prefs(&mut self, rel_id: &str, pref: Pref) -> Result<(), EngineError> {
        send_envelope(
            &self.db,
            &self.transport,
            rel_id,
            Payload::Pref(pref),
            None,
            false,
        )
        .await?;
        Ok(())
    }
}
