//! `settings` table repository: user preferences as opaque key → bytes.
//! The table layer stays key-agnostic so settings changes never require
//! a schema migration.
//!
//! Value encodings for the typed helpers: bools are `b"1"`/`b"0"`,
//! u64s are 8 big-endian bytes, strings are UTF-8. Anything else is
//! opaque bytes via the raw [`SettingsRepository`] trait.

use rusqlite::{params, Connection};

use super::{Db, StoreError};

/// The settings key space.
pub mod keys {
    // Profile.
    pub const PROFILE_NAME: &str = "profile_name";
    pub const PROFILE_AVATAR: &str = "profile_avatar";

    // Notifications / behavior.
    pub const NOTIFY_ARRIVALS: &str = "notify_arrivals";
    pub const SNATCH_ENABLED: &str = "snatch_enabled";
    pub const RECEIVE_MEDIA: &str = "receive_media";
    pub const INACTIVITY_ERASE_HOURS: &str = "inactivity_erase_hours";
    pub const DO_NOT_DISTURB: &str = "do_not_disturb";
    pub const PRESENCE_SHARE: &str = "presence_share";

    // Transport.
    pub const ONION_MODE: &str = "onion_mode";
    pub const TOR_RECONNECT_HINT_AT: &str = "tor_reconnect_hint_at";

    /// Onion-mode literals.
    pub const MODE_FAST: &str = "fast";
    pub const MODE_NORMAL: &str = "normal";
    pub const MODE_SAVER: &str = "saver";

    // Appearance (theme fields live inside THEME_JSON, as before).
    pub const THEME_JSON: &str = "theme_json";
    pub const WALL_DEFAULT_BLUR: &str = "wall_default_blur";
    pub const WALL_DEFAULT_DIM: &str = "wall_default_dim";
    pub const WALL_LIST_BLUR: &str = "wall_list_blur";
    pub const WALL_LIST_DIM: &str = "wall_list_dim";
    pub const WALL_DEFAULT_DEK: &str = "wall_default_dek";
    pub const WALL_LIST_DEK: &str = "wall_list_dek";
    pub const WALL_VERSION: &str = "wall_version";
    pub const WALL_DEFAULT_SCALE: &str = "wall_default_scale";
    pub const WALL_DEFAULT_OFF_X: &str = "wall_default_off_x";
    pub const WALL_DEFAULT_OFF_Y: &str = "wall_default_off_y";
    pub const WALL_LIST_SCALE: &str = "wall_list_scale";
    pub const WALL_LIST_OFF_X: &str = "wall_list_off_x";
    pub const WALL_LIST_OFF_Y: &str = "wall_list_off_y";

    // Preference broadcast.
    pub const LAST_PREF_SENT_AT: &str = "last_pref_sent_at";

    // Capability defaults applied to new relationships.
    pub const DEFAULT_CAP_ATTACH: &str = "default_cap_attach";
    pub const DEFAULT_CAP_EMOJI: &str = "default_cap_emoji";
    pub const DEFAULT_CAP_PRESENCE: &str = "default_cap_presence";
    pub const DEFAULT_CAP_TYPING: &str = "default_cap_typing";
    pub const DEFAULT_CAP_RECEIPTS: &str = "default_cap_receipts";
    pub const DEFAULT_CAP_GREEN_DOT: &str = "default_cap_green_dot";
    pub const CAP_DEFAULTS_V2_APPLIED: &str = "cap_defaults_v2_applied";

    // Profile share/sync state.
    pub const PROFILE_SYNC_FANOUT_AT: &str = "profile_sync_fanout_at";
    pub const PROFILE_SYNC_SEND: &str = "profile_sync_send";
    pub const PROFILE_SYNC_RECEIVE_DISABLED: &str = "profile_sync_receive_disabled";

    /// Per-relationship profile flow markers.
    pub fn profile_sent(rel_id: &str) -> String {
        format!("profile_sent_{rel_id}")
    }
    pub fn profile_req_sent(rel_id: &str) -> String {
        format!("profile_req_sent_{rel_id}")
    }
    pub fn profile_trade_await(rel_id: &str) -> String {
        format!("profile_trade_await_{rel_id}")
    }
    pub fn profile_trade_owed(rel_id: &str) -> String {
        format!("profile_trade_owed_{rel_id}")
    }
    pub fn profile_sync_sent(rel_id: &str) -> String {
        format!("profile_sync_sent_{rel_id}")
    }
    /// Onboarding chip dismissal, per hosted service.
    pub fn share_chip_dismissed(service_id: &str) -> String {
        format!("share_chip_dismissed_{service_id}")
    }

    // Internal engine scratch (not user settings; namespaced by suffix).
    /// When a contact close started (drives the settle-then-burn sweep).
    pub fn close_started_at(rel_id: &str) -> String {
        format!("close_started_at:{rel_id}")
    }
    /// When we last sent a RESYNC_REQ to this peer (rate limit).
    pub fn resync_req_at(rel_id: &str) -> String {
        format!("resync_req_at:{rel_id}")
    }
    /// Last intro processed at this invitation service (intro flood
    /// flood throttle; persisted so a restart doesn't reset it).
    pub fn intro_at(service_id: &str) -> String {
        format!("intro_at:{service_id}")
    }
    /// Accepter-side activation burst already fired for this peer.
    pub fn activation_sent(rel_id: &str) -> String {
        format!("activation_sent:{rel_id}")
    }
    /// Outbound app_seq high-water mark (u64 BE) for this peer: keeps
    /// `next_out_seq` monotonic after retention sweeps / history cuts
    /// erase the ledger rows it would otherwise be derived from.
    pub fn out_seq_floor(rel_id: &str) -> String {
        format!("out_seq_floor:{rel_id}")
    }
}

/// Typed accessors over the opaque blob store. Absent keys return
/// `None`; malformed encodings are `StoreError::Corrupt` (fail closed).
pub trait TypedSettings {
    fn get_bool(&self, key: &str) -> Result<Option<bool>, StoreError>;
    fn set_bool(&self, key: &str, value: bool) -> Result<(), StoreError>;
    fn get_u64(&self, key: &str) -> Result<Option<u64>, StoreError>;
    fn set_u64(&self, key: &str, value: u64) -> Result<(), StoreError>;
    fn get_string(&self, key: &str) -> Result<Option<String>, StoreError>;
    fn set_string(&self, key: &str, value: &str) -> Result<(), StoreError>;
}

impl TypedSettings for Db {
    fn get_bool(&self, key: &str) -> Result<Option<bool>, StoreError> {
        match self.setting(key)? {
            None => Ok(None),
            Some(v) if v == b"1" => Ok(Some(true)),
            Some(v) if v == b"0" => Ok(Some(false)),
            Some(_) => Err(StoreError::Corrupt(format!("bool setting {key}"))),
        }
    }

    fn set_bool(&self, key: &str, value: bool) -> Result<(), StoreError> {
        self.set_setting(key, if value { b"1" } else { b"0" })
    }

    fn get_u64(&self, key: &str) -> Result<Option<u64>, StoreError> {
        match self.setting(key)? {
            None => Ok(None),
            Some(v) => {
                let bytes: [u8; 8] = v
                    .try_into()
                    .map_err(|_| StoreError::Corrupt(format!("u64 setting {key}")))?;
                Ok(Some(u64::from_be_bytes(bytes)))
            }
        }
    }

    fn set_u64(&self, key: &str, value: u64) -> Result<(), StoreError> {
        self.set_setting(key, &value.to_be_bytes())
    }

    fn get_string(&self, key: &str) -> Result<Option<String>, StoreError> {
        match self.setting(key)? {
            None => Ok(None),
            Some(v) => String::from_utf8(v)
                .map(Some)
                .map_err(|_| StoreError::Corrupt(format!("string setting {key}"))),
        }
    }

    fn set_string(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.set_setting(key, value.as_bytes())
    }
}

pub trait SettingsRepository {
    fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), StoreError>;
    fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn delete_setting(&self, key: &str) -> Result<bool, StoreError>;
    fn all_settings(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError>;
}

fn set_setting_on(conn: &Connection, key: &str, value: &[u8]) -> Result<(), StoreError> {
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

fn setting_on(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
    use rusqlite::OptionalExtension;
    conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        params![key],
        |r| r.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn delete_setting_on(conn: &Connection, key: &str) -> Result<bool, StoreError> {
    let n = conn.execute("DELETE FROM settings WHERE key = ?1", params![key])?;
    Ok(n > 0)
}

fn all_settings_on(conn: &Connection) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
    let mut stmt = conn.prepare("SELECT key, value FROM settings ORDER BY key ASC")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

impl SettingsRepository for Db {
    fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        set_setting_on(self.conn(), key, value)
    }

    fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        setting_on(self.conn(), key)
    }

    fn delete_setting(&self, key: &str) -> Result<bool, StoreError> {
        delete_setting_on(self.conn(), key)
    }

    fn all_settings(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        all_settings_on(self.conn())
    }
}

/// The pairing layer holds `&Connection` (no `Db`); same repository.
impl SettingsRepository for Connection {
    fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        set_setting_on(self, key, value)
    }

    fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        setting_on(self, key)
    }

    fn delete_setting(&self, key: &str) -> Result<bool, StoreError> {
        delete_setting_on(self, key)
    }

    fn all_settings(&self) -> Result<Vec<(String, Vec<u8>)>, StoreError> {
        all_settings_on(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.setting("k").unwrap().is_none());
        db.set_setting("k", b"v1").unwrap();
        assert_eq!(db.setting("k").unwrap().as_deref(), Some(b"v1".as_slice()));
        db.set_setting("k", b"v2").unwrap();
        assert_eq!(db.setting("k").unwrap().as_deref(), Some(b"v2".as_slice()));
        assert!(db.delete_setting("k").unwrap());
        assert!(!db.delete_setting("k").unwrap());
        assert!(db.all_settings().unwrap().is_empty());
    }

    #[test]
    fn typed_settings_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.get_bool(keys::NOTIFY_ARRIVALS).unwrap(), None);
        db.set_bool(keys::NOTIFY_ARRIVALS, true).unwrap();
        assert_eq!(db.get_bool(keys::NOTIFY_ARRIVALS).unwrap(), Some(true));
        db.set_bool(keys::NOTIFY_ARRIVALS, false).unwrap();
        assert_eq!(db.get_bool(keys::NOTIFY_ARRIVALS).unwrap(), Some(false));

        db.set_u64(keys::INACTIVITY_ERASE_HOURS, 72).unwrap();
        assert_eq!(db.get_u64(keys::INACTIVITY_ERASE_HOURS).unwrap(), Some(72));

        db.set_string(keys::ONION_MODE, keys::MODE_SAVER).unwrap();
        assert_eq!(
            db.get_string(keys::ONION_MODE).unwrap().as_deref(),
            Some("saver")
        );

        // Malformed encodings fail closed.
        db.set_setting(keys::NOTIFY_ARRIVALS, b"yes").unwrap();
        assert!(matches!(
            db.get_bool(keys::NOTIFY_ARRIVALS),
            Err(StoreError::Corrupt(_))
        ));
        db.set_setting(keys::INACTIVITY_ERASE_HOURS, b"short")
            .unwrap();
        assert!(matches!(
            db.get_u64(keys::INACTIVITY_ERASE_HOURS),
            Err(StoreError::Corrupt(_))
        ));
    }

    #[test]
    fn key_names_match_spec() {
        // Spot-check the wire values.
        assert_eq!(keys::PROFILE_NAME, "profile_name");
        assert_eq!(keys::PROFILE_AVATAR, "profile_avatar");
        assert_eq!(keys::RECEIVE_MEDIA, "receive_media");
        assert_eq!(keys::DEFAULT_CAP_TYPING, "default_cap_typing");
        assert_eq!(keys::profile_sent("ab"), "profile_sent_ab");
        assert_eq!(keys::share_chip_dismissed("cd"), "share_chip_dismissed_cd");
        assert_eq!(keys::close_started_at("ef"), "close_started_at:ef");
    }
}
