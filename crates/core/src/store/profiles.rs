//! `profiles` table repository: peer profiles landed via PROFILE
//! envelopes. Our own profile is a settings concern;
//! this table is per-relationship peer data only.

use rusqlite::params;

use super::{Db, StoreError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRow {
    pub rel_id: String,
    pub name: String,
    /// Already-compressed JPEG (media-prepared by the sender), possibly
    /// empty (name-only profile).
    pub jpeg: Vec<u8>,
    pub updated_at: u64,
}

pub trait ProfilesRepository {
    /// Land a peer's profile. Replace semantics: the newest PROFILE
    /// envelope wins.
    fn put_profile(&self, rel_id: &str, name: &str, jpeg: &[u8]) -> Result<(), StoreError>;
    fn profile(&self, rel_id: &str) -> Result<Option<ProfileRow>, StoreError>;
    fn delete_profile(&self, rel_id: &str) -> Result<bool, StoreError>;
}

impl ProfilesRepository for Db {
    fn put_profile(&self, rel_id: &str, name: &str, jpeg: &[u8]) -> Result<(), StoreError> {
        self.conn().execute(
            "INSERT OR REPLACE INTO profiles (rel_id, name, jpeg, updated_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![rel_id, name, jpeg, self.clock().now_secs() as i64],
        )?;
        Ok(())
    }

    fn profile(&self, rel_id: &str) -> Result<Option<ProfileRow>, StoreError> {
        use rusqlite::OptionalExtension;
        self.conn()
            .query_row(
                "SELECT rel_id, name, jpeg, updated_at FROM profiles WHERE rel_id = ?1",
                params![rel_id],
                |r| {
                    Ok(ProfileRow {
                        rel_id: r.get(0)?,
                        name: r.get(1)?,
                        jpeg: r.get(2)?,
                        updated_at: r.get::<_, i64>(3)? as u64,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn delete_profile(&self, rel_id: &str) -> Result<bool, StoreError> {
        let n = self
            .conn()
            .execute("DELETE FROM profiles WHERE rel_id = ?1", params![rel_id])?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_replace_delete() {
        let db = Db::open_in_memory().unwrap();
        assert!(db.profile("rel").unwrap().is_none());
        db.put_profile("rel", "Alice", b"\xff\xd8\xff").unwrap();
        db.put_profile("rel", "Alice v2", b"").unwrap();
        let row = db.profile("rel").unwrap().unwrap();
        assert_eq!(row.name, "Alice v2");
        assert!(row.jpeg.is_empty());
        assert!(db.delete_profile("rel").unwrap());
        assert!(!db.delete_profile("rel").unwrap());
    }
}
