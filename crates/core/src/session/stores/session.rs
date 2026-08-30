//! `SessionStore` over SQLCipher.

use libsignal_protocol::{ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError};
use rusqlite::{params, Connection};

use super::{corrupt, store_err};

pub struct SqliteSessionStore<'a> {
    pub db: &'a Connection,
    pub namespace: String,
}

#[async_trait::async_trait(?Send)]
impl SessionStore for SqliteSessionStore<'_> {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let blob: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT record FROM signal_sessions WHERE namespace = ?1 AND address = ?2",
                params![self.namespace, address.to_string()],
                |r| r.get(0),
            )
            .ok();
        blob.map(|b| SessionRecord::deserialize(&b).map_err(|e| corrupt("load_session", e)))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let bytes = record.serialize()?;
        self.db
            .execute(
                "INSERT OR REPLACE INTO signal_sessions (namespace, address, record)
                 VALUES (?1, ?2, ?3)",
                params![self.namespace, address.to_string(), bytes],
            )
            .map_err(store_err("store_session"))?;
        Ok(())
    }
}
