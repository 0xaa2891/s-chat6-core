//! `IdentityKeyStore` over SQLCipher: TOFU within the relationship
//! namespace — the first identity seen is the QR-verified one (pinned at
//! pairing time); any later change is an attack or corruption.

use libsignal_protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, ProtocolAddress,
    SignalProtocolError,
};
use rusqlite::{params, Connection};

use super::{corrupt, store_err};

pub struct SqliteIdentityStore<'a> {
    pub db: &'a Connection,
    pub namespace: String,
}

#[async_trait::async_trait(?Send)]
impl IdentityKeyStore for SqliteIdentityStore<'_> {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let blob: Vec<u8> = self
            .db
            .query_row(
                "SELECT identity_keypair FROM signal_locals WHERE namespace = ?1",
                params![self.namespace],
                |r| r.get(0),
            )
            .map_err(store_err("get_identity_key_pair"))?;
        IdentityKeyPair::try_from(blob.as_slice()).map_err(|e| corrupt("get_identity_key_pair", e))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        self.db
            .query_row(
                "SELECT registration_id FROM signal_locals WHERE namespace = ?1",
                params![self.namespace],
                |r| r.get(0),
            )
            .map_err(store_err("get_local_registration_id"))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing = self.get_identity(address).await?;
        let replaced = existing.as_ref().is_some_and(|old| old != identity);
        self.db
            .execute(
                "INSERT OR REPLACE INTO signal_identities (namespace, address, key)
                 VALUES (?1, ?2, ?3)",
                params![
                    self.namespace,
                    address.to_string(),
                    identity.serialize().as_ref()
                ],
            )
            .map_err(store_err("save_identity"))?;
        Ok(IdentityChange::from_changed(replaced))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        // TOFU: trust the pinned identity, distrust any change (fail closed).
        match self.get_identity(address).await? {
            None => Ok(true),
            Some(stored) => Ok(stored == *identity),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let blob: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT key FROM signal_identities WHERE namespace = ?1 AND address = ?2",
                params![self.namespace, address.to_string()],
                |r| r.get(0),
            )
            .ok();
        blob.map(|b| IdentityKey::try_from(b.as_slice()).map_err(|e| corrupt("get_identity", e)))
            .transpose()
    }
}
