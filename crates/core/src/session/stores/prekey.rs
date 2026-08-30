//! Pre-key stores over SQLCipher: one-time, signed, and Kyber (PQ)
//! pre-keys, including last-resort Kyber reuse semantics.

use libsignal_protocol::{
    KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
    PublicKey, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use rusqlite::{params, Connection};

use super::{corrupt, store_err};

pub struct SqlitePreKeyStore<'a> {
    pub db: &'a Connection,
    pub namespace: String,
}

#[async_trait::async_trait(?Send)]
impl PreKeyStore for SqlitePreKeyStore<'_> {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let blob: Vec<u8> = self
            .db
            .query_row(
                "SELECT record FROM signal_prekeys WHERE namespace = ?1 AND id = ?2",
                params![self.namespace, id],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => SignalProtocolError::InvalidPreKeyId,
                other => store_err("get_pre_key")(other),
            })?;
        PreKeyRecord::deserialize(&blob).map_err(|e| corrupt("get_pre_key", e))
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        self.db
            .execute(
                "INSERT OR REPLACE INTO signal_prekeys (namespace, id, record)
                 VALUES (?1, ?2, ?3)",
                params![self.namespace, id, record.serialize()?],
            )
            .map_err(store_err("save_pre_key"))?;
        Ok(())
    }

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        self.db
            .execute(
                "DELETE FROM signal_prekeys WHERE namespace = ?1 AND id = ?2",
                params![self.namespace, id],
            )
            .map_err(store_err("remove_pre_key"))?;
        Ok(())
    }
}

pub struct SqliteSignedPreKeyStore<'a> {
    pub db: &'a Connection,
    pub namespace: String,
}

#[async_trait::async_trait(?Send)]
impl SignedPreKeyStore for SqliteSignedPreKeyStore<'_> {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let blob: Vec<u8> = self
            .db
            .query_row(
                "SELECT record FROM signal_signed_prekeys WHERE namespace = ?1 AND id = ?2",
                params![self.namespace, id],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => SignalProtocolError::InvalidSignedPreKeyId,
                other => store_err("get_signed_pre_key")(other),
            })?;
        use libsignal_protocol::GenericSignedPreKey;
        SignedPreKeyRecord::deserialize(&blob).map_err(|e| corrupt("get_signed_pre_key", e))
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        use libsignal_protocol::GenericSignedPreKey;
        let id: u32 = signed_prekey_id.into();
        self.db
            .execute(
                "INSERT OR REPLACE INTO signal_signed_prekeys (namespace, id, record)
                 VALUES (?1, ?2, ?3)",
                params![self.namespace, id, record.serialize()?],
            )
            .map_err(store_err("save_signed_pre_key"))?;
        Ok(())
    }
}

pub struct SqliteKyberPreKeyStore<'a> {
    pub db: &'a Connection,
    pub namespace: String,
}

#[async_trait::async_trait(?Send)]
impl KyberPreKeyStore for SqliteKyberPreKeyStore<'_> {
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let blob: Vec<u8> = self
            .db
            .query_row(
                "SELECT record FROM signal_kyber_prekeys WHERE namespace = ?1 AND id = ?2",
                params![self.namespace, id],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => SignalProtocolError::InvalidKyberPreKeyId,
                other => store_err("get_kyber_pre_key")(other),
            })?;
        use libsignal_protocol::GenericSignedPreKey;
        KyberPreKeyRecord::deserialize(&blob).map_err(|e| corrupt("get_kyber_pre_key", e))
    }

    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        use libsignal_protocol::GenericSignedPreKey;
        let id: u32 = kyber_prekey_id.into();
        // Re-saving must not resurrect a consumed key: used_with survives.
        self.db
            .execute(
                "INSERT INTO signal_kyber_prekeys (namespace, id, record, used_with)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(namespace, id) DO UPDATE SET record = excluded.record",
                params![self.namespace, id, record.serialize()?],
            )
            .map_err(store_err("save_kyber_pre_key"))?;
        Ok(())
    }

    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        // Last-resort semantics (idempotent under retransmission): the
        // first consumer pins (signed pre-key, base key); the same tuple
        // again is a redelivery, a *different* tuple is reuse — fail closed.
        let id: u32 = kyber_prekey_id.into();
        let spk: u32 = ec_prekey_id.into();
        let mut tuple = spk.to_be_bytes().to_vec();
        tuple.extend_from_slice(base_key.serialize().as_ref());
        let used: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT used_with FROM signal_kyber_prekeys WHERE namespace = ?1 AND id = ?2",
                params![self.namespace, id],
                |r| r.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => SignalProtocolError::InvalidKyberPreKeyId,
                other => store_err("mark_kyber_pre_key_used")(other),
            })?;
        match used {
            None => {
                self.db
                    .execute(
                        "UPDATE signal_kyber_prekeys SET used_with = ?3
                         WHERE namespace = ?1 AND id = ?2",
                        params![self.namespace, id, tuple],
                    )
                    .map_err(store_err("mark_kyber_pre_key_used"))?;
                Ok(())
            }
            Some(existing) if existing == tuple => Ok(()),
            Some(_) => Err(SignalProtocolError::InvalidState(
                "mark_kyber_pre_key_used",
                format!("kyber pre-key {id} reused with a different base key"),
            )),
        }
    }
}
