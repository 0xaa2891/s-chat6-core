//! Persona: per-relationship key material (offer/accept both generate
//! one) — identity key pair, registration id, and the fixed-id pre-key
//! triple advertised in the pairing QR.

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyId, KyberPreKeyRecord,
    KyberPreKeyStore, PreKeyBundle, PreKeyId, PreKeyRecord, PreKeyStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::Rng;
use rusqlite::Connection;

use crate::store::StoreError;

use super::error::SessionError;
use super::{csprng, stores, KYBER_PREKEY_ID, ONE_TIME_PREKEY_ID, SIGNED_PREKEY_ID};

pub struct Persona {
    pub identity: IdentityKeyPair,
    pub registration_id: u32,
    pub signed_pre_key: SignedPreKeyRecord,
    pub kyber_pre_key: KyberPreKeyRecord,
    pub one_time_pre_key: PreKeyRecord,
}

pub fn generate_persona() -> Result<Persona, SessionError> {
    let mut rng = csprng();
    let identity = IdentityKeyPair::generate(&mut rng);
    let registration_id = rng.random_range(1..=0x3FFFu32);

    let signed_pair = KeyPair::generate(&mut rng);
    let signed_sig = identity
        .private_key()
        .calculate_signature(signed_pair.public_key.serialize().as_ref(), &mut rng)
        .map_err(|e| SessionError::Malformed(format!("spk sign: {e}")))?;
    let signed_pre_key = SignedPreKeyRecord::new(
        SignedPreKeyId::from(SIGNED_PREKEY_ID),
        Timestamp::from_epoch_millis(0),
        &signed_pair,
        &signed_sig,
    );

    let kyber_pre_key = KyberPreKeyRecord::generate(
        libsignal_protocol::kem::KeyType::MLKEM1024,
        KyberPreKeyId::from(KYBER_PREKEY_ID),
        identity.private_key(),
    )
    .map_err(|e| SessionError::Malformed(format!("kyber keygen: {e}")))?;

    let one_time_pre_key = PreKeyRecord::new(
        PreKeyId::from(ONE_TIME_PREKEY_ID),
        &KeyPair::generate(&mut rng),
    );

    Ok(Persona {
        identity,
        registration_id,
        signed_pre_key,
        kyber_pre_key,
        one_time_pre_key,
    })
}

/// Persist a fresh persona's private state under `namespace`.
pub async fn store_persona(
    db: &Connection,
    namespace: &str,
    persona: &Persona,
) -> Result<(), SessionError> {
    stores::create_local(db, namespace, persona.registration_id, &persona.identity)
        .map_err(|e| SessionError::Store(StoreError::Corrupt(e.to_string())))?;
    stores::SqlitePreKeyStore {
        db,
        namespace: namespace.into(),
    }
    .save_pre_key(
        PreKeyId::from(ONE_TIME_PREKEY_ID),
        &persona.one_time_pre_key,
    )
    .await
    .map_err(|e| SessionError::Store(StoreError::Corrupt(e.to_string())))?;
    stores::SqliteSignedPreKeyStore {
        db,
        namespace: namespace.into(),
    }
    .save_signed_pre_key(
        SignedPreKeyId::from(SIGNED_PREKEY_ID),
        &persona.signed_pre_key,
    )
    .await
    .map_err(|e| SessionError::Store(StoreError::Corrupt(e.to_string())))?;
    stores::SqliteKyberPreKeyStore {
        db,
        namespace: namespace.into(),
    }
    .save_kyber_pre_key(KyberPreKeyId::from(KYBER_PREKEY_ID), &persona.kyber_pre_key)
    .await
    .map_err(|e| SessionError::Store(StoreError::Corrupt(e.to_string())))?;
    Ok(())
}

/// The public pre-key bundle a persona advertises (inside the pairing QR).
pub fn persona_bundle(persona: &Persona) -> Result<PreKeyBundle, SessionError> {
    use libsignal_protocol::GenericSignedPreKey as _;
    PreKeyBundle::new(
        persona.registration_id,
        1u32.try_into().expect("device id 1"),
        Some((
            PreKeyId::from(ONE_TIME_PREKEY_ID),
            persona.one_time_pre_key.public_key().map_err(sig_err)?,
        )),
        SignedPreKeyId::from(SIGNED_PREKEY_ID),
        persona.signed_pre_key.public_key().map_err(sig_err)?,
        persona.signed_pre_key.signature().map_err(sig_err)?,
        KyberPreKeyId::from(KYBER_PREKEY_ID),
        persona.kyber_pre_key.public_key().map_err(sig_err)?,
        persona.kyber_pre_key.signature().map_err(sig_err)?,
        *persona.identity.identity_key(),
    )
    .map_err(sig_err)
}

fn sig_err(e: SignalProtocolError) -> SessionError {
    SessionError::Malformed(format!("bundle: {e}"))
}
