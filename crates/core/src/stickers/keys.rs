//! Pack signing keys (XEdDSA over Curve25519, same primitive family as
//! the session layer). The private half lives in `sticker_pack_keys`;
//! the public half is the pack's identity on the wire (`pack_pk`).

use libsignal_protocol::{KeyPair, PrivateKey, PublicKey};
use rand::RngCore;

use crate::store::{hex_encode, Db, StoreError};

/// A pack keypair. `public` is the 32-byte raw key (no DJB type byte).
pub struct PackKey {
    pub public: [u8; 32],
    pair: KeyPair,
}

impl PackKey {
    pub fn generate() -> Self {
        let mut rng = crate::session::csprng();
        let pair = KeyPair::generate(&mut rng);
        let raw = pair.public_key.serialize();
        // libsignal serializes as 0x05 ‖ key; the wire wants the raw key.
        let public: [u8; 32] = raw[1..].try_into().expect("curve25519 key is 33 bytes");
        Self { public, pair }
    }

    /// Sign a pack document body (XEdDSA).
    pub fn sign(&self, body: &[u8]) -> Vec<u8> {
        let mut rng = crate::session::csprng();
        self.pair
            .private_key
            .calculate_signature(body, &mut rng)
            .expect("xeddsa signing cannot fail with a valid key")
            .to_vec()
    }
}

/// Rebuild a `PublicKey` from the 32-byte wire form.
fn public_from_raw(raw: &[u8; 32]) -> Result<PublicKey, StoreError> {
    let mut buf = Vec::with_capacity(33);
    buf.push(0x05); // DJB curve25519 type byte
    buf.extend_from_slice(raw);
    PublicKey::deserialize(&buf).map_err(|e| StoreError::Corrupt(format!("pack pk: {e}")))
}

/// Verify a pack document signature (injected into
/// `StickerPackDoc::decode_signed`).
pub fn verify_with(pack_pk: &[u8; 32], body: &[u8], sig: &[u8]) -> bool {
    match public_from_raw(pack_pk) {
        Ok(pk) => pk.verify_signature(body, sig),
        Err(_) => false,
    }
}

/// Persist the private half of a pack key (packs we created).
pub fn store_pack_key(db: &Db, pack_id: &[u8; 16], key: &PackKey) -> Result<(), StoreError> {
    use crate::store::sticker_items::StickerItemsRepository;
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&key.pair.private_key.serialize());
    // Best-effort hygiene: the DB copy is the durable one (SQLCipher
    // at rest); the stack copy is zeroed on the way out.
    let r = db.put_pack_key(pack_id, &secret);
    secret.iter_mut().for_each(|b| *b = 0);
    r
}

/// Load + reconstruct a pack key for re-signing (pack edits).
pub fn load_pack_key(db: &Db, pack_id: &[u8; 16]) -> Result<Option<PackKey>, StoreError> {
    use crate::store::sticker_items::StickerItemsRepository;
    use rusqlite::OptionalExtension;
    let Some(secret) = db.pack_key(pack_id)? else {
        return Ok(None);
    };
    let private = PrivateKey::deserialize(&secret)
        .map_err(|e| StoreError::Corrupt(format!("pack key: {e}")))?;
    let public_raw: [u8; 32] = {
        // The public half rides on the pack row (it is the pack's wire
        // identity); the private half alone cannot recompute it cheaply.
        let stored: Option<Vec<u8>> = db
            .conn()
            .query_row(
                "SELECT pack_pk FROM stickers WHERE pack_id = ?1",
                rusqlite::params![hex_encode(pack_id)],
                |r| r.get(0),
            )
            .optional()?;
        let Some(raw) = stored else {
            return Err(StoreError::Corrupt("pack key without pack row".into()));
        };
        raw.try_into()
            .map_err(|_| StoreError::Corrupt("pack pk not 32 bytes".into()))?
    };
    let public = public_from_raw(&public_raw)?;
    Ok(Some(PackKey {
        public: public_raw,
        pair: KeyPair::new(public, private),
    }))
}

/// Random pack id.
pub fn random_pack_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id
}
