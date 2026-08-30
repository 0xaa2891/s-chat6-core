//! Pairing QR payload.
//!
//! One-way invitation: the inviter shows this payload (as a QR matrix or a
//! Base58 one-time code), the accepter scans/pastes it and initiates. The
//! payload is a libsignal pre-key bundle plus the inviter's onion address,
//! restricted-discovery (v3 client-auth) public key, a SAS nonce, and an
//! expiry — signed by the persona identity key (XEdDSA, the libsignal
//! Curve25519 signature — the persona identity signs its own bundle).
//!
//! Fail closed: any invalid field, bad signature, or expired payload aborts
//! pairing with no partial state written.
//!
//! Wire layout (hand-rolled; u8/u16be/u32be/u64be, `lp` = u16be length
//! prefix, no serde):
//!
//! ```text
//! "SPAIR7" ‖ u8 version=1
//! lp identity_key(33) ‖ u32be registration_id
//! u8 has_prekey [‖ u32be pre_key_id ‖ lp pre_key_public(33)]
//! u32be signed_pre_key_id ‖ lp spk_public(33) ‖ lp spk_signature(64)
//! u32be kyber_pre_key_id ‖ lp kyber_public ‖ lp kyber_signature(64)
//! lp onion_raw(35) ‖ lp client_auth_public(32) ‖ lp nonce(32)
//! u64be expires_at_epoch_seconds
//! lp signature(64)        -- XEdDSA over everything above
//! ```

use libsignal_protocol::{
    DeviceId, IdentityKey, KyberPreKeyId, PreKeyBundle, PreKeyId, PrivateKey, PublicKey,
    SignedPreKeyId,
};
use thiserror::Error;

use crate::transport::onion::{self, ONION_RAW_BYTES};

pub const QR_LABEL: &[u8] = b"SPAIR7";
pub const QR_VERSION: u8 = 1;
/// Invitation lifetime: 5 minutes.
/// Applies to the QR and to the one-time code (same payload).
pub const OFFER_TTL_SECONDS: u64 = 300;

const MAX_FIELD: usize = 4096;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PairingError {
    #[error("invalid pairing payload: {0}")]
    Invalid(String),
    #[error("pairing offer expired")]
    Expired,
    #[error("pairing signature invalid")]
    BadSignature,
}

#[derive(Clone, Debug)]
pub struct PairingPayload {
    pub identity_key: Vec<u8>,
    pub registration_id: u32,
    pub pre_key: Option<(u32, Vec<u8>)>,
    pub signed_pre_key_id: u32,
    pub signed_pre_key_public: Vec<u8>,
    pub signed_pre_key_signature: Vec<u8>,
    pub kyber_pre_key_id: u32,
    pub kyber_pre_key_public: Vec<u8>,
    pub kyber_pre_key_signature: Vec<u8>,
    pub onion: [u8; ONION_RAW_BYTES],
    pub client_auth_public: [u8; 32],
    pub nonce: [u8; 32],
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

// -- hand-rolled codec -------------------------------------------------------

struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u32be(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn u64be(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn raw(&mut self, v: &[u8]) {
        self.0.extend_from_slice(v);
    }
    fn lp(&mut self, v: &[u8]) {
        self.u32be_len(v.len());
        self.raw(v);
    }
    fn u32be_len(&mut self, len: usize) {
        // lp fields are u16be-length-prefixed.
        self.0.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    // Invariant: returns exactly `n` bytes on success — the fixed-width
    // readers below rely on this for their infallible `try_into().unwrap()`.
    fn take(&mut self, n: usize) -> Result<&'a [u8], PairingError> {
        if self.pos + n > self.buf.len() {
            return Err(PairingError::Invalid("truncated".into()));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, PairingError> {
        Ok(self.take(1)?[0])
    }
    fn u32be(&mut self) -> Result<u32, PairingError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64be(&mut self) -> Result<u64, PairingError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn lp(&mut self, max: usize) -> Result<&'a [u8], PairingError> {
        let len = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as usize;
        if len == 0 || len > max {
            return Err(PairingError::Invalid(format!(
                "lp length {len} out of range"
            )));
        }
        self.take(len)
    }
    fn expect_end(&self) -> Result<(), PairingError> {
        if self.pos != self.buf.len() {
            return Err(PairingError::Invalid("trailing bytes".into()));
        }
        Ok(())
    }
}

impl PairingPayload {
    /// The public half of a persona, ready to sign. `onion` is the raw
    /// 35-byte v3 address of the service this persona hosts.
    #[allow(clippy::too_many_arguments)]
    pub fn from_bundle(
        bundle: &PreKeyBundle,
        onion: [u8; ONION_RAW_BYTES],
        client_auth_public: [u8; 32],
        nonce: [u8; 32],
        expires_at: u64,
    ) -> Result<Self, PairingError> {
        let map = |e: libsignal_protocol::SignalProtocolError| {
            PairingError::Invalid(format!("bundle: {e}"))
        };
        Ok(Self {
            identity_key: bundle.identity_key().map_err(map)?.serialize().to_vec(),
            registration_id: bundle.registration_id().map_err(map)?,
            pre_key: match (
                bundle.pre_key_id().map_err(map)?,
                bundle.pre_key_public().map_err(map)?,
            ) {
                (Some(id), Some(pk)) => Some((id.into(), pk.serialize().to_vec())),
                _ => None,
            },
            signed_pre_key_id: bundle.signed_pre_key_id().map_err(map)?.into(),
            signed_pre_key_public: bundle
                .signed_pre_key_public()
                .map_err(map)?
                .serialize()
                .to_vec(),
            signed_pre_key_signature: bundle.signed_pre_key_signature().map_err(map)?.to_vec(),
            kyber_pre_key_id: bundle.kyber_pre_key_id().map_err(map)?.into(),
            kyber_pre_key_public: bundle
                .kyber_pre_key_public()
                .map_err(map)?
                .serialize()
                .to_vec(),
            kyber_pre_key_signature: bundle.kyber_pre_key_signature().map_err(map)?.to_vec(),
            onion,
            client_auth_public,
            nonce,
            expires_at,
            signature: Vec::new(),
        })
    }

    pub fn signed_body(&self) -> Vec<u8> {
        let mut w = Writer(Vec::with_capacity(2560));
        w.raw(QR_LABEL);
        w.u8(QR_VERSION);
        w.lp(&self.identity_key);
        w.u32be(self.registration_id);
        match &self.pre_key {
            Some((id, pk)) => {
                w.u8(1);
                w.u32be(*id);
                w.lp(pk);
            }
            None => w.u8(0),
        }
        w.u32be(self.signed_pre_key_id);
        w.lp(&self.signed_pre_key_public);
        w.lp(&self.signed_pre_key_signature);
        w.u32be(self.kyber_pre_key_id);
        w.lp(&self.kyber_pre_key_public);
        w.lp(&self.kyber_pre_key_signature);
        w.lp(&self.onion);
        w.lp(&self.client_auth_public);
        w.lp(&self.nonce);
        w.u64be(self.expires_at);
        w.0
    }

    /// Sign the payload with the persona identity key (XEdDSA).
    pub fn sign(mut self, identity: &PrivateKey) -> Result<Self, PairingError> {
        let mut rng = crate::session::csprng();
        let sig = identity
            .calculate_signature(&self.signed_body(), &mut rng)
            .map_err(|e| PairingError::Invalid(format!("sign: {e}")))?;
        self.signature = sig.to_vec();
        Ok(self)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signed_body();
        out.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Strict decode. Structural errors only — cryptographic checks live in
    /// [`PairingPayload::verify`].
    pub fn decode(bytes: &[u8]) -> Result<Self, PairingError> {
        // Total-payload cap: per-field caps bound each lp
        // read, but the sum must be bounded too — a QR/code payload has
        // no business being larger than this.
        if bytes.len() > crate::limits::pairing::MAX_QR_PAYLOAD_BYTES {
            return Err(PairingError::Invalid(format!(
                "payload too large: {} > {}",
                bytes.len(),
                crate::limits::pairing::MAX_QR_PAYLOAD_BYTES
            )));
        }
        let mut r = Reader { buf: bytes, pos: 0 };
        if r.take(QR_LABEL.len())? != QR_LABEL {
            return Err(PairingError::Invalid("label mismatch".into()));
        }
        if r.u8()? != QR_VERSION {
            return Err(PairingError::Invalid("unsupported version".into()));
        }
        let identity_key = r.lp(64)?.to_vec();
        let registration_id = r.u32be()?;
        let pre_key = match r.u8()? {
            0 => None,
            1 => Some((r.u32be()?, r.lp(64)?.to_vec())),
            other => return Err(PairingError::Invalid(format!("has_prekey {other}"))),
        };
        let signed_pre_key_id = r.u32be()?;
        let signed_pre_key_public = r.lp(64)?.to_vec();
        let signed_pre_key_signature = r.lp(64)?.to_vec();
        let kyber_pre_key_id = r.u32be()?;
        let kyber_pre_key_public = r.lp(MAX_FIELD)?.to_vec();
        let kyber_pre_key_signature = r.lp(64)?.to_vec();
        let onion: [u8; ONION_RAW_BYTES] = r
            .lp(ONION_RAW_BYTES)?
            .try_into()
            .map_err(|_| PairingError::Invalid("onion length".into()))?;
        let client_auth_public: [u8; 32] = r
            .lp(32)?
            .try_into()
            .map_err(|_| PairingError::Invalid("client auth length".into()))?;
        let nonce: [u8; 32] = r
            .lp(32)?
            .try_into()
            .map_err(|_| PairingError::Invalid("nonce length".into()))?;
        let expires_at = r.u64be()?;
        let signature = r.lp(64)?.to_vec();
        r.expect_end()?;
        Ok(Self {
            identity_key,
            registration_id,
            pre_key,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            kyber_pre_key_id,
            kyber_pre_key_public,
            kyber_pre_key_signature,
            onion,
            client_auth_public,
            nonce,
            expires_at,
            signature,
        })
    }

    pub fn identity(&self) -> Result<IdentityKey, PairingError> {
        IdentityKey::try_from(self.identity_key.as_slice())
            .map_err(|e| PairingError::Invalid(format!("identity key: {e}")))
    }

    /// Fail-closed validation: outer signature, both pre-key signatures,
    /// onion checksum, and (when `enforce_expiry`) the 5-minute TTL.
    /// Expiry is enforced at scan/paste time only — an intro that arrives
    /// later from a peer who accepted in time is still valid.
    pub fn verify(&self, now_epoch_seconds: u64, enforce_expiry: bool) -> Result<(), PairingError> {
        if enforce_expiry && self.expires_at < now_epoch_seconds {
            return Err(PairingError::Expired);
        }
        let identity = self.identity()?;
        if !identity
            .public_key()
            .verify_signature(&self.signed_body(), &self.signature)
        {
            return Err(PairingError::BadSignature);
        }
        if !identity
            .public_key()
            .verify_signature(&self.signed_pre_key_public, &self.signed_pre_key_signature)
        {
            return Err(PairingError::BadSignature);
        }
        if !identity
            .public_key()
            .verify_signature(&self.kyber_pre_key_public, &self.kyber_pre_key_signature)
        {
            return Err(PairingError::BadSignature);
        }
        // Onion checksum + version byte.
        onion::hostname_from_raw(&self.onion)
            .map_err(|e| PairingError::Invalid(format!("onion: {e}")))?;
        Ok(())
    }

    /// Rebuild the libsignal bundle (accepter side, PQXDH initiator).
    pub fn to_bundle(&self) -> Result<PreKeyBundle, PairingError> {
        let map =
            |e: libsignal_protocol::SignalProtocolError| PairingError::Invalid(format!("{e}"));
        let device_id: DeviceId = 1u32.try_into().expect("device id 1");
        let pre_key = match &self.pre_key {
            Some((id, pk)) => Some((
                PreKeyId::from(*id),
                PublicKey::deserialize(pk).map_err(|e| PairingError::Invalid(format!("{e}")))?,
            )),
            None => None,
        };
        PreKeyBundle::new(
            self.registration_id,
            device_id,
            pre_key,
            SignedPreKeyId::from(self.signed_pre_key_id),
            PublicKey::deserialize(&self.signed_pre_key_public)
                .map_err(|e| PairingError::Invalid(format!("{e}")))?,
            self.signed_pre_key_signature.clone(),
            KyberPreKeyId::from(self.kyber_pre_key_id),
            libsignal_protocol::kem::PublicKey::deserialize(&self.kyber_pre_key_public)
                .map_err(map)?,
            self.kyber_pre_key_signature.clone(),
            self.identity()?,
        )
        .map_err(map)
    }
}

// ---------------------------------------------------------------------------
// QR matrix (core emits the matrix; clients only draw it)

pub struct QrMatrix {
    pub size: u32,
    /// Row-major, 1 = dark module.
    pub modules: Vec<u8>,
}

pub fn render_qr_matrix(payload: &[u8]) -> Result<QrMatrix, PairingError> {
    let code = qrcode::QrCode::new(payload)
        .map_err(|e| PairingError::Invalid(format!("qr encode: {e}")))?;
    let size = code.width() as u32;
    let modules = code
        .to_colors()
        .into_iter()
        .map(|c| match c {
            qrcode::Color::Dark => 1u8,
            qrcode::Color::Light => 0u8,
        })
        .collect();
    Ok(QrMatrix { size, modules })
}

// ---------------------------------------------------------------------------
// One-time code: the same payload as copy-pasteable Base58 text
// (Base58 → QR bytes). Same 5-minute TTL.

pub fn encode_code(qr_bytes: &[u8]) -> String {
    bs58::encode(qr_bytes).into_string()
}

pub fn decode_code(code: &str) -> Result<Vec<u8>, PairingError> {
    bs58::decode(code.trim())
        .into_vec()
        .map_err(|e| PairingError::Invalid(format!("base58: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session;

    fn payload(now: u64) -> PairingPayload {
        let persona = session::generate_persona().unwrap();
        let bundle = session::persona_bundle(&persona).unwrap();
        let onion = {
            let (_, host) = onion::generate_v3_key_blob();
            onion::raw_from_hostname(&host).unwrap()
        };
        PairingPayload::from_bundle(&bundle, onion, [9u8; 32], [7u8; 32], now + 300)
            .unwrap()
            .sign(persona.identity.private_key())
            .unwrap()
    }

    #[test]
    fn roundtrip_and_verify() {
        let now = 1_800_000_000u64;
        let p = payload(now);
        let bytes = p.encode();
        let back = PairingPayload::decode(&bytes).unwrap();
        back.verify(now, true).unwrap();
        assert_eq!(back.identity_key, p.identity_key);
        assert_eq!(back.nonce, p.nonce);
        assert_eq!(back.onion, p.onion);
        // The bundle survives the round trip.
        back.to_bundle().unwrap();
    }

    #[test]
    fn expired_rejected_only_when_enforced() {
        let now = 1_800_000_000u64;
        let p = payload(now);
        let later = now + OFFER_TTL_SECONDS + 1;
        assert_eq!(p.verify(later, true), Err(PairingError::Expired));
        // Intro receive path does not enforce expiry.
        p.verify(later, false).unwrap();
    }

    #[test]
    fn tampered_signature_rejected() {
        let now = 1_800_000_000u64;
        let p = payload(now);
        let mut bytes = p.encode();
        // Flip a byte inside the signed body (the nonce region).
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let back = PairingPayload::decode(&bytes).unwrap();
        assert_eq!(back.verify(now, true), Err(PairingError::BadSignature));
    }

    #[test]
    fn truncated_and_trailing_rejected() {
        let now = 1_800_000_000u64;
        let bytes = payload(now).encode();
        assert!(PairingPayload::decode(&bytes[..bytes.len() - 3]).is_err());
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(PairingPayload::decode(&longer).is_err());
        assert!(PairingPayload::decode(b"wrong-label-payload").is_err());
    }

    #[test]
    fn total_payload_cap_enforced() {
        // Per-field caps bound each read; the total must be
        // bounded too. A real payload fits comfortably under the cap…
        let now = 1_800_000_000u64;
        let bytes = payload(now).encode();
        assert!(bytes.len() <= crate::limits::pairing::MAX_QR_PAYLOAD_BYTES);
        assert!(PairingPayload::decode(&bytes).is_ok());
        // …and anything over the cap is refused before parsing.
        let huge = vec![0u8; crate::limits::pairing::MAX_QR_PAYLOAD_BYTES + 1];
        assert!(matches!(
            PairingPayload::decode(&huge),
            Err(PairingError::Invalid(_))
        ));
    }

    #[test]
    fn code_roundtrip() {
        let now = 1_800_000_000u64;
        let bytes = payload(now).encode();
        let code = encode_code(&bytes);
        assert_eq!(decode_code(&code).unwrap(), bytes);
        assert!(decode_code("not base58 !!!").is_err());
    }

    #[test]
    fn qr_matrix_is_square() {
        let now = 1_800_000_000u64;
        let bytes = payload(now).encode();
        let matrix = render_qr_matrix(&bytes).unwrap();
        assert_eq!(matrix.modules.len() as u32, matrix.size * matrix.size);
    }
}
