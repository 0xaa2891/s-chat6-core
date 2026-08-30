//! Pairing, session, and frame ingest at the boundary.

use std::time::SystemTime;

use crate::{pairing, session};

use super::{CoreError, SchatCore};

#[derive(uniffi::Record, Clone, Debug)]
pub struct PairingOfferFfi {
    /// Signed pairing payload — render with [`render_qr_matrix`].
    pub qr_bytes: Vec<u8>,
    /// The same payload as a Base58 one-time code (5-minute expiry).
    pub code: String,
    pub onion: String,
    pub expires_at: u64,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct QrMatrixFfi {
    pub size: u32,
    /// Row-major, 1 = dark module. Clients only draw this.
    pub modules: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct AcceptedFfi {
    pub rel_id: String,
    /// 8-digit safety code (optional out-of-band compare; not a pairing gate).
    pub sas: String,
    pub peer_onion: String,
    pub onion: String,
}

#[derive(uniffi::Record, Clone, Debug)]
pub struct RequestInfoFfi {
    pub rel_id: String,
    pub sas: String,
    pub peer_onion: String,
    pub created_at: u64,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionStateFfi {
    Missing,
    Active,
    Broken,
}

#[derive(uniffi::Enum, Clone, Debug)]
pub enum IngestFfi {
    RequestReceived {
        rel_id: String,
        sas: String,
        plaintext: Vec<u8>,
    },
    Message {
        rel_id: String,
        plaintext: Vec<u8>,
    },
    Duplicate,
    SessionBroken {
        rel_id: String,
        reason: String,
    },
    Dropped,
    /// Vault locked: the frame sits in the Tier-A queue at rest until
    /// `unlock` drains it.
    Queued,
}

/// Render a QR payload to a module matrix. Core owns the QR encoding;
/// clients only draw.
#[uniffi::export]
pub fn render_qr_matrix(payload: &[u8]) -> Result<QrMatrixFfi, CoreError> {
    let matrix =
        pairing::qr::render_qr_matrix(payload).map_err(|e| CoreError::Other(e.to_string()))?;
    Ok(QrMatrixFfi {
        size: matrix.size,
        modules: matrix.modules,
    })
}

#[uniffi::export]
impl SchatCore {
    /// Create a pairing offer (inviter side). Render `qr_bytes` via
    /// [`render_qr_matrix`] or hand over `code` as text. 5-minute expiry.
    pub fn pairing_offer(&self) -> Result<PairingOfferFfi, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        let offer = self.rt.block_on(pairing::offer(
            eng.db.conn(),
            &self.transport,
            SystemTime::now(),
        ))?;
        Ok(PairingOfferFfi {
            qr_bytes: offer.qr_bytes,
            code: offer.code,
            onion: offer.onion,
            expires_at: offer.expires_at,
        })
    }

    /// Abort the outstanding offer.
    pub fn pairing_abort(&self) -> Result<(), CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(self
            .rt
            .block_on(pairing::abort_offer(eng.db.conn(), &self.transport))?)
    }

    /// Accept an offer from raw QR payload bytes (accepter side — the only
    /// side that scans or pastes). Returns the relationship and safety code.
    pub fn pairing_accept(&self, qr_bytes: Vec<u8>) -> Result<AcceptedFfi, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        let accepted = self.rt.block_on(pairing::accept(
            eng.db.conn(),
            &self.transport,
            &qr_bytes,
            SystemTime::now(),
        ))?;
        Ok(AcceptedFfi {
            rel_id: accepted.rel_id,
            sas: accepted.sas,
            peer_onion: accepted.peer_onion,
            onion: accepted.onion,
        })
    }

    /// Accept an offer from a pasted one-time code.
    pub fn pairing_accept_code(&self, code: String) -> Result<AcceptedFfi, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        let accepted = self.rt.block_on(pairing::accept_code(
            eng.db.conn(),
            &self.transport,
            &code,
            SystemTime::now(),
        ))?;
        Ok(AcceptedFfi {
            rel_id: accepted.rel_id,
            sas: accepted.sas,
            peer_onion: accepted.peer_onion,
            onion: accepted.onion,
        })
    }

    /// The safety code for a relationship (re-display in the chat UI).
    /// Pairing does not require comparing it.
    pub fn pairing_sas(&self, rel_id: String) -> Result<String, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(pairing::sas_for(eng.db.conn(), &rel_id)?)
    }

    /// Accept a pending message request (inviter). Restricts the invitation
    /// service to the peer and runs the activation burst.
    pub fn pairing_accept_request(&self, rel_id: String) -> Result<(), CoreError> {
        let mut v = self.unlocked()?;
        let eng = v.engine_mut()?;
        Ok(self.rt.block_on(eng.accept_request(&rel_id))?)
    }

    /// Incoming message requests awaiting acceptance (inviter's bucket).
    pub fn pairing_requests(&self) -> Result<Vec<RequestInfoFfi>, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(pairing::pending_requests(eng.db.conn())?
            .into_iter()
            .map(|r| RequestInfoFfi {
                rel_id: r.rel_id,
                sas: r.sas,
                peer_onion: r.peer_onion,
                created_at: r.created_at,
            })
            .collect())
    }

    /// Encrypt and send one application payload to a relationship over the
    /// transport. I11: re-sending the same `msg_id` retransmits identical
    /// ciphertext bytes.
    pub fn send_message(
        &self,
        rel_id: String,
        msg_id: String,
        plaintext: Vec<u8>,
        alert: bool,
    ) -> Result<(), CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(self.rt.block_on(pairing::send_message(
            eng.db.conn(),
            &self.transport,
            &rel_id,
            &msg_id,
            &plaintext,
            alert,
            SystemTime::now(),
        ))?)
    }

    /// Transport-free encrypt (tests, harness, outbox plumbing): returns
    /// the ciphertext frame for `msg_id` — stored bytes on re-encrypt.
    pub fn session_encrypt(
        &self,
        rel_id: String,
        msg_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(self.rt.block_on(session::encrypt(
            eng.db.conn(),
            &rel_id,
            &msg_id,
            &plaintext,
            SystemTime::now(),
        ))?)
    }

    pub fn session_state(&self, rel_id: String) -> Result<SessionStateFfi, CoreError> {
        let v = self.unlocked()?;
        let eng = v.engine()?;
        Ok(match session::session_state(eng.db.conn(), &rel_id)? {
            session::SessionState::None => SessionStateFfi::Missing,
            session::SessionState::Active => SessionStateFfi::Active,
            session::SessionState::Broken => SessionStateFfi::Broken,
        })
    }

    /// Route one inbound transport frame (the record bytes out of
    /// `OpaqueFrame.frame`, plus the optional intro). While locked the
    /// frame is appended to the Tier-A queue at rest and `Queued` is
    /// returned; `unlock` drains it through this same path.
    pub fn ingest_frame(
        &self,
        service_id: String,
        intro: Option<Vec<u8>>,
        record: Vec<u8>,
    ) -> Result<IngestFfi, CoreError> {
        let mut v = self.vaulted()?;
        if v.is_locked() {
            self.rt
                .block_on(v.ingest_drop(&service_id, intro.as_deref(), &record))?;
            return Ok(IngestFfi::Queued);
        }
        let eng = v.engine()?;
        let outcome = self.rt.block_on(pairing::ingest_frame(
            eng.db.conn(),
            &self.transport,
            &service_id,
            intro.as_deref(),
            &record,
            SystemTime::now(),
        ))?;
        Ok(match outcome {
            pairing::Ingest::RequestReceived {
                rel_id,
                sas,
                plaintext,
            } => IngestFfi::RequestReceived {
                rel_id,
                sas,
                plaintext,
            },
            pairing::Ingest::Message { rel_id, plaintext } => {
                IngestFfi::Message { rel_id, plaintext }
            }
            pairing::Ingest::Duplicate => IngestFfi::Duplicate,
            pairing::Ingest::SessionBroken { rel_id, reason } => {
                IngestFfi::SessionBroken { rel_id, reason }
            }
            pairing::Ingest::Dropped => IngestFfi::Dropped,
        })
    }
}
