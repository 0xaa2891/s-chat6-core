//! The UniFFI boundary: one [`SchatCore`] object, one [`SchatEvent`]
//! stream, flat [`CoreError`]s. Split by domain (`vault`, `transport`,
//! `pairing`, `messaging`, `features`) but frozen as one surface.
//! Rich error types stay inside the crate; the boundary
//! carries the message.

mod features;
mod messaging;
mod pairing;
mod transport;
mod vault;

pub use features::*;
pub use messaging::*;
pub use pairing::*;
pub use transport::*;
pub use vault::*;

use std::sync::{Arc, Mutex};

use thiserror::Error;
use tracing_subscriber::EnvFilter;

use crate::transport::Transport;

/// Flat FFI error. Rich error types stay inside the crate; the boundary
/// carries the message (the FFI surface is frozen).
#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("{0}")]
    Other(String),
}

impl From<crate::transport::error::TransportError> for CoreError {
    fn from(e: crate::transport::error::TransportError) -> Self {
        CoreError::Transport(e.to_string())
    }
}

impl From<crate::store::StoreError> for CoreError {
    fn from(e: crate::store::StoreError) -> Self {
        CoreError::Other(e.to_string())
    }
}

impl From<crate::pairing::PairingFailure> for CoreError {
    fn from(e: crate::pairing::PairingFailure) -> Self {
        CoreError::Other(e.to_string())
    }
}

impl From<crate::session::SessionError> for CoreError {
    fn from(e: crate::session::SessionError) -> Self {
        CoreError::Other(e.to_string())
    }
}

impl From<crate::engine::EngineError> for CoreError {
    fn from(e: crate::engine::EngineError) -> Self {
        CoreError::Other(e.to_string())
    }
}

impl From<crate::vault::VaultError> for CoreError {
    fn from(e: crate::vault::VaultError) -> Self {
        CoreError::Other(e.to_string())
    }
}

/// The entire Rust → client channel: one enum, one listener trait.
#[derive(uniffi::Enum, Clone, Debug)]
pub enum SchatEvent {
    Transport(crate::transport::status::TransportStatus),
    /// Alert flag on a first-sight inbound frame — drives the client's
    /// notification decision. No content, ever.
    Arrival {
        service_id: String,
    },
}

#[uniffi::export]
pub trait SchatEventListener: Send + Sync {
    fn on_event(&self, event: SchatEvent);
}

/// The core object: transport, pairing + sessions, and the feature
/// engine behind the vault. The object starts **locked**, the
/// client calls `unlock` with its DEK, and every store-backed method
/// fails closed until then. One mutex (the libsignal chain is
/// single-threaded — never call concurrently).
#[derive(uniffi::Object)]
pub struct SchatCore {
    pub(crate) rt: tokio::runtime::Runtime,
    pub(crate) transport: Arc<Transport>,
    pub(crate) vaulted: Mutex<crate::vault::VaultedEngine>,
}

#[uniffi::export]
impl SchatCore {
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Result<Arc<Self>, CoreError> {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .try_init();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| CoreError::Other(format!("tokio runtime: {e}")))?;
        let data_dir = std::path::PathBuf::from(&data_dir);
        let transport = Transport::new(&data_dir);
        let vaulted = crate::vault::VaultedEngine::new(&data_dir, transport.clone())
            .map_err(|e| CoreError::Other(e.to_string()))?;
        Ok(Arc::new(Self {
            rt,
            transport,
            vaulted: Mutex::new(vaulted),
        }))
    }
}

impl SchatCore {
    pub(crate) fn vaulted(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, crate::vault::VaultedEngine>, CoreError> {
        self.vaulted
            .lock()
            .map_err(|_| CoreError::Other("vault mutex poisoned".into()))
    }

    /// A vault guard whose engine is present — every store-backed call
    /// fails closed while locked.
    pub(crate) fn unlocked(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, crate::vault::VaultedEngine>, CoreError> {
        let g = self.vaulted()?;
        if g.is_locked() {
            return Err(CoreError::Other("vault is locked".into()));
        }
        Ok(g)
    }
}

pub(crate) fn hex_id16(s: &str) -> Result<[u8; 16], CoreError> {
    let v = crate::store::hex_decode(s)?;
    <[u8; 16]>::try_from(v.as_slice())
        .map_err(|_| CoreError::Other("expected a 16-byte hex id".into()))
}

pub(crate) fn hex_id32(s: &str) -> Result<[u8; 32], CoreError> {
    let v = crate::store::hex_decode(s)?;
    <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| CoreError::Other("expected a 32-byte hex id".into()))
}
