//! Vault lifecycle at the boundary (the DEK contract).

use super::{CoreError, SchatCore};

#[uniffi::export]
impl SchatCore {
    /// Client DEK in → open SQLCipher, restore relationship services,
    /// drain the Tier-A queue. Returns how many queued frames were
    /// drained. Wrong DEK fails closed (no partial state, no oracle).
    /// The core never derives or stores DEKs — bytes in, that's all.
    pub fn unlock(&self, dek: Vec<u8>) -> Result<u32, CoreError> {
        let dek: [u8; 32] = dek
            .try_into()
            .map_err(|_| CoreError::Other("DEK must be 32 bytes".into()))?;
        let mut v = self.vaulted()?;
        let report = self.rt.block_on(v.unlock(dek))?;
        Ok(report.drained)
    }

    /// Zeroize the Tier-B DEK, close SQLCipher, drop all session state.
    /// Inbound frames keep queueing at rest (Tier-A). Always safe.
    pub fn lock(&self) {
        if let Ok(mut v) = self.vaulted() {
            v.lock();
        }
    }

    pub fn is_locked(&self) -> bool {
        self.vaulted().map(|v| v.is_locked()).unwrap_or(true)
    }

    /// Inbound frames sitting in the Tier-A queue, waiting for unlock.
    pub fn queued_drops(&self) -> u32 {
        self.vaulted().map(|v| v.queued_drops()).unwrap_or(0)
    }

    /// Irreversible: lock, stop the transport, delete the store and
    /// every key file the core owns. The next launch is a fresh install.
    pub fn panic_wipe(&self) -> Result<(), CoreError> {
        self.rt.block_on(self.transport.stop());
        let mut v = self.vaulted()?;
        let report = v.panic_wipe();
        if report.errors > 0 {
            return Err(CoreError::Other(format!(
                "panic wipe incomplete: {} errors",
                report.errors
            )));
        }
        Ok(())
    }
}
