//! Kill switch.
//!
//! A persisted flag. When on: `SETCONF DisableNetwork 1` is applied and the
//! [`super::socks::Sender`] refuses every send with
//! `TransportError::KillSwitch` — no traffic, fail closed. Persists across
//! restarts in the instance data dir.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const FILE_NAME: &str = "tor_kill_switch";

#[derive(Clone)]
pub struct KillSwitch {
    file: PathBuf,
    on: Arc<AtomicBool>,
}

impl KillSwitch {
    /// Load the persisted flag (missing/unreadable file = off, as before).
    pub fn load(data_dir: &std::path::Path) -> Self {
        let file = data_dir.join(FILE_NAME);
        let on = std::fs::read_to_string(&file)
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        Self {
            file,
            on: Arc::new(AtomicBool::new(on)),
        }
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::SeqCst)
    }

    pub fn flag(&self) -> Arc<AtomicBool> {
        self.on.clone()
    }

    /// Persist and apply in-memory. The `DisableNetwork` side is applied by
    /// the transport supervisor (it owns the control connection).
    pub fn set(&self, on: bool) -> std::io::Result<()> {
        if let Some(parent) = self.file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.file, if on { "1" } else { "0" })?;
        self.on.store(on, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_across_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = KillSwitch::load(tmp.path());
        assert!(!ks.is_on());
        ks.set(true).unwrap();
        assert!(ks.is_on());
        let reloaded = KillSwitch::load(tmp.path());
        assert!(reloaded.is_on());
        reloaded.set(false).unwrap();
        assert!(!KillSwitch::load(tmp.path()).is_on());
    }
}
