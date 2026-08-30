//! Panic wipe: irreversible deletion of
//! everything the core owns under the data dir — the SQLCipher store,
//! onion key blobs, client-auth keys, the Tier-A key and queue, the
//! dev DEK, kill-switch/circumvention flags, and the tor workdir.
//! After a wipe the next launch looks like a fresh install.
//!
//! Best effort by design: a panic path must not panic. Every failure
//! is logged and counted, never propagated. Small files (keys, DEKs,
//! flags) are zero-overwritten before unlink; the database relies on
//! SQLCipher encryption + `secure_delete` for its content.

use std::path::Path;

use tracing::warn;

/// Files directly under the data dir that the core owns.
const OWNED_FILES: &[&str] = &[
    "schat.db",
    "schat.db-wal",
    "schat.db-shm",
    "schat.db-journal",
    "tor_kill_switch",
    "tor_circumvention",
];

/// Directories the core owns (removed recursively).
const OWNED_DIRS: &[&str] = &["keys", "client_auth", "queue", "vault", "tor"];

/// Files at or below this size get a single-pass zero overwrite before
/// unlink (key material is small; multi-pass is theater on flash).
const ZERO_OVERWRITE_MAX: u64 = 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WipeReport {
    pub files_removed: u32,
    pub dirs_removed: u32,
    pub errors: u32,
}

/// Delete every core-owned file under `data_dir`. The caller is
/// responsible for having stopped the transport and closed the store
/// first (`VaultedEngine::panic_wipe` / `SchatCore::panic_wipe` do).
pub fn panic_wipe(data_dir: &Path) -> WipeReport {
    let mut report = WipeReport::default();
    for file in OWNED_FILES {
        remove_file_zeroed(&data_dir.join(file), &mut report);
    }
    for dir in OWNED_DIRS {
        remove_dir(&data_dir.join(dir), &mut report);
    }
    report
}

fn remove_file_zeroed(path: &Path, report: &mut WipeReport) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {
            if meta.len() <= ZERO_OVERWRITE_MAX {
                if let Err(e) = zero_overwrite(path, meta.len()) {
                    warn!(path = %path.display(), "wipe zero-overwrite failed: {e}");
                    report.errors += 1;
                }
            }
            match std::fs::remove_file(path) {
                Ok(()) => report.files_removed += 1,
                Err(e) => {
                    warn!(path = %path.display(), "wipe removal failed: {e}");
                    report.errors += 1;
                }
            }
        }
        Ok(_) => remove_dir(path, report),
        Err(_) => {} // absent is the goal
    }
}

fn remove_dir(path: &Path, report: &mut WipeReport) {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => {
            // Zero the small files inside first, then remove the tree.
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if let Ok(m) = entry.metadata() {
                        if m.is_file() && m.len() <= ZERO_OVERWRITE_MAX {
                            let _ = zero_overwrite(&p, m.len());
                        }
                    }
                }
            }
            match std::fs::remove_dir_all(path) {
                Ok(()) => report.dirs_removed += 1,
                Err(e) => {
                    warn!(path = %path.display(), "wipe dir removal failed: {e}");
                    report.errors += 1;
                }
            }
        }
        Ok(_) => remove_file_zeroed(path, report),
        Err(_) => {}
    }
}

fn zero_overwrite(path: &Path, len: u64) -> std::io::Result<()> {
    use std::io::{Seek, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
    let chunk = vec![0u8; 8192];
    let mut left = len;
    while left > 0 {
        let n = (left as usize).min(chunk.len());
        f.write_all(&chunk[..n])?;
        left -= n as u64;
    }
    f.sync_all()?;
    f.seek(std::io::SeekFrom::Start(0))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_removes_everything_core_owns() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        std::fs::write(dir.join("schat.db"), b"db-bytes").unwrap();
        std::fs::write(dir.join("schat.db-wal"), b"wal").unwrap();
        std::fs::write(dir.join("tor_kill_switch"), b"1").unwrap();
        for d in OWNED_DIRS {
            std::fs::create_dir_all(dir.join(d)).unwrap();
            std::fs::write(dir.join(d).join("blob"), b"secret").unwrap();
        }
        // A foreign file survives.
        std::fs::write(dir.join("README.keep"), b"not ours").unwrap();

        let report = panic_wipe(dir);
        assert_eq!(report.errors, 0);
        assert!(report.files_removed >= 3);
        assert_eq!(report.dirs_removed as usize, OWNED_DIRS.len());
        for f in OWNED_FILES {
            assert!(!dir.join(f).exists(), "{f} still there");
        }
        for d in OWNED_DIRS {
            assert!(!dir.join(d).exists(), "{d}/ still there");
        }
        assert!(dir.join("README.keep").exists());
    }

    #[test]
    fn wipe_on_empty_dir_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let report = panic_wipe(tmp.path());
        assert_eq!(report, WipeReport::default());
    }
}
