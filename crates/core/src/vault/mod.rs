//! `vault/` — the lock boundary.
//!
//! # The contract
//!
//! The core exposes exactly two vault operations:
//!
//! ```text
//! unlock(dek: [u8; 32])   -- client supplies the DEK; core opens
//!                             SQLCipher, restores sessions, drains the
//!                             Tier-A queue.
//! lock()                  -- core zeroizes the Tier-B DEK, closes
//!                             SQLCipher, drops all session state; the
//!                             Tier-A queue keeps appending while locked.
//! ```
//!
//! **The platform ships no KDF, no wrap format, and no passphrase
//! ceremony.**
//! How a client derives or stores the DEK is the client dev's choice
//! (the Android reference client uses BiometricPrompt → Keystore wrap →
//! Argon2id; a desktop client could use a keychain item; a
//! headless bot could read a file). The core never sees a passphrase,
//! never derives a key, never wraps one. Bytes in, that's all.
//!
//! Consequences a client can rely on:
//!
//! - `lock()` is always safe to call (backgrounding, snatch detection,
//!   timeout) — inbound frames queue at rest, Tier-A encrypted.
//! - `unlock(dek)` with a wrong DEK fails closed: SQLCipher refuses the
//!   database, no partial state, no oracle.
//! - The Tier-B DEK is never persisted by the core and never crosses
//!   the FFI boundary except as the `unlock` argument.
//!
//! # Tier model
//!
//! - **Tier A** (`tier_a`): 32 bytes, always in RAM. Wraps the
//!   queue-at-rest ([`DropQueue`]) so a locked instance still receives.
//!   Platformless: persisted as a raw key file in `keys/` — the same
//!   at-rest tier as the onion service keys already there.
//! - **Tier B** (`tier_b`): the client-supplied SQLCipher DEK. In RAM
//!   only between `unlock` and `lock`; zeroized on lock. Never
//!   persisted by the core.
//!
//! All key material rides in [`zeroize::Zeroizing`] wrappers.

pub mod queue;
pub mod wipe;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod audit;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use thiserror::Error;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::engine::{Engine, EngineError, EngineEvent};
use crate::pairing::{self, PairingFailure};
use crate::store::{Db, StoreError};
use crate::transport::Transport;

pub use queue::{DropQueue, QueuedDrop};
pub use wipe::{panic_wipe as wipe_data_dir, WipeReport};

const TIER_A_FILE: &str = "tier_a.key";
const DB_FILE: &str = "schat.db";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("unlock failed: wrong DEK or corrupt store (fail closed, no oracle)")]
    BadDek,
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("queue: {0}")]
    Queue(String),
    #[error("pairing: {0}")]
    Pairing(#[from] PairingFailure),
    #[error("engine: {0}")]
    Engine(#[from] EngineError),
}

/// What happened to one inbound drop handed to a (possibly locked)
/// vault. The daemon/FFI map this onto their event streams.
#[derive(Clone, Debug)]
pub enum DropOutcome {
    /// Vault is locked; the frame sits in the Tier-A queue at rest.
    Queued,
    Request {
        rel_id: String,
        sas: String,
        events: Vec<EngineEvent>,
    },
    Message {
        rel_id: String,
        events: Vec<EngineEvent>,
    },
    Duplicate,
    SessionBroken {
        rel_id: String,
        reason: String,
    },
    Dropped,
}

#[derive(Clone, Debug, Default)]
pub struct UnlockReport {
    /// Queued frames drained and ingested after unlock.
    pub drained: u32,
    /// Engine events raised while draining.
    pub events: Vec<EngineEvent>,
    /// Frames that failed ingest during the drain (logged, skipped).
    pub errors: u32,
}

/// The vault + engine pair every host drives (CLI daemon, `SchatCore`,
/// tests). Owns the Tier-A key and queue across lock transitions; the
/// [`Engine`] (and with it the SQLCipher connection, the libsignal
/// session state, and all RAM feature tables) exists only while
/// unlocked.
///
/// Single-threaded driver, same rule as `Engine`: never call
/// concurrently (the libsignal chain is `!Send`).
pub struct VaultedEngine {
    data_dir: PathBuf,
    transport: Arc<Transport>,
    tier_b: Option<Zeroizing<[u8; 32]>>,
    /// The Tier-A queue; owns the Tier-A key (always in RAM, locked or
    /// not) so appends keep working while the engine is gone.
    queue: DropQueue,
    engine: Option<Engine>,
}

impl VaultedEngine {
    /// Load (or generate) the Tier-A key and open the queue. Starts
    /// **locked**: no database is opened until [`unlock`](Self::unlock).
    pub fn new(data_dir: &Path, transport: Arc<Transport>) -> Result<Self, VaultError> {
        let tier_a = load_or_generate_tier_a(data_dir)?;
        let queue = DropQueue::new(&data_dir.join("queue"), tier_a)?;
        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            transport,
            tier_b: None,
            queue,
            engine: None,
        })
    }

    pub fn is_locked(&self) -> bool {
        self.engine.is_none()
    }

    /// The engine, if unlocked. Locking between this call and its use
    /// is impossible for holders of `&mut self` / the mutex guard.
    pub fn engine(&self) -> Result<&Engine, VaultError> {
        self.engine.as_ref().ok_or(VaultError::Locked)
    }

    pub fn engine_mut(&mut self) -> Result<&mut Engine, VaultError> {
        self.engine.as_mut().ok_or(VaultError::Locked)
    }

    /// Queued-at-rest drops waiting for unlock.
    pub fn queued_drops(&self) -> u32 {
        self.queue.len() as u32
    }

    /// Client DEK in → open SQLCipher, restore relationship services,
    /// drain the Tier-A queue through the normal ingest path. Wrong DEK
    /// fails closed: no partial state, no oracle.
    pub async fn unlock(&mut self, dek: [u8; 32]) -> Result<UnlockReport, VaultError> {
        if self.engine.is_some() {
            return Ok(UnlockReport::default());
        }
        let dek = Zeroizing::new(dek);
        let db = open_store_with_dek(&self.data_dir.join(DB_FILE), &dek)?;
        pairing::restore_services(db.conn(), &self.transport).await?;
        let mut engine = Engine::new(db, self.transport.clone());

        let mut report = UnlockReport::default();
        for drop in self.queue.drain()? {
            match ingest_and_dispatch(&mut engine, &self.transport, &drop).await {
                Ok(events) => {
                    report.drained += 1;
                    report.events.extend(events);
                }
                Err(e) => {
                    report.errors += 1;
                    warn!(service_id = %drop.service_id, "queued frame failed ingest on unlock: {e}");
                }
            }
        }
        if report.drained > 0 || report.errors > 0 {
            info!(
                drained = report.drained,
                errors = report.errors,
                "unlock drained the tier-a queue"
            );
        }
        self.engine = Some(engine);
        self.tier_b = Some(dek);
        Ok(report)
    }

    /// Zeroize the Tier-B DEK, close SQLCipher, drop all session and
    /// RAM feature state. The Tier-A queue keeps appending. Always
    /// safe to call.
    pub fn lock(&mut self) {
        if self.engine.take().is_some() {
            info!("vault locked: store closed, session state dropped");
        }
        // Zeroizing drop: the DEK bytes are overwritten here.
        self.tier_b = None;
    }

    /// Route one inbound transport frame. Locked → Tier-A queue at
    /// rest. Unlocked → session ingest → engine dispatch.
    pub async fn ingest_drop(
        &mut self,
        service_id: &str,
        intro: Option<&[u8]>,
        frame: &[u8],
    ) -> Result<DropOutcome, VaultError> {
        if self.engine.is_none() {
            self.queue.enqueue(service_id, intro, frame)?;
            return Ok(DropOutcome::Queued);
        }
        let engine = self.engine.as_mut().expect("checked above");
        let outcome = pairing::ingest_frame(
            engine.db.conn(),
            &self.transport,
            service_id,
            intro,
            frame,
            SystemTime::now(),
        )
        .await?;
        Ok(match outcome {
            pairing::Ingest::RequestReceived {
                rel_id,
                sas,
                plaintext,
            } => {
                let events = dispatch(engine, &rel_id, plaintext).await?;
                DropOutcome::Request {
                    rel_id,
                    sas,
                    events,
                }
            }
            pairing::Ingest::Message { rel_id, plaintext } => {
                let events = dispatch(engine, &rel_id, plaintext).await?;
                DropOutcome::Message { rel_id, events }
            }
            pairing::Ingest::Duplicate => DropOutcome::Duplicate,
            pairing::Ingest::SessionBroken { rel_id, reason } => {
                DropOutcome::SessionBroken { rel_id, reason }
            }
            pairing::Ingest::Dropped => DropOutcome::Dropped,
        })
    }

    /// Irreversible: lock, then delete the store and every key file the
    /// core owns. The transport is **not** stopped here (it belongs to
    /// the host); call `Transport::stop` first when one is running.
    pub fn panic_wipe(&mut self) -> WipeReport {
        self.lock();
        let report = wipe_data_dir(&self.data_dir);
        info!(?report, "panic wipe complete");
        report
    }
}

/// One decrypted queued drop through the normal ingest + dispatch path.
async fn ingest_and_dispatch(
    engine: &mut Engine,
    transport: &Arc<Transport>,
    drop: &QueuedDrop,
) -> Result<Vec<EngineEvent>, VaultError> {
    let outcome = pairing::ingest_frame(
        engine.db.conn(),
        transport,
        &drop.service_id,
        drop.intro.as_deref(),
        &drop.frame,
        SystemTime::now(),
    )
    .await?;
    match outcome {
        pairing::Ingest::RequestReceived {
            rel_id, plaintext, ..
        }
        | pairing::Ingest::Message { rel_id, plaintext } => {
            dispatch(engine, &rel_id, plaintext).await
        }
        // Duplicates/drops from the queue are normal (retransmission
        // arrived while locked, then again after unlock).
        _ => Ok(Vec::new()),
    }
}

/// Decrypted envelope → engine. The plaintext copy is zeroized after
/// dispatch; the locked-state memory audit depends on it.
async fn dispatch(
    engine: &mut Engine,
    rel_id: &str,
    plaintext: Vec<u8>,
) -> Result<Vec<EngineEvent>, VaultError> {
    let plaintext = Zeroizing::new(plaintext);
    Ok(engine.handle_plaintext(rel_id, &plaintext).await?)
}

/// Open the store with a client-supplied DEK. A pre-vault plaintext
/// database (dev data dirs from before the vault) is migrated to
/// SQLCipher in place first; anything else that refuses the key fails
/// closed as [`VaultError::BadDek`].
pub fn open_store_with_dek(path: &Path, dek: &[u8; 32]) -> Result<Db, VaultError> {
    migrate_plaintext_if_needed(path, dek)?;
    match Db::open(path, Some(dek)) {
        Ok(db) => Ok(db),
        Err(StoreError::TooNew { found }) => Err(VaultError::Store(StoreError::TooNew { found })),
        Err(e) => {
            warn!("keyed open refused: {e}");
            Err(VaultError::BadDek)
        }
    }
}

/// Encrypt a pre-Phase-5 plaintext store in place (`sqlcipher_export`).
/// Detected by the `SQLite format 3\0` magic — an encrypted (or absent)
/// file needs nothing.
fn migrate_plaintext_if_needed(path: &Path, dek: &[u8; 32]) -> Result<(), VaultError> {
    use std::io::Read;
    let mut magic = [0u8; 16];
    match std::fs::File::open(path) {
        Ok(mut f) => {
            if f.read_exact(&mut magic).is_err() {
                return Ok(()); // shorter than the header: not a sqlite file
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    if &magic != b"SQLite format 3\0" {
        return Ok(()); // already encrypted (or not sqlite — keyed open decides)
    }
    info!(path = %path.display(), "migrating plaintext store to SQLCipher");

    let tmp = path.with_extension("sqlcipher-migrate");
    let _ = std::fs::remove_file(&tmp);
    let version: u32;
    {
        let conn = rusqlite::Connection::open(path)?;
        conn.pragma_update(None, "cipher_memory_security", true)?;
        // Fold any WAL content into the main file before exporting.
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        version = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let key_sql = Zeroizing::new(format!("\"x'{}'\"", crate::store::hex_encode(dek)));
        conn.execute(
            "ATTACH DATABASE ?1 AS enc KEY ?2",
            rusqlite::params![tmp.to_string_lossy().as_ref(), &*key_sql],
        )?;
        conn.execute_batch("SELECT sqlcipher_export('enc');")?;
        conn.execute_batch(&format!("PRAGMA enc.user_version = {version};"))?;
        conn.execute_batch("DETACH DATABASE enc;")?;
    }
    for suffix in ["wal", "shm", "journal"] {
        let _ = std::fs::remove_file(path.with_extension(suffix));
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Tier A: load the persisted key or generate one. The file sits next to
/// the onion key blobs, which are the same sensitivity tier.
fn load_or_generate_tier_a(data_dir: &Path) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let path = data_dir.join("keys").join(TIER_A_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let key: [u8; 32] = bytes
                .try_into()
                .map_err(|_| VaultError::Queue(format!("{}: not 32 bytes", path.display())))?;
            Ok(Zeroizing::new(key))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut key);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, key)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            Ok(Zeroizing::new(key))
        }
        Err(e) => Err(e.into()),
    }
}

/// Test double for the client side of the contract.
///
/// This is **not a shipped KDF**. It stands in for "the client derives
/// or loads a DEK somehow" so tests can drive the contract without a
/// keystore. The fixed-pepper SHA-256 here exists only to make the
/// double deterministic.
#[cfg(test)]
pub mod test_double {
    use sha2::{Digest, Sha256};

    /// A fake client-side DEK source. Deterministic per (instance, purpose)
    /// so tests can "relock" and "reunlock" with the same bytes.
    pub struct TestDekSource {
        instance: String,
    }

    impl TestDekSource {
        pub fn new(instance: &str) -> Self {
            Self {
                instance: instance.to_string(),
            }
        }

        /// NOT A KDF. Test-only stand-in for a client's own derivation.
        pub fn derive_dek(&self) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"s-chat6-test-dek-double");
            h.update(self.instance.as_bytes());
            h.finalize().into()
        }
    }
}
