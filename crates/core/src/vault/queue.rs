//! Queue-at-rest (one process).
//!
//! Inbound frames that arrive while the vault is locked are appended
//! here as Tier-A-encrypted blobs. The queue **never decrypts the E2E
//! payload** — the frame it wraps is already session ciphertext; the
//! Tier-A wrap protects the queue metadata (service id, intro) and
//! keeps a disk dump from yielding a readable inbox index.
//!
//! Tier A is backed by a 32-byte key file in
//! `keys/` — the same at-rest protection tier as the onion service
//! keys already stored there. A client that wants hardware backing can
//! supply its own key management above the core; the queue format does
//! not change.
//!
//! Fail toward loss: caps at [`MAX_FILES`] / [`MAX_BYTES`];
//! past the cap new drops are refused, and undecryptable files are
//! deleted on sight. Loss is always loud (tracing + counters), never
//! silent.

use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use zeroize::Zeroizing;

use super::VaultError;

// Queue caps, declared in the bounds catalog.
pub use crate::limits::queue::{MAX_BYTES, MAX_FILES};

const MAGIC: &[u8; 3] = b"S6Q";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

/// One queued inbound drop, decrypted from its at-rest blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedDrop {
    pub service_id: String,
    pub intro: Option<Vec<u8>>,
    pub frame: Vec<u8>,
}

/// The Tier-A encrypted drop queue. Cloneable handle; all state is on
/// disk (no cross-process file locking is needed in one process —
/// the core serializes callers).
#[derive(Clone)]
pub struct DropQueue {
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
    max_files: usize,
    max_bytes: u64,
}

impl DropQueue {
    pub fn new(dir: &Path, key: Zeroizing<[u8; 32]>) -> Result<Self, VaultError> {
        Self::with_caps(dir, key, MAX_FILES, MAX_BYTES)
    }

    /// Test constructor with shrunken caps.
    pub fn with_caps(
        dir: &Path,
        key: Zeroizing<[u8; 32]>,
        max_files: usize,
        max_bytes: u64,
    ) -> Result<Self, VaultError> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            key,
            max_files,
            max_bytes,
        })
    }

    /// Serialize + wrap + append one drop. Returns `false` when the
    /// queue is full and the drop was refused (fail toward loss).
    pub fn enqueue(
        &self,
        service_id: &str,
        intro: Option<&[u8]>,
        frame: &[u8],
    ) -> Result<bool, VaultError> {
        let (files, bytes) = self.usage()?;
        let blob = encode_blob(service_id, intro, frame);
        if files >= self.max_files || bytes + blob.len() as u64 + 40 > self.max_bytes {
            warn!(
                service_id,
                files, bytes, "drop queue full; refusing inbound frame (fail toward loss)"
            );
            return Ok(false);
        }
        let wrapped = self.wrap(&blob)?;
        let name = format!(
            "{}.{}",
            sanitize(service_id),
            crate::store::hex_encode(&Sha256::digest(&blob))
        );
        let path = self.dir.join(&name);
        let tmp = self.dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, &wrapped)?;
        std::fs::rename(&tmp, &path)?;
        debug!(service_id, "queued inbound frame at rest");
        Ok(true)
    }

    /// Oldest-first drain: unwrap every queued blob, deleting each file
    /// as it is consumed. Undecryptable files are deleted (fail toward
    /// loss) with a warning.
    pub fn drain(&self) -> Result<Vec<QueuedDrop>, VaultError> {
        let mut out = Vec::new();
        for path in self.files_oldest_first()? {
            let wrapped = std::fs::read(&path)?;
            match self.unwrap_blob(&wrapped).and_then(|b| decode_blob(&b)) {
                Ok(drop) => out.push(drop),
                Err(e) => warn!(path = %path.display(), "purging undecryptable queue file: {e}"),
            }
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(path = %path.display(), "queue file removal failed: {e}");
            }
        }
        Ok(out)
    }

    /// Delete every queued drop without reading it.
    pub fn purge(&self) -> Result<u32, VaultError> {
        let mut n = 0;
        for path in self.files_oldest_first()? {
            std::fs::remove_file(path)?;
            n += 1;
        }
        Ok(n)
    }

    /// How many drops sit at rest right now.
    pub fn len(&self) -> usize {
        self.usage().map(|(files, _)| files).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn usage(&self) -> Result<(usize, u64), VaultError> {
        let mut files = 0;
        let mut bytes = 0u64;
        for path in self.files_oldest_first()? {
            files += 1;
            bytes += std::fs::metadata(&path)?.len();
        }
        Ok((files, bytes))
    }

    fn files_oldest_first(&self) -> Result<Vec<PathBuf>, VaultError> {
        let mut entries: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || !name.contains('.') {
                continue; // temp files and foreign files
            }
            let modified = entry
                .metadata()?
                .modified()
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            entries.push((modified, entry.path()));
        }
        entries.sort();
        Ok(entries.into_iter().map(|(_, p)| p).collect())
    }

    fn wrap(&self, blob: &[u8]) -> Result<Vec<u8>, VaultError> {
        let cipher = Aes256Gcm::new_from_slice(&*self.key)
            .map_err(|e| VaultError::Queue(format!("tier-a key: {e}")))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), blob)
            .map_err(|_| VaultError::Queue("tier-a wrap failed".into()))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap_blob(&self, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        if wrapped.len() < NONCE_LEN + 16 {
            return Err(VaultError::Queue("queue file too short".into()));
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.key)
            .map_err(|e| VaultError::Queue(format!("tier-a key: {e}")))?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&wrapped[..NONCE_LEN]),
                &wrapped[NONCE_LEN..],
            )
            .map_err(|_| VaultError::Queue("tier-a unwrap failed".into()))?;
        Ok(Zeroizing::new(pt))
    }
}

/// `S6Q` v1: magic ‖ version ‖ lp16(service_id) ‖ u8 has_intro ‖
/// [lp16(intro)] ‖ lp32(frame). Hand-rolled, big-endian length prefixes.
fn encode_blob(service_id: &str, intro: Option<&[u8]>, frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(service_id.len() as u16).to_be_bytes());
    out.extend_from_slice(service_id.as_bytes());
    match intro {
        Some(intro) => {
            out.push(1);
            out.extend_from_slice(&(intro.len() as u16).to_be_bytes());
            out.extend_from_slice(intro);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
    out.extend_from_slice(frame);
    out
}

fn decode_blob(blob: &[u8]) -> Result<QueuedDrop, VaultError> {
    let bad = |m: &str| VaultError::Queue(format!("queue blob: {m}"));
    if blob.len() < 4 || &blob[..3] != MAGIC || blob[3] != VERSION {
        return Err(bad("bad magic/version"));
    }
    let mut pos = 4;
    // Invariant: yields exactly `n` bytes on success — the fixed-width
    // `try_into().unwrap()` conversions below are infallible by it.
    let take = |pos: &mut usize, n: usize| -> Result<&[u8], VaultError> {
        let end = pos.checked_add(n).ok_or_else(|| bad("overflow"))?;
        let slice = blob.get(*pos..end).ok_or_else(|| bad("truncated"))?;
        *pos = end;
        Ok(slice)
    };
    let id_len = u16::from_be_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
    let service_id =
        std::str::from_utf8(take(&mut pos, id_len)?).map_err(|_| bad("service id not utf8"))?;
    let has_intro = take(&mut pos, 1)?[0];
    let intro = match has_intro {
        0 => None,
        1 => {
            let n = u16::from_be_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
            Some(take(&mut pos, n)?.to_vec())
        }
        _ => return Err(bad("bad intro flag")),
    };
    let frame_len = u32::from_be_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
    let frame = take(&mut pos, frame_len)?.to_vec();
    if pos != blob.len() {
        return Err(bad("trailing bytes"));
    }
    Ok(QueuedDrop {
        service_id: service_id.to_string(),
        intro,
        frame,
    })
}

fn sanitize(service_id: &str) -> String {
    service_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(tmp: &tempfile::TempDir) -> DropQueue {
        DropQueue::new(&tmp.path().join("queue"), Zeroizing::new([9u8; 32])).unwrap()
    }

    #[test]
    fn roundtrip_and_order() {
        let tmp = tempfile::tempdir().unwrap();
        let q = queue(&tmp);
        q.enqueue("svc-a", None, b"frame-1").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(5));
        q.enqueue("svc-b", Some(b"intro"), b"frame-2").unwrap();
        assert_eq!(q.len(), 2);
        let drops = q.drain().unwrap();
        assert_eq!(drops.len(), 2);
        assert_eq!(drops[0].service_id, "svc-a");
        assert_eq!(drops[0].frame, b"frame-1");
        assert_eq!(drops[0].intro, None);
        assert_eq!(drops[1].intro.as_deref(), Some(b"intro".as_slice()));
        assert_eq!(q.len(), 0, "drain consumes the files");
    }

    #[test]
    fn at_rest_is_wrapped() {
        let tmp = tempfile::tempdir().unwrap();
        let q = queue(&tmp);
        let frame = b"opaque-session-ciphertext-marker";
        q.enqueue("svc", Some(b"intro-marker"), frame).unwrap();
        let files: Vec<_> = std::fs::read_dir(tmp.path().join("queue"))
            .unwrap()
            .collect();
        assert_eq!(files.len(), 1);
        let raw = std::fs::read(files[0].as_ref().unwrap().path()).unwrap();
        let haystack = String::from_utf8_lossy(&raw);
        assert!(!haystack.contains("intro-marker"));
        // Full-binary search for the frame bytes, not just lossy utf8.
        assert!(!raw.windows(frame.len()).any(|w| w == frame.as_slice()));
    }

    #[test]
    fn caps_fail_toward_loss() {
        let tmp = tempfile::tempdir().unwrap();
        let q = DropQueue::with_caps(
            &tmp.path().join("queue"),
            Zeroizing::new([1u8; 32]),
            2,
            1 << 20,
        )
        .unwrap();
        assert!(q.enqueue("a", None, b"1").unwrap());
        assert!(q.enqueue("b", None, b"2").unwrap());
        assert!(!q.enqueue("c", None, b"3").unwrap(), "third refused");
        assert_eq!(q.len(), 2);
        let drops = q.drain().unwrap();
        assert_eq!(drops.len(), 2);
    }

    #[test]
    fn undecryptable_files_are_purged() {
        let tmp = tempfile::tempdir().unwrap();
        let q = queue(&tmp);
        q.enqueue("svc", None, b"frame").unwrap();
        // Corrupt every wrapped byte.
        for entry in std::fs::read_dir(tmp.path().join("queue")).unwrap() {
            let path = entry.unwrap().path();
            let mut raw = std::fs::read(&path).unwrap();
            for b in raw.iter_mut() {
                *b ^= 0xff;
            }
            std::fs::write(&path, raw).unwrap();
        }
        let drops = q.drain().unwrap();
        assert!(drops.is_empty());
        assert_eq!(q.len(), 0, "corrupt files deleted, not kept");
    }
}
