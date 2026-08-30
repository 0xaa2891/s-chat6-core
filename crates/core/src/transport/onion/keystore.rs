//! Key blob persistence. A plain file behind the trait; the SQLCipher
//! settings repository can replace it without touching the onion module.

use std::path::PathBuf;

use async_trait::async_trait;

use crate::transport::error::TransportError;

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, TransportError>;
    async fn put(&self, key: &str, value: &str) -> Result<(), TransportError>;
    async fn delete(&self, key: &str) -> Result<(), TransportError>;
    async fn keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>, TransportError>;
}

/// File-backed stub (`<dir>/<key>` with `/` in keys mapped to subdirs);
/// the SQLCipher settings repository can replace it without touching
/// the onion module.
pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn path_for(&self, key: &str) -> Result<PathBuf, TransportError> {
        if key.is_empty()
            || key
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '/' | '.')))
        {
            return Err(TransportError::KeyStore(format!("bad key {key:?}")));
        }
        Ok(self.dir.join(key))
    }
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn get(&self, key: &str) -> Result<Option<String>, TransportError> {
        match std::fs::read_to_string(self.path_for(key)?) {
            Ok(s) => Ok(Some(s.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn put(&self, key: &str, value: &str) -> Result<(), TransportError> {
        let path = self.path_for(key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, value)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), TransportError> {
        match std::fs::remove_file(self.path_for(key)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>, TransportError> {
        let base = self.path_for(prefix)?;
        let mut out = Vec::new();
        if base.is_dir() {
            for entry in std::fs::read_dir(&base)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    out.push(format!("{prefix}{}", entry.file_name().to_string_lossy()));
                }
            }
        }
        out.sort();
        Ok(out)
    }
}
