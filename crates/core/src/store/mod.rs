//! `store/` — SQLCipher-backed persistence.
//!
//! Tables (schema v2): `meta`, `pending_pairing`, `relationships`, the
//! libsignal `signal_*` tables, the I11 `message_ciphertexts` cache, plus
//! the tables `messages`, `outbox`, `attachments`, `stickers`,
//! `settings`.
//!
//! Encryption: the DB is opened with an optional 32-byte key (SQLCipher
//! `PRAGMA key`). The vault supplies the DEK; until then the
//! core opens the store unkeyed. Fail closed: a database with a
//! `user_version` newer than this build is refused, never downgraded.
//!
//! Time: every repository reads time through the injected [`Clock`]
//! (production = [`SystemClock`], tests = [`FakeClock`]).

pub mod attachments;
pub mod chunks;
pub mod clock;
pub mod inbound_seqs;
pub mod messages;
pub mod outbox;
pub mod profiles;
pub mod relationships;
pub mod schema;
pub mod settings;
pub mod sticker_cache;
pub mod sticker_items;
pub mod stickers;
pub mod tombstones;

pub use clock::{Clock, FakeClock, SystemClock};
pub use schema::SCHEMA_VERSION;

use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("database schema version {found} is newer than supported {SCHEMA_VERSION}")]
    TooNew { found: u32 },
    #[error("corrupt row: {0}")]
    Corrupt(String),
}

/// A single SQLCipher connection. Sync by nature; callers serialize
/// access (the core holds it behind a mutex). WAL + busy_timeout let a
/// second process's reader coexist with our writer.
pub struct Db {
    conn: Connection,
    clock: Arc<dyn Clock>,
}

impl Db {
    /// Open (or create) the store at `path`. `key` is the raw 32-byte
    /// SQLCipher key; `None` opens a plaintext database (pre-vault).
    pub fn open(path: &Path, key: Option<&[u8]>) -> Result<Self, StoreError> {
        Self::open_with_clock(path, key, Arc::new(SystemClock))
    }

    pub fn open_with_clock(
        path: &Path,
        key: Option<&[u8]>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Self::init(Connection::open(path)?, key, clock)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::open_in_memory_with_clock(Arc::new(SystemClock))
    }

    pub fn open_in_memory_with_clock(clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, None, clock)
    }

    fn init(
        conn: Connection,
        key: Option<&[u8]>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        // Zero SQLCipher's internal buffers (incl. decrypted page cache)
        // on free — the locked-state memory audit depends on this. Must
        // be set before `key` so the key schedule itself is covered.
        conn.pragma_update(None, "cipher_memory_security", true)?;
        if let Some(key) = key {
            // Raw 32-byte key, hex-encoded (SQLCipher raw-key syntax).
            // Zeroizing: the hex string is a copy of the DEK.
            let key_sql = zeroize::Zeroizing::new(format!("\"x'{}'\"", hex_encode(key)));
            conn.pragma_update(None, "key", &*key_sql)?;
        }
        conn.pragma_update(None, "foreign_keys", true)?;
        // WAL: readers don't block the writer; busy_timeout: a concurrent
        // writer waits instead of erroring with SQLITE_BUSY.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000u64)?;
        // Cryptographic erasure: deleted rows are zeroed, not just
        // unlinked — the TTL sweeper's erasure must be real.
        conn.pragma_update(None, "secure_delete", true)?;
        schema::migrate(&conn)?;
        Ok(Self { conn, clock })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn clock(&self) -> &dyn Clock {
        &*self.clock
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, StoreError> {
    if s.len() % 2 != 0 {
        return Err(StoreError::Corrupt("odd hex length".into()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .map_err(|e| StoreError::Corrupt(format!("bad hex: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_db_gets_current_schema() {
        let db = Db::open_in_memory().unwrap();
        let v: u32 = db
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        // All feature tables exist.
        for table in [
            "messages",
            "outbox",
            "attachments",
            "stickers",
            "settings",
            "attachment_chunks",
            "sticker_items",
            "sticker_pack_keys",
            "sticker_cache",
            "sticker_serves",
            "profiles",
            "tombstones",
        ] {
            let n: i64 = db
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "missing table {table}");
        }
    }

    #[test]
    fn migration_v1_to_current_preserves_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("migrate.db");
        {
            // Build a v1-only database by hand (simulating an old install).
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(crate::store::schema::SCHEMA_V1_FOR_TESTS)
                .unwrap();
            conn.pragma_update(None, "user_version", 1u32).unwrap();
            conn.execute(
                "INSERT INTO signal_locals (namespace, registration_id, identity_keypair)
                 VALUES ('p', 7, X'00')",
                [],
            )
            .unwrap();
        }
        let db = Db::open(&path, None).unwrap();
        let v: u32 = db
            .conn()
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        // The v1 row survived the migration.
        let reg: i64 = db
            .conn()
            .query_row(
                "SELECT registration_id FROM signal_locals WHERE namespace='p'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reg, 7);
        // And the v2 tables are usable.
        db.conn()
            .execute("INSERT INTO settings (key, value) VALUES ('k', X'01')", [])
            .unwrap();
    }

    #[test]
    fn newer_schema_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("schat.db");
        {
            let db = Db::open(&path, None).unwrap();
            db.conn()
                .pragma_update(None, "user_version", 99u32)
                .unwrap();
        }
        match Db::open(&path, None) {
            Err(StoreError::TooNew { found: 99 }) => {}
            Err(other) => panic!("expected TooNew, got {other:?}"),
            Ok(_) => panic!("expected TooNew, got Ok"),
        }
    }

    #[test]
    fn keyed_db_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("keyed.db");
        let key = [7u8; 32];
        {
            let db = Db::open(&path, Some(&key)).unwrap();
            db.conn()
                .execute("INSERT INTO meta (key, value) VALUES ('k', X'01')", [])
                .unwrap();
        }
        // Wrong/no key must fail to read (SQLCipher: file is encrypted).
        assert!(Db::open(&path, None).is_err());
        let db = Db::open(&path, Some(&key)).unwrap();
        let v: Vec<u8> = db
            .conn()
            .query_row("SELECT value FROM meta WHERE key='k'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, vec![1]);
    }

    #[test]
    fn concurrent_writers_do_not_lose_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("concurrent.db");
        // Writer 1 creates the schema.
        Db::open(&path, None).unwrap();

        let mut handles = Vec::new();
        for t in 0..4u8 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                let db = Db::open(&path, None).unwrap();
                for i in 0..25u8 {
                    db.conn()
                        .execute(
                            "INSERT INTO settings (key, value) VALUES (?1, X'01')",
                            [format!("t{t}-{i}")],
                        )
                        .unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let db = Db::open(&path, None).unwrap();
        let n: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM settings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 100);
    }
}
