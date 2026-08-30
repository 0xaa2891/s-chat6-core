//! Schema + migration ladder. `user_version`-based, forward-only, fail
//! closed: a database newer than this build is refused, never downgraded.
//!
//! Each entry in `MIGRATIONS` takes the database from version `i` to
//! `i + 1` and runs inside its own transaction — a failed migration
//! leaves the database at its previous version, never half-applied.

use rusqlite::Connection;

use super::StoreError;

/// v0 → v1: initial schema (pairing + libsignal state + I11 cache).
const SCHEMA_V1: &str = "
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- Single-slot pending invitation (we are the inviter). One offer at a
-- time; a new offer replaces the old, expiry sweeps it.
CREATE TABLE pending_pairing (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    service_id TEXT NOT NULL,
    onion TEXT NOT NULL,
    qr_bytes BLOB NOT NULL,
    client_auth_private TEXT NOT NULL,  -- base32 x25519, our half of the offer
    expires_at INTEGER NOT NULL
);

CREATE TABLE relationships (
    rel_id TEXT PRIMARY KEY,            -- hex of SHA-256 relationship id
    role TEXT NOT NULL,                 -- 'inviter' | 'accepter'
    state TEXT NOT NULL,                -- 'request' | 'active'
    service_id TEXT NOT NULL,           -- our hosted service id for this relationship
    onion TEXT NOT NULL,                -- our onion hostname
    peer_onion TEXT NOT NULL,
    peer_identity_key BLOB NOT NULL,    -- serialized libsignal IdentityKey
    peer_client_auth_public TEXT NOT NULL,  -- base32 x25519 (authorizes peer on our service)
    our_client_auth_private TEXT NOT NULL,  -- base32 x25519 (authenticates us to peer's service)
    our_nonce BLOB NOT NULL,
    peer_nonce BLOB NOT NULL,
    our_qr_bytes BLOB NOT NULL,         -- our signed pairing payload (intro source)
    sas_confirmed INTEGER NOT NULL DEFAULT 0,
    intro_pending INTEGER NOT NULL DEFAULT 0,
    session_state TEXT NOT NULL DEFAULT 'active', -- 'active' | 'broken'
    created_at INTEGER NOT NULL
);

-- Per-relationship libsignal state. `namespace` is the relationship id
-- hex, or 'pending' for the single outstanding invitation's persona
-- (migrated to the rel_id when the peer's intro arrives).
CREATE TABLE signal_locals (
    namespace TEXT PRIMARY KEY,
    registration_id INTEGER NOT NULL,
    identity_keypair BLOB NOT NULL
);
CREATE TABLE signal_identities (
    namespace TEXT NOT NULL,
    address TEXT NOT NULL,
    key BLOB NOT NULL,
    PRIMARY KEY (namespace, address)
);
CREATE TABLE signal_sessions (
    namespace TEXT NOT NULL,
    address TEXT NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (namespace, address)
);
CREATE TABLE signal_prekeys (
    namespace TEXT NOT NULL,
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (namespace, id)
);
CREATE TABLE signal_signed_prekeys (
    namespace TEXT NOT NULL,
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (namespace, id)
);
CREATE TABLE signal_kyber_prekeys (
    namespace TEXT NOT NULL,
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    used_with BLOB,  -- signed_prekey_id u32be ‖ base_key, set on first use
    PRIMARY KEY (namespace, id)
);

-- I11: one msg_id → one ciphertext. Retransmission sends stored bytes.
CREATE TABLE message_ciphertexts (
    msg_id TEXT PRIMARY KEY,
    rel_id TEXT NOT NULL,
    frame_bytes BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
";

/// v1 → v2: message ledger, outbox, attachments,
/// stickers, settings.
const SCHEMA_V2: &str = "
-- The message ledger: one row per envelope, both directions. `payload`
-- is the *decoded* inner payload (post-decrypt); the wire record for
-- retransmission lives in `outbox` / `message_ciphertexts`.
CREATE TABLE messages (
    msg_id TEXT PRIMARY KEY,            -- hex of 16-byte message id
    rel_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    app_seq INTEGER NOT NULL,
    sent_at INTEGER NOT NULL,           -- sender-claimed; clamped by sync
    received_at INTEGER,                -- inbound only
    env_type INTEGER NOT NULL,
    ref_id TEXT,                        -- hex of 16-byte ref id
    payload BLOB NOT NULL,
    state TEXT NOT NULL,                -- 'received' | 'queued' | 'transmitted' | 'acknowledged' | 'failed'
    expires_at INTEGER,                 -- TTL horizon; NULL = keep
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_messages_rel_seq ON messages(rel_id, direction, app_seq);
CREATE INDEX idx_messages_expiry ON messages(expires_at) WHERE expires_at IS NOT NULL;

-- Delivery queue: records built, padded, and ready to hand to the
-- transport. A row leaves the outbox on transmit; the message row's
-- state tracks the full lifecycle from there.
CREATE TABLE outbox (
    msg_id TEXT PRIMARY KEY,
    rel_id TEXT NOT NULL,
    record BLOB NOT NULL,               -- bucket-sized wire record
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,        -- undelivered past this → failed
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_outbox_due ON outbox(next_attempt_at);

-- Attachment transfer state. `chunks` is an LSB-first bitmap of received
-- (inbound) or sent (outbound) chunk indexes; chunk payloads themselves
-- live in the media layer, keyed by head_id.
CREATE TABLE attachments (
    head_id TEXT PRIMARY KEY,           -- hex of 16-byte head id
    rel_id TEXT NOT NULL,
    msg_id TEXT NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
    media_class INTEGER NOT NULL,
    mime_hint TEXT NOT NULL,
    uncompressed_n INTEGER NOT NULL,
    chunk_count INTEGER NOT NULL,
    chunk_bucket INTEGER NOT NULL,
    content_sha256 BLOB NOT NULL,
    caption TEXT NOT NULL DEFAULT '',
    flags INTEGER NOT NULL DEFAULT 0,
    chunks BLOB NOT NULL DEFAULT X'',
    complete INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_attachments_msg ON attachments(msg_id);

-- Installed sticker/emoji packs (pack-level metadata; item bodies ride
-- the attachment pipeline).
CREATE TABLE stickers (
    pack_id TEXT PRIMARY KEY,           -- hex of 16-byte pack id
    pack_pk BLOB NOT NULL,
    title TEXT NOT NULL,
    kind INTEGER NOT NULL,
    visibility INTEGER NOT NULL,
    item_count INTEGER NOT NULL,
    icon_item_id INTEGER NOT NULL,
    installed_at INTEGER NOT NULL
);

-- User preferences. `meta` stays internal:
-- schema bookkeeping and sync cursors never mix with user settings.
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
";

/// v2 → v3: feature state. Per-relationship caps/policy/close
/// columns, message edit/tombstone/read markers, attachment chunk blobs,
/// sticker item blobs + pack keys + loose-item cache + serve quota, and
/// peer profiles.
const SCHEMA_V3: &str = "
ALTER TABLE relationships ADD COLUMN peer_caps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE relationships ADD COLUMN policy_ttl_sec INTEGER NOT NULL DEFAULT 86400;
-- Agreed rule flags: bit0 screenshot, bit1 attach_download (default on).
ALTER TABLE relationships ADD COLUMN policy_flags INTEGER NOT NULL DEFAULT 3;
-- Capability wants, packed: local in low byte, peer in high byte
-- Default: both sides want everything.
ALTER TABLE relationships ADD COLUMN policy_wants INTEGER NOT NULL DEFAULT 31868; -- 0x7C7C
-- Pending rule proposal: ttl(4 BE) + flags(1: screenshot, download,
-- inbound) + propose msg_id(16). NULL = no pending proposal.
ALTER TABLE relationships ADD COLUMN policy_pending BLOB;
-- Last OP_SYNC we sent (hourly cadence + resync replies).
ALTER TABLE relationships ADD COLUMN policy_last_sync_at INTEGER NOT NULL DEFAULT 0;
-- NULL = open; otherwise the honest closing state ('closing' | 'closed_by_peer').
ALTER TABLE relationships ADD COLUMN close_state TEXT;
-- DELETE_ALL cut: inbound history-type envelopes with app_seq below
-- this are dropped.
ALTER TABLE relationships ADD COLUMN history_cut_seq INTEGER NOT NULL DEFAULT 0;
-- Peer's receive preferences (PREF payload, raw bytes; NULL = unknown).
ALTER TABLE relationships ADD COLUMN peer_prefs BLOB;
-- User-chosen contact name; wins over the peer's profile name.
ALTER TABLE relationships ADD COLUMN custom_name TEXT;

-- The v2 attachments table predates the head fields.
ALTER TABLE attachments ADD COLUMN orig_ext TEXT NOT NULL DEFAULT '';
-- View-once: payloads erased after the client renders them.
ALTER TABLE attachments ADD COLUMN consumed INTEGER NOT NULL DEFAULT 0;

-- Pack provenance for the device quotas:
-- cached = auto-cached public pack (LRU-evicted, not user-installed),
-- from_rel = who sent it (per-sender pack cap), last_used for LRU.
ALTER TABLE stickers ADD COLUMN cached INTEGER NOT NULL DEFAULT 0;
ALTER TABLE stickers ADD COLUMN from_rel TEXT;
ALTER TABLE stickers ADD COLUMN last_used_at INTEGER NOT NULL DEFAULT 0;

ALTER TABLE messages ADD COLUMN edited INTEGER NOT NULL DEFAULT 0;
-- Edit bookkeeping for the 30-edits / stale-seq rules.
ALTER TABLE messages ADD COLUMN edit_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN last_edit_seq INTEGER NOT NULL DEFAULT 0;
-- Tombstoned rows keep their slot (threading, resync seqs) but the
-- payload is wiped at tombstone time.
ALTER TABLE messages ADD COLUMN tombstone INTEGER NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN read_at INTEGER;

-- Chunk payloads for the attachment pipeline (metadata lives in
-- `attachments`). secure_delete zeroes pages on sweep.
CREATE TABLE attachment_chunks (
    head_id TEXT NOT NULL,
    idx INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (head_id, idx)
);

-- Item blobs for installed sticker/emoji packs (metadata in `stickers`).
CREATE TABLE sticker_items (
    pack_id TEXT NOT NULL,
    item_id INTEGER NOT NULL,
    w INTEGER NOT NULL,
    h INTEGER NOT NULL,
    sha256 BLOB NOT NULL,
    bytes BLOB NOT NULL,
    PRIMARY KEY (pack_id, item_id)
);

-- Signing keys for packs we created (Curve25519 private, XEdDSA).
CREATE TABLE sticker_pack_keys (
    pack_id TEXT PRIMARY KEY,
    secret BLOB NOT NULL
);

-- Loose-item receive cache: private-pack items and items from packs we
-- never installed. LRU/TTL-evicted by the sticker module's quotas.
CREATE TABLE sticker_cache (
    sha256 BLOB PRIMARY KEY,
    bytes BLOB NOT NULL,
    w INTEGER NOT NULL,
    h INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    pack_id TEXT,
    from_rel TEXT,
    created_at INTEGER NOT NULL
);

-- Outbound pack-serving quota (WANT_PACK answers per peer per day).
CREATE TABLE sticker_serves (
    rel_id TEXT NOT NULL,
    day INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (rel_id, day)
);

-- Peer profiles landed via PROFILE envelopes.
CREATE TABLE profiles (
    rel_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    jpeg BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Delete tombstones: a DELETE records the
-- target msg_id here so a late-arriving copy of that message (resync,
-- out-of-order) is dropped on sight. TTL 24 h, cap 4096 per rel —
-- prune expired, then oldest.
CREATE TABLE tombstones (
    rel_id TEXT NOT NULL,
    ref_id TEXT NOT NULL,
    expiry INTEGER NOT NULL,
    PRIMARY KEY (rel_id, ref_id)
);

-- Every inbound envelope's app_seq, history and ephemeral alike.
-- The resync receive view reads
-- THIS, not the message ledger — typing/presence beats consume seqs
-- and must count toward continuity without polluting the ledger.
CREATE TABLE inbound_seqs (
    rel_id TEXT NOT NULL,
    app_seq INTEGER NOT NULL,
    PRIMARY KEY (rel_id, app_seq)
);

-- Backfill from the v2 ledger (pre-v3 inbound rows were all ledgered).
INSERT INTO inbound_seqs (rel_id, app_seq)
    SELECT rel_id, app_seq FROM messages WHERE direction = 'in';
";

/// v3 → v4: drop the SAS-confirmation flag. Safety codes stay computed
/// from pairing payloads; they are no longer a stored pairing gate.
const SCHEMA_V4: &str = "
ALTER TABLE relationships DROP COLUMN sas_confirmed;
";

/// v4 → v5: orphan-chunk attribution. Chunks that arrive
/// before their ATTACH_HEAD are stored durably here, so they need the
/// relationship they came from (per-rel caps) and an arrival timestamp
/// (TTL sweep). Rows written before v5 keep the empty/0 defaults; the
/// sweep treats `created_at = 0` as already expired.
const SCHEMA_V5: &str = "
ALTER TABLE attachment_chunks ADD COLUMN rel_id TEXT NOT NULL DEFAULT '';
ALTER TABLE attachment_chunks ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX idx_attachment_chunks_rel ON attachment_chunks(rel_id);
";

/// v5 → v6: inbound replay cache. SHA-256 of every
/// successfully decrypted inbound frame, per relationship. A
/// byte-identical replay drops as a duplicate BEFORE libsignal sees it:
/// past the retained receiver-chain window a replayed ciphertext is
/// otherwise indistinguishable from a session break, so a
/// captured-and-replayed frame would be a one-packet DoS. Rows expire
/// on the message TTL; beyond it a replay fails closed (Broken).
const SCHEMA_V6: &str = "
CREATE TABLE inbound_frames (
    rel_id TEXT NOT NULL,
    frame_hash BLOB NOT NULL,           -- SHA-256 of the record payload
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (rel_id, frame_hash)
);
";

/// The migration ladder. `MIGRATIONS[i]` upgrades v(i) → v(i+1).
const MIGRATIONS: &[&str] = &[
    SCHEMA_V1, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5, SCHEMA_V6,
];

/// Exposed so the migration test can build a v1-only database by hand.
#[cfg(test)]
pub(crate) const SCHEMA_V1_FOR_TESTS: &str = SCHEMA_V1;

/// The schema version this build speaks.
pub const SCHEMA_VERSION: u32 = MIGRATIONS.len() as u32;

/// Bring `conn` up to [`SCHEMA_VERSION`]. Fail closed on a newer
/// database; each step is transactional.
pub fn migrate(conn: &Connection) -> Result<(), StoreError> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::TooNew { found: version });
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        let target = i as u32 + 1;
        tx.pragma_update(None, "user_version", target)?;
        tx.commit()?;
    }
    Ok(())
}
