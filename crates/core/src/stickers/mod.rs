//! `stickers/` — STICKER / STICKER_CTRL feature logic:
//! inline `:e:` tokens, pack creation + signing, install/verify, the
//! WANT_ITEM / ITEM_BODY / WANT_PACK / PACK_BODY fetch dance, and the
//! device quotas.
//!
//! Submodule map: `tokens` (inline `:e:` parsing), `keys` (pack
//! signing), `packs` (create/install/remove + quotas), `send`
//! (outbound items + serving), `inbound` (receive + fetch state).

pub mod inbound;
pub mod keys;
pub mod packs;
pub mod send;
pub mod tokens;

use std::collections::HashMap;

use schat_wire_types::sticker::limits;

use crate::store::{Db, StoreError};

/// RAM reassembly buffer for one chunked transfer (item, pack doc, or
/// thumbs doc). Bounded by `limits::MAX_PENDING_*`; swept on TTL.
#[derive(Clone, Debug)]
pub struct PendingChunks {
    pub chunk_count: u16,
    pub chunks: HashMap<u16, Vec<u8>>,
    pub total_bytes: usize,
    pub created_at: u64,
}

impl PendingChunks {
    fn new(chunk_count: u16, now: u64) -> Self {
        Self {
            chunk_count,
            chunks: HashMap::new(),
            total_bytes: 0,
            created_at: now,
        }
    }

    /// Add one chunk. Returns the reassembled blob when complete.
    fn add(&mut self, index: u16, data: &[u8]) -> Option<Vec<u8>> {
        if index >= self.chunk_count || self.chunks.contains_key(&index) {
            return None;
        }
        self.total_bytes += data.len();
        self.chunks.insert(index, data.to_vec());
        if self.chunks.len() == self.chunk_count as usize {
            let mut out = Vec::with_capacity(self.total_bytes);
            for i in 0..self.chunk_count {
                out.extend_from_slice(self.chunks.get(&i)?);
            }
            Some(out)
        } else {
            None
        }
    }
}

/// Per-peer RAM buffers for in-flight ITEM_BODY / PACK_BODY /
/// THUMBS_BODY reassembly.
#[derive(Default)]
pub struct PendingBuffers {
    /// key: sha256 hex (items) or pack_id hex (packs/thumbs).
    items: HashMap<String, PendingChunks>,
    packs: HashMap<String, PendingChunks>,
    thumbs: HashMap<String, PendingChunks>,
}

impl PendingBuffers {
    pub fn new() -> Self {
        Self::default()
    }

    fn admit<'a>(
        map: &'a mut HashMap<String, PendingChunks>,
        key: &str,
        chunk_count: u16,
        max_entries: usize,
        now: u64,
    ) -> Option<&'a mut PendingChunks> {
        if !map.contains_key(key) {
            if map.len() >= max_entries {
                return None; // over quota: refuse a new transfer
            }
            map.insert(key.to_string(), PendingChunks::new(chunk_count, now));
        }
        map.get_mut(key)
    }

    /// Feed one ITEM_BODY chunk. `Some(blob)` on completion (entry
    /// consumed).
    pub fn feed_item(
        &mut self,
        sha_key: &str,
        index: u16,
        count: u16,
        data: &[u8],
        now: u64,
    ) -> Option<Vec<u8>> {
        let entry = Self::admit(
            &mut self.items,
            sha_key,
            count,
            limits::MAX_PENDING_ITEMS,
            now,
        )?;
        if entry.chunk_count != count {
            return None; // plan changed mid-transfer: fail closed
        }
        if entry.total_bytes + data.len() > limits::MAX_PENDING_ITEM_BYTES {
            self.items.remove(sha_key);
            return None;
        }
        let done = entry.add(index, data);
        if done.is_some() {
            self.items.remove(sha_key);
        }
        done
    }

    pub fn feed_pack(
        &mut self,
        pack_key: &str,
        index: u16,
        count: u16,
        data: &[u8],
        now: u64,
    ) -> Option<Vec<u8>> {
        let entry = Self::admit(
            &mut self.packs,
            pack_key,
            count,
            limits::MAX_PENDING_PACKS,
            now,
        )?;
        if entry.chunk_count != count {
            return None;
        }
        if entry.total_bytes + data.len() > limits::MAX_PACK_DOC_BYTES {
            self.packs.remove(pack_key);
            return None;
        }
        let done = entry.add(index, data);
        if done.is_some() {
            self.packs.remove(pack_key);
        }
        done
    }

    pub fn feed_thumbs(
        &mut self,
        pack_key: &str,
        index: u16,
        count: u16,
        data: &[u8],
        now: u64,
    ) -> Option<Vec<u8>> {
        let entry = Self::admit(
            &mut self.thumbs,
            pack_key,
            count,
            limits::MAX_PENDING_PACKS,
            now,
        )?;
        if entry.chunk_count != count {
            return None;
        }
        if entry.total_bytes + data.len() > limits::MAX_THUMBS_DOC_BYTES {
            self.thumbs.remove(pack_key);
            return None;
        }
        let done = entry.add(index, data);
        if done.is_some() {
            self.thumbs.remove(pack_key);
        }
        done
    }

    /// Progress for an in-flight pack download: (complete items, total).
    pub fn pack_progress(&self, pack_key: &str) -> Option<(usize, usize)> {
        let entry = self.packs.get(pack_key)?;
        let mut partial = Vec::with_capacity(entry.total_bytes);
        for i in 0..entry.chunk_count {
            partial.extend_from_slice(entry.chunks.get(&i)?);
        }
        schat_wire_types::sticker::StickerPackDoc::scan_partial(&partial)
    }

    /// Drop stale buffers.
    pub fn sweep(&mut self, now: u64) {
        let ttl = limits::PENDING_CHUNK_TTL_SEC;
        self.items.retain(|_, e| now < e.created_at + ttl);
        self.packs.retain(|_, e| now < e.created_at + ttl);
        self.thumbs.retain(|_, e| now < e.created_at + ttl);
    }

    /// Burn path: forget everything about a peer. Buffers are keyed by
    /// content id, not rel — a full clear is the honest answer (the
    /// buffers are small and per-process).
    pub fn forget(&mut self, _rel_id: &str) {
        // Content-keyed buffers carry no rel scope; clearing all is
        // bounded (≤ 64 items + 4 packs) and simpler than scoping.
        self.items.clear();
        self.packs.clear();
        self.thumbs.clear();
    }
}

/// Cache hygiene: TTL + LRU eviction for the loose-item cache and
/// auto-cached packs.
pub fn sweep_cache(db: &Db) -> Result<(), StoreError> {
    let now = db.clock().now_secs();
    let horizon = now.saturating_sub(limits::CACHE_TTL_SEC);
    db.conn().execute(
        "DELETE FROM sticker_cache WHERE created_at < ?1",
        [horizon as i64],
    )?;
    // Entry-count cap: evict oldest first.
    db.conn().execute(
        "DELETE FROM sticker_cache WHERE sha256 NOT IN (
            SELECT sha256 FROM sticker_cache ORDER BY created_at DESC LIMIT ?1
        )",
        [limits::MAX_CACHE_ENTRIES as i64],
    )?;
    // Auto-cached packs: TTL + LRU beyond the cap.
    db.conn().execute(
        "DELETE FROM stickers WHERE cached = 1 AND last_used_at < ?1",
        [horizon as i64],
    )?;
    db.conn().execute(
        "DELETE FROM stickers WHERE cached = 1 AND pack_id NOT IN (
            SELECT pack_id FROM stickers WHERE cached = 1
            ORDER BY last_used_at DESC LIMIT ?1
        )",
        [limits::MAX_CACHED_PACKS as i64],
    )?;
    // Item blobs of evicted packs die with them.
    db.conn().execute(
        "DELETE FROM sticker_items WHERE pack_id NOT IN (SELECT pack_id FROM stickers)",
        [],
    )?;
    Ok(())
}
