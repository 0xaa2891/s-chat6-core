//! Vault gate tests: lock/unlock cycle with state restoration,
//! locked-receive → unlock → drain, wrong-DEK fail-closed, plaintext
//! store migration, panic wipe. All headless over the mock transport
//! (frames handed over in memory, as in `pairing::tests`).

use std::sync::Arc;
use std::time::SystemTime;

use super::test_double::TestDekSource;
use super::*;
use crate::pairing;
use crate::store::messages::MessagesRepository;
use crate::store::outbox::OutboxRepository;
use crate::store::settings::{keys, SettingsRepository, TypedSettings};
use crate::transport::{framing, Transport};

struct Peer {
    ve: VaultedEngine,
    transport: Arc<Transport>,
    dek: [u8; 32],
    dir: std::path::PathBuf,
    _tmp: tempfile::TempDir,
}

impl Peer {
    async fn new(name: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let mut ve = VaultedEngine::new(tmp.path(), transport.clone()).unwrap();
        let dek = TestDekSource::new(name).derive_dek();
        ve.unlock(dek).await.unwrap();
        Self {
            ve,
            transport,
            dek,
            dir: tmp.path().to_path_buf(),
            _tmp: tmp,
        }
    }

    fn db(&self) -> &Db {
        &self.ve.engine().unwrap().db
    }
}

/// The service a frame to `to` arrives at (relationship, else pending
/// invitation). Caller must fetch this before locking the peer.
fn peer_service(to: &Peer, rel_id: &str) -> Option<String> {
    if let Some(rel) = pairing::load_relationship(to.db().conn(), rel_id).unwrap() {
        return Some(rel.service_id);
    }
    pairing::load_pending(to.db().conn())
        .unwrap()
        .map(|p| p.service_id)
}

/// Pump every due outbox record from → to through the vault ingest
/// path. Returns (queued-while-locked count, events).
async fn pump(
    from: &mut Peer,
    to: &mut Peer,
    rel_id: &str,
    to_service: &str,
) -> (u32, Vec<EngineEvent>) {
    let rows = from.db().due(64).unwrap();
    let mut events = Vec::new();
    let mut queued = 0;
    for row in rows.iter().filter(|r| r.rel_id == rel_id) {
        let intro = pairing::load_relationship(from.db().conn(), rel_id)
            .unwrap()
            .and_then(|r| r.intro_pending.then(|| r.our_qr_bytes.clone()));
        let packed = framing::pack(intro.as_deref(), &row.record, false).unwrap();
        let mut slice: &[u8] = &packed;
        let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
        match to
            .ve
            .ingest_drop(to_service, opaque.intro.as_deref(), &opaque.frame)
            .await
            .unwrap()
        {
            DropOutcome::Request { events: ev, .. } | DropOutcome::Message { events: ev, .. } => {
                events.extend(ev)
            }
            DropOutcome::Queued => queued += 1,
            DropOutcome::Duplicate | DropOutcome::Dropped => {}
            DropOutcome::SessionBroken { reason, .. } => panic!("session broken: {reason}"),
        }
        from.db().dequeue(&row.msg_id).unwrap();
    }
    (queued, events)
}

async fn quiesce(a: &mut Peer, b: &mut Peer, rel_id: &str) {
    let a_svc = peer_service(a, rel_id);
    let b_svc = peer_service(b, rel_id);
    for _ in 0..20 {
        let (qa, _) = pump(a, b, rel_id, b_svc.as_deref().unwrap()).await;
        let (qb, _) = pump(b, a, rel_id, a_svc.as_deref().unwrap()).await;
        if qa + qb == 0 && a.db().due(64).unwrap().is_empty() && b.db().due(64).unwrap().is_empty()
        {
            break;
        }
    }
}

/// offer → accept → first frame → request accepted → bursts settled.
async fn pair_up() -> (Peer, Peer, String) {
    let mut inviter = Peer::new("inviter").await;
    let mut accepter = Peer::new("accepter").await;
    let now = SystemTime::now();

    let offer = pairing::offer(inviter.db().conn(), &inviter.transport, now)
        .await
        .unwrap();
    let accepted = pairing::accept(
        accepter.db().conn(),
        &accepter.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .unwrap();
    let rel_id = accepted.rel_id.clone();

    accepter
        .ve
        .engine_mut()
        .unwrap()
        .send_text(&rel_id, "hi", None)
        .await
        .unwrap();
    let inviter_svc = peer_service(&inviter, &rel_id).unwrap();
    let (_, events) = pump(&mut accepter, &mut inviter, &rel_id, &inviter_svc).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, EngineEvent::Message { .. })),
        "intro message landed: {events:?}"
    );
    pairing::accept_request(inviter.db().conn(), &inviter.transport, &rel_id)
        .await
        .unwrap();
    quiesce(&mut inviter, &mut accepter, &rel_id).await;
    (inviter, accepter, rel_id)
}

fn thread_bodies(peer: &Peer, rel_id: &str) -> Vec<String> {
    peer.db()
        .thread_visible(rel_id, 100, None)
        .unwrap()
        .into_iter()
        .filter_map(|r| String::from_utf8(r.payload).ok())
        .collect()
}

#[tokio::test]
async fn lock_unlock_cycle_restores_state() {
    let (mut inviter, mut accepter, rel_id) = pair_up().await;

    inviter
        .ve
        .engine_mut()
        .unwrap()
        .send_text(&rel_id, "before lock", None)
        .await
        .unwrap();
    let accepter_svc = peer_service(&accepter, &rel_id).unwrap();
    pump(&mut inviter, &mut accepter, &rel_id, &accepter_svc).await;
    assert!(thread_bodies(&accepter, &rel_id)
        .iter()
        .any(|b| b.contains("before lock")));

    // Lock: engine gone, sends refuse, lock is idempotent.
    accepter.ve.lock();
    accepter.ve.lock();
    assert!(accepter.ve.is_locked());
    assert!(matches!(accepter.ve.engine(), Err(VaultError::Locked)));

    // Unlock with the same DEK: store reopens, sessions restore.
    let report = accepter.ve.unlock(accepter.dek).await.unwrap();
    assert_eq!(report.drained, 0);
    assert!(thread_bodies(&accepter, &rel_id)
        .iter()
        .any(|b| b.contains("before lock")));

    // The restored session still encrypts both directions.
    accepter
        .ve
        .engine_mut()
        .unwrap()
        .send_text(&rel_id, "after relock", None)
        .await
        .unwrap();
    let inviter_svc = peer_service(&inviter, &rel_id).unwrap();
    pump(&mut accepter, &mut inviter, &rel_id, &inviter_svc).await;
    assert!(thread_bodies(&inviter, &rel_id)
        .iter()
        .any(|b| b.contains("after relock")));
}

#[tokio::test]
async fn wrong_dek_fails_closed() {
    let mut peer = Peer::new("carol").await;
    peer.db().set_string(keys::PROFILE_NAME, "carol").unwrap();
    peer.ve.lock();

    // Wrong DEK: fail closed, no partial state, still locked.
    let bad = peer.ve.unlock([0u8; 32]).await;
    assert!(matches!(bad, Err(VaultError::BadDek)));
    assert!(peer.ve.is_locked());

    // Right DEK opens; state intact.
    peer.ve.unlock(peer.dek).await.unwrap();
    assert_eq!(
        peer.db().get_string(keys::PROFILE_NAME).unwrap().as_deref(),
        Some("carol")
    );
}

#[tokio::test]
async fn locked_receive_queues_then_unlock_drains() {
    let (mut inviter, mut accepter, rel_id) = pair_up().await;
    let accepter_svc = peer_service(&accepter, &rel_id).unwrap();

    accepter.ve.lock();
    inviter
        .ve
        .engine_mut()
        .unwrap()
        .send_text(&rel_id, "while locked", None)
        .await
        .unwrap();
    let (queued, events) = pump(&mut inviter, &mut accepter, &rel_id, &accepter_svc).await;
    assert_eq!(queued, 1, "frame queued at rest, not ingested");
    assert!(events.is_empty());
    assert_eq!(accepter.ve.queued_drops(), 1);

    let report = accepter.ve.unlock(accepter.dek).await.unwrap();
    assert_eq!(report.drained, 1);
    assert_eq!(report.errors, 0);
    assert!(
        report
            .events
            .iter()
            .any(|e| matches!(e, EngineEvent::Message { .. })),
        "drain dispatched the message: {:?}",
        report.events
    );
    assert!(thread_bodies(&accepter, &rel_id)
        .iter()
        .any(|b| b.contains("while locked")));
    assert_eq!(accepter.ve.queued_drops(), 0);
}

#[tokio::test]
async fn panic_wipe_leaves_a_fresh_install() {
    let (mut inviter, mut accepter, rel_id) = pair_up().await;
    let accepter_svc = peer_service(&accepter, &rel_id).unwrap();
    let data_dir = accepter.dir.clone();

    // Something in the store, something in the queue.
    accepter.ve.lock();
    inviter
        .ve
        .engine_mut()
        .unwrap()
        .send_text(&rel_id, "queued before wipe", None)
        .await
        .unwrap();
    pump(&mut inviter, &mut accepter, &rel_id, &accepter_svc).await;
    assert_eq!(accepter.ve.queued_drops(), 1);

    let report = accepter.ve.panic_wipe();
    assert_eq!(report.errors, 0);
    assert!(!data_dir.join("schat.db").exists());
    assert!(!data_dir.join("keys").exists());
    assert!(!data_dir.join("queue").exists());

    // Next launch: fresh install. A new DEK opens a new empty store.
    let transport = Transport::new(&data_dir);
    let mut fresh = VaultedEngine::new(&data_dir, transport).unwrap();
    fresh.unlock([3u8; 32]).await.unwrap();
    let rels =
        pairing::relationship::list_relationships(fresh.engine().unwrap().db.conn()).unwrap();
    assert!(rels.is_empty());
}

#[test]
fn plaintext_store_migrates_to_keyed_on_first_open() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("schat.db");
    let dek = [7u8; 32];
    {
        let db = Db::open(&path, None).unwrap();
        db.set_setting("migrated", b"yes").unwrap();
    }
    assert!(path.exists());

    let db = open_store_with_dek(&path, &dek).unwrap();
    assert_eq!(
        db.setting("migrated").unwrap().as_deref(),
        Some(b"yes".as_slice())
    );
    drop(db);

    // The file is encrypted now: no SQLite magic, no plaintext open.
    let mut magic = [0u8; 16];
    use std::io::Read;
    std::fs::File::open(&path)
        .unwrap()
        .read_exact(&mut magic)
        .unwrap();
    assert_ne!(&magic, b"SQLite format 3\0");
    assert!(Db::open(&path, None).is_err());
    assert!(matches!(
        open_store_with_dek(&path, &[8u8; 32]),
        Err(VaultError::BadDek)
    ));
}

#[tokio::test]
async fn lock_keeps_queue_append_alive() {
    let tmp = tempfile::tempdir().unwrap();
    let transport = Transport::new(tmp.path());
    let mut ve = VaultedEngine::new(tmp.path(), transport).unwrap();
    // Never unlocked: queue append works from the start.
    let outcome = ve.ingest_drop("svc", None, b"frame").await.unwrap();
    assert!(matches!(outcome, DropOutcome::Queued));
    assert_eq!(ve.queued_drops(), 1);
    ve.lock(); // always safe
    assert!(ve.is_locked());
}

/// While locked, no Tier-B plaintext lives in RAM. A random
/// canary message is sent B→A, received and stored, then both peers
/// lock and drop. After a heap scrub, the whole address space is
/// scanned: any full-canary hit is a leak. The canary is random per
/// run, so no other test or binary rodata can collide with it.
///
/// Only meaningful on platforms with a process-memory reader.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[tokio::test]
async fn locked_state_holds_no_plaintext_canary() {
    use zeroize::Zeroizing;

    // 24 random bytes → 48 hex chars; distinctive, no rodata collision.
    let mut raw = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut raw);
    let canary = Zeroizing::new(crate::store::hex_encode(&raw));

    let (mut a, mut b, rel_id) = pair_up().await;

    // B sends the canary; A receives, decrypts, stores it.
    b.ve.engine_mut()
        .unwrap()
        .send_text(&rel_id, &canary, None)
        .await
        .unwrap();
    let a_svc = peer_service(&a, &rel_id).unwrap();
    let (_, events) = pump(&mut b, &mut a, &rel_id, &a_svc).await;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, EngineEvent::Message { .. })),
        "canary delivered: {events:?}"
    );

    // Lock both vaults (Tier-B DEKs zeroized, SQLCipher connections
    // closed with cipher_memory_security on), then drop everything.
    a.ve.lock();
    b.ve.lock();
    drop(a);
    drop(b);

    super::audit::scrub_heap();
    // A live leak (what this test exists to catch) is a still-allocated
    // buffer: it survives every scrub round. A freed crumb only survives
    // until the allocator recycles its size class, which can take more
    // than one scrub pass under full-suite parallel load. Fail only if
    // the canary persists across all rounds.
    let mut hits = usize::MAX;
    for round in 0..3 {
        if round > 0 {
            super::audit::scrub_heap();
        }
        hits = super::audit::live_canary_hits(canary.as_bytes());
        if hits == 0 {
            break;
        }
    }
    assert_eq!(hits, 0, "plaintext canary survived the lock");
}

/// Scanner self-check: a live plaintext copy MUST be found. Without
/// this, `locked_state_holds_no_plaintext_canary` could pass vacuously
/// if the region reader silently broke.
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[test]
fn scanner_finds_a_live_canary() {
    let mut raw = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut raw);
    // The needle/verify reference (excluded from the scan) …
    let reference = zeroize::Zeroizing::new(crate::store::hex_encode(&raw));
    // … and a separate live copy standing in for leaked plaintext.
    let planted = reference.clone();
    let hits = super::audit::live_canary_hits(reference.as_bytes());
    assert!(hits >= 1, "scanner missed a live canary copy");
    drop(planted);
}
