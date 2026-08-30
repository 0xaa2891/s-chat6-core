//! Shared helpers for the CLI commands: daemon construction, status
//! rendering, the text payload record, and the online wait.

use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Duration;

use schat_core::engine::{Engine, EngineEvent};
use schat_core::store::Db;
use schat_core::transport::daemon::{chutney_extra_torrc_lines, SubprocessTor};
use schat_core::transport::framing;
use schat_core::transport::status::{TorState, TransportStatus};
use schat_core::transport::Transport;

use crate::args::Args;

pub fn tor_binary() -> PathBuf {
    if let Ok(p) = std::env::var("SCHAT_TOR") {
        return PathBuf::from(p);
    }
    // Default: tor on PATH.
    PathBuf::from("tor")
}

/// Build a subprocess daemon for this instance dir, optionally joined to a
/// Chutney testnet.
pub fn make_daemon(
    data_dir: &std::path::Path,
    chutney_nodes: Option<&PathBuf>,
) -> Arc<SubprocessTor> {
    let extra = match chutney_nodes {
        Some(dir) => chutney_extra_torrc_lines(dir).unwrap_or_else(|e| {
            eprintln!("error: cannot read chutney nodes dir: {e}");
            process::exit(1)
        }),
        None => Vec::new(),
    };
    SubprocessTor::new(
        tor_binary(),
        data_dir.join("tor"),
        SubprocessTor::free_port().expect("free socks port"),
        SubprocessTor::free_port().expect("free control port"),
        extra,
    )
}

pub fn render_status(s: &TransportStatus) -> String {
    let tor = match &s.tor {
        TorState::Off => "off".to_string(),
        TorState::Starting => "starting".to_string(),
        TorState::Bootstrapping { pct } => format!("bootstrapping {pct}%"),
        TorState::Online => "online".to_string(),
        TorState::Degraded { reason } => format!("degraded: {reason}"),
        TorState::Dead { reason } => format!("dead: {reason}"),
    };
    let services = s
        .services
        .iter()
        .map(|svc| {
            format!(
                "{}={:?}({})",
                svc.service_id,
                svc.state,
                svc.onion.clone().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "tor={tor} kill_switch={} mode={} outbox={} inbox={} last_error={} services=[{services}]",
        s.kill_switch,
        s.mode.as_str(),
        s.outbox.queued,
        s.inbox.pending,
        s.last_error.clone().unwrap_or_else(|| "-".into()),
    )
}

/// Build a text payload record: bucket 256, version byte, u16 len, text.
pub fn text_record(text: &str) -> Vec<u8> {
    let mut rec = vec![0u8; framing::RECORD_BUCKETS[0]];
    rec[0] = framing::VERSION_V2;
    let bytes = text.as_bytes();
    let len = bytes.len().min(250);
    rec[1..3].copy_from_slice(&(len as u16).to_be_bytes());
    rec[3..3 + len].copy_from_slice(&bytes[..len]);
    rec
}

pub async fn wait_online(transport: &Arc<Transport>, timeout: Duration) -> bool {
    let mut rx = transport.subscribe();
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if matches!(rx.borrow().tor, TorState::Online) {
            return true;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
        if tokio::time::timeout(Duration::from_secs(5), rx.changed())
            .await
            .is_err()
        {
            // re-check on timeout
        }
    }
}

// -- Dev-DEK vault plumbing ------------------------------------------------
//
// Headless dev mode: the Tier-B DEK is generated once and stored at
// `vault/dek` in the instance's data dir (explicitly NOT a shipped
// security feature — real clients pass the DEK to `unlock` and never
// persist it). `vault/locked` is the lock marker a running daemon
// watches: present = locked, absent = unlocked.

pub fn vault_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("vault")
}

pub fn dev_dek_path(data_dir: &std::path::Path) -> PathBuf {
    vault_dir(data_dir).join("dek")
}

pub fn locked_marker_path(data_dir: &std::path::Path) -> PathBuf {
    vault_dir(data_dir).join("locked")
}

pub fn is_locked(data_dir: &std::path::Path) -> bool {
    locked_marker_path(data_dir).exists()
}

/// Read the dev DEK, generating it on first use.
pub fn load_or_generate_dek(data_dir: &std::path::Path) -> Result<[u8; 32], String> {
    use rand::RngCore;
    let path = dev_dek_path(data_dir);
    match std::fs::read(&path) {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| format!("{}: dev DEK is not 32 bytes", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut dek = [0u8; 32];
            rand::rng().fill_bytes(&mut dek);
            std::fs::create_dir_all(vault_dir(data_dir)).map_err(|e| format!("vault dir: {e}"))?;
            std::fs::write(&path, dek).map_err(|e| format!("write dev DEK: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            eprintln!(
                "note: generated a dev-mode DEK at {} (headless convenience, not a shipped security feature)",
                path.display()
            );
            Ok(dek)
        }
        Err(e) => Err(format!("read dev DEK: {e}")),
    }
}

/// Open the instance store with the dev DEK. Refuses while the lock
/// marker is present (fail closed); migrates a pre-vault plaintext
/// store on first keyed open.
pub fn open_cli_db(data_dir: &std::path::Path) -> Result<Db, String> {
    if is_locked(data_dir) {
        return Err("instance is locked (run `schat-cli unlock`)".into());
    }
    let dek = load_or_generate_dek(data_dir)?;
    schat_core::vault::open_store_with_dek(&data_dir.join("schat.db"), &dek)
        .map_err(|e| format!("open store: {e}"))
}

/// Open the store without a transport (read-only commands).
pub fn offline_engine(a: &Args) -> Result<Engine, String> {
    let db = open_cli_db(&a.data_dir)?;
    Ok(Engine::new(db, Transport::new(&a.data_dir)))
}

/// Open the store, bring tor up, and wait for online (send commands).
pub async fn start_engine(a: &Args) -> Result<(Engine, Arc<Transport>), String> {
    let transport = Transport::new(&a.data_dir);
    transport
        .set_daemon(make_daemon(&a.data_dir, a.chutney_nodes.as_ref()))
        .await;
    transport.start().await.map_err(|e| format!("start: {e}"))?;
    if !wait_online(&transport, Duration::from_secs(120)).await {
        transport.stop().await;
        return Err("tor did not come online in 120 s".into());
    }
    let db = match open_cli_db(&a.data_dir) {
        Ok(db) => db,
        Err(e) => {
            transport.stop().await;
            return Err(e);
        }
    };
    Ok((Engine::new(db, transport.clone()), transport))
}

/// `start_engine` for command bodies: on failure, report and return
/// `None` so the caller exits 1 without an unwrap.
pub async fn start_engine_or_report(a: &Args) -> Option<(Engine, Arc<Transport>)> {
    match start_engine(a).await {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("error: {e}");
            None
        }
    }
}

/// Print the outcome, let the local tor drain the cells, shut down.
pub async fn finish(transport: &Arc<Transport>, result: Result<String, String>) -> i32 {
    match result {
        Ok(msg) => {
            println!("{msg}");
            // The write only queued the cells in the local tor; exiting at
            // once kills the daemon before the rendezvous circuit relays
            // them. Long-lived clients never see this — the CLI drains.
            tokio::time::sleep(Duration::from_secs(3)).await;
            transport.stop().await;
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            transport.stop().await;
            1
        }
    }
}

/// One-line rendering of an engine event (daemon log).
pub fn render_event(e: &EngineEvent) -> String {
    use EngineEvent::*;
    match e {
        Message { rel_id, msg_id } => format!("message: rel={rel_id} id={}", hex(msg_id)),
        Edited { rel_id, msg_id } => format!("edited: rel={rel_id} id={}", hex(msg_id)),
        Deleted { rel_id, msg_id } => format!("deleted: rel={rel_id} id={}", hex(msg_id)),
        HistoryCleared { rel_id } => format!("history-cleared: rel={rel_id}"),
        Read { rel_id, msg_id } => format!("read: rel={rel_id} id={}", hex(msg_id)),
        Typing { rel_id, typing } => format!("typing: rel={rel_id} typing={typing}"),
        Presence {
            rel_id,
            in_app,
            do_not_disturb,
        } => format!("presence: rel={rel_id} in_app={in_app} dnd={do_not_disturb}"),
        ProfileUpdated { rel_id } => format!("profile-updated: rel={rel_id}"),
        ProfileRequested { rel_id } => format!("profile-requested: rel={rel_id}"),
        PeerPrefs { rel_id } => format!("peer-prefs: rel={rel_id}"),
        Sticker {
            rel_id,
            msg_id,
            ready,
        } => format!("sticker: rel={rel_id} id={} ready={ready}", hex(msg_id)),
        StickerPackInstalled { pack_id } => format!("pack-installed: pack={}", hex(pack_id)),
        StickerPackRefused { pack_id, reason } => {
            format!("pack-refused: pack={} reason={reason}", hex(pack_id))
        }
        StickerThumbs { pack_id, .. } => format!("pack-thumbs: pack={}", hex(pack_id)),
        AttachmentProgress {
            rel_id,
            head_id,
            received,
            total,
        } => format!(
            "attach-progress: rel={rel_id} head={} {received}/{total}",
            hex(head_id)
        ),
        AttachmentComplete {
            rel_id,
            head_id,
            msg_id,
        } => format!(
            "attach-complete: rel={rel_id} head={} msg={}",
            hex(head_id),
            hex(msg_id)
        ),
        AttachmentFailed { rel_id, head_id } => {
            format!("attach-failed: rel={rel_id} head={}", hex(head_id))
        }
        AttachmentChunkDropped { rel_id, head_id } => {
            format!("attach-chunk-dropped: rel={rel_id} head={}", hex(head_id))
        }
        PolicyChanged { rel_id } => format!("policy-changed: rel={rel_id}"),
        ContactClosed { rel_id } => format!("contact-closed: rel={rel_id}"),
        GapDetected { rel_id } => format!("gap-detected: rel={rel_id} (resync requested)"),
    }
}

fn hex(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
