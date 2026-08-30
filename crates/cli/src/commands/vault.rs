//! Vault commands: `lock`, `unlock --dek-file`, `panic-wipe`,
//! `sweep-expired`.
//!
//! The CLI process model is one process per command, so lock/unlock
//! are *state transitions the daemon observes*: `lock` writes the
//! `vault/locked` marker, `unlock` installs the dev DEK and removes it.
//! A running daemon picks the change up on its upkeep tick (≤ 5 s);
//! one-shot commands refuse to open the store while the marker is
//! present. In-process clients call `SchatCore.lock()`/`unlock(dek)`
//! directly — this file marker dance is the headless harness only.

use crate::args::Args;
use crate::util::{
    dev_dek_path, load_or_generate_dek, locked_marker_path, offline_engine, render_event, vault_dir,
};

/// `schat-cli lock`: the daemon zeroizes its Tier-B DEK and closes the
/// store on its next tick; inbound frames queue at rest (Tier-A).
pub fn lock(a: &Args) -> i32 {
    let dir = vault_dir(&a.data_dir);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("error: vault dir: {e}");
        return 1;
    }
    let marker = locked_marker_path(&a.data_dir);
    if marker.exists() {
        println!("already locked");
        return 0;
    }
    if let Err(e) = std::fs::write(&marker, b"locked\n") {
        eprintln!("error: write lock marker: {e}");
        return 1;
    }
    println!("locked — a running daemon locks within ~5 s; inbound frames queue at rest");
    0
}

/// `schat-cli unlock [--dek-file PATH]`: install the dev DEK (from
/// PATH if given, else the instance's own, generated on first use) and
/// clear the lock marker. The daemon opens the store, restores
/// sessions, and drains the queue on its next tick.
pub fn unlock(a: &Args) -> i32 {
    if let Some(src) = &a.dek_file {
        let bytes = match std::fs::read(src) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: read {}: {e}", src.display());
                return 1;
            }
        };
        if bytes.len() != 32 {
            eprintln!("error: {}: DEK must be 32 bytes", src.display());
            return 1;
        }
        let dest = dev_dek_path(&a.data_dir);
        if let Err(e) = std::fs::create_dir_all(vault_dir(&a.data_dir))
            .and_then(|_| std::fs::write(&dest, &bytes))
        {
            eprintln!("error: install dev DEK: {e}");
            return 1;
        }
    } else if let Err(e) = load_or_generate_dek(&a.data_dir) {
        eprintln!("error: {e}");
        return 1;
    }
    let marker = locked_marker_path(&a.data_dir);
    if marker.exists() {
        if let Err(e) = std::fs::remove_file(&marker) {
            eprintln!("error: clear lock marker: {e}");
            return 1;
        }
    }
    println!("unlocked — a running daemon opens the store and drains the queue within ~5 s");
    0
}

/// `schat-cli panic-wipe`: irreversible. Deletes the store and every
/// key file the core owns; the next launch is a fresh install.
pub fn panic_wipe(a: &Args) -> i32 {
    let report = schat_core::vault::wipe_data_dir(&a.data_dir);
    println!(
        "panic wipe: {} files, {} dirs removed, {} errors",
        report.files_removed, report.dirs_removed, report.errors
    );
    if report.errors > 0 {
        eprintln!("warning: wipe incomplete — inspect the data dir");
        return 1;
    }
    0
}

/// `schat-cli sweep-expired`: run the TTL sweeper once (cryptographic
/// erasure of expired rows) plus the pairing-offer sweep, and report.
/// Refuses while locked, like every store-backed command.
pub async fn sweep_expired(a: &Args) -> i32 {
    let mut engine = match offline_engine(a) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    if let Err(e) = schat_core::pairing::sweep_expired(
        engine.db.conn(),
        &engine.transport,
        std::time::SystemTime::now(),
    )
    .await
    {
        eprintln!("error: offer sweep: {e}");
        return 1;
    }
    match engine.sweep().await {
        Ok(events) => {
            for e in &events {
                println!("{}", render_event(e));
            }
            println!("sweep complete ({} events)", events.len());
            0
        }
        Err(e) => {
            eprintln!("error: sweep: {e}");
            1
        }
    }
}
