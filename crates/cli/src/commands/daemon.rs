//! `schat-cli daemon`: bring the transport up, host the inbox service,
//! and run the engine behind the vault: inbound drops → decrypt →
//! `handle_plaintext` → events while unlocked, Tier-A queue-at-rest
//! while locked; outbox drains and sweeps on a timer, until
//! interrupted.
//!
//! Lock control is the `vault/locked` marker file (the CLI is one
//! process per command): `schat-cli lock` writes it, `schat-cli
//! unlock` clears it; the daemon transitions on its upkeep tick.

use std::time::Duration;

use schat_core::engine::EngineEvent;
use schat_core::vault::{DropOutcome, VaultedEngine};

use crate::args::Args;
use crate::util::{is_locked, load_or_generate_dek, make_daemon, render_event, render_status};

pub async fn run(a: &Args) -> i32 {
    let transport = schat_core::transport::Transport::new(&a.data_dir);
    transport
        .set_daemon(make_daemon(&a.data_dir, a.chutney_nodes.as_ref()))
        .await;
    transport.set_mode(a.mode);
    if let Err(e) = transport.start().await {
        eprintln!("error: start: {e}");
        return 1;
    }
    let onion = match transport.host_service("inbox", a.restricted).await {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: host service: {e}");
            return 1;
        }
    };
    println!("onion: {onion}");

    // The vault starts locked; open it unless the marker says locked.
    let mut core = match VaultedEngine::new(&a.data_dir, transport.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: vault: {e}");
            return 1;
        }
    };
    if is_locked(&a.data_dir) {
        println!("locked: inbound frames queue at rest until `schat-cli unlock`");
    } else {
        match load_or_generate_dek(&a.data_dir) {
            Ok(dek) => match core.unlock(dek).await {
                Ok(report) => print_unlock(&report),
                Err(e) => eprintln!("error: unlock: {e} (staying locked)"),
            },
            Err(e) => eprintln!("error: {e} (staying locked)"),
        }
    }

    // Status printer.
    let mut status_rx = transport.subscribe();
    tokio::spawn(async move {
        loop {
            println!("status: {}", render_status(&status_rx.borrow()));
            if status_rx.changed().await.is_err() {
                return;
            }
        }
    });

    if a.flap {
        let transport = transport.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                println!("flap: network down");
                let _ = transport.on_network_changed(false).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                println!("flap: network up (roaming reset)");
                let _ = transport.on_network_changed(true).await;
            }
        });
    }

    // The engine loop runs on the main task, NOT a spawned one:
    // libsignal's store traits are `async_trait(?Send)`, so the
    // decrypt/encrypt chain is a single-threaded future and
    // `tokio::spawn` (which requires Send) cannot take it. (Clients:
    // drive the engine on one dedicated thread.)
    let mut drops = transport.subscribe_drops();
    let mut upkeep = tokio::time::interval(Duration::from_secs(5));
    upkeep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            drop = drops.recv() => {
                match drop {
                    Ok(drop) => {
                        if let Ok(engine) = core.engine() {
                            let _ = schat_core::pairing::sweep_expired(
                                engine.db.conn(),
                                &transport,
                                std::time::SystemTime::now(),
                            )
                            .await;
                        }
                        match core
                            .ingest_drop(
                                &drop.service_id,
                                drop.frame.intro.as_deref(),
                                &drop.frame.frame,
                            )
                            .await
                        {
                            Ok(DropOutcome::Queued) => {
                                println!("queued: locked, {} at rest", core.queued_drops());
                            }
                            Ok(DropOutcome::Request { rel_id, sas, events }) => {
                                println!("request: rel={rel_id} sas={sas}");
                                print_events(&events);
                            }
                            Ok(DropOutcome::Message { events, .. }) => print_events(&events),
                            Ok(DropOutcome::Duplicate) | Ok(DropOutcome::Dropped) => {}
                            Ok(DropOutcome::SessionBroken { rel_id, reason }) => {
                                println!("session-broken: rel={rel_id} reason={reason}")
                            }
                            Err(e) => eprintln!("ingest error: {e}"),
                        }
                        // The drop is ingested or queued — report the
                        // drain so TransportStatus.inbox stops accruing.
                        transport.note_inbound_drain();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        eprintln!("drop log lagged by {n}")
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            _ = upkeep.tick() => {
                observe_lock_marker(a, &mut core).await;
                if let Ok(engine) = core.engine_mut() {
                    match engine.drain_outbox().await {
                        Ok(n) if n > 0 => println!("outbox: drained {n}"),
                        Err(e) => eprintln!("drain error: {e}"),
                        _ => {}
                    }
                    match engine.sweep().await {
                        Ok(events) => print_events(&events),
                        Err(e) => eprintln!("sweep error: {e}"),
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    transport.stop().await;
    0
}

/// Lock/unlock transitions driven by the marker file (`schat-cli
/// lock` / `unlock` run in their own processes).
async fn observe_lock_marker(a: &Args, core: &mut VaultedEngine) {
    let marker = is_locked(&a.data_dir);
    if marker && !core.is_locked() {
        core.lock();
        println!("locked: store closed, session state dropped; inbound queues at rest");
    } else if !marker && core.is_locked() {
        match load_or_generate_dek(&a.data_dir) {
            Ok(dek) => match core.unlock(dek).await {
                Ok(report) => print_unlock(&report),
                Err(e) => eprintln!("unlock failed: {e} (staying locked)"),
            },
            Err(e) => eprintln!("unlock failed: {e} (staying locked)"),
        }
    }
}

fn print_unlock(report: &schat_core::vault::UnlockReport) {
    if report.drained > 0 || report.errors > 0 {
        println!(
            "unlocked: drained {} queued frame(s), {} error(s)",
            report.drained, report.errors
        );
        print_events(&report.events);
    } else {
        println!("unlocked");
    }
}

fn print_events(events: &[EngineEvent]) {
    for e in events {
        println!("{}", render_event(e));
    }
}
