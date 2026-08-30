//! `schat-cli` — the only UI until CORE DONE. Every core capability lands
//! here the same week it lands in the library.
//!
//! Core commands:
//!   schat-cli ping
//!   schat-cli daemon --data-dir DIR [--chutney-nodes DIR] [--simulate-network-flap]
//!                    [--mode fast|normal|saver] [--restricted]
//!   schat-cli send   --data-dir DIR --to ONION [--chutney-nodes DIR] [--text TEXT] [--alert]
//!   schat-cli status --data-dir DIR [--chutney-nodes DIR] [--once]
//!
//! Pairing commands (one-way pairing: only the accepter scans/pastes):
//!   schat-cli pair --data-dir DIR --offer [--out FILE]
//!   schat-cli pair --data-dir DIR (--accept FILE | --code CODE)
//!   schat-cli pair --data-dir DIR --accept-request [--rel REL_ID]
//!   schat-cli pair --data-dir DIR --requests
//!   schat-cli pair --data-dir DIR --abort
//!   schat-cli send --data-dir DIR --rel REL_ID [--text TEXT] [--msg-id ID] [--alert]
//!
//! Vault commands (the daemon observes the marker within ~5 s):
//!   schat-cli lock --data-dir DIR
//!   schat-cli unlock --data-dir DIR [--dek-file PATH]
//!   schat-cli panic-wipe --data-dir DIR
//!   schat-cli sweep-expired --data-dir DIR

mod args;
mod commands;
mod util;

use std::process;

use args::{parse_args, usage};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    // Transport diagnostics go to stderr (RUST_LOG=info,schat_core=debug);
    // stdout stays machine-readable for the status/drop lines.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let args = parse_args();
    let code = match args.cmd.as_str() {
        "ping" => {
            println!("{}", schat_core::ping());
            0
        }
        "daemon" => commands::daemon::run(&args).await,
        "send" => commands::send::run(&args).await,
        "status" => commands::status::run(&args).await,
        "pair" => commands::pair::run(&args).await,
        // Feature commands.
        "edit" => commands::text::edit(&args).await,
        "delete" => commands::text::delete(&args).await,
        "read" => commands::text::read(&args).await,
        "typing" => commands::text::typing(&args).await,
        "presence" => commands::text::presence(&args).await,
        "thread" => commands::text::thread(&args).await,
        "attach" => commands::attach::send(&args).await,
        "attach-save" => commands::attach::save(&args).await,
        "profile" => commands::profile::run(&args).await,
        "policy" => commands::policy::run(&args).await,
        "sticker" => commands::stickers::run(&args).await,
        "close" => commands::close::run(&args).await,
        // Vault.
        "lock" => commands::vault::lock(&args),
        "unlock" => commands::vault::unlock(&args),
        "panic-wipe" => commands::vault::panic_wipe(&args),
        "sweep-expired" => commands::vault::sweep_expired(&args).await,
        "media-sniff" => commands::media::sniff_cmd(&args),
        "media-strip" => commands::media::strip_cmd(&args),
        "media-prepare-sticker" => commands::media::prepare_cmd(&args),
        _ => usage(2),
    };
    process::exit(code);
}
