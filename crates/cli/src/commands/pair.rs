//! `schat-cli pair`: the pairing ceremony. Offer/accept are
//! offline operations (the invitation service publishes when a daemon
//! next attaches); --accept-request re-hosts the inviter's service restricted,
//! also fine offline.

use std::time::SystemTime;

use schat_core::pairing;
use schat_core::transport::Transport;

use crate::args::{usage_msg, Args};
use crate::util::open_cli_db;

pub async fn run(a: &Args) -> i32 {
    let db = match open_cli_db(&a.data_dir) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let transport = Transport::new(&a.data_dir);
    let now = SystemTime::now();

    if a.offer {
        return match pairing::offer(db.conn(), &transport, now).await {
            Ok(offer) => {
                println!("onion: {}", offer.onion);
                println!("expires_at: {}", offer.expires_at);
                println!("code: {}", offer.code);
                if let Some(out) = &a.out {
                    if let Err(e) = std::fs::write(out, &offer.qr_bytes) {
                        eprintln!("error: write {out}: {e}");
                        return 1;
                    }
                    println!("qr-bytes: written to {out}");
                }
                0
            }
            Err(e) => {
                eprintln!("error: offer: {e}");
                1
            }
        };
    }

    if a.accept.is_some() || a.code.is_some() {
        let result = match (&a.accept, &a.code) {
            (Some(path), None) => match std::fs::read(path) {
                Ok(bytes) => pairing::accept(db.conn(), &transport, &bytes, now).await,
                Err(e) => {
                    eprintln!("error: read {path}: {e}");
                    return 1;
                }
            },
            (None, Some(code)) => pairing::accept_code(db.conn(), &transport, code, now).await,
            _ => usage_msg("use either --accept FILE or --code CODE, not both"),
        };
        return match result {
            Ok(accepted) => {
                println!("rel_id: {}", accepted.rel_id);
                println!("peer_onion: {}", accepted.peer_onion);
                println!("onion: {}", accepted.onion);
                println!("safety: {}", accepted.sas);
                0
            }
            Err(e) => {
                eprintln!("error: accept: {e}");
                1
            }
        };
    }

    if a.requests {
        return match pairing::pending_requests(db.conn()) {
            Ok(requests) => {
                if requests.is_empty() {
                    println!("no pending requests");
                }
                for r in requests {
                    println!(
                        "request: rel_id={} safety={} peer={} created_at={}",
                        r.rel_id, r.sas, r.peer_onion, r.created_at
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("error: requests: {e}");
                1
            }
        };
    }

    if a.accept_request {
        let rel_id = match &a.rel {
            Some(rel) => rel.clone(),
            None => match pairing::pending_requests(db.conn()) {
                Ok(mut requests) if requests.len() == 1 => requests.remove(0).rel_id,
                Ok(_) => {
                    eprintln!("error: ambiguous — pass --rel REL_ID (see --requests)");
                    return 1;
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            },
        };
        let mut engine = schat_core::engine::Engine::new(db, transport.clone());
        return match engine.accept_request(&rel_id).await {
            Ok(()) => {
                println!("accepted: {rel_id}");
                0
            }
            Err(e) => {
                eprintln!("error: accept-request: {e}");
                1
            }
        };
    }

    if a.abort {
        return match pairing::abort_offer(db.conn(), &transport).await {
            Ok(()) => {
                println!("offer aborted");
                0
            }
            Err(e) => {
                eprintln!("error: abort: {e}");
                1
            }
        };
    }

    usage_msg(
        "pair needs one of --offer / --accept / --code / --accept-request / --requests / --abort",
    )
}
