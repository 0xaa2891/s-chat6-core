//! Profile commands: set our name/avatar, show profiles, broadcast an
//! update, request a peer's profile.

use schat_core::profile;
use schat_core::store::profiles::ProfilesRepository;

use crate::args::{usage_msg, Args};
use crate::util::{finish, offline_engine, start_engine_or_report};

pub async fn run(a: &Args) -> i32 {
    if a.set {
        let name = a
            .name
            .clone()
            .unwrap_or_else(|| usage_msg("--set needs --name NAME"));
        let jpeg = match &a.jpeg {
            Some(path) => match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: read {path}: {e}");
                    return 1;
                }
            },
            None => Vec::new(),
        };
        let engine = match offline_engine(a) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        return match profile::set_our_profile(&engine.db, &name, &jpeg) {
            Ok(()) => {
                println!("profile set: name={name} jpeg={} bytes", jpeg.len());
                0
            }
            Err(e) => {
                eprintln!("error: set profile: {e}");
                1
            }
        };
    }

    if a.show {
        let engine = match offline_engine(a) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        return match &a.rel {
            Some(rel) => match engine.db.profile(rel) {
                Ok(Some(p)) => {
                    println!("peer {rel}: name={} jpeg={} bytes", p.name, p.jpeg.len());
                    0
                }
                Ok(None) => {
                    println!("peer {rel}: no profile yet");
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            },
            None => match profile::our_profile(&engine.db) {
                Ok(p) => {
                    println!("our profile: name={} jpeg={} bytes", p.name, p.jpeg.len());
                    0
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    1
                }
            },
        };
    }

    if a.broadcast {
        let Some((mut engine, transport)) = start_engine_or_report(a).await else {
            return 1;
        };
        let result = engine
            .broadcast_profile()
            .await
            .map(|n| format!("profile broadcast to {n} peers"))
            .map_err(|e| e.to_string());
        return finish(&transport, result).await;
    }

    if a.request {
        let rel = a
            .rel
            .clone()
            .unwrap_or_else(|| usage_msg("--request needs --rel REL_ID"));
        let Some((mut engine, transport)) = start_engine_or_report(a).await else {
            return 1;
        };
        let result = engine
            .send_profile_req(&rel)
            .await
            .map(|()| format!("profile requested from {rel}"))
            .map_err(|e| e.to_string());
        return finish(&transport, result).await;
    }

    usage_msg("profile needs one of --set / --show / --broadcast / --request")
}
