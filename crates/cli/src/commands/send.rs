//! `schat-cli send`: one-shot send, either raw (`--to ONION`) or
//! session-encrypted (`--rel REL_ID`).

use std::time::Duration;

use schat_core::transport::Transport;

use crate::args::{usage_msg, Args};
use crate::util::{make_daemon, open_cli_db, text_record, wait_online};

pub async fn run(a: &Args) -> i32 {
    let transport = Transport::new(&a.data_dir);
    transport
        .set_daemon(make_daemon(&a.data_dir, a.chutney_nodes.as_ref()))
        .await;
    if let Err(e) = transport.start().await {
        eprintln!("error: start: {e}");
        return 1;
    }
    if !wait_online(&transport, Duration::from_secs(120)).await {
        eprintln!("error: tor did not come online in 120 s");
        transport.stop().await;
        return 1;
    }

    let result = if let Some(rel_id) = &a.rel {
        // A real MSG envelope through the engine (ledgered,
        // outboxed, resync-able). The daemon drains what we can't send.
        let db = match open_cli_db(&a.data_dir) {
            Ok(db) => db,
            Err(e) => {
                eprintln!("error: {e}");
                transport.stop().await;
                return 1;
            }
        };
        let mut engine = schat_core::engine::Engine::new(db, transport.clone());
        engine
            .send_text(rel_id, a.text.as_deref().unwrap_or("ping"), None)
            .await
            .map(|id| {
                format!(
                    "sent to relationship {rel_id} (msg_id {})",
                    id.iter().map(|b| format!("{b:02x}")).collect::<String>()
                )
            })
            .map_err(|e| e.to_string())
    } else if let Some(dest) = &a.to {
        let record = text_record(a.text.as_deref().unwrap_or("ping"));
        transport
            .send_frame(dest, &record, a.alert)
            .await
            .map(|()| format!("transmitted to {dest}"))
            .map_err(|e| e.to_string())
    } else {
        usage_msg("send needs --to ONION or --rel REL_ID");
    };

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
            eprintln!("error: send: {e}");
            transport.stop().await;
            1
        }
    }
}
