//! Chat-policy commands: show the state, propose/accept/decline rule
//! changes, and set capability wants.

use schat_core::policy::{self, PolicyState};

use crate::args::{usage_msg, Args};
use crate::util::{finish, offline_engine, start_engine_or_report};

fn cap_id(name: &str) -> u8 {
    match name {
        "attach" | "attachments" => policy::CAP_ID_ATTACH,
        "emoji" => policy::CAP_ID_EMOJI,
        "presence" => policy::CAP_ID_PRESENCE,
        "typing" => policy::CAP_ID_TYPING,
        "receipts" | "read" => policy::CAP_ID_RECEIPTS,
        _ => usage_msg("unknown cap (attach|emoji|presence|typing|receipts)"),
    }
}

fn render(state: &PolicyState) -> String {
    let pending = match &state.pending {
        Some(p) => format!(
            "pending({} ttl={} screenshot={} attach_download={})",
            if p.inbound { "theirs" } else { "ours" },
            p.ttl_sec,
            p.screenshot,
            p.attach_download
        ),
        None => "none".into(),
    };
    format!(
        "ttl={} screenshot={} attach_download={} enforced[attach={} emoji={} presence={} typing={} receipts={}] {pending}",
        state.ttl_sec,
        state.screenshot,
        state.attach_download,
        state.attachments(),
        state.emoji(),
        state.presence(),
        state.typing(),
        state.receipts(),
    )
}

pub async fn run(a: &Args) -> i32 {
    let rel = a
        .rel
        .clone()
        .unwrap_or_else(|| usage_msg("needs --rel REL_ID"));

    if a.show {
        let engine = match offline_engine(a) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        return match engine.chat_policy(&rel) {
            Ok(state) => {
                println!("{}", render(&state));
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
    }

    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };

    let result = if a.propose {
        let ttl = a
            .ttl
            .unwrap_or_else(|| usage_msg("--propose needs --ttl SEC"));
        let screenshot = a
            .screenshot
            .unwrap_or_else(|| usage_msg("--propose needs --screenshot on|off"));
        let attach_dl = a
            .attach_download
            .unwrap_or_else(|| usage_msg("--propose needs --attach-download on|off"));
        engine
            .propose_rules(&rel, ttl, screenshot, attach_dl)
            .await
            .map(|()| "proposal sent".to_string())
            .map_err(|e| e.to_string())
    } else if a.accept_rules {
        engine
            .accept_rules(&rel)
            .await
            .map(|_| "proposal accepted".to_string())
            .map_err(|e| e.to_string())
    } else if a.decline {
        engine
            .decline_rules(&rel)
            .map(|()| "proposal declined".to_string())
            .map_err(|e| e.to_string())
    } else if let Some(cap) = &a.cap {
        let on = match (a.on, a.off) {
            (true, false) => true,
            (false, true) => false,
            _ => usage_msg("--cap needs --on or --off"),
        };
        engine
            .set_capability(&rel, cap_id(cap), on)
            .await
            .map(|_| format!("cap {cap} set to {on}"))
            .map_err(|e| e.to_string())
    } else {
        usage_msg("policy needs --show / --propose / --accept-rules / --decline / --cap");
    };
    finish(&transport, result).await
}
