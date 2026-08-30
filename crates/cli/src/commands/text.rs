//! Text-message commands: edit, delete, read receipts, typing,
//! presence broadcast, and the rendered thread view.

use schat_core::pairing;
use schat_core::store::messages::MessagesRepository;

use crate::args::{hex_id, usage_msg, Args};
use crate::util::{finish, offline_engine, start_engine_or_report};

fn rel(a: &Args) -> &String {
    a.rel
        .as_ref()
        .unwrap_or_else(|| usage_msg("needs --rel REL_ID"))
}

fn target(a: &Args) -> [u8; 16] {
    hex_id(
        a.msg_id
            .as_ref()
            .unwrap_or_else(|| usage_msg("needs --msg-id ID")),
    )
}

pub async fn edit(a: &Args) -> i32 {
    let text = a
        .text
        .clone()
        .unwrap_or_else(|| usage_msg("needs --text TEXT"));
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = engine
        .send_edit(rel(a), &target(a), &text)
        .await
        .map(|id| format!("edited (edit id {})", hex_id_str(&id)))
        .map_err(|e| e.to_string());
    finish(&transport, result).await
}

pub async fn delete(a: &Args) -> i32 {
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = engine
        .send_delete(rel(a), &target(a))
        .await
        .map(|id| format!("deleted (delete id {})", hex_id_str(&id)))
        .map_err(|e| e.to_string());
    finish(&transport, result).await
}

pub async fn read(a: &Args) -> i32 {
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = engine
        .send_read(rel(a), &target(a))
        .await
        .map(|()| "read receipt sent".to_string())
        .map_err(|e| e.to_string());
    finish(&transport, result).await
}

pub async fn typing(a: &Args) -> i32 {
    let typing = on_off(a);
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = engine
        .send_typing(rel(a), typing)
        .await
        .map(|()| format!("typing={typing} sent"))
        .map_err(|e| e.to_string());
    finish(&transport, result).await
}

/// Presence is per-relationship on the wire; the CLI broadcasts to
/// every active relationship.
pub async fn presence(a: &Args) -> i32 {
    let in_app = on_off(a);
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = async {
        let rels = pairing::relationship::list_relationships(engine.db.conn())
            .map_err(|e| e.to_string())?;
        let mut sent = 0u32;
        for r in rels.iter().filter(|r| r.state == "active") {
            engine
                .send_presence(&r.rel_id, in_app, a.dnd)
                .await
                .map_err(|e| e.to_string())?;
            sent += 1;
        }
        Ok(format!(
            "presence in_app={in_app} dnd={} → {sent} peers",
            a.dnd
        ))
    }
    .await;
    finish(&transport, result).await
}

/// Render the visible thread (content + system lines, oldest first).
pub async fn thread(a: &Args) -> i32 {
    let engine = match offline_engine(a) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match engine.db.thread_visible(rel(a), 200, None) {
        Ok(rows) => {
            for row in rows.iter().rev() {
                let dir = if row.direction.as_str() == "out" {
                    "→"
                } else {
                    "←"
                };
                let body = String::from_utf8_lossy(&row.payload);
                let flags = [
                    row.edited.then_some("edited"),
                    row.tombstone.then_some("tombstone"),
                    row.read_at.is_some().then_some("read"),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(",");
                println!(
                    "{} seq={} id={} type={} state={} {}{}",
                    dir,
                    row.app_seq,
                    hex_id_str(&row.msg_id),
                    row.env_type,
                    row.state.as_str(),
                    body,
                    if flags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{flags}]")
                    },
                );
            }
            0
        }
        Err(e) => {
            eprintln!("error: thread: {e}");
            1
        }
    }
}

fn on_off(a: &Args) -> bool {
    match (a.on, a.off) {
        (true, false) => true,
        (false, true) => false,
        _ => usage_msg("needs --on or --off"),
    }
}

fn hex_id_str(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}
