//! Sticker commands: create a signed pack from image files, list
//! installed packs, send an item, fetch a pack from a peer, remove one.

use schat_core::media::prepare_sticker;
use schat_core::stickers::packs;
use schat_core::util::sha256;
use schat_core::wire_types::sticker::{limits, PackDocItem};

use crate::args::{hex_id, usage_msg, Args};
use crate::util::{finish, offline_engine, start_engine_or_report};

fn parse_kind(v: Option<&String>) -> u8 {
    match v.map(|s| s.as_str()) {
        None | Some("emoji") => limits::KIND_EMOJI,
        Some("sticker") => limits::KIND_STICKER,
        _ => usage_msg("--kind emoji|sticker"),
    }
}

fn parse_visibility(v: Option<&String>) -> u8 {
    match v.map(|s| s.as_str()) {
        None | Some("public") => limits::VISIBILITY_PUBLIC,
        Some("private") => limits::VISIBILITY_PRIVATE,
        _ => usage_msg("--visibility public|private"),
    }
}

fn hex_str(id: &[u8]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub async fn run(a: &Args) -> i32 {
    if a.create {
        return create(a);
    }
    if a.list {
        let engine = match offline_engine(a) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        return match packs::list_packs(&engine.db) {
            Ok(packs) => {
                if packs.is_empty() {
                    println!("no packs installed");
                }
                for p in packs {
                    println!(
                        "pack={} title={} kind={} items={} cached={}",
                        hex_str(&p.pack_id),
                        p.title,
                        p.kind,
                        p.item_count,
                        p.cached
                    );
                }
                0
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
    }
    if a.remove {
        let pack_id = hex_id::<16>(
            a.pack
                .as_ref()
                .unwrap_or_else(|| usage_msg("needs --pack ID")),
        );
        let engine = match offline_engine(a) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("error: {e}");
                return 1;
            }
        };
        let mut engine = engine;
        return match engine.remove_pack(&pack_id) {
            Ok(true) => {
                println!("pack removed");
                0
            }
            Ok(false) => {
                eprintln!("error: no such pack");
                1
            }
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
    }

    // Online operations.
    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let result = if a.send {
        let rel = a
            .rel
            .clone()
            .unwrap_or_else(|| usage_msg("--send needs --rel REL_ID"));
        let pack_id = hex_id::<16>(
            a.pack
                .as_ref()
                .unwrap_or_else(|| usage_msg("--send needs --pack ID")),
        );
        let item = a.item.unwrap_or_else(|| usage_msg("--send needs --item N"));
        engine
            .send_sticker(&rel, &pack_id, item)
            .await
            .map(|id| format!("sticker sent (id {})", hex_str(&id)))
            .map_err(|e| e.to_string())
    } else if a.fetch {
        let rel = a
            .rel
            .clone()
            .unwrap_or_else(|| usage_msg("--fetch needs --rel REL_ID"));
        let pack_id = hex_id::<16>(
            a.pack
                .as_ref()
                .unwrap_or_else(|| usage_msg("--fetch needs --pack ID")),
        );
        let pk = hex_id::<32>(
            a.pk.as_ref()
                .unwrap_or_else(|| usage_msg("--fetch needs --pk HEX")),
        );
        engine
            .fetch_pack(&rel, &pack_id, &pk)
            .await
            .map(|()| "pack fetch requested (watch the daemon log)".to_string())
            .map_err(|e| e.to_string())
    } else {
        usage_msg("sticker needs --create / --list / --send / --fetch / --remove");
    };
    finish(&transport, result).await
}

/// Create + sign a pack from image files (media prep runs locally —
/// the core-first rule: no Android involved).
fn create(a: &Args) -> i32 {
    let title = a
        .title
        .clone()
        .unwrap_or_else(|| usage_msg("--create needs --title T"));
    let files = a
        .files
        .clone()
        .unwrap_or_else(|| usage_msg("--create needs --files A,B,.."));
    let kind = parse_kind(a.kind.as_ref());
    let visibility = parse_visibility(a.visibility.as_ref());

    let mut items = Vec::new();
    for (i, path) in files.split(',').enumerate() {
        let raw = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("error: read {path}: {e}");
                return 1;
            }
        };
        let prepared = match prepare_sticker(&raw, kind) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: prepare {path}: {e}");
                return 1;
            }
        };
        items.push(PackDocItem {
            item_id: (i + 1) as u16,
            w: prepared.width as u16,
            h: prepared.height as u16,
            sha256: sha256(&prepared.bytes),
            bytes: prepared.bytes,
        });
    }

    let engine = match offline_engine(a) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let mut engine = engine;
    match engine.create_pack(&title, kind, visibility, 1, items) {
        Ok((pack_id, pack_pk)) => {
            println!(
                "pack created: id={} pk={}",
                hex_str(&pack_id),
                hex_str(&pack_pk)
            );
            0
        }
        Err(e) => {
            eprintln!("error: create pack: {e}");
            1
        }
    }
}
