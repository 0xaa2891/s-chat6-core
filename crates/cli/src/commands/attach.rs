//! Attachment commands: send a file (inline or chunked) and export a
//! received transfer's bytes.

use schat_core::attach::class_for_mime;
use schat_core::media::{sniff, MediaKind};

use crate::args::{hex_id, usage_msg, Args};
use crate::util::{finish, offline_engine, start_engine_or_report};

pub async fn send(a: &Args) -> i32 {
    let rel = a
        .rel
        .clone()
        .unwrap_or_else(|| usage_msg("needs --rel REL_ID"));
    let path = a
        .file
        .clone()
        .unwrap_or_else(|| usage_msg("needs --file PATH"));
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: read {path}: {e}");
            return 1;
        }
    };
    let kind = sniff(&bytes);
    if kind == MediaKind::Reject {
        eprintln!("error: {path}: unrecognized or disallowed media type");
        return 1;
    }
    let mime = format!(
        "{}/{}",
        if kind.as_str() == "mp4" || kind.as_str() == "webm" {
            "video"
        } else {
            "image"
        },
        kind.as_str()
    );
    let ext = std::path::Path::new(&path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_string();

    let Some((mut engine, transport)) = start_engine_or_report(a).await else {
        return 1;
    };
    let caption = a.caption.clone().unwrap_or_default();
    let result = engine
        .send_attachment(
            &rel,
            &schat_core::attach::AttachmentSpec {
                media_class: class_for_mime(&mime),
                mime_hint: mime.clone(),
                orig_ext: ext,
                bytes: bytes.clone(),
                caption,
                view_once: a.view_once,
            },
        )
        .await
        .map(|head| {
            format!(
                "attachment sent (head {}, {} bytes, view_once={})",
                head.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                bytes.len(),
                a.view_once
            )
        })
        .map_err(|e| e.to_string());
    finish(&transport, result).await
}

/// Export a completed transfer's bytes (`--msg-id` is the head id).
pub async fn save(a: &Args) -> i32 {
    let head = hex_id::<16>(
        a.msg_id
            .as_ref()
            .unwrap_or_else(|| usage_msg("needs --msg-id HEAD_ID")),
    );
    let out = a
        .out
        .clone()
        .unwrap_or_else(|| usage_msg("needs --out FILE"));
    let engine = match offline_engine(a) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match engine.attachment_bytes(&head) {
        Ok(Some(bytes)) => {
            if let Err(e) = std::fs::write(&out, &bytes) {
                eprintln!("error: write {out}: {e}");
                return 1;
            }
            println!("wrote {} bytes to {out}", bytes.len());
            0
        }
        Ok(None) => {
            eprintln!("error: no complete attachment {head:02x?} (incomplete, consumed, or gone)");
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}
