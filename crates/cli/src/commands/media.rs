//! Media preparation commands — the core-first litmus (no Android
//! involved): sniff, EXIF strip + re-encode, sticker prep.

use schat_core::media::{prepare_sticker, sniff, strip_and_reencode_image};
use schat_core::wire_types::sticker::limits;

use crate::args::{usage_msg, Args};

fn read_file(a: &Args) -> Result<(String, Vec<u8>), i32> {
    let file = a
        .file
        .clone()
        .unwrap_or_else(|| usage_msg("needs --file PATH"));
    match std::fs::read(&file) {
        Ok(b) => Ok((file, b)),
        Err(e) => {
            eprintln!("error: read {file}: {e}");
            Err(1)
        }
    }
}

/// `schat-cli media-sniff --file PATH`
pub fn sniff_cmd(a: &Args) -> i32 {
    let (file, bytes) = match read_file(a) {
        Ok(v) => v,
        Err(c) => return c,
    };
    println!("{file}: {} ({} bytes)", sniff(&bytes).as_str(), bytes.len());
    0
}

/// `schat-cli media-strip --file PATH --out FILE` (EXIF + metadata gone)
pub fn strip_cmd(a: &Args) -> i32 {
    let (file, bytes) = match read_file(a) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let out = a
        .out
        .clone()
        .unwrap_or_else(|| usage_msg("needs --out FILE"));
    match strip_and_reencode_image(&bytes) {
        Ok(clean) => {
            if let Err(e) = std::fs::write(&out, &clean) {
                eprintln!("error: write {out}: {e}");
                return 1;
            }
            println!(
                "{file}: stripped + re-encoded {} → {} bytes → {out}",
                bytes.len(),
                clean.len()
            );
            0
        }
        Err(e) => {
            eprintln!("error: strip: {e}");
            1
        }
    }
}

/// `schat-cli media-prepare-sticker --file PATH [--kind sticker|emoji] [--out FILE]`
pub fn prepare_cmd(a: &Args) -> i32 {
    let (file, bytes) = match read_file(a) {
        Ok(v) => v,
        Err(c) => return c,
    };
    let kind = match a.kind.as_deref() {
        None | Some("sticker") => limits::KIND_STICKER,
        Some("emoji") => limits::KIND_EMOJI,
        _ => usage_msg("--kind sticker|emoji"),
    };
    match prepare_sticker(&bytes, kind) {
        Ok(p) => {
            println!(
                "{file}: prepared {}x{} item={} bytes thumb={} bytes",
                p.width,
                p.height,
                p.bytes.len(),
                p.thumb.len()
            );
            if let Some(out) = &a.out {
                if let Err(e) = std::fs::write(out, &p.bytes) {
                    eprintln!("error: write {out}: {e}");
                    return 1;
                }
                println!("wrote {out}");
            }
            0
        }
        Err(e) => {
            eprintln!("error: prepare: {e}");
            1
        }
    }
}
