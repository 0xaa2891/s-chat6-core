//! Bounds tests: for every wire cap in `limits`, the
//! at-limit value passes and one over fails — on construction/encode
//! and on decode. All caps are declared in `schat_wire_types::limits`
//! and re-exported by the feature modules; these tests import through
//! the catalog to pin that down.

use schat_wire_types::attach::{AttachChunk, AttachHead, AttachHeadPayload, CLASS_IMAGE};
use schat_wire_types::bin::Writer;
use schat_wire_types::edit::Edit;
use schat_wire_types::envelope::{Envelope, Payload};
use schat_wire_types::limits;
use schat_wire_types::msg::Msg;
use schat_wire_types::pref::Pref;
use schat_wire_types::profile::{name_ok, Profile};
use schat_wire_types::resync::ResyncReq;
use schat_wire_types::WirePayload;

fn msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn head(chunk_count: u16) -> AttachHead {
    AttachHead {
        media_class: CLASS_IMAGE,
        mime_hint: "image/jpeg".into(),
        orig_ext: "jpg".into(),
        uncompressed_n: 100_000,
        chunk_count,
        chunk_bucket: chunk_count,
        content_sha256: [0x33; 32],
        caption: String::new(),
        flags: 0,
    }
}

fn encode_head(h: &AttachHead) -> Result<Vec<u8>, schat_wire_types::WireError> {
    AttachHeadPayload {
        head: h.clone(),
        inline: None,
    }
    .encode_payload()
}

#[test]
fn msg_body_at_limit_ok_over_fails() {
    let max = limits::msg::MAX_BODY_BYTES;
    assert!(Msg::new("x".repeat(max)).is_ok());
    assert!(Msg::new("x".repeat(max + 1)).is_err());
    // Construction-bypassing values are still refused at encode.
    let m = Msg {
        body: "x".repeat(max + 1),
    };
    assert!(m.encode_payload().is_err());
    // And at decode (the anti-abuse boundary): MSG is raw UTF-8.
    assert!(Msg::decode_payload(&vec![b'x'; max + 1]).is_err());
    assert!(Msg::decode_payload(&vec![b'x'; max]).is_ok());
    // EDIT shares the body cap.
    assert!(Edit::new("x".repeat(max)).is_ok());
    assert!(Edit::new("x".repeat(max + 1)).is_err());
}

#[test]
fn profile_fields_at_limit_ok_over_fails() {
    let name_max = limits::profile::MAX_NAME_BYTES;
    assert!(name_ok(&"n".repeat(name_max)));
    assert!(!name_ok(&"n".repeat(name_max + 1)));

    let jpeg_max = limits::profile::MAX_JPEG;
    let mut jpeg = vec![0xff, 0xd8, 0xff];
    jpeg.resize(jpeg_max, 0);
    let ok = Profile {
        name: "n".into(),
        jpeg: jpeg.clone(),
    };
    assert!(ok.encode_payload().is_ok());
    let mut over_jpeg = vec![0xff, 0xd8, 0xff];
    over_jpeg.resize(jpeg_max + 1, 0);
    let over = Profile {
        name: "n".into(),
        jpeg: over_jpeg,
    };
    assert!(over.encode_payload().is_err());

    // Decode side: lp caps refuse over-long fields before allocation.
    let mut w = Writer::new();
    w.u8(1);
    w.lp("n".repeat(name_max + 1).as_bytes());
    w.lp(&jpeg);
    assert!(Profile::decode_payload(&w.finish()).is_err());
    let mut w = Writer::new();
    w.u8(1);
    w.lp(b"n");
    w.lp(&vec![0u8; jpeg_max + 1]);
    assert!(Profile::decode_payload(&w.finish()).is_err());
}

#[test]
fn attach_head_fields_at_limit_ok_over_fails() {
    let mut h = head(limits::attach::MAX_CHUNKS);
    h.chunk_bucket = limits::attach::MAX_CHUNKS;
    assert!(encode_head(&h).is_ok(), "chunk_count at limit");
    let over = head(limits::attach::MAX_CHUNKS + 1);
    assert!(encode_head(&over).is_err(), "chunk_count over limit");

    let mut h = head(1);
    h.uncompressed_n = limits::attach::MAX_ATTACH;
    assert!(encode_head(&h).is_ok(), "uncompressed_n at limit");
    h.uncompressed_n = limits::attach::MAX_ATTACH + 1;
    assert!(encode_head(&h).is_err(), "uncompressed_n over limit");

    let mut h = head(1);
    h.orig_ext = "e".repeat(limits::attach::MAX_EXT);
    assert!(encode_head(&h).is_ok(), "ext at limit");
    h.orig_ext = "e".repeat(limits::attach::MAX_EXT + 1);
    assert!(encode_head(&h).is_err(), "ext over limit");

    let mut h = head(1);
    h.mime_hint = "m".repeat(limits::attach::MAX_MIME);
    assert!(encode_head(&h).is_ok(), "mime at limit");
    h.mime_hint = "m".repeat(limits::attach::MAX_MIME + 1);
    assert!(encode_head(&h).is_err(), "mime over limit");

    let mut h = head(1);
    h.caption = "c".repeat(limits::attach::MAX_CAPTION);
    assert!(encode_head(&h).is_ok(), "caption at limit");
    h.caption = "c".repeat(limits::attach::MAX_CAPTION + 1);
    assert!(encode_head(&h).is_err(), "caption over limit");
}

#[test]
fn attach_chunk_data_at_limit_ok_over_fails() {
    let at = AttachChunk {
        head_id: msg_id(3),
        index: 0,
        pad: false,
        data: vec![0u8; limits::attach::CHUNK_DATA_MAX],
    };
    let bytes = at.encode_payload().unwrap();
    assert!(AttachChunk::decode_payload(&bytes).is_ok());

    let over = AttachChunk {
        data: vec![0u8; limits::attach::CHUNK_DATA_MAX + 1],
        ..at.clone()
    };
    assert!(over.encode_payload().is_err());
    // Decode side: lp cap refuses before allocation.
    let mut w = Writer::new();
    w.u8(1);
    w.raw(&msg_id(3));
    w.u16be(0);
    w.u8(0);
    w.lp(&vec![0u8; limits::attach::CHUNK_DATA_MAX + 1]);
    assert!(AttachChunk::decode_payload(&w.finish()).is_err());
}

#[test]
fn pref_erase_hours_at_limit_ok_over_fails() {
    let at = Pref {
        receive_media: true,
        listen_saver: false,
        inactivity_erase_hours: limits::pref::MAX_ERASE_HOURS,
    };
    let bytes = at.encode_payload().unwrap();
    assert_eq!(Pref::decode_payload(&bytes).unwrap(), at);

    let over = Pref {
        inactivity_erase_hours: limits::pref::MAX_ERASE_HOURS + 1,
        ..at
    };
    assert!(over.encode_payload().is_err());
    // Decode side.
    let mut w = Writer::new();
    w.u8(1);
    w.u32be(0);
    w.u32be(limits::pref::MAX_ERASE_HOURS + 1);
    assert!(Pref::decode_payload(&w.finish()).is_err());
}

#[test]
fn resync_bitmap_at_limit_ok_over_fails() {
    let at = ResyncReq {
        max_contiguous_seq: 7,
        received_seq_bitmap: vec![0xa5u8; limits::resync::MAX_BITMAP_BYTES],
        caps: 0,
        history_hash: [0u8; 32],
    };
    let bytes = at.encode_payload().unwrap();
    assert!(ResyncReq::decode_payload(&bytes).is_ok());

    let over = ResyncReq {
        received_seq_bitmap: vec![0xa5u8; limits::resync::MAX_BITMAP_BYTES + 1],
        ..at.clone()
    };
    assert!(over.encode_payload().is_err());
}

#[test]
fn envelope_total_at_limit_ok_over_fails() {
    // The MSG body cap (16 KiB) is far below the envelope ceiling, so
    // approach the ceiling with an inline attachment head instead.
    // Solve for the inline size that lands the encoded envelope exactly
    // on the cap: measure the fixed overhead with a 1-byte inline.
    let head_for = |n: usize| AttachHead {
        media_class: CLASS_IMAGE,
        mime_hint: "image/jpeg".into(),
        orig_ext: "jpg".into(),
        uncompressed_n: n as u32,
        chunk_count: 0,
        chunk_bucket: 0,
        content_sha256: [0x33; 32],
        caption: String::new(),
        flags: 0,
    };
    let env_for = |n: usize| Envelope {
        msg_id: msg_id(1),
        app_seq: 1,
        sent_at: 1,
        ref_id: None,
        payload: Payload::AttachHead(AttachHeadPayload {
            head: head_for(n),
            inline: Some(vec![0u8; n]),
        }),
    };
    let overhead = env_for(1).encode().unwrap().len() - 1;
    let n = limits::envelope::MAX_ENVELOPE_BYTES - overhead;
    let bytes = env_for(n).encode().unwrap();
    assert_eq!(bytes.len(), limits::envelope::MAX_ENVELOPE_BYTES);
    assert!(
        Envelope::decode(&bytes).is_ok(),
        "at-limit envelope decodes"
    );
    assert!(
        env_for(n + 1).encode().is_err(),
        "one over the ceiling refused"
    );
}

#[test]
fn sticker_item_bounds_at_limit_ok_over_fails() {
    use limits::sticker::*;
    // Emoji: exactly square, at edge/byte caps.
    assert!(item_ok(
        KIND_EMOJI,
        MAX_EDGE_EMOJI,
        MAX_EDGE_EMOJI,
        MAX_BYTES_EMOJI
    ));
    assert!(!item_ok(KIND_EMOJI, MAX_EDGE_EMOJI + 1, MAX_EDGE_EMOJI, 1));
    assert!(!item_ok(KIND_EMOJI, 100, 100, MAX_BYTES_EMOJI + 1));
    assert!(!item_ok(KIND_EMOJI, 100, 101, 1024), "emoji must be square");
    // Sticker: 1:3..3:1 aspect, at edge/byte caps.
    assert!(item_ok(
        KIND_STICKER,
        MAX_EDGE_STICKER,
        MAX_EDGE_STICKER,
        MAX_BYTES_STICKER
    ));
    assert!(item_ok(KIND_STICKER, 480, 160, 1024), "exactly 3:1 passes");
    assert!(!item_ok(KIND_STICKER, MAX_EDGE_STICKER + 1, 100, 1024));
    assert!(!item_ok(KIND_STICKER, 100, 100, MAX_BYTES_STICKER + 1));
    assert!(!item_ok(KIND_STICKER, 400, 100, 1024), "aspect beyond 3:1");
    assert!(!item_ok(9, 100, 100, 1024), "unknown kind refused");
    assert!(!item_ok(KIND_EMOJI, 0, 0, 0), "zero dimensions refused");
}
