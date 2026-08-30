//! Golden vectors: hand-computed expected bytes for every envelope type.
//! If a future refactor silently changes the wire, this test fails — the
//! bytes below are the spec, not the encoder's output.

use schat_wire_types::attach::{AttachChunk, AttachHead, AttachHeadPayload, CLASS_IMAGE};
use schat_wire_types::caps;
use schat_wire_types::contact::ContactClose;
use schat_wire_types::delete::{Delete, DeleteAll};
use schat_wire_types::edit::Edit;
use schat_wire_types::envelope::{Envelope, Payload};
use schat_wire_types::msg::Msg;
use schat_wire_types::policy::{self, ChatPolicy};
use schat_wire_types::pref::Pref;
use schat_wire_types::presence::Presence;
use schat_wire_types::profile::{Profile, ProfileReq};
use schat_wire_types::read::Read;
use schat_wire_types::resync::ResyncReq;
use schat_wire_types::sticker::{StickerCtrl, StickerItem};
use schat_wire_types::typing::Typing;

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 0xf) as usize] as char);
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// msg_id 00 01 02 … 0f, app_seq 1, sent_at 1 700 000 000, no ref.
const HDR: &str = concat!(
    "000102030405060708090a0b0c0d0e0f", // msg_id
    "0000000000000001",                 // app_seq = 1
    "000000006553f100",                 // sent_at = 1_700_000_000
    "00",                               // ref_len = 0
);

fn golden(payload: Payload, expected_hex: &str) {
    let env = Envelope {
        msg_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        app_seq: 1,
        sent_at: 1_700_000_000,
        ref_id: None,
        payload,
    };
    let encoded = env.encode().unwrap();
    assert_eq!(hex(&encoded), expected_hex, "encode mismatch");
    let decoded = Envelope::decode(&unhex(expected_hex)).unwrap();
    assert_eq!(decoded, env, "decode mismatch");
}

#[test]
fn msg_golden() {
    // type=01 ‖ hdr ‖ lp("hi")
    golden(
        Payload::Msg(Msg::new("hi".into()).unwrap()),
        &format!("01{HDR}000000026869"),
    );
}

#[test]
fn edit_golden() {
    // type=02 ‖ hdr ‖ lp("ok")
    golden(
        Payload::Edit(Edit::new("ok".into()).unwrap()),
        &format!("02{HDR}000000026f6b"),
    );
}

#[test]
fn delete_golden() {
    // type=03 ‖ hdr ‖ lp(empty)
    golden(Payload::Delete(Delete), &format!("03{HDR}00000000"));
}

#[test]
fn delete_all_golden() {
    golden(Payload::DeleteAll(DeleteAll), &format!("04{HDR}00000000"));
}

#[test]
fn resync_req_golden() {
    // payload: u64 42 ‖ lp bitmap [0x05] ‖ u32 caps=0x7f (LOCAL) ‖ 32×0xaa
    let payload_hex = format!("000000000000002a00000001050000007f{}", "aa".repeat(32));
    golden(
        Payload::ResyncReq(ResyncReq {
            max_contiguous_seq: 42,
            received_seq_bitmap: vec![0x05],
            caps: caps::LOCAL,
            history_hash: [0xaa; 32],
        }),
        &format!("05{HDR}{:08x}{}", payload_hex.len() / 2, payload_hex),
    );
}

#[test]
fn attach_head_chunked_golden() {
    // payload: v=1 ‖ class=1 ‖ lp "image/jpeg" ‖ lp "jpg" ‖ n=1000 ‖
    // count=2 ‖ bucket=2 ‖ 32×0x33 (no caption/flags tail)
    let payload_hex = format!(
        "0101{}{}00000003{}000003e800020002{}",
        "0000000a",
        "696d6167652f6a706567", // "image/jpeg"
        "6a7067",               // "jpg"
        "33".repeat(32)
    );
    golden(
        Payload::AttachHead(AttachHeadPayload {
            head: AttachHead {
                media_class: CLASS_IMAGE,
                mime_hint: "image/jpeg".into(),
                orig_ext: "jpg".into(),
                uncompressed_n: 1000,
                chunk_count: 2,
                chunk_bucket: 2,
                content_sha256: [0x33; 32],
                caption: String::new(),
                flags: 0,
            },
            inline: None,
        }),
        &format!("06{HDR}{:08x}{}", payload_hex.len() / 2, payload_hex),
    );
}

#[test]
fn attach_chunk_golden() {
    // payload: 16×0x22 ‖ index=5 ‖ pad=0 ‖ lp [01 02 03]
    let payload_hex = format!("{}00050000000003010203", "22".repeat(16));
    golden(
        Payload::AttachChunk(AttachChunk {
            head_id: [0x22; 16],
            index: 5,
            pad: false,
            data: vec![1, 2, 3],
        }),
        &format!("07{HDR}{:08x}{}", payload_hex.len() / 2, payload_hex),
    );
}

#[test]
fn contact_close_golden() {
    golden(
        Payload::ContactClose(ContactClose),
        &format!("08{HDR}00000000"),
    );
}

#[test]
fn profile_golden() {
    // payload: v=1 ‖ lp "ab" ‖ lp empty-jpeg
    golden(
        Payload::Profile(Profile {
            name: "ab".into(),
            jpeg: Vec::new(),
        }),
        &format!("09{HDR}0000000b0100000002616200000000"),
    );
}

#[test]
fn pref_golden() {
    // payload: v=1 ‖ flags=3 ‖ hours=720
    golden(
        Payload::Pref(Pref {
            receive_media: true,
            listen_saver: true,
            inactivity_erase_hours: 720,
        }),
        &format!("0a{HDR}000000090100000003000002d0"),
    );
}

#[test]
fn profile_req_golden() {
    golden(Payload::ProfileReq(ProfileReq), &format!("0b{HDR}00000000"));
}

#[test]
fn sticker_golden() {
    // payload: v=1 ‖ kind=2 ‖ vis=1 ‖ 16×0x10 ‖ 32×0x20 ‖ id=3 ‖
    // w=512 ‖ h=512 ‖ 32×0x30 ‖ has_bytes=0
    let payload_hex = format!(
        "010201{}{}000302000200{}00",
        "10".repeat(16),
        "20".repeat(32),
        "30".repeat(32)
    );
    golden(
        Payload::Sticker(StickerItem {
            kind: 2,
            visibility: 1,
            pack_id: [0x10; 16],
            pack_pk: [0x20; 32],
            item_id: 3,
            w: 512,
            h: 512,
            content_sha256: [0x30; 32],
            bytes: None,
        }),
        &format!("0e{HDR}{:08x}{}", payload_hex.len() / 2, payload_hex),
    );
}

#[test]
fn sticker_ctrl_ack_golden() {
    // payload: v=1 ‖ op=1 ‖ 32×0xaa
    let payload_hex = format!("0101{}", "aa".repeat(32));
    golden(
        Payload::StickerCtrl(StickerCtrl::Ack([0xaa; 32])),
        &format!("0f{HDR}{:08x}{}", payload_hex.len() / 2, payload_hex),
    );
}

#[test]
fn presence_golden() {
    // payload: v=1 ‖ flags = in_app|dnd = 3
    golden(
        Payload::Presence(Presence {
            in_app: true,
            do_not_disturb: true,
        }),
        &format!("10{HDR}000000020103"),
    );
}

#[test]
fn chat_policy_golden() {
    // payload: v=1 ‖ op=1 ‖ ttl=86400 ‖ flags=3 ‖ cap_id=0 ‖ cap_on=0 ‖
    // 16×0x11
    let payload_hex = format!("010100015180000000030000{}", "11".repeat(16));
    golden(
        Payload::ChatPolicy(ChatPolicy {
            op: policy::OP_RULE_PROPOSE,
            ttl_sec: policy::TTL_24H,
            screenshot: true,
            attach_download: true,
            want_attach: false,
            want_emoji: false,
            want_presence: false,
            want_typing: false,
            want_receipts: false,
            cap_id: 0,
            cap_on: false,
            propose_id: [0x11; 16],
        }),
        &format!("11{HDR}{:08x}{}", payload_hex.len() / 2, payload_hex),
    );
}

#[test]
fn typing_golden() {
    // payload: v=1 ‖ flags=1
    golden(
        Payload::Typing(Typing { typing: true }),
        &format!("12{HDR}000000020101"),
    );
}

#[test]
fn read_golden() {
    golden(Payload::Read(Read), &format!("13{HDR}00000000"));
}

#[test]
fn envelope_with_ref_golden() {
    // DELETE with ref_id = 16×0x22: ref_len=16 rides in the header.
    let env = Envelope {
        msg_id: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        app_seq: 1,
        sent_at: 1_700_000_000,
        ref_id: Some([0x22; 16]),
        payload: Payload::Delete(Delete),
    };
    let expected = format!(
        "03000102030405060708090a0b0c0d0e0f0000000000000001000000006553f10010{}00000000",
        "22".repeat(16)
    );
    assert_eq!(hex(&env.encode().unwrap()), expected);
    assert_eq!(Envelope::decode(&unhex(&expected)).unwrap(), env);
}
