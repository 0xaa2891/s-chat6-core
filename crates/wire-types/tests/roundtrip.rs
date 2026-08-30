//! Round-trip every envelope type: encode → decode must be the identity.

use schat_wire_types::attach::{
    AttachChunk, AttachHead, AttachHeadPayload, CHUNK_DATA_MAX, CLASS_IMAGE, FLAG_VIEW_ONCE,
};
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
use schat_wire_types::resync::{self, ResyncReq};
use schat_wire_types::sticker::{PackRef, StickerCtrl, StickerItem};
use schat_wire_types::typing::Typing;
use schat_wire_types::WirePayload;

fn msg_id(seed: u8) -> [u8; 16] {
    [seed; 16]
}

fn roundtrip(payload: Payload) {
    let env = Envelope {
        msg_id: msg_id(7),
        app_seq: 42,
        sent_at: 1_700_000_000,
        ref_id: None,
        payload,
    };
    let bytes = env.encode().unwrap();
    let back = Envelope::decode(&bytes).unwrap();
    assert_eq!(back, env);
}

#[test]
fn msg() {
    roundtrip(Payload::Msg(Msg::new("hello world".into()).unwrap()));
    roundtrip(Payload::Msg(Msg::new(String::new()).unwrap()));
    roundtrip(Payload::Msg(Msg::new("emoji: \u{1F600}".into()).unwrap()));
}

#[test]
fn edit() {
    let env = Envelope {
        msg_id: msg_id(8),
        app_seq: 7,
        sent_at: 1_700_000_001,
        ref_id: Some(msg_id(9)),
        payload: Payload::Edit(Edit::new("edited body".into()).unwrap()),
    };
    let bytes = env.encode().unwrap();
    assert_eq!(Envelope::decode(&bytes).unwrap(), env);
}

#[test]
fn delete_and_delete_all() {
    let env = Envelope {
        msg_id: msg_id(1),
        app_seq: 1,
        sent_at: 1,
        ref_id: Some(msg_id(2)),
        payload: Payload::Delete(Delete),
    };
    let bytes = env.encode().unwrap();
    assert_eq!(Envelope::decode(&bytes).unwrap(), env);

    roundtrip(Payload::DeleteAll(DeleteAll));
}

#[test]
fn resync_req() {
    let bitmap = vec![0b1010_0001u8, 0xff, 0x00];
    let hash = resync::hash_contiguous(100, &bitmap);
    roundtrip(Payload::ResyncReq(ResyncReq {
        max_contiguous_seq: 100,
        received_seq_bitmap: bitmap,
        caps: caps::LOCAL,
        history_hash: hash,
    }));
    // Empty bitmap (nothing above the contiguous horizon).
    roundtrip(Payload::ResyncReq(ResyncReq {
        max_contiguous_seq: 0,
        received_seq_bitmap: Vec::new(),
        caps: 0,
        history_hash: [0u8; 32],
    }));
}

fn head(chunk_count: u16, chunk_bucket: u16) -> AttachHead {
    AttachHead {
        media_class: CLASS_IMAGE,
        mime_hint: "image/jpeg".into(),
        orig_ext: "jpg".into(),
        uncompressed_n: 100_000,
        chunk_count,
        chunk_bucket,
        content_sha256: [0x33; 32],
        caption: String::new(),
        flags: 0,
    }
}

#[test]
fn attach_head_chunked() {
    roundtrip(Payload::AttachHead(AttachHeadPayload {
        head: head(4, 4),
        inline: None,
    }));
    // With caption (CAP_V16 tail).
    let mut h = head(2, 2);
    h.caption = "a caption".into();
    roundtrip(Payload::AttachHead(AttachHeadPayload {
        head: h,
        inline: None,
    }));
    // Caption + view-once flag (CAP_V17 tail).
    let mut h = head(2, 2);
    h.caption = "cap".into();
    h.flags = FLAG_VIEW_ONCE;
    roundtrip(Payload::AttachHead(AttachHeadPayload {
        head: h,
        inline: None,
    }));
    // Flags with empty caption.
    let mut h = head(2, 2);
    h.flags = FLAG_VIEW_ONCE;
    roundtrip(Payload::AttachHead(AttachHeadPayload {
        head: h,
        inline: None,
    }));
}

#[test]
fn attach_head_inline() {
    let bytes = vec![0u8; 1024];
    let mut h = head(0, 0);
    h.uncompressed_n = 1024;
    roundtrip(Payload::AttachHead(AttachHeadPayload {
        head: h.clone(),
        inline: Some(bytes.clone()),
    }));
    // Inline with caption + flags.
    h.caption = "inline cap".into();
    h.flags = FLAG_VIEW_ONCE;
    roundtrip(Payload::AttachHead(AttachHeadPayload {
        head: h,
        inline: Some(bytes),
    }));
}

#[test]
fn attach_chunk() {
    roundtrip(Payload::AttachChunk(AttachChunk {
        head_id: msg_id(0x22),
        index: 5,
        pad: false,
        data: vec![1, 2, 3],
    }));
    // Pad chunk: empty data.
    roundtrip(Payload::AttachChunk(AttachChunk {
        head_id: msg_id(0x22),
        index: 6,
        pad: true,
        data: Vec::new(),
    }));
    // Ceiling-size chunk.
    roundtrip(Payload::AttachChunk(AttachChunk {
        head_id: msg_id(0x22),
        index: 0,
        pad: false,
        data: vec![0xabu8; CHUNK_DATA_MAX],
    }));
}

#[test]
fn contact_close() {
    roundtrip(Payload::ContactClose(ContactClose));
}

#[test]
fn profile() {
    roundtrip(Payload::Profile(Profile {
        name: "alice".into(),
        jpeg: vec![0xff, 0xd8, 0xff, 0xe0, 1, 2, 3],
    }));
    // No photo.
    roundtrip(Payload::Profile(Profile {
        name: "bob".into(),
        jpeg: Vec::new(),
    }));
    roundtrip(Payload::ProfileReq(ProfileReq));
}

#[test]
fn pref() {
    roundtrip(Payload::Pref(Pref {
        receive_media: true,
        listen_saver: true,
        inactivity_erase_hours: 720,
    }));
    roundtrip(Payload::Pref(Pref::default()));
}

#[test]
fn sticker_item() {
    let item = StickerItem {
        kind: 2,
        visibility: 1,
        pack_id: msg_id(0x10),
        pack_pk: [0x20; 32],
        item_id: 3,
        w: 512,
        h: 512,
        content_sha256: [0x30; 32],
        bytes: None,
    };
    roundtrip(Payload::Sticker(item.clone()));
    roundtrip(Payload::Sticker(StickerItem {
        bytes: Some(vec![1, 2, 3, 4]),
        ..item
    }));
}

#[test]
fn sticker_ctrl_all_ops() {
    let pack_ref = PackRef {
        pack_id: msg_id(0x10),
        pack_pk: [0x20; 32],
        kind: 2,
        visibility: 1,
        item_id: 3,
        w: 512,
        h: 512,
    };
    for ctrl in [
        StickerCtrl::Ack([0xaa; 32]),
        StickerCtrl::WantItem(vec![0xbb; 8]),
        StickerCtrl::WantItem([0xcc; 32].to_vec()),
        StickerCtrl::ItemBody {
            sha: [0xdd; 32],
            chunk_index: 0,
            chunk_count: 2,
            data: vec![1, 2, 3],
            pack: None,
        },
        StickerCtrl::ItemBody {
            sha: [0xdd; 32],
            chunk_index: 1,
            chunk_count: 2,
            data: vec![4, 5, 6],
            pack: Some(pack_ref),
        },
        StickerCtrl::WantPack {
            pack_id: msg_id(0x10),
            pack_pk: [0x20; 32],
        },
        StickerCtrl::PackBody {
            pack_id: msg_id(0x10),
            pack_pk: [0x20; 32],
            chunk_index: 0,
            chunk_count: 1,
            data: vec![9; 100],
        },
        StickerCtrl::PackRefused {
            pack_id: msg_id(0x10),
            pack_pk: [0x20; 32],
            reason: 2,
        },
        StickerCtrl::WantThumbs {
            pack_id: msg_id(0x10),
            pack_pk: [0x20; 32],
        },
        StickerCtrl::ThumbsBody {
            pack_id: msg_id(0x10),
            pack_pk: [0x20; 32],
            chunk_index: 0,
            chunk_count: 1,
            data: vec![8; 50],
        },
    ] {
        let bytes = ctrl.encode_payload().unwrap();
        let back = StickerCtrl::decode_payload(&bytes).unwrap();
        assert_eq!(back, ctrl);
        roundtrip(Payload::StickerCtrl(ctrl));
    }
}

#[test]
fn presence() {
    roundtrip(Payload::Presence(Presence {
        in_app: true,
        do_not_disturb: false,
    }));
    roundtrip(Payload::Presence(Presence {
        in_app: true,
        do_not_disturb: true,
    }));
    roundtrip(Payload::Presence(Presence::default()));
}

#[test]
fn typing() {
    roundtrip(Payload::Typing(Typing { typing: true }));
    roundtrip(Payload::Typing(Typing { typing: false }));
}

#[test]
fn chat_policy() {
    roundtrip(Payload::ChatPolicy(ChatPolicy {
        op: policy::OP_RULE_PROPOSE,
        ttl_sec: policy::TTL_24H,
        screenshot: true,
        attach_download: true,
        want_attach: true,
        want_emoji: true,
        want_presence: true,
        want_typing: true,
        want_receipts: true,
        cap_id: 0,
        cap_on: false,
        propose_id: msg_id(0x44),
    }));
    roundtrip(Payload::ChatPolicy(ChatPolicy {
        op: policy::OP_CAP_SET,
        ttl_sec: 0,
        screenshot: false,
        attach_download: false,
        want_attach: false,
        want_emoji: false,
        want_presence: false,
        want_typing: false,
        want_receipts: false,
        cap_id: policy::CAP_ID_TYPING,
        cap_on: true,
        propose_id: [0u8; 16],
    }));
}

#[test]
fn read() {
    let env = Envelope {
        msg_id: msg_id(5),
        app_seq: 9,
        sent_at: 1_700_000_002,
        ref_id: Some(msg_id(6)),
        payload: Payload::Read(Read),
    };
    let bytes = env.encode().unwrap();
    assert_eq!(Envelope::decode(&bytes).unwrap(), env);
}

#[test]
fn unknown_type_is_i7_drop() {
    // Codes 12/13 and anything else unknown decode to
    // UnknownType carrying the envelope identity.
    for code in [0u8, 12, 13, 20, 200, 255] {
        let mut bytes = vec![code];
        bytes.extend_from_slice(&msg_id(1));
        bytes.extend_from_slice(&7u64.to_be_bytes());
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.push(0); // ref_len
        bytes.extend_from_slice(&0u32.to_be_bytes()); // empty payload
        match Envelope::decode(&bytes) {
            Err(schat_wire_types::WireError::UnknownType {
                code: got,
                msg_id: mid,
                app_seq,
            }) => {
                assert_eq!(got, code);
                assert_eq!(mid, msg_id(1));
                assert_eq!(app_seq, 7);
            }
            other => panic!("code {code}: expected UnknownType, got {other:?}"),
        }
    }
}

#[test]
fn envelope_rejects_bad_ref_len_and_trailing() {
    let env = Envelope {
        msg_id: msg_id(1),
        app_seq: 1,
        sent_at: 1,
        ref_id: None,
        payload: Payload::Msg(Msg::new("x".into()).unwrap()),
    };
    let bytes = env.encode().unwrap();
    // Trailing garbage.
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Envelope::decode(&longer).is_err());
    // Truncated.
    assert!(Envelope::decode(&bytes[..bytes.len() - 1]).is_err());
    // Bad ref_len (not 0 or 16).
    let mut bad = bytes.clone();
    bad[1 + 16 + 8 + 8] = 5;
    assert!(Envelope::decode(&bad).is_err());
}
