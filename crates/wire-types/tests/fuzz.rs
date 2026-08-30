//! Proptest: no decoder may panic on arbitrary bytes, and valid values
//! round-trip through encode/decode.

use proptest::prelude::*;

use schat_wire_types::attach::{AttachChunk, AttachHeadPayload};
use schat_wire_types::contact::ContactClose;
use schat_wire_types::delete::{Delete, DeleteAll};
use schat_wire_types::edit::Edit;
use schat_wire_types::envelope::Envelope;
use schat_wire_types::msg::Msg;
use schat_wire_types::policy::ChatPolicy;
use schat_wire_types::pref::Pref;
use schat_wire_types::presence::Presence;
use schat_wire_types::profile::{Profile, ProfileReq};
use schat_wire_types::read::Read;
use schat_wire_types::resync::{self, ResyncReq};
use schat_wire_types::sticker::{StickerCtrl, StickerItem, StickerPackDoc, StickerThumbsDoc};
use schat_wire_types::typing::Typing;
use schat_wire_types::WirePayload;

fn decode_everything(bytes: &[u8]) {
    // The envelope decoder and every payload decoder must return, never
    // panic. Errors are fine; panics are bugs.
    let _ = Envelope::decode(bytes);
    let _ = Msg::decode_payload(bytes);
    let _ = Edit::decode_payload(bytes);
    let _ = Delete::decode_payload(bytes);
    let _ = DeleteAll::decode_payload(bytes);
    let _ = ResyncReq::decode_payload(bytes);
    let _ = AttachHeadPayload::decode_payload(bytes);
    let _ = AttachChunk::decode_payload(bytes);
    let _ = ContactClose::decode_payload(bytes);
    let _ = Profile::decode_payload(bytes);
    let _ = Pref::decode_payload(bytes);
    let _ = ProfileReq::decode_payload(bytes);
    let _ = StickerItem::decode_payload(bytes);
    let _ = StickerCtrl::decode_payload(bytes);
    let _ = Presence::decode_payload(bytes);
    let _ = ChatPolicy::decode_payload(bytes);
    let _ = Typing::decode_payload(bytes);
    let _ = Read::decode_payload(bytes);
    let _ = StickerPackDoc::scan_partial(bytes);
    let _ = StickerThumbsDoc::decode(bytes);
    let _ = StickerPackDoc::decode_signed(bytes, &[0u8; 32], |_, _, _| true, |_| [0u8; 32]);
}

proptest! {
    #[test]
    fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        decode_everything(&bytes);
    }

    /// Truncations of a valid envelope at every offset.
    #[test]
    fn truncations_never_panic(
        body in proptest::collection::vec(any::<u8>(), 0..512),
        cut in any::<proptest::sample::Index>(),
    ) {
        let env = Envelope {
            msg_id: [1u8; 16],
            app_seq: 5,
            sent_at: 100,
            ref_id: Some([2u8; 16]),
            payload: schat_wire_types::envelope::Payload::Msg(
                Msg::new(String::from_utf8_lossy(&body).into_owned())
                    .unwrap_or_else(|_| Msg::new("x".into()).unwrap()),
            ),
        };
        let bytes = env.encode().unwrap();
        let at = cut.index(bytes.len());
        decode_everything(&bytes[..at]);
    }

    #[test]
    fn resync_round_trip(
        max_seq in any::<u64>(),
        bitmap in proptest::collection::vec(any::<u8>(), 0..=resync::MAX_BITMAP_BYTES),
        caps in any::<u32>(),
        hash in any::<[u8; 32]>(),
    ) {
        let req = ResyncReq {
            max_contiguous_seq: max_seq,
            received_seq_bitmap: bitmap,
            caps,
            history_hash: hash,
        };
        let bytes = req.encode_payload().unwrap();
        prop_assert_eq!(ResyncReq::decode_payload(&bytes).unwrap(), req);
    }

    #[test]
    fn msg_round_trip(body in ".*") {
        if let Ok(m) = Msg::new(body) {
            let bytes = m.encode_payload().unwrap();
            prop_assert_eq!(Msg::decode_payload(&bytes).unwrap(), m);
        }
    }
}
