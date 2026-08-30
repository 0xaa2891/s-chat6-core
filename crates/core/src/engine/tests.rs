//! Feature tests: two engines paired headlessly, frames pumped
//! in memory over a mock transport. Covers text /
//! edit / delete / read, attachments (inline + chunked + view-once),
//! presence / typing, policy, stickers, contact close, and resync.

use std::time::SystemTime;

use schat_wire_types::policy as wire_policy;
use schat_wire_types::sticker::{limits as sticker_limits, PackDocItem};

use super::{Engine, EngineEvent};
use crate::pairing::{self, Ingest};
use crate::store::attachments::AttachmentsRepository;
use crate::store::messages::{DeliveryState, MessagesRepository};
use crate::store::outbox::{OutboxRepository, OutboxRow};
use crate::store::tombstones::TombstonesRepository;
use crate::store::Db;
use crate::transport::{framing, Transport};

struct Peer {
    engine: Engine,
    _tmp: tempfile::TempDir,
}

impl Peer {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let db = Db::open_in_memory().unwrap();
        Self {
            engine: Engine::new(db, transport),
            _tmp: tmp,
        }
    }
}

/// The service a frame to `to` arrives at: the relationship's service,
/// or — before the peer has a relationship — the pending invitation.
fn peer_service(to: &Peer, rel_id: &str) -> Option<String> {
    if let Some(rel) = pairing::load_relationship(to.engine.db.conn(), rel_id).unwrap() {
        return Some(rel.service_id);
    }
    pairing::load_pending(to.engine.db.conn())
        .unwrap()
        .map(|p| p.service_id)
}

/// Deliver one outbox row to the peer, returning the peer's events.
async fn deliver(from: &Peer, to: &mut Peer, rel_id: &str, row: &OutboxRow) -> Vec<EngineEvent> {
    let intro = pairing::load_relationship(from.engine.db.conn(), rel_id)
        .unwrap()
        .and_then(|r| r.intro_pending.then(|| r.our_qr_bytes.clone()));
    let service_id = peer_service(to, rel_id).expect("peer service");
    let packed = framing::pack(intro.as_deref(), &row.record, false).unwrap();
    let mut slice: &[u8] = &packed;
    let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
    let outcome = pairing::ingest_frame(
        to.engine.db.conn(),
        &to.engine.transport,
        &service_id,
        opaque.intro.as_deref(),
        &opaque.frame,
        SystemTime::now(),
    )
    .await
    .unwrap();
    from.engine.db.dequeue(&row.msg_id).unwrap();
    from.engine
        .db
        .set_delivery(&row.msg_id, DeliveryState::Transmitted)
        .unwrap();
    let plaintext = match outcome {
        Ingest::RequestReceived { plaintext, .. } | Ingest::Message { plaintext, .. } => plaintext,
        // I11 retransmission of an already-processed frame: normal.
        Ingest::Duplicate => return Vec::new(),
        other => panic!(
            "unexpected ingest {other:?} (msg_id={}, rel={rel_id})",
            crate::store::hex_encode(&row.msg_id)
        ),
    };
    to.engine
        .handle_plaintext(rel_id, &plaintext)
        .await
        .unwrap()
}

/// Pump every due record from → to. Returns (frames delivered, events).
async fn pump(from: &mut Peer, to: &mut Peer, rel_id: &str) -> (usize, Vec<EngineEvent>) {
    let rows = from.engine.db.due(64).unwrap();
    let mut events = Vec::new();
    let mut n = 0;
    for row in rows {
        if row.rel_id != rel_id {
            continue;
        }
        if peer_service(to, rel_id).is_none() {
            break; // peer burned the relationship; frames drop on the floor
        }
        events.extend(deliver(from, to, rel_id, &row).await);
        n += 1;
    }
    (n, events)
}

/// Pump both directions until nothing moves (cap 20 rounds).
async fn quiesce(a: &mut Peer, b: &mut Peer, rel_id: &str) -> (Vec<EngineEvent>, Vec<EngineEvent>) {
    let mut ea = Vec::new();
    let mut eb = Vec::new();
    for _ in 0..20 {
        let (na, va) = pump(a, b, rel_id).await;
        let (nb, vb) = pump(b, a, rel_id).await;
        eb.extend(va);
        ea.extend(vb);
        if na == 0 && nb == 0 {
            break;
        }
    }
    (ea, eb)
}

/// Full pairing ceremony ending in an active relationship both sides:
/// offer → accept → first message (intro frame) → request accepted →
/// activation bursts exchanged and settled.
async fn pair_up() -> (Peer, Peer, String) {
    let mut inviter = Peer::new();
    let mut accepter = Peer::new();
    let now = SystemTime::now();

    let offer = pairing::offer(inviter.engine.db.conn(), &inviter.engine.transport, now)
        .await
        .unwrap();
    let accepted = pairing::accept(
        accepter.engine.db.conn(),
        &accepter.engine.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .unwrap();
    let rel_id = accepted.rel_id.clone();

    accepter
        .engine
        .send_text(&rel_id, "hi", None)
        .await
        .unwrap();
    let events = pump(&mut accepter, &mut inviter, &rel_id).await.1;
    assert!(
        events
            .iter()
            .any(|e| matches!(e, EngineEvent::Message { .. })),
        "inviter sees the first message: {events:?}"
    );

    inviter.engine.accept_request(&rel_id).await.unwrap();
    quiesce(&mut inviter, &mut accepter, &rel_id).await;

    // Both sides active; intros retired.
    let a = pairing::load_relationship(inviter.engine.db.conn(), &rel_id)
        .unwrap()
        .unwrap();
    let b = pairing::load_relationship(accepter.engine.db.conn(), &rel_id)
        .unwrap()
        .unwrap();
    assert_eq!(a.state, "active");
    assert_eq!(b.state, "active");
    assert!(
        !b.intro_pending,
        "inviter's burst cleared the accepter's intro"
    );
    (inviter, accepter, rel_id)
}

/// Rendered text bodies, oldest first (MSG payloads are raw UTF-8).
fn bodies(peer: &Peer, rel_id: &str) -> Vec<String> {
    peer.engine
        .db
        .thread_visible(rel_id, 100, None)
        .unwrap()
        .into_iter()
        .rev()
        .filter(|r| r.env_type == schat_wire_types::envelope::EnvelopeType::Msg.code())
        .map(|r| String::from_utf8(r.payload).unwrap())
        .collect()
}

#[tokio::test]
async fn text_edit_delete_read_flow() {
    let (mut a, mut b, rel_id) = pair_up().await;

    // Text roundtrip.
    let msg_id = a.engine.send_text(&rel_id, "hello b", None).await.unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Message {
        rel_id: rel_id.clone(),
        msg_id,
    }));
    assert_eq!(bodies(&b, &rel_id), ["hi", "hello b"]);

    // Read receipt.
    b.engine.send_read(&rel_id, &msg_id).await.unwrap();
    let events = pump(&mut b, &mut a, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Read {
        rel_id: rel_id.clone(),
        msg_id,
    }));
    let row = a.engine.db.message(&msg_id).unwrap().unwrap();
    assert!(row.read_at.is_some());

    // Edit within the window.
    let edit_id = a
        .engine
        .send_edit(&rel_id, &msg_id, "hello b (edited)")
        .await
        .unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Edited {
        rel_id: rel_id.clone(),
        msg_id,
    }));
    assert_eq!(bodies(&b, &rel_id), ["hi", "hello b (edited)"]);
    // Local echo on the sender too.
    let row = a.engine.db.message(&msg_id).unwrap().unwrap();
    assert_eq!(row.edit_count, 1);
    assert_eq!(String::from_utf8(row.payload).unwrap(), "hello b (edited)");
    // The edit envelope itself is not a thread row.
    assert!(a.engine.db.message(&edit_id).unwrap().is_some());

    // Delete for everyone.
    a.engine.send_delete(&rel_id, &msg_id).await.unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Deleted {
        rel_id: rel_id.clone(),
        msg_id,
    }));
    assert_eq!(bodies(&b, &rel_id), ["hi"]);
    let row = b.engine.db.message(&msg_id).unwrap().unwrap();
    assert!(row.tombstone);
    assert!(row.payload.is_empty());
}

#[tokio::test]
async fn delete_before_arrival_tombstones() {
    let (mut a, mut b, rel_id) = pair_up().await;

    let msg_id = a.engine.send_text(&rel_id, "doomed", None).await.unwrap();
    a.engine.send_delete(&rel_id, &msg_id).await.unwrap();

    // Deliver ONLY the delete; the message frame stays queued.
    let rows = a.engine.db.due(64).unwrap();
    let delete_row = rows
        .iter()
        .find(|r| r.msg_id != msg_id)
        .expect("delete frame queued");
    let events = deliver(&a, &mut b, &rel_id, delete_row).await;
    // No Deleted event (there was no row to remove from the UI) — but
    // the tombstone is recorded so the late original drops.
    assert!(!events
        .iter()
        .any(|e| matches!(e, EngineEvent::Deleted { .. })));
    assert!(b.engine.db.is_tombstoned(&rel_id, &msg_id).unwrap());

    // The late-arriving original drops on the tombstone: no Message
    // event, no ledger row.
    let msg_row = rows.iter().find(|r| r.msg_id == msg_id).unwrap();
    let events = deliver(&a, &mut b, &rel_id, msg_row).await;
    assert!(!events
        .iter()
        .any(|e| matches!(e, EngineEvent::Message { .. })));
    assert!(b.engine.db.message(&msg_id).unwrap().is_none());
}

#[tokio::test]
async fn attachment_inline_and_chunked() {
    let (mut a, mut b, rel_id) = pair_up().await;

    // Inline: small enough to ride the head.
    let small = vec![7u8; 1_000];
    let head_inline = a
        .engine
        .send_attachment(
            &rel_id,
            &crate::attach::AttachmentSpec {
                media_class: 2,
                mime_hint: "video/mp4".into(),
                orig_ext: "mp4".into(),
                bytes: small.clone(),
                caption: "pic".into(),
                view_once: false,
            },
        )
        .await
        .unwrap();
    let events = quiesce(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::AttachmentComplete {
        rel_id: rel_id.clone(),
        head_id: head_inline,
        msg_id: head_inline,
    }));
    assert_eq!(
        b.engine.attachment_bytes(&head_inline).unwrap().unwrap(),
        small
    );

    // Chunked: 60 KB forces multiple chunk envelopes.
    let big: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
    let head_big = a
        .engine
        .send_attachment(
            &rel_id,
            &crate::attach::AttachmentSpec {
                media_class: 2,
                mime_hint: "video/mp4".into(),
                orig_ext: "mp4".into(),
                bytes: big.clone(),
                caption: String::new(),
                view_once: false,
            },
        )
        .await
        .unwrap();
    let events = quiesce(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::AttachmentComplete {
        rel_id: rel_id.clone(),
        head_id: head_big,
        msg_id: head_big,
    }));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, EngineEvent::AttachmentProgress { .. })),
        "progress events fired: {events:?}"
    );
    assert_eq!(b.engine.attachment_bytes(&head_big).unwrap().unwrap(), big);
}

#[tokio::test]
async fn view_once_consumed_on_open() {
    let (mut a, mut b, rel_id) = pair_up().await;
    let bytes = vec![3u8; 500];
    let head = a
        .engine
        .send_attachment(
            &rel_id,
            &crate::attach::AttachmentSpec {
                media_class: 2,
                mime_hint: "video/mp4".into(),
                orig_ext: "mp4".into(),
                bytes: bytes.clone(),
                caption: String::new(),
                view_once: true,
            },
        )
        .await
        .unwrap();
    quiesce(&mut a, &mut b, &rel_id).await;

    // First open consumes: the bytes are wiped for good.
    b.engine.attachment_viewed(&head).unwrap();
    assert!(b.engine.attachment_bytes(&head).unwrap().is_none());
}

#[tokio::test]
async fn presence_and_typing_are_ephemeral() {
    let (mut a, mut b, rel_id) = pair_up().await;
    let now = b.engine.now();

    a.engine.send_presence(&rel_id, true, false).await.unwrap();
    a.engine.send_typing(&rel_id, true).await.unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Presence {
        rel_id: rel_id.clone(),
        in_app: true,
        do_not_disturb: false,
    }));
    assert!(events.contains(&EngineEvent::Typing {
        rel_id: rel_id.clone(),
        typing: true,
    }));
    let p = b.engine.presence.state(&rel_id, now);
    assert!(p.in_app && !p.do_not_disturb);
    assert!(b.engine.typing.is_typing(&rel_id, now));

    a.engine.send_typing(&rel_id, false).await.unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Typing {
        rel_id: rel_id.clone(),
        typing: false,
    }));
    assert!(!b.engine.typing.is_typing(&rel_id, now));

    // Ephemerals consume sequence numbers but are never ledgered.
    let stored = b.engine.db.thread(&rel_id, 100, None).unwrap();
    assert!(
        stored.iter().all(|r| {
            r.env_type != schat_wire_types::envelope::EnvelopeType::Typing.code()
                && r.env_type != schat_wire_types::envelope::EnvelopeType::Presence.code()
        }),
        "no typing/presence rows in the ledger: {stored:?}"
    );
}

#[tokio::test]
async fn policy_propose_accept_and_capability() {
    let (mut a, mut b, rel_id) = pair_up().await;

    a.engine
        .propose_rules(&rel_id, wire_policy::TTL_1H, true, false)
        .await
        .unwrap();
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::PolicyChanged {
        rel_id: rel_id.clone(),
    }));
    let pending = b.engine.chat_policy(&rel_id).unwrap().pending.unwrap();
    assert!(pending.inbound);
    assert_eq!(pending.ttl_sec, wire_policy::TTL_1H);
    // Rules not yet applied on either side.
    assert_eq!(
        b.engine.chat_policy(&rel_id).unwrap().ttl_sec,
        wire_policy::TTL_24H
    );

    b.engine.accept_rules(&rel_id).await.unwrap();
    quiesce(&mut a, &mut b, &rel_id).await;
    for peer in [&a, &b] {
        let state = peer.engine.chat_policy(&rel_id).unwrap();
        assert_eq!(state.ttl_sec, wire_policy::TTL_1H);
        assert!(state.screenshot);
        assert!(state.pending.is_none());
    }

    // Capability wants are two-to-enable: default on; one side off
    // disables for both.
    assert!(a.engine.chat_policy(&rel_id).unwrap().typing());
    a.engine
        .set_capability(&rel_id, wire_policy::CAP_ID_TYPING, false)
        .await
        .unwrap();
    quiesce(&mut a, &mut b, &rel_id).await;
    for peer in [&a, &b] {
        assert!(!peer.engine.chat_policy(&rel_id).unwrap().typing());
    }
}

fn sticker_item(item_id: u16, seed: u8) -> PackDocItem {
    let bytes = vec![seed; 100];
    PackDocItem {
        item_id,
        w: 64,
        h: 64,
        sha256: crate::util::sha256(&bytes),
        bytes,
    }
}

#[tokio::test]
async fn sticker_pack_fetch_and_send() {
    let (mut a, mut b, rel_id) = pair_up().await;

    let (pack_id, pack_pk) = a
        .engine
        .create_pack(
            "mypack",
            sticker_limits::KIND_EMOJI,
            sticker_limits::VISIBILITY_PUBLIC,
            1,
            vec![sticker_item(1, 11), sticker_item(2, 22)],
        )
        .unwrap();

    // B fetches the pack (WANT_PACK → PACK_BODY chunks → install).
    b.engine
        .fetch_pack(&rel_id, &pack_id, &pack_pk)
        .await
        .unwrap();
    let events = quiesce(&mut a, &mut b, &rel_id).await.1;
    assert!(
        events.iter().any(
            |e| matches!(e, EngineEvent::StickerPackInstalled { pack_id: p } if *p == pack_id)
        ),
        "pack installed: {events:?}"
    );
    let info = crate::stickers::packs::pack_info(&b.engine.db, &pack_id)
        .unwrap()
        .unwrap();
    assert_eq!(info.title, "mypack");

    // B sends an item back to A (A has the pack → ready immediately).
    let msg_id = b.engine.send_sticker(&rel_id, &pack_id, 1).await.unwrap();
    let events = pump(&mut b, &mut a, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::Sticker {
        rel_id: rel_id.clone(),
        msg_id,
        ready: true,
    }));
}

#[tokio::test]
async fn close_contact_burns_both_sides() {
    let (mut a, mut b, rel_id) = pair_up().await;
    a.engine.send_text(&rel_id, "farewell", None).await.unwrap();
    pump(&mut a, &mut b, &rel_id).await;

    a.engine.close_contact(&rel_id).await.unwrap();
    // B receives DELETE_ALL then CONTACT_CLOSE and burns locally.
    let events = pump(&mut a, &mut b, &rel_id).await.1;
    assert!(events.contains(&EngineEvent::ContactClosed {
        rel_id: rel_id.clone(),
    }));
    assert!(
        pairing::load_relationship(b.engine.db.conn(), &rel_id)
            .unwrap()
            .is_none(),
        "peer relationship burned"
    );
    assert!(b.engine.db.thread(&rel_id, 100, None).unwrap().is_empty());

    // A's outbox settled; the sweeper completes the burn.
    a.engine.sweep().await.unwrap();
    assert!(
        pairing::load_relationship(a.engine.db.conn(), &rel_id)
            .unwrap()
            .is_none(),
        "our relationship burned after control frames settled"
    );
    assert!(a.engine.db.thread(&rel_id, 100, None).unwrap().is_empty());
}

/// Regression: a STALE RESYNC_REQ (built before the peer's view
/// caught up) makes us retransmit frames the peer already decrypted.
/// The retransmission rides a fresh record (new CSPRNG padding), so
/// transport-layer frame dedup cannot see it; the session layer must
/// reject the replayed ciphertext and no second `Message` event may
/// fire (I7: k deliveries = one effect).
#[tokio::test]
async fn stale_resync_retransmit_does_not_duplicate_events() {
    let (mut a, mut b, rel_id) = pair_up().await;

    let mut ids = Vec::new();
    for i in 0..4 {
        ids.push(
            a.engine
                .send_text(&rel_id, &format!("m{i}"), None)
                .await
                .unwrap(),
        );
    }
    let mut first_events = Vec::new();
    for row in a.engine.db.due(64).unwrap() {
        if row.rel_id == rel_id {
            first_events.extend(deliver(&a, &mut b, &rel_id, &row).await);
        }
    }
    assert_eq!(
        first_events
            .iter()
            .filter(|e| matches!(e, EngineEvent::Message { .. }))
            .count(),
        4,
        "first delivery: four Message events"
    );

    // B's stale request: view stuck at the activation seq, everything
    // above "missing". A retransmits all four (fresh padding, pinned
    // ciphertext); B must drop every one as a session-layer duplicate.
    let stale = schat_wire_types::resync::ResyncReq {
        max_contiguous_seq: 1,
        received_seq_bitmap: vec![0u8; (crate::sync::resync::BITMAP_BITS / 8) as usize],
        caps: schat_wire_types::caps::LOCAL,
        history_hash: [0u8; schat_wire_types::resync::HASH_BYTES],
    };
    crate::engine::send::send_envelope(
        &b.engine.db,
        &b.engine.transport,
        &rel_id,
        schat_wire_types::envelope::Payload::ResyncReq(stale),
        None,
        false,
    )
    .await
    .unwrap();
    // Deliver B's request to A; A requeues the retransmissions.
    for row in b.engine.db.due(64).unwrap() {
        if row.rel_id == rel_id {
            deliver(&b, &mut a, &rel_id, &row).await;
        }
    }
    // Now deliver A's retransmissions to B.
    let requeued = a
        .engine
        .db
        .due(64)
        .unwrap()
        .into_iter()
        .filter(|r| r.rel_id == rel_id)
        .count();
    assert!(requeued >= 4, "stale request must trigger retransmission");
    let mut second_events = Vec::new();
    for row in a.engine.db.due(64).unwrap() {
        if row.rel_id == rel_id {
            second_events.extend(deliver(&a, &mut b, &rel_id, &row).await);
        }
    }
    let dup_events = second_events
        .iter()
        .filter(|e| matches!(e, EngineEvent::Message { msg_id, .. } if ids.contains(msg_id)))
        .count();
    assert_eq!(dup_events, 0, "retransmission must not re-fire events");
    assert_eq!(bodies(&b, &rel_id), ["hi", "m0", "m1", "m2", "m3"]);
}

#[tokio::test]
async fn resync_recovers_dropped_frame() {
    let (mut a, mut b, rel_id) = pair_up().await;

    let m1 = a.engine.send_text(&rel_id, "one", None).await.unwrap();
    let m2 = a.engine.send_text(&rel_id, "two", None).await.unwrap();
    let m3 = a.engine.send_text(&rel_id, "three", None).await.unwrap();

    // Deliver m1 and m3; m2's frame is lost on the wire (its outbox row
    // is removed, so only the resync protocol can recover it).
    let rows = a.engine.db.due(64).unwrap();
    for row in rows.iter().filter(|r| r.msg_id == m1 || r.msg_id == m3) {
        deliver(&a, &mut b, &rel_id, row).await;
    }
    a.engine.db.dequeue(&m2).unwrap();
    assert_eq!(bodies(&b, &rel_id), ["hi", "one", "three"]);

    // The gap triggered a RESYNC_REQ; pumping settles it: A retransmits
    // m2 (identical ciphertext, fresh frame) and B fills the hole.
    quiesce(&mut a, &mut b, &rel_id).await;
    assert_eq!(bodies(&b, &rel_id), ["hi", "one", "two", "three"]);
    // B's receive view acked m1/m3; m2's ack awaits B's next view (its
    // retransmitted copy arrived after the view was built).
    for m in [m1, m3] {
        let row = a.engine.db.message(&m).unwrap().unwrap();
        assert_eq!(row.state, DeliveryState::Acknowledged, "acked after resync");
    }
    assert_eq!(
        a.engine.db.message(&m2).unwrap().unwrap().state,
        DeliveryState::Transmitted
    );
}

#[tokio::test]
async fn send_attachment_strips_metadata_and_generic_ext() {
    // No bypass — a still image sent through the engine is
    // stripped/re-encoded, and the wire carries a generic ext, never
    // the client's claimed one (filename non-leakage).
    let (mut a, mut b, rel_id) = pair_up().await;

    // Real JPEG with an EXIF APP1 segment (GPS marker) spliced in.
    let mut jpeg = {
        let img = image::DynamicImage::new_rgb8(120, 90);
        let mut out = std::io::Cursor::new(Vec::new());
        img.write_to(&mut out, image::ImageFormat::Jpeg).unwrap();
        out.into_inner()
    };
    let payload = b"Exif\0\0II*\0 GPS: 48.8584 N, 2.2945 E";
    let app1_len = (payload.len() + 2) as u16;
    let mut seg = vec![0xff, 0xe1];
    seg.extend_from_slice(&app1_len.to_be_bytes());
    seg.extend_from_slice(payload);
    jpeg.splice(2..2, seg);

    let head = a
        .engine
        .send_attachment(
            &rel_id,
            &crate::attach::AttachmentSpec {
                media_class: 1,
                mime_hint: "image/jpeg".into(),
                orig_ext: "beach-2024".into(), // leaky claim; must not propagate
                bytes: jpeg.clone(),
                caption: String::new(),
                view_once: false,
            },
        )
        .await
        .unwrap();
    quiesce(&mut a, &mut b, &rel_id).await;

    let row = b.engine.db.attachment(&head).unwrap().unwrap();
    assert_eq!(row.orig_ext, "jpg", "generic ext on the wire");
    assert_eq!(row.mime_hint, "image/jpeg");
    let got = b.engine.attachment_bytes(&head).unwrap().unwrap();
    assert_ne!(got, jpeg, "the peer receives the stripped re-encode");
    assert!(
        !got.windows(4).any(|w| w == b"Exif") && !got.windows(3).any(|w| w == b"GPS"),
        "EXIF/GPS metadata must not reach the peer"
    );
    // And it is still a real, decodable image.
    assert_eq!(crate::media::sniff(&got), crate::media::MediaKind::Jpeg);

    // Fail closed: garbage labeled as an image is refused, never sent raw.
    let refused = a
        .engine
        .send_attachment(
            &rel_id,
            &crate::attach::AttachmentSpec {
                media_class: 1,
                mime_hint: "image/jpeg".into(),
                orig_ext: "jpg".into(),
                bytes: b"definitely not an image".to_vec(),
                caption: String::new(),
                view_once: false,
            },
        )
        .await;
    assert!(refused.is_err(), "non-image bytes refused fail-closed");
}

#[tokio::test]
async fn orphan_chunks_capped_per_head_and_relationship() {
    // Chunks whose ATTACH_HEAD never arrives are bounded
    // per head and per relationship; over-cap chunks drop loudly.
    use crate::limits::orphan::*;
    use schat_wire_types::attach::AttachChunk;

    let (_a, mut b, rel_id) = pair_up().await;
    let chunk = |head: [u8; 16], index: u16| AttachChunk {
        head_id: head,
        index,
        pad: false,
        data: vec![0x55u8; 100],
    };
    let dropped = |events: &[EngineEvent]| {
        events
            .iter()
            .filter(|e| matches!(e, EngineEvent::AttachmentChunkDropped { .. }))
            .count()
    };

    // Per-head cap: exactly MAX_ORPHAN_CHUNKS_PER_HEAD are stored…
    let head1 = [0x01u8; 16];
    let mut events = Vec::new();
    for i in 0..MAX_ORPHAN_CHUNKS_PER_HEAD {
        b.engine
            .on_attach_chunk(&rel_id, &chunk(head1, i as u16), &mut events)
            .unwrap();
    }
    assert_eq!(dropped(&events), 0, "at-limit chunks all stored");
    // …and one over the cap is refused with an event.
    b.engine
        .on_attach_chunk(
            &rel_id,
            &chunk(head1, MAX_ORPHAN_CHUNKS_PER_HEAD as u16),
            &mut events,
        )
        .unwrap();
    assert_eq!(dropped(&events), 1, "over-cap chunk dropped loudly");

    // Per-relationship cap: fill the bucket with fresh heads (head1
    // already holds MAX_ORPHAN_CHUNKS_PER_HEAD), then one more drops.
    let mut stored = MAX_ORPHAN_CHUNKS_PER_HEAD;
    let mut head_n = 2u8;
    while stored < MAX_ORPHAN_CHUNKS_PER_REL {
        let head = [head_n; 16];
        head_n += 1;
        let room = (MAX_ORPHAN_CHUNKS_PER_REL - stored).min(MAX_ORPHAN_CHUNKS_PER_HEAD);
        for i in 0..room {
            b.engine
                .on_attach_chunk(&rel_id, &chunk(head, i as u16), &mut events)
                .unwrap();
        }
        stored += room;
    }
    let before = dropped(&events);
    b.engine
        .on_attach_chunk(&rel_id, &chunk([0xffu8; 16], 0), &mut events)
        .unwrap();
    assert_eq!(dropped(&events), before + 1, "per-rel cap drops loudly");

    // Once the head arrives the transfer's own bounds govern, so an
    // honest peer is never orphan-capped: the sweep is the backstop.
    // TTL sweep reclaims orphans whose head never landed.
    use crate::store::chunks::ChunksRepository;
    let old_head = [0x77u8; 16];
    b.engine
        .db
        .put_chunk(&old_head, 0, b"stale", &rel_id, 0)
        .unwrap();
    let report = crate::sync::Sync::new(&b.engine.db)
        .sweep_expired()
        .unwrap();
    assert!(
        report.orphan_chunks_erased >= 1,
        "stale orphan swept: {report:?}"
    );
    assert!(b.engine.db.chunk(&old_head, 0).unwrap().is_none());
    // Fresh orphans survive the sweep.
    assert!(b.engine.db.chunk(&head1, 0).unwrap().is_some());
}
