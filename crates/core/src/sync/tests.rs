//! Gate tests, headless with a mock transport (records moved
//! in memory): `offline_delivery`,
//! `message_expiry`, `clock_skew`.

use std::sync::Arc;
use std::time::SystemTime;

use rand::RngCore;
use schat_wire_types::envelope::{Envelope, Payload};
use schat_wire_types::msg::Msg;

use super::ingress::{ingest_envelope, IngestOutcome};
use super::outbox::drain;
use super::resync::{build_request, handle_request};
use super::{Sync, SyncError, MESSAGE_TTL_SECS};
use crate::pairing::{accept, accept_request, ingest_frame, load_pending, offer, Ingest};
use crate::session;
use crate::store::clock::{Clock, FakeClock};
use crate::store::messages::{DeliveryState, Direction, MessagesRepository, NewMessage};
use crate::store::outbox::OutboxRepository;
use crate::store::{hex_encode, Db};
use crate::transport::framing;
use crate::transport::Transport;
use crate::wire::envelope::decode_envelope;
use crate::wire::frame as wire_frame;

const T0: u64 = 1_700_000_000;

struct Instance {
    db: Db,
    transport: Arc<Transport>,
    clock: FakeClock,
    _tmp: tempfile::TempDir,
}

impl Instance {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let clock = FakeClock::new(T0);
        let db = Db::open_in_memory_with_clock(Arc::new(clock.clone())).unwrap();
        Self {
            db,
            transport,
            clock,
            _tmp: tmp,
        }
    }
}

struct Paired {
    inviter: Instance,
    accepter: Instance,
    rel_id: String,
}

/// offer → accept → intro frame → request → inviter accepts the request.
async fn pair_up() -> Paired {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let now = SystemTime::now();

    let offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    let accepted = accept(
        accepter.db.conn(),
        &accepter.transport,
        &offer.qr_bytes,
        now,
    )
    .await
    .unwrap();

    let row = crate::pairing::load_relationship(accepter.db.conn(), &accepted.rel_id)
        .unwrap()
        .unwrap();
    let frame = session::encrypt(accepter.db.conn(), &accepted.rel_id, "intro", b"hi", now)
        .await
        .unwrap();
    let record = wire_frame::build_record(&frame).unwrap();
    let packed = framing::pack(Some(&row.our_qr_bytes), &record, true).unwrap();
    let mut slice: &[u8] = &packed;
    let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();

    let pending = load_pending(inviter.db.conn()).unwrap().unwrap();
    let outcome = ingest_frame(
        inviter.db.conn(),
        &inviter.transport,
        &pending.service_id,
        opaque.intro.as_deref(),
        &opaque.frame,
        now,
    )
    .await
    .unwrap();
    let rel_id = match outcome {
        Ingest::RequestReceived { rel_id, .. } => rel_id,
        other => panic!("expected RequestReceived, got {other:?}"),
    };
    accept_request(inviter.db.conn(), &inviter.transport, &rel_id)
        .await
        .unwrap();

    Paired {
        inviter,
        accepter,
        rel_id,
    }
}

fn random_msg_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Build, encrypt, ledger, and queue a text message. Returns msg_id.
async fn queue_text(db: &Db, rel_id: &str, body: &str) -> [u8; 16] {
    let now = db.clock().now_secs();
    let seq = db.next_out_seq(rel_id).unwrap();
    let msg_id = random_msg_id();
    let env = Envelope {
        msg_id,
        app_seq: seq,
        sent_at: now,
        ref_id: None,
        payload: Payload::Msg(Msg::new(body.into()).unwrap()),
    };
    let plaintext = env.encode().unwrap();
    let frame = session::encrypt(
        db.conn(),
        rel_id,
        &hex_encode(&msg_id),
        &plaintext,
        SystemTime::now(),
    )
    .await
    .unwrap();
    let record = wire_frame::build_record(&frame).unwrap();
    db.insert_message(&NewMessage {
        msg_id,
        rel_id: rel_id.into(),
        direction: Direction::Out,
        app_seq: seq,
        sent_at: now,
        received_at: None,
        env_type: env.envelope_type().code(),
        ref_id: None,
        payload: env.payload.encode().unwrap(),
        state: DeliveryState::Queued,
        expires_at: Some(now + MESSAGE_TTL_SECS),
    })
    .unwrap();
    db.enqueue(&msg_id, rel_id, &record, MESSAGE_TTL_SECS)
        .unwrap();
    msg_id
}

/// Simulate the wire on a record the transport "sent": decrypt at the
/// receiver and land the envelope in its ledger.
async fn receive_record(receiver: &Instance, rel_id: &str, record: &[u8]) -> IngestOutcome {
    let frame = wire_frame::parse_record(record).unwrap();
    let plaintext = session::decrypt(receiver.db.conn(), rel_id, frame, SystemTime::now())
        .await
        .unwrap();
    let env = decode_envelope(&plaintext).unwrap();
    ingest_envelope(&receiver.db, rel_id, &env).unwrap()
}

/// Encrypt a RESYNC_REQ envelope from `from` and decrypt it at `to`.
async fn pass_resync_req(
    from: &Instance,
    to: &Instance,
    rel_id: &str,
) -> schat_wire_types::resync::ResyncReq {
    let req = build_request(&from.db, rel_id).unwrap();
    let msg_id = random_msg_id();
    let env = Envelope {
        msg_id,
        app_seq: from.db.next_out_seq(rel_id).unwrap(),
        sent_at: from.clock.now_secs(),
        ref_id: None,
        payload: Payload::ResyncReq(req),
    };
    let plaintext = env.encode().unwrap();
    let frame = session::encrypt(
        from.db.conn(),
        rel_id,
        &hex_encode(&msg_id),
        &plaintext,
        SystemTime::now(),
    )
    .await
    .unwrap();
    let decrypted = session::decrypt(to.db.conn(), rel_id, &frame, SystemTime::now())
        .await
        .unwrap();
    let env = decode_envelope(&decrypted).unwrap();
    match env.payload {
        Payload::ResyncReq(req) => req,
        other => panic!("expected ResyncReq, got {other:?}"),
    }
}

#[tokio::test]
async fn offline_delivery() {
    let p = pair_up().await;
    let (sender, receiver) = (&p.accepter, &p.inviter);

    // Three messages queued while the receiver is offline: every send
    // fails, backoff pushes them out of the due set.
    let mut ids = Vec::new();
    for body in ["m1", "m2", "m3"] {
        ids.push(queue_text(&sender.db, &p.rel_id, body).await);
    }
    let outcome = drain(&sender.db, 10, |_, _| {
        Err(SyncError::Send("peer offline".into()))
    })
    .unwrap();
    assert_eq!(outcome.deferred.len(), 3);
    assert!(outcome.transmitted.is_empty());
    assert!(sender.db.due(10).unwrap().is_empty(), "backed off");
    for id in &ids {
        assert_eq!(
            sender.db.message(id).unwrap().unwrap().state,
            DeliveryState::Queued,
            "a failed socket write is not 'sent'"
        );
    }

    // One simulated hour passes; the receiver returns.
    sender.clock.advance(3600);
    receiver.clock.advance(3600);

    // Drain again: m1/m2 are delivered, m3's socket write "succeeds" but
    // the frame is blackholed (lost after the write — the case resync
    // exists for).
    let mut sent_records: Vec<Vec<u8>> = Vec::new();
    let outcome = drain(&sender.db, 10, |_, record| {
        sent_records.push(record.to_vec());
        Ok(())
    })
    .unwrap();
    assert_eq!(outcome.transmitted.len(), 3);
    for id in &ids {
        assert_eq!(
            sender.db.message(id).unwrap().unwrap().state,
            DeliveryState::Transmitted
        );
    }
    for rec in &sent_records[..2] {
        assert_eq!(
            receive_record(receiver, &p.rel_id, rec).await,
            IngestOutcome::Stored { opens_gap: false }
        );
    }
    let view = receiver.db.receive_view(&p.rel_id, 4096).unwrap();
    assert_eq!(view.max_contiguous_seq, 2);

    // The receiver's resync: sender retransmits the lost frame from its
    // I11 cache (byte-identical) and acks the two covered messages.
    let req = pass_resync_req(receiver, sender, &p.rel_id).await;
    let retransmits = handle_request(&sender.db, &p.rel_id, &req).unwrap();
    assert_eq!(retransmits.len(), 1);
    assert_eq!(retransmits[0].app_seq, 3);
    // Immutable retransmission: the frame is the stored ciphertext.
    let stored = session::stored_ciphertext(
        sender.db.conn(),
        &p.rel_id,
        &hex_encode(&retransmits[0].msg_id),
    )
    .unwrap()
    .unwrap();
    assert_eq!(retransmits[0].frame, stored);
    for id in &ids[..2] {
        assert_eq!(
            sender.db.message(id).unwrap().unwrap().state,
            DeliveryState::Acknowledged
        );
    }

    // Deliver the retransmission; the receiver's ledger completes.
    let record = wire_frame::build_record(&retransmits[0].frame).unwrap();
    assert_eq!(
        receive_record(receiver, &p.rel_id, &record).await,
        IngestOutcome::Stored { opens_gap: false }
    );
    let view = receiver.db.receive_view(&p.rel_id, 4096).unwrap();
    assert_eq!(view.max_contiguous_seq, 3);

    // Bodies landed intact and in order.
    let thread = receiver.db.thread(&p.rel_id, 10, None).unwrap();
    let bodies: Vec<String> = thread
        .iter()
        .rev()
        .map(|m| String::from_utf8(m.payload.clone()).unwrap())
        .collect();
    assert_eq!(bodies, vec!["m1", "m2", "m3"]);

    // The next resync covers seq 3 → final ack, nothing retransmitted.
    let req = pass_resync_req(receiver, sender, &p.rel_id).await;
    let retransmits = handle_request(&sender.db, &p.rel_id, &req).unwrap();
    assert!(retransmits.is_empty());
    assert_eq!(
        sender.db.message(&ids[2]).unwrap().unwrap().state,
        DeliveryState::Acknowledged
    );
}

#[tokio::test]
async fn message_expiry() {
    let p = pair_up().await;

    // Inbound message on the inviter, outbound queued on the accepter.
    let inbound_id = random_msg_id();
    let env = Envelope {
        msg_id: inbound_id,
        app_seq: 1,
        sent_at: p.inviter.clock.now_secs(),
        ref_id: None,
        payload: Payload::Msg(Msg::new("hello".into()).unwrap()),
    };
    ingest_envelope(&p.inviter.db, &p.rel_id, &env).unwrap();
    let out_id = queue_text(&p.accepter.db, &p.rel_id, "doomed").await;

    // Just under the horizon: nothing swept.
    p.inviter.clock.advance(MESSAGE_TTL_SECS - 1);
    p.accepter.clock.advance(MESSAGE_TTL_SECS - 1);
    assert_eq!(
        Sync::new(&p.inviter.db)
            .sweep_expired()
            .unwrap()
            .messages_erased,
        0
    );
    assert_eq!(
        Sync::new(&p.accepter.db).sweep_expired().unwrap(),
        super::SweepReport::default()
    );

    // Past 24h: rows erased on both sides.
    p.inviter.clock.advance(2);
    p.accepter.clock.advance(2);
    let report = Sync::new(&p.inviter.db).sweep_expired().unwrap();
    assert_eq!(report.messages_erased, 1);
    assert!(p.inviter.db.message(&inbound_id).unwrap().is_none());

    let report = Sync::new(&p.accepter.db).sweep_expired().unwrap();
    assert_eq!(report.messages_erased, 1);
    assert_eq!(report.outbox_failed, 1);
    assert!(p.accepter.db.message(&out_id).unwrap().is_none());
    assert_eq!(p.accepter.db.queued_len().unwrap(), 0);
}

#[tokio::test]
async fn clock_skew() {
    let p = pair_up().await;
    let now = p.inviter.clock.now_secs();

    // Grossly-future sent_at: rejected, nothing stored.
    let evil = Envelope {
        msg_id: random_msg_id(),
        app_seq: 1,
        sent_at: now + 3600,
        ref_id: None,
        payload: Payload::Msg(Msg::new("pin me to the top".into()).unwrap()),
    };
    let evil_id = evil.msg_id;
    assert!(matches!(
        ingest_envelope(&p.inviter.db, &p.rel_id, &evil),
        Err(SyncError::FutureTimestamp { .. })
    ));
    assert!(p.inviter.db.message(&evil_id).unwrap().is_none());

    // Mildly-future sent_at (honest skew): clamped to local now.
    let mild = Envelope {
        msg_id: random_msg_id(),
        app_seq: 1,
        sent_at: now + 60,
        ref_id: None,
        payload: Payload::Msg(Msg::new("ok".into()).unwrap()),
    };
    let mild_id = mild.msg_id;
    assert_eq!(
        ingest_envelope(&p.inviter.db, &p.rel_id, &mild).unwrap(),
        IngestOutcome::Stored { opens_gap: false }
    );
    let row = p.inviter.db.message(&mild_id).unwrap().unwrap();
    assert_eq!(row.sent_at, now, "clamped to the receiver's clock");
}

/// Mock-transport round trip: two paired instances exchange all
/// 17 envelope types through real session crypto; every one decodes
/// intact and lands in the ledger.
#[tokio::test]
async fn all_17_types_round_trip_through_session() {
    use schat_wire_types::attach::{AttachChunk, AttachHead, AttachHeadPayload, CLASS_IMAGE};
    use schat_wire_types::contact::ContactClose;
    use schat_wire_types::delete::{Delete, DeleteAll};
    use schat_wire_types::edit::Edit;
    use schat_wire_types::policy::{self, ChatPolicy};
    use schat_wire_types::pref::Pref;
    use schat_wire_types::presence::Presence;
    use schat_wire_types::profile::{Profile, ProfileReq};
    use schat_wire_types::read::Read;
    use schat_wire_types::sticker::{StickerCtrl, StickerItem};
    use schat_wire_types::typing::Typing;

    let p = pair_up().await;
    let (sender, receiver) = (&p.accepter, &p.inviter);
    let ref_id = random_msg_id();

    let payloads: Vec<Payload> = vec![
        Payload::Msg(Msg::new("hello".into()).unwrap()),
        Payload::Edit(Edit::new("fixed".into()).unwrap()),
        Payload::Delete(Delete),
        Payload::DeleteAll(DeleteAll),
        Payload::ResyncReq(build_request(&sender.db, &p.rel_id).unwrap()),
        Payload::AttachHead(AttachHeadPayload {
            head: AttachHead {
                media_class: CLASS_IMAGE,
                mime_hint: "image/jpeg".into(),
                orig_ext: "jpg".into(),
                uncompressed_n: 1000,
                chunk_count: 2,
                chunk_bucket: 2,
                content_sha256: [3u8; 32],
                caption: String::new(),
                flags: 0,
            },
            inline: None,
        }),
        Payload::AttachChunk(AttachChunk {
            head_id: [4u8; 16],
            index: 0,
            pad: false,
            data: vec![1, 2, 3],
        }),
        Payload::ContactClose(ContactClose),
        Payload::Profile(Profile {
            name: "Alice".into(),
            jpeg: Vec::new(),
        }),
        Payload::Pref(Pref {
            receive_media: true,
            listen_saver: false,
            inactivity_erase_hours: 720,
        }),
        Payload::ProfileReq(ProfileReq),
        Payload::Sticker(StickerItem {
            kind: 2,
            visibility: 1,
            pack_id: [5u8; 16],
            pack_pk: [6u8; 32],
            item_id: 1,
            w: 512,
            h: 512,
            content_sha256: [7u8; 32],
            bytes: None,
        }),
        Payload::StickerCtrl(StickerCtrl::Ack([8u8; 32])),
        Payload::Presence(Presence {
            in_app: true,
            do_not_disturb: false,
        }),
        Payload::ChatPolicy(ChatPolicy {
            op: policy::OP_RULE_PROPOSE,
            ttl_sec: policy::TTL_24H,
            screenshot: false,
            attach_download: true,
            want_attach: false,
            want_emoji: false,
            want_presence: true,
            want_typing: false,
            want_receipts: false,
            cap_id: 0,
            cap_on: false,
            propose_id: random_msg_id(),
        }),
        Payload::Typing(Typing { typing: true }),
        Payload::Read(Read),
    ];
    assert_eq!(payloads.len(), 17, "the wire speaks exactly 17 types");

    for (i, payload) in payloads.into_iter().enumerate() {
        let msg_id = random_msg_id();
        // EDIT/DELETE/READ carry their target in the envelope's ref_id.
        let targeted = matches!(
            payload,
            Payload::Edit(_) | Payload::Delete(_) | Payload::Read(_)
        );
        let env = Envelope {
            msg_id,
            app_seq: i as u64 + 1,
            sent_at: sender.clock.now_secs(),
            ref_id: targeted.then_some(ref_id),
            payload,
        };
        let plaintext = env.encode().unwrap();
        let frame = session::encrypt(
            sender.db.conn(),
            &p.rel_id,
            &hex_encode(&msg_id),
            &plaintext,
            SystemTime::now(),
        )
        .await
        .unwrap();
        let record = wire_frame::build_record(&frame).unwrap();
        let parsed = wire_frame::parse_record(&record).unwrap();
        let decrypted = session::decrypt(receiver.db.conn(), &p.rel_id, parsed, SystemTime::now())
            .await
            .unwrap();
        let got = decode_envelope(&decrypted).unwrap();
        assert_eq!(got, env, "type code {} mangled", env.envelope_type().code());
        assert_eq!(
            ingest_envelope(&receiver.db, &p.rel_id, &got).unwrap(),
            IngestOutcome::Stored { opens_gap: false }
        );
    }

    let view = receiver.db.receive_view(&p.rel_id, 4096).unwrap();
    assert_eq!(view.max_contiguous_seq, 17);
    assert_eq!(receiver.db.thread(&p.rel_id, 50, None).unwrap().len(), 17);
}

#[tokio::test]
async fn duplicate_delivery_is_dropped() {
    let p = pair_up().await;
    let env = Envelope {
        msg_id: random_msg_id(),
        app_seq: 1,
        sent_at: p.inviter.clock.now_secs(),
        ref_id: None,
        payload: Payload::Msg(Msg::new("once".into()).unwrap()),
    };
    assert_eq!(
        ingest_envelope(&p.inviter.db, &p.rel_id, &env).unwrap(),
        IngestOutcome::Stored { opens_gap: false }
    );
    assert_eq!(
        ingest_envelope(&p.inviter.db, &p.rel_id, &env).unwrap(),
        IngestOutcome::Duplicate
    );
    assert_eq!(p.inviter.db.thread(&p.rel_id, 10, None).unwrap().len(), 1);
}
