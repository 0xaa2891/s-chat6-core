//! The pairing gate, headless: full pairing ceremony between two
//! instances over a mock transport (frames handed over in memory),
//! then encrypt → decrypt → retransmit-identical → session-broken.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rusqlite::Connection;

use super::offer::load_pending;
use super::relationship::insert_relationship;
use super::*;
use crate::session::{self, stores, SessionError};
use crate::store::Db;
use crate::transport::framing;
use crate::transport::Transport;

struct Instance {
    db: Db,
    transport: Arc<Transport>,
    _tmp: tempfile::TempDir,
}

impl Instance {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let transport = Transport::new(tmp.path());
        let db = Db::open_in_memory().unwrap();
        Self {
            db,
            transport,
            _tmp: tmp,
        }
    }
}

/// Simulate the wire: pack a record (with optional intro), read it back.
async fn wire(intro: Option<&[u8]>, frame: &[u8], alert: bool) -> (Option<Vec<u8>>, Vec<u8>) {
    let record = framing::build_record(frame).unwrap();
    let packed = framing::pack(intro, &record, alert).unwrap();
    let mut slice: &[u8] = &packed;
    let opaque = framing::read_frame(&mut slice).await.unwrap().unwrap();
    (opaque.intro, opaque.frame)
}

struct Paired {
    inviter: Instance,
    accepter: Instance,
    rel_id: String,
    sas: String,
}

/// offer → accept → intro frame delivered → request received.
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

    // Accepter's first frame carries the intro (its own signed payload).
    let row = load_relationship(accepter.db.conn(), &accepted.rel_id)
        .unwrap()
        .unwrap();
    assert!(row.intro_pending);
    let frame = session::encrypt(
        accepter.db.conn(),
        &accepted.rel_id,
        "m1",
        b"hello inviter",
        now,
    )
    .await
    .unwrap();
    // First frame must be a PreKeySignalMessage.
    assert_eq!(frame[0], session::TAG_PREKEY);
    let (intro, record) = wire(Some(&row.our_qr_bytes), &frame, true).await;

    let pending = load_pending(inviter.db.conn()).unwrap().unwrap();
    let outcome = ingest_frame(
        inviter.db.conn(),
        &inviter.transport,
        &pending.service_id,
        intro.as_deref(),
        &record,
        now,
    )
    .await
    .unwrap();
    let (rel_id, sas, plaintext) = match outcome {
        Ingest::RequestReceived {
            rel_id,
            sas,
            plaintext,
        } => (rel_id, sas, plaintext),
        other => panic!("expected RequestReceived, got {other:?}"),
    };
    assert_eq!(plaintext, b"hello inviter");
    assert_eq!(rel_id, accepted.rel_id, "both sides derive the same rel_id");
    assert_eq!(sas, accepted.sas, "both sides derive the same safety code");

    Paired {
        inviter,
        accepter,
        rel_id,
        sas,
    }
}

#[tokio::test]
async fn full_ceremony_round_trip() {
    let p = pair_up().await;
    let now = SystemTime::now();

    // The request sits in the inviter's bucket.
    let requests = pending_requests(p.inviter.db.conn()).unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].sas, p.sas);

    // Inviter cannot send before accepting the request.
    let gated = send_message(
        p.inviter.db.conn(),
        &p.inviter.transport,
        &p.rel_id,
        "early",
        b"nope",
        false,
        now,
    )
    .await;
    assert!(matches!(gated, Err(PairingFailure::NotARequest)));

    accept_request(p.inviter.db.conn(), &p.inviter.transport, &p.rel_id)
        .await
        .unwrap();
    let row = load_relationship(p.inviter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap();
    assert_eq!(row.state, STATE_ACTIVE);

    // Inviter replies; accepter decrypts; accepter's intro_pending clears.
    let reply = session::encrypt(p.inviter.db.conn(), &p.rel_id, "m2", b"hi accepter", now)
        .await
        .unwrap();
    assert_eq!(reply[0], session::TAG_SIGNAL);
    let (intro, record) = wire(None, &reply, false).await;
    assert!(intro.is_none());
    let accepter_row = load_relationship(p.accepter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap();
    let outcome = ingest_frame(
        p.accepter.db.conn(),
        &p.accepter.transport,
        &accepter_row.service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();
    match outcome {
        Ingest::Message { plaintext, .. } => assert_eq!(plaintext, b"hi accepter"),
        other => panic!("expected Message, got {other:?}"),
    }
    let accepter_row = load_relationship(p.accepter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap();
    assert!(
        !accepter_row.intro_pending,
        "peer reply clears intro_pending"
    );
}

#[tokio::test]
async fn triple_ratchet_pq_state_advances() {
    // The pinned tag initializes SPQR V1 unconditionally at session
    // establishment ("Require that all clients speak SPQR") and steps
    // the PQ ratchet on every send/recv. Prove it's live: the session's
    // serialized PQ state must exist and change with each message.
    use libsignal_protocol::SessionStore as _;

    async fn pq_state(db: &Connection, rel_id: &str) -> Vec<u8> {
        let store = stores::SqliteSessionStore {
            db,
            namespace: rel_id.into(),
        };
        let rec = store
            .load_session(&session::remote_address(rel_id).unwrap())
            .await
            .unwrap()
            .expect("session exists");
        rec.current_pq_state()
            .expect("SPQR state present from establishment")
            .clone()
    }

    let p = pair_up().await;
    let now = SystemTime::now();

    let accepter0 = pq_state(p.accepter.db.conn(), &p.rel_id).await;
    let inviter0 = pq_state(p.inviter.db.conn(), &p.rel_id).await;
    assert!(!accepter0.is_empty(), "SPQR active on accepter");
    assert!(!inviter0.is_empty(), "SPQR active on inviter");

    accept_request(p.inviter.db.conn(), &p.inviter.transport, &p.rel_id)
        .await
        .unwrap();

    // Inviter → accepter.
    let reply = session::encrypt(p.inviter.db.conn(), &p.rel_id, "m2", b"pq?", now)
        .await
        .unwrap();
    let (_, record) = wire(None, &reply, false).await;
    let service_id = load_relationship(p.accepter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    ingest_frame(
        p.accepter.db.conn(),
        &p.accepter.transport,
        &service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();

    let accepter1 = pq_state(p.accepter.db.conn(), &p.rel_id).await;
    let inviter1 = pq_state(p.inviter.db.conn(), &p.rel_id).await;
    assert_ne!(accepter0, accepter1, "accepter PQ ratchet stepped on recv");
    assert_ne!(inviter0, inviter1, "inviter PQ ratchet stepped on send");

    // Accepter → inviter: steps again.
    let reply2 = session::encrypt(p.accepter.db.conn(), &p.rel_id, "m3", b"pq!", now)
        .await
        .unwrap();
    let (_, record2) = wire(None, &reply2, false).await;
    let inv_service = load_relationship(p.inviter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    ingest_frame(
        p.inviter.db.conn(),
        &p.inviter.transport,
        &inv_service,
        None,
        &record2,
        now,
    )
    .await
    .unwrap();

    let accepter2 = pq_state(p.accepter.db.conn(), &p.rel_id).await;
    let inviter2 = pq_state(p.inviter.db.conn(), &p.rel_id).await;
    assert_ne!(accepter1, accepter2, "accepter PQ ratchet stepped on send");
    assert_ne!(inviter1, inviter2, "inviter PQ ratchet stepped on recv");
}

#[tokio::test]
async fn i11_retransmit_is_byte_identical() {
    let p = pair_up().await;
    let now = SystemTime::now();
    let a = session::encrypt(p.accepter.db.conn(), &p.rel_id, "m9", b"same", now)
        .await
        .unwrap();
    let b = session::encrypt(p.accepter.db.conn(), &p.rel_id, "m9", b"same", now)
        .await
        .unwrap();
    assert_eq!(a, b, "I11: one msg_id → one ciphertext");
    // A different msg_id encrypts fresh (ratchet advanced).
    let c = session::encrypt(p.accepter.db.conn(), &p.rel_id, "m10", b"same", now)
        .await
        .unwrap();
    assert_ne!(a, c);
}

#[tokio::test]
async fn duplicate_delivery_is_transient_not_broken() {
    let p = pair_up().await;
    let now = SystemTime::now();
    accept_request(p.inviter.db.conn(), &p.inviter.transport, &p.rel_id)
        .await
        .unwrap();
    let reply = session::encrypt(p.inviter.db.conn(), &p.rel_id, "m2", b"hi", now)
        .await
        .unwrap();
    let service_id = load_relationship(p.accepter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let (_, record) = wire(None, &reply, false).await;
    // First delivery decrypts.
    let first = ingest_frame(
        p.accepter.db.conn(),
        &p.accepter.transport,
        &service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();
    assert!(matches!(first, Ingest::Message { .. }));
    // Retransmission: duplicate, session stays active.
    let second = ingest_frame(
        p.accepter.db.conn(),
        &p.accepter.transport,
        &service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();
    assert!(matches!(second, Ingest::Duplicate));
    assert_eq!(
        session::session_state(p.accepter.db.conn(), &p.rel_id).unwrap(),
        session::SessionState::Active
    );
}

#[tokio::test]
async fn tampered_ciphertext_breaks_session_fail_closed() {
    let p = pair_up().await;
    let now = SystemTime::now();
    accept_request(p.inviter.db.conn(), &p.inviter.transport, &p.rel_id)
        .await
        .unwrap();
    let mut reply = session::encrypt(p.inviter.db.conn(), &p.rel_id, "m2", b"hi", now)
        .await
        .unwrap();
    // Flip a byte near the end (the MAC region).
    let n = reply.len();
    reply[n - 2] ^= 0x01;
    let service_id = load_relationship(p.accepter.db.conn(), &p.rel_id)
        .unwrap()
        .unwrap()
        .service_id;
    let (_, record) = wire(None, &reply, false).await;
    let outcome = ingest_frame(
        p.accepter.db.conn(),
        &p.accepter.transport,
        &service_id,
        None,
        &record,
        now,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, Ingest::SessionBroken { .. }));
    assert_eq!(
        session::session_state(p.accepter.db.conn(), &p.rel_id).unwrap(),
        session::SessionState::Broken
    );
    // No auto-reset: further decrypt attempts refuse.
    let again = session::decrypt(p.accepter.db.conn(), &p.rel_id, &reply, now).await;
    assert!(matches!(again, Err(SessionError::Broken(_))));
    // And the accepter cannot send on a broken session.
    let send = session::encrypt(p.accepter.db.conn(), &p.rel_id, "m3", b"x", now).await;
    assert!(matches!(send, Err(SessionError::Broken(_))));
}

#[tokio::test]
async fn expired_offer_fails_closed() {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let now = SystemTime::now();
    let offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    let later = now + Duration::from_secs(qr::OFFER_TTL_SECONDS + 1);
    let result = accept(
        accepter.db.conn(),
        &accepter.transport,
        &offer.qr_bytes,
        later,
    )
    .await;
    assert!(matches!(
        result,
        Err(PairingFailure::Payload(qr::PairingError::Expired))
    ));
    // Fail closed: nothing written on the accepter side.
    let count: i64 = accepter
        .db
        .conn()
        .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    let locals: i64 = accepter
        .db
        .conn()
        .query_row("SELECT COUNT(*) FROM signal_locals", [], |r| r.get(0))
        .unwrap();
    assert_eq!(locals, 0);
}

#[tokio::test]
async fn tampered_qr_fails_closed() {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let now = SystemTime::now();
    let offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    let mut bad = offer.qr_bytes.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x40;
    let result = accept(accepter.db.conn(), &accepter.transport, &bad, now).await;
    assert!(matches!(result, Err(PairingFailure::Payload(_))));
    let count: i64 = accepter
        .db
        .conn()
        .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn self_pairing_rejected() {
    let instance = Instance::new();
    let now = SystemTime::now();
    let offer = offer(instance.db.conn(), &instance.transport, now)
        .await
        .unwrap();
    let result = accept(
        instance.db.conn(),
        &instance.transport,
        &offer.qr_bytes,
        now,
    )
    .await;
    assert!(matches!(result, Err(PairingFailure::SelfPairing)));
}

#[tokio::test]
async fn one_time_code_path_matches_qr_path() {
    let inviter = Instance::new();
    let accepter = Instance::new();
    let now = SystemTime::now();
    let offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    // Paste the code instead of scanning the QR.
    let accepted = accept_code(accepter.db.conn(), &accepter.transport, &offer.code, now)
        .await
        .unwrap();
    assert!(!accepted.rel_id.is_empty());
    assert_eq!(accepted.sas.len(), 8);
}

#[tokio::test]
async fn sweep_removes_expired_offer_and_persona() {
    let inviter = Instance::new();
    let now = SystemTime::now();
    let offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    assert!(load_pending(inviter.db.conn()).unwrap().is_some());
    let later = now + Duration::from_secs(qr::OFFER_TTL_SECONDS + 1);
    sweep_expired(inviter.db.conn(), &inviter.transport, later)
        .await
        .unwrap();
    assert!(load_pending(inviter.db.conn()).unwrap().is_none());
    let locals: i64 = inviter
        .db
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM signal_locals WHERE namespace = 'pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(locals, 0, "expired persona destroyed");
    // And the service is gone from the transport.
    assert!(!inviter
        .transport
        .status()
        .services
        .iter()
        .any(|s| s.onion.as_deref() == Some(offer.onion.as_str())));
}

#[tokio::test]
async fn abort_clears_pending() {
    let inviter = Instance::new();
    let now = SystemTime::now();
    offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    abort_offer(inviter.db.conn(), &inviter.transport)
        .await
        .unwrap();
    assert!(load_pending(inviter.db.conn()).unwrap().is_none());
}

#[tokio::test]
async fn encrypt_rejects_oversize_plaintext_before_storing() {
    // Bounds gate: a plaintext that can never fit a record
    // bucket is refused before crypto and before the I11 row exists.
    let p = pair_up().await;
    let now = SystemTime::now();
    let oversize = vec![0u8; schat_wire_types::limits::envelope::MAX_ENVELOPE_BYTES + 1];
    let result = session::encrypt(p.accepter.db.conn(), &p.rel_id, "big", &oversize, now).await;
    assert!(
        matches!(result, Err(SessionError::TooLarge { .. })),
        "oversize plaintext refused"
    );
    // Fail closed: nothing was stored under that msg_id.
    assert!(
        session::stored_ciphertext(p.accepter.db.conn(), &p.rel_id, "big")
            .unwrap()
            .is_none()
    );

    // At-limit plaintext encrypts and the frame fits a record bucket.
    let at_limit = vec![0u8; schat_wire_types::limits::envelope::MAX_ENVELOPE_BYTES];
    // The envelope ceiling leaves room for Signal overhead; raw payloads
    // at the exact ceiling may still overflow the record — the gate
    // guarantees *rejection before store*, the record check guarantees
    // *rejection before send*. Both layers fail closed.
    match session::encrypt(p.accepter.db.conn(), &p.rel_id, "max", &at_limit, now).await {
        Ok(frame) => assert!(framing::build_record(&frame).is_ok()),
        Err(SessionError::TooLarge { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
    }
}

#[tokio::test]
async fn pending_request_bucket_is_capped() {
    // One open offer cannot accumulate unbounded request
    // rows. Insert the cap's worth of dummy requests directly, then the
    // gate must report full for a new rel_id but not for an existing one.
    let inviter = Instance::new();
    let db = inviter.db.conn();
    let dummy_key = [7u8; 33];
    let nonce = [1u8; 32];
    for i in 0..crate::limits::pairing::MAX_PENDING_REQUESTS {
        insert_relationship(
            db,
            &format!("rel{i:032x}"),
            ROLE_INVITER,
            STATE_REQUEST,
            &format!("svc{i}"),
            "our.onion",
            "peer.onion",
            &dummy_key,
            "auth",
            "priv",
            &nonce,
            &nonce,
            b"qr",
            false,
            1000,
        )
        .unwrap();
    }
    assert!(super::ingest::request_bucket_full(db, &format!("rel{:032x}", 0xdead)).unwrap());
    // A re-intro for an existing request is a redelivery, not growth.
    assert!(!super::ingest::request_bucket_full(db, &format!("rel{:032x}", 0)).unwrap());
}

#[tokio::test]
async fn intro_identity_mismatch_dropped() {
    // An intro whose claimed identity differs from the pre-key
    // message's identity must not create a relationship.
    let inviter = Instance::new();
    let accepter = Instance::new();
    let now = SystemTime::now();
    let inviter_offer = offer(inviter.db.conn(), &inviter.transport, now)
        .await
        .unwrap();
    let accepted = accept(
        accepter.db.conn(),
        &accepter.transport,
        &inviter_offer.qr_bytes,
        now,
    )
    .await
    .unwrap();
    let frame = session::encrypt(accepter.db.conn(), &accepted.rel_id, "m1", b"x", now)
        .await
        .unwrap();
    // Forge: someone else's payload as the intro.
    let other = Instance::new();
    let other_offer = offer(other.db.conn(), &other.transport, now).await.unwrap();
    let (_, record) = wire(Some(&other_offer.qr_bytes), &frame, true).await;
    let pending = load_pending(inviter.db.conn()).unwrap().unwrap();
    let outcome = ingest_frame(
        inviter.db.conn(),
        &inviter.transport,
        &pending.service_id,
        Some(&other_offer.qr_bytes),
        &record,
        now,
    )
    .await
    .unwrap();
    assert!(matches!(outcome, Ingest::Dropped));
    let count: i64 = inviter
        .db
        .conn()
        .query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}
