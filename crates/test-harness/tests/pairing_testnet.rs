//! Combined gate: the full pairing ceremony and an encrypted
//! round-trip between two headless instances over **real** onion services
//! on the Chutney testnet — no mock transport.
//!
//! Skips unless `SCHAT_CHUTNEY_NODES` points at a running Chutney nodes dir
//! (see `tools/testnet/run-testnet.sh`) and a `tor` binary is available.

use std::time::{Duration, SystemTime};

use schat_core::pairing::{self, Ingest};
use schat_core::store::Db;
use schat_test_harness::{chutney_nodes, tor_binary, TestInstance};
use tokio::sync::broadcast::error::RecvError;

const ONLINE_TIMEOUT: Duration = Duration::from_secs(180);
const SEND_TIMEOUT: Duration = Duration::from_secs(180);
const DROP_TIMEOUT: Duration = Duration::from_secs(180);

macro_rules! require_testnet {
    () => {
        match chutney_nodes() {
            Some(dir) if tor_binary().is_some() => dir,
            _ => {
                eprintln!(
                    "skip: set SCHAT_CHUTNEY_NODES to a running Chutney nodes dir \
                     (tools/testnet/run-testnet.sh s-chat6-min)"
                );
                return;
            }
        }
    };
}

/// Alice (inviter) offers, Bob (accepter) scans; Bob's request arrives over
/// Tor, Alice accepts, then both exchange libsignal-encrypted messages in
/// both directions — every frame carried by a real onion circuit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_and_encrypted_roundtrip_over_tor() {
    let nodes = require_testnet!();
    let alice = TestInstance::new("alice-p2", &nodes).await.expect("alice");
    let bob = TestInstance::new("bob-p2", &nodes).await.expect("bob");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await, "alice online");
    assert!(bob.wait_online(ONLINE_TIMEOUT).await, "bob online");

    let alice_db = Db::open_in_memory().expect("alice db");
    let bob_db = Db::open_in_memory().expect("bob db");
    let now = SystemTime::now();

    // Stage 2: alice creates a one-way offer (real onion service, 5-min TTL).
    let offer = pairing::offer(alice_db.conn(), &alice.transport, now)
        .await
        .expect("offer");
    eprintln!("offer: onion={} ttl={}s", offer.onion, offer.expires_at);

    // Bob accepts from the QR bytes: verifies signature + expiry, builds his
    // persona, processes alice's PQXDH bundle, hosts his restricted service.
    let accepted = pairing::accept(bob_db.conn(), &bob.transport, &offer.qr_bytes, now)
        .await
        .expect("accept");
    eprintln!("accepted: rel={} sas={}", accepted.rel_id, accepted.sas);

    // Bob's first send carries his intro + first encrypted message to
    // alice's invitation onion. Retry until alice's descriptor propagates
    // through the testnet HSDirs (I11: same msg_id → byte-identical retry).
    let mut alice_drops = alice.drops();
    let send_deadline = std::time::Instant::now() + SEND_TIMEOUT;
    loop {
        match pairing::send_message(
            bob_db.conn(),
            &bob.transport,
            &accepted.rel_id,
            "m1",
            b"hi alice, add me?",
            true,
            now,
        )
        .await
        {
            Ok(()) => break,
            Err(e) if std::time::Instant::now() < send_deadline => {
                eprintln!("bob intro send not yet routable: {e}; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => panic!("bob intro send failed: {e}"),
        }
    }

    // Alice ingests frames from her real inbound listener until the request
    // arrives: intro verified, first message decrypted, SAS computed.
    let ingest_deadline = std::time::Instant::now() + DROP_TIMEOUT;
    let (rel_id, sas_alice, intro_plaintext) = loop {
        let remaining = ingest_deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remaining.is_zero(), "alice never received bob's request");
        match tokio::time::timeout(remaining, alice_drops.recv()).await {
            Ok(Ok(drop)) => {
                match pairing::ingest_frame(
                    alice_db.conn(),
                    &alice.transport,
                    &drop.service_id,
                    drop.frame.intro.as_deref(),
                    &drop.frame.frame,
                    SystemTime::now(),
                )
                .await
                {
                    Ok(Ingest::RequestReceived {
                        rel_id,
                        sas,
                        plaintext,
                    }) => break (rel_id, sas, plaintext),
                    Ok(other) => eprintln!("alice ingest: {other:?} (waiting for request)"),
                    Err(e) => eprintln!("alice ingest error: {e} (waiting for request)"),
                }
            }
            Ok(Err(RecvError::Lagged(_))) => continue,
            other => panic!("alice drop stream ended: {other:?}"),
        }
    };
    assert_eq!(intro_plaintext, b"hi alice, add me?");
    assert_eq!(rel_id, accepted.rel_id, "same relationship both sides");
    assert_eq!(sas_alice, accepted.sas, "safety codes match out of band");

    // Alice accepts the request: her service flips to restricted,
    // discoverable only by bob's client-auth key.
    pairing::accept_request(alice_db.conn(), &alice.transport, &rel_id)
        .await
        .expect("accept request");

    // Alice → Bob, over tor, end-to-end encrypted.
    let mut bob_drops = bob.drops();
    let send_deadline = std::time::Instant::now() + SEND_TIMEOUT;
    loop {
        match pairing::send_message(
            alice_db.conn(),
            &alice.transport,
            &rel_id,
            "m2",
            b"hello bob",
            true,
            now,
        )
        .await
        {
            Ok(()) => break,
            Err(e) if std::time::Instant::now() < send_deadline => {
                eprintln!("alice send not yet routable: {e}; retrying");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => panic!("alice send failed: {e}"),
        }
    }
    let plaintext = wait_for_message(&bob, &bob_db, &mut bob_drops).await;
    assert_eq!(plaintext, b"hello bob", "bob decrypted alice's message");

    // Bob → Alice, the other way around.
    pairing::send_message(
        bob_db.conn(),
        &bob.transport,
        &rel_id,
        "m3",
        b"hello alice",
        true,
        now,
    )
    .await
    .expect("bob reply send");
    let plaintext = wait_for_message(&alice, &alice_db, &mut alice_drops).await;
    assert_eq!(plaintext, b"hello alice", "alice decrypted bob's reply");

    alice.stop().await;
    bob.stop().await;
}

/// Ingest drops until one decrypts to an application message.
async fn wait_for_message(
    inst: &TestInstance,
    db: &Db,
    drops: &mut tokio::sync::broadcast::Receiver<schat_core::transport::inbound::InboundDrop>,
) -> Vec<u8> {
    let deadline = std::time::Instant::now() + DROP_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "{} never received the message",
            inst.name
        );
        match tokio::time::timeout(remaining, drops.recv()).await {
            Ok(Ok(drop)) => {
                match pairing::ingest_frame(
                    db.conn(),
                    &inst.transport,
                    &drop.service_id,
                    drop.frame.intro.as_deref(),
                    &drop.frame.frame,
                    SystemTime::now(),
                )
                .await
                {
                    Ok(Ingest::Message { plaintext, .. }) => break plaintext,
                    Ok(other) => eprintln!("{} ingest: {other:?} (waiting)", inst.name),
                    Err(e) => eprintln!("{} ingest error: {e} (waiting)", inst.name),
                }
            }
            Ok(Err(RecvError::Lagged(_))) => continue,
            other => panic!("{} drop stream ended: {other:?}", inst.name),
        }
    }
}
