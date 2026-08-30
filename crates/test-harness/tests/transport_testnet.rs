//! Gate tests against the Chutney simulated Tor network.
//!
//! Every test **skips** unless `SCHAT_CHUTNEY_NODES` points at a configured,
//! running Chutney nodes dir (see `tools/testnet/run-testnet.sh`) and a `tor`
//! binary is available. No test ever touches the real Tor network.

use std::time::Duration;

use schat_core::transport::circumvention::CircumventionConfig;
use schat_core::transport::control::ControlClient;
use schat_core::transport::daemon::TorDaemon;
use schat_core::transport::error::TransportError;
use schat_core::transport::status::TorState;
use schat_test_harness::{chutney_nodes, tor_binary, TestInstance};

const ONLINE_TIMEOUT: Duration = Duration::from_secs(180);
const DROP_TIMEOUT: Duration = Duration::from_secs(120);

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

/// Route transport tracing into test output (`--nocapture`, RUST_LOG).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

/// 1.1 step 6: authenticate against a real Chutney-spawned tor and read
/// bootstrap progress to 100.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_bootstrap_testnet() {
    let nodes = require_testnet!();
    let inst = TestInstance::new("ctl", &nodes).await.expect("instance");
    let deadline = std::time::Instant::now() + ONLINE_TIMEOUT;
    let pct = loop {
        let auth = inst.daemon.control_auth();
        if let Ok(control) = ControlClient::connect(inst.daemon.control_addr(), auth).await {
            if let Ok(100) = control.bootstrap_progress().await {
                break 100u8;
            }
        }
        if std::time::Instant::now() > deadline {
            panic!("tor did not reach PROGRESS=100 on the testnet");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    assert_eq!(pct, 100);
    inst.stop().await;
}

/// Two headless instances exchange raw frames both directions.
/// Also covers `onion_publish` (B fetches A's descriptor to connect).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_instances_exchange_frames() {
    let nodes = require_testnet!();
    let alice = TestInstance::new("alice", &nodes).await.expect("alice");
    let bob = TestInstance::new("bob", &nodes).await.expect("bob");

    let alice_onion = alice.host("inbox", false).await.expect("alice host");
    let bob_onion = bob.host("inbox", false).await.expect("bob host");

    assert!(alice.wait_online(ONLINE_TIMEOUT).await, "alice online");
    assert!(bob.wait_online(ONLINE_TIMEOUT).await, "bob online");

    let mut alice_drops = alice.drops();
    let mut bob_drops = bob.drops();

    alice
        .send_text(&bob_onion, "hello-bob", true)
        .await
        .expect("alice send");
    assert!(
        bob.wait_for_drop(&mut bob_drops, "hello-bob", DROP_TIMEOUT)
            .await,
        "bob received alice's frame"
    );

    bob.send_text(&alice_onion, "hello-alice", true)
        .await
        .expect("bob send");
    assert!(
        alice
            .wait_for_drop(&mut alice_drops, "hello-alice", DROP_TIMEOUT)
            .await,
        "alice received bob's frame"
    );

    alice.stop().await;
    bob.stop().await;
}

/// A restricted service is undiscoverable without the client key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restricted_discovery_negative() {
    let nodes = require_testnet!();
    let alice = TestInstance::new("alice-rd", &nodes).await.expect("alice");
    let bob = TestInstance::new("bob-rd", &nodes).await.expect("bob");

    let onion = alice.host("chat", true).await.expect("restricted host");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await);
    assert!(bob.wait_online(ONLINE_TIMEOUT).await);

    // Bob has no client-auth key: the descriptor fetch must fail. The send
    // path surfaces this as a connect failure (never a silent drop).
    let mut bob_drops = bob.drops();
    let _ = &mut bob_drops;
    let result = alice.transport.status(); // keep status exercised
    assert!(matches!(result.tor, TorState::Online));
    let err = bob.send_text(&onion, "should-not-arrive", false).await;
    assert!(err.is_err(), "send without client key must fail");

    // With the private key installed, discovery works.
    let private = alice
        .transport
        .client_auth_private("chat")
        .await
        .expect("key lookup")
        .expect("restricted service has a client key");
    bob.transport
        .install_client_auth(&onion, &private)
        .await
        .expect("install client auth");

    let mut alice_drops = alice.drops();
    // Retry until the descriptor fetch with auth succeeds (HSDir propagation).
    let deadline = std::time::Instant::now() + DROP_TIMEOUT;
    loop {
        match bob.send_text(&onion, "authorized", true).await {
            Ok(()) => break,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => panic!("authorized send failed: {e}"),
        }
    }
    assert!(
        alice
            .wait_for_drop(&mut alice_drops, "authorized", DROP_TIMEOUT)
            .await,
        "alice received bob's authorized frame"
    );

    alice.stop().await;
    bob.stop().await;
}

/// Kill a peer's tor, restart it: the same onion address comes back
/// (persisted key blob) and the descriptor republishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn descriptor_republish() {
    let nodes = require_testnet!();
    let alice = TestInstance::new("alice-rp", &nodes).await.expect("alice");
    let bob = TestInstance::new("bob-rp", &nodes).await.expect("bob");

    let onion_before = alice.host("inbox", false).await.expect("host");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await);
    assert!(bob.wait_online(ONLINE_TIMEOUT).await);

    // Kill alice's tor and restart the whole transport stack.
    alice.transport.stop().await;
    alice.daemon.start().await.expect("daemon restart");
    alice.transport.start().await.expect("transport restart");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await, "alice back online");

    let onion_after = alice
        .transport
        .status()
        .services
        .iter()
        .find(|s| s.service_id == "inbox")
        .and_then(|s| s.onion.clone())
        .expect("service re-hosted");
    assert_eq!(
        onion_before, onion_after,
        "key blob persisted across restart"
    );

    let mut alice_drops = alice.drops();
    // Republish + client-side descriptor refetch (bob's tor holds a stale
    // cached descriptor with dead intro points) takes minutes on a
    // 20 s-consensus testnet — much longer than a fresh publish.
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    loop {
        match bob.send_text(&onion_after, "after-republish", true).await {
            Ok(()) => break,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => panic!("send after republish failed: {e}"),
        }
    }
    assert!(
        alice
            .wait_for_drop(&mut alice_drops, "after-republish", DROP_TIMEOUT)
            .await,
        "alice received frame after republish"
    );

    alice.stop().await;
    bob.stop().await;
}

/// Kill switch: all traffic stops, then resumes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kill_switch() {
    init_tracing();
    let nodes = require_testnet!();
    let alice = TestInstance::new("alice-ks", &nodes).await.expect("alice");
    let bob = TestInstance::new("bob-ks", &nodes).await.expect("bob");
    let bob_onion = bob.host("inbox", false).await.expect("bob host");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await);
    assert!(bob.wait_online(ONLINE_TIMEOUT).await);

    alice
        .transport
        .set_kill_switch(true)
        .await
        .expect("kill switch on");
    let err = alice.send_text(&bob_onion, "blocked", false).await;
    assert!(
        matches!(err, Err(TransportError::KillSwitch)),
        "send refused while kill switch on: {err:?}"
    );
    assert!(alice.transport.status().kill_switch);

    alice
        .transport
        .set_kill_switch(false)
        .await
        .expect("kill switch off");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await, "alice back online");

    let mut bob_drops = bob.drops();
    alice
        .send_text(&bob_onion, "resumed", true)
        .await
        .expect("send after release");
    assert!(
        bob.wait_for_drop(&mut bob_drops, "resumed", DROP_TIMEOUT)
            .await,
        "bob received after kill switch release"
    );

    alice.stop().await;
    bob.stop().await;
}

/// Circumvention config applies as a SETCONF batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn circumvention() {
    let nodes = require_testnet!();
    let inst = TestInstance::new("circ", &nodes).await.expect("instance");
    assert!(inst.wait_online(ONLINE_TIMEOUT).await);

    let config = CircumventionConfig {
        use_bridges: false,
        bridges: vec![],
        fascist_firewall: true,
        prefer_ipv6: false,
        use_ipv4: true,
        use_ipv6: false,
        pt_available: false,
    };
    let warning = inst
        .transport
        .apply_circumvention(&config)
        .await
        .expect("apply circumvention");
    assert!(warning.is_none(), "no PT bridges → no warning");

    // PT bridge without a PT binary → honest warning.
    let pt_config = CircumventionConfig {
        use_bridges: true,
        bridges: vec!["obfs4 127.0.0.1:1 cert=deadbeef".into()],
        pt_available: false,
        ..Default::default()
    };
    let warning = inst
        .transport
        .apply_circumvention(&pt_config)
        .await
        .expect("apply pt config");
    assert!(warning.is_some(), "PT warning surfaced");

    // Restore defaults so the instance is not left firewalled.
    inst.transport
        .apply_circumvention(&CircumventionConfig::default())
        .await
        .expect("reset circumvention");
    inst.stop().await;
}

/// Roaming reset: network flap runs the DisableNetwork dance and recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn roaming_reset() {
    let nodes = require_testnet!();
    let alice = TestInstance::new("alice-roam", &nodes)
        .await
        .expect("alice");
    let bob = TestInstance::new("bob-roam", &nodes).await.expect("bob");
    let bob_onion = bob.host("inbox", false).await.expect("bob host");
    assert!(alice.wait_online(ONLINE_TIMEOUT).await);
    assert!(bob.wait_online(ONLINE_TIMEOUT).await);

    alice
        .transport
        .on_network_changed(false)
        .await
        .expect("path lost");
    let status = alice.transport.status();
    assert!(
        matches!(status.tor, TorState::Degraded { .. }),
        "degraded after path loss: {:?}",
        status.tor
    );

    alice
        .transport
        .on_network_changed(true)
        .await
        .expect("path regained");
    assert!(
        alice.wait_online(ONLINE_TIMEOUT).await,
        "alice online after roaming reset"
    );

    let mut bob_drops = bob.drops();
    let deadline = std::time::Instant::now() + DROP_TIMEOUT;
    loop {
        match alice.send_text(&bob_onion, "post-flap", true).await {
            Ok(()) => break,
            Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
            Err(e) => panic!("send after flap failed: {e}"),
        }
    }
    assert!(
        bob.wait_for_drop(&mut bob_drops, "post-flap", DROP_TIMEOUT)
            .await,
        "bob received after roaming reset"
    );

    alice.stop().await;
    bob.stop().await;
}
