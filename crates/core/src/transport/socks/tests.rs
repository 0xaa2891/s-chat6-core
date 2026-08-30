//! SOCKS path tests: handshake bytes against a mock server, sender
//! coalescing / hold / reconnect behavior, kill-switch and offline gates,
//! and the backoff schedule.

use super::*;
use crate::transport::error::TransportError;
use crate::transport::onion;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn accept_socks(
    listener: &tokio::net::TcpListener,
    expected_host: &str,
) -> tokio::net::TcpStream {
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut greeting = [0u8; 3];
    sock.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x01, 0x02]);
    sock.write_all(&[0x05, 0x02]).await.unwrap();
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x01);
    let mut user = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut user).await.unwrap();
    assert_eq!(user, b"chat");
    let mut plen = [0u8; 1];
    sock.read_exact(&mut plen).await.unwrap();
    let mut pass = vec![0u8; plen[0] as usize];
    sock.read_exact(&mut pass).await.unwrap();
    assert_eq!(pass, b"chat");
    sock.write_all(&[0x01, 0x00]).await.unwrap();
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.unwrap();
    assert_eq!(req, [0x05, 0x01, 0x00, 0x03]);
    let mut hlen = [0u8; 1];
    sock.read_exact(&mut hlen).await.unwrap();
    let mut host = vec![0u8; hlen[0] as usize];
    sock.read_exact(&mut host).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&host), expected_host);
    let mut port = [0u8; 2];
    sock.read_exact(&mut port).await.unwrap();
    assert_eq!(u16::from_be_bytes(port), 80);
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    sock
}

async fn echo_read(sock: &mut tokio::net::TcpStream, payload_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; payload_len];
    sock.read_exact(&mut buf).await.unwrap();
    sock.write_all(&buf).await.unwrap();
    buf
}

async fn handshake_and_read(
    listener: &tokio::net::TcpListener,
    expected_host: &str,
    payload_len: usize,
) -> Vec<u8> {
    let mut sock = accept_socks(listener, expected_host).await;
    echo_read(&mut sock, payload_len).await
}

async fn mock_socks_server(listener: tokio::net::TcpListener, expected_host: String) -> Vec<u8> {
    handshake_and_read(&listener, &expected_host, 259).await
}

fn test_onion() -> String {
    onion::hostname_from_pubkey(&[9u8; 32])
}

#[tokio::test]
async fn handshake_bytes_and_connect() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = test_onion();
    let server = tokio::spawn(mock_socks_server(listener, format!("{host}.onion")));

    let mut stream = socks_connect(addr, &host, 80, PURPOSE_CHAT).await.unwrap();
    let payload = vec![0xabu8; 259];
    stream.write_all(&payload).await.unwrap();
    let mut echo = vec![0u8; 259];
    stream.read_exact(&mut echo).await.unwrap();
    assert_eq!(echo, payload);
    assert_eq!(server.await.unwrap(), payload);
}

#[tokio::test]
async fn sender_delivers_coalesced() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = format!("{}.onion", test_onion());
    let server = tokio::spawn(mock_socks_server(listener, host.clone()));

    let sender = Sender::new(
        addr,
        80,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(true)),
    );
    let payload = vec![0x42u8; 259];
    sender.send(&host, payload.clone()).await.unwrap();
    assert_eq!(server.await.unwrap(), payload);
}

#[tokio::test]
async fn sender_reuses_stream_within_hold() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = format!("{}.onion", test_onion());
    let host_for_server = host.clone();
    let server = tokio::spawn(async move {
        let mut sock = accept_socks(&listener, &host_for_server).await;
        let a = echo_read(&mut sock, 259).await;
        let b = echo_read(&mut sock, 259).await;
        (a, b)
    });

    let sender = Sender::with_hold(
        addr,
        80,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(true)),
        Duration::from_secs(5),
    );
    let first = vec![0x11u8; 259];
    let second = vec![0x22u8; 259];
    sender.send(&host, first.clone()).await.unwrap();
    sender.send(&host, second.clone()).await.unwrap();
    let (a, b) = server.await.unwrap();
    assert_eq!(a, first);
    assert_eq!(b, second);
}

#[tokio::test]
async fn sender_new_connect_after_hold() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = format!("{}.onion", test_onion());
    let host_for_server = host.clone();
    let server = tokio::spawn(async move {
        let a = handshake_and_read(&listener, &host_for_server, 259).await;
        let b = handshake_and_read(&listener, &host_for_server, 259).await;
        (a, b)
    });

    let sender = Sender::with_hold(
        addr,
        80,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(true)),
        Duration::from_millis(40),
    );
    let first = vec![0x11u8; 259];
    let second = vec![0x22u8; 259];
    sender.send(&host, first.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    sender.send(&host, second.clone()).await.unwrap();
    let (a, b) = server.await.unwrap();
    assert_eq!(a, first);
    assert_eq!(b, second);
}

#[tokio::test]
async fn kill_switch_refuses_sends() {
    let sender = Sender::new(
        "127.0.0.1:1".parse().unwrap(),
        80,
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(true)),
    );
    let err = sender
        .send(&format!("{}.onion", test_onion()), vec![1])
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::KillSwitch));
}

#[tokio::test]
async fn offline_refuses_sends() {
    let sender = Sender::new(
        "127.0.0.1:1".parse().unwrap(),
        80,
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    );
    let err = sender
        .send(&format!("{}.onion", test_onion()), vec![1])
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Offline));
}

#[test]
fn backoff_schedule_matches_port() {
    // 1500 << min(fails-1, 4), capped 24000, plus <1000 jitter.
    assert_eq!(connect_backoff(1, 0), Duration::from_millis(1500));
    assert_eq!(connect_backoff(2, 0), Duration::from_millis(3000));
    assert_eq!(connect_backoff(3, 0), Duration::from_millis(6000));
    assert_eq!(connect_backoff(4, 0), Duration::from_millis(12000));
    assert_eq!(connect_backoff(5, 0), Duration::from_millis(24000));
    assert_eq!(connect_backoff(8, 0), Duration::from_millis(24000));
    assert_eq!(connect_backoff(1, 999), Duration::from_millis(1500 + 999));
}

#[tokio::test]
async fn handshake_rejects_wrong_method() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        sock.read_exact(&mut greeting).await.unwrap();
        sock.write_all(&[0x05, 0xff]).await.unwrap(); // no acceptable methods
    });
    let err = socks_connect(addr, &test_onion(), 80, PURPOSE_CHAT)
        .await
        .unwrap_err();
    assert!(matches!(err, TransportError::Socks(_)));
    server.await.unwrap();
}

#[tokio::test]
async fn domain_atyp_never_resolves() {
    // A syntactically valid but nonexistent onion still goes out as
    // ATYP=domain — the mock asserts the exact hostname bytes, then we
    // drop both ends (no payload in this test).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host = test_onion();
    let expected = format!("{host}.onion");
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        sock.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x02]);
        sock.write_all(&[0x05, 0x02]).await.unwrap();
        let mut hdr = [0u8; 2];
        sock.read_exact(&mut hdr).await.unwrap();
        let mut user = vec![0u8; hdr[1] as usize];
        sock.read_exact(&mut user).await.unwrap();
        assert_eq!(user, b"chat");
        let mut plen = [0u8; 1];
        sock.read_exact(&mut plen).await.unwrap();
        let mut pass = vec![0u8; plen[0] as usize];
        sock.read_exact(&mut pass).await.unwrap();
        sock.write_all(&[0x01, 0x00]).await.unwrap();
        let mut req = [0u8; 4];
        sock.read_exact(&mut req).await.unwrap();
        assert_eq!(req[3], 0x03, "ATYP must be domain");
        let mut hlen = [0u8; 1];
        sock.read_exact(&mut hlen).await.unwrap();
        let mut got = vec![0u8; hlen[0] as usize];
        sock.read_exact(&mut got).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&got), expected);
        let mut port = [0u8; 2];
        sock.read_exact(&mut port).await.unwrap();
        sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    });
    let _stream = socks_connect(addr, &host, 80, PURPOSE_CHAT).await.unwrap();
    server.await.unwrap();
}
