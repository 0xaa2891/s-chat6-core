//! Control-port tests: reply parser units, a scripted mock server that
//! checks the client's commands byte-for-byte, the attach
//! contract double, and parser proptests.

use super::*;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

#[test]
fn parse_single_line_reply() {
    let mut p = ReplyParser::new();
    assert!(p.feed("250-service/version=0.4.9.11").unwrap().is_none());
    let reply = p.feed("250 OK").unwrap().expect("complete");
    assert_eq!(reply.code, 250);
    assert_eq!(reply.get("service/version"), Some("0.4.9.11"));
}

#[test]
fn parse_data_block_reply() {
    let mut p = ReplyParser::new();
    assert!(p.feed("250+status/bootstrap-phase=").unwrap().is_none());
    assert!(p
        .feed("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"")
        .unwrap()
        .is_none());
    assert!(p.feed(".").unwrap().is_none());
    let reply = p.feed("250 OK").unwrap().expect("complete");
    assert_eq!(
        reply.get("status/bootstrap-phase"),
        Some("NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"")
    );
}

#[test]
fn parse_error_reply() {
    let mut p = ReplyParser::new();
    let reply = p
        .feed("512 Syntax error in SETCONF argument")
        .unwrap()
        .expect("complete");
    assert_eq!(reply.code, 512);
    assert!(!reply.is_ok());
}

#[test]
fn garbage_line_rejected() {
    let mut p = ReplyParser::new();
    assert!(p.feed("hello world").is_err());
    assert!(p.feed("25 OK").is_err());
    assert!(p.feed("250?bad separator").is_err());
}

#[test]
fn parse_events() {
    assert_eq!(
        parse_event("650 HS_DESC UPLOADED abc123 UNKNOWN"),
        TorEvent::HsDesc {
            action: "UPLOADED".into(),
            args: vec!["abc123".into(), "UNKNOWN".into()]
        }
    );
    match parse_event("650 STATUS_GENERAL NOTICE BOOTSTRAP PROGRESS=100") {
        TorEvent::StatusGeneral {
            severity, action, ..
        } => {
            assert_eq!(severity, "NOTICE");
            assert_eq!(action, "BOOTSTRAP");
        }
        other => panic!("{other:?}"),
    }
    match parse_event("650 CIRC 42 BUILT $fingerprint~name") {
        TorEvent::Circ { action, .. } => assert_eq!(action, "BUILT"),
        other => panic!("{other:?}"),
    }
}

/// Scripted mock control server: replays a captured session and checks
/// the client's commands byte-for-byte.
#[tokio::test]
async fn mock_server_session_byte_exact() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    async fn read_line(sock: &mut tokio::net::TcpStream) -> String {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = sock.read(&mut byte).await.unwrap();
            if n == 0 {
                return String::from_utf8_lossy(&out).to_string();
            }
            out.push(byte[0]);
            if out.ends_with(b"\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&out[..out.len() - 2]).to_string()
    }

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();

        // AUTHENTICATE with cookie 0x00 0x01 0xff
        assert_eq!(read_line(&mut sock).await, "AUTHENTICATE 0001ff");
        sock.write_all(b"250 OK\r\n").await.unwrap();

        // SETEVENTS
        assert_eq!(
            read_line(&mut sock).await,
            "SETEVENTS HS_DESC STATUS_GENERAL CIRC"
        );
        sock.write_all(b"250 OK\r\n").await.unwrap();

        // GETINFO with a data-block reply, and an event interleaved *before* it
        assert_eq!(read_line(&mut sock).await, "GETINFO status/bootstrap-phase");
        sock.write_all(b"650 STATUS_GENERAL NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n")
            .await
            .unwrap();
        sock.write_all(b"250+status/bootstrap-phase=\r\nNOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n.\r\n250 OK\r\n")
            .await
            .unwrap();

        // SETCONF batch
        assert_eq!(read_line(&mut sock).await, "SETCONF DisableNetwork=\"1\"");
        sock.write_all(b"250 OK\r\n").await.unwrap();

        // SIGNAL NEWNYM
        assert_eq!(read_line(&mut sock).await, "SIGNAL NEWNYM");
        sock.write_all(b"250 OK\r\n").await.unwrap();

        // 5xx surfaces as ControlReply
        assert_eq!(read_line(&mut sock).await, "GETINFO no/such-key");
        sock.write_all(b"552 Unrecognized key\r\n").await.unwrap();
    });

    let client = ControlClient::connect(
        addr,
        ControlAuth::Cookie {
            bytes: vec![0, 1, 0xff],
        },
    )
    .await
    .unwrap();
    let mut events = client.events();

    client
        .setevents(&["HS_DESC", "STATUS_GENERAL", "CIRC"])
        .await
        .unwrap();

    let pct = client.bootstrap_progress().await.unwrap();
    assert_eq!(pct, 100);
    // The interleaved event arrived on the broadcast channel, not the reply.
    let ev = events.recv().await.unwrap();
    assert!(matches!(ev, TorEvent::StatusGeneral { .. }));

    client
        .setconf(&[("DisableNetwork".into(), "1".into())])
        .await
        .unwrap();
    client.signal("NEWNYM").await.unwrap();

    let err = client.getinfo("no/such-key").await.unwrap_err();
    match err {
        TransportError::ControlReply { code, .. } => assert_eq!(code, 552),
        other => panic!("{other:?}"),
    }

    server.await.unwrap();
}

/// Supervisor guard: a command storm fails fast past the burst
/// budget instead of queueing unbounded work onto the daemon; the first
/// honest burst always passes.
#[tokio::test]
async fn command_storm_throttled() {
    use crate::ratelimit::{self, Surface};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        loop {
            // Read one CRLF-terminated line; answer every command.
            let mut byte = [0u8; 1];
            buf.clear();
            loop {
                let n = sock.read(&mut byte).await.unwrap();
                if n == 0 {
                    return; // client gone
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n") {
                    break;
                }
            }
            if buf.starts_with(b"GETINFO") {
                sock.write_all(b"250-status/circuit-established=1\r\n250 OK\r\n")
                    .await
                    .unwrap();
            } else {
                sock.write_all(b"250 OK\r\n").await.unwrap();
            }
        }
    });

    let client = ControlClient::connect(addr, ControlAuth::NoAuth)
        .await
        .unwrap();
    let before = ratelimit::limited(Surface::ControlCmd);

    // Wall-clock refill is 8 tokens per *whole second*. A slow runner
    // (Linux CI) can spend several seconds on this loop, so the storm
    // has to be long enough that refill cannot cover it.
    const ATTEMPTS: u32 = 250;
    let mut ok = 0u32;
    let mut limited = 0u32;
    for _ in 0..ATTEMPTS {
        match client.circuit_established().await {
            Ok(_) => ok += 1,
            Err(TransportError::Control(_)) => limited += 1,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
    // AUTHENTICATE consumed one token at connect. The honest burst
    // still passes; the tail is refused.
    let burst = crate::limits::rate::CONTROL_CMD_BURST;
    assert!(ok >= burst - 1, "honest burst passes: ok={ok}");
    assert!(limited >= 16, "storm tail throttled: {limited} (ok={ok})");
    assert_eq!(
        ratelimit::limited(Surface::ControlCmd) - before,
        u64::from(limited),
        "every throttled command counted"
    );
    drop(client);
    let _ = server.await;
}

/// Contract double: stands in for the Android shell that reads
/// the cookie itself and hands bytes through `attach_tor(...)`.
#[test]
fn attach_contract_double() {
    struct FakeAndroidShell {
        cookie: Vec<u8>,
    }
    impl FakeAndroidShell {
        fn read_cookie(&self) -> ControlAuth {
            ControlAuth::Cookie {
                bytes: self.cookie.clone(),
            }
        }
    }
    let shell = FakeAndroidShell {
        cookie: vec![0xde, 0xad],
    };
    match shell.read_cookie() {
        ControlAuth::Cookie { bytes } => assert_eq!(bytes, vec![0xde, 0xad]),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn hex_encoding() {
    assert_eq!(hex_encode(&[0x00, 0x01, 0xff, 0xab]), "0001ffab");
}

mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The parser must never panic on arbitrary input lines.
        #[test]
        fn parser_never_panics(lines in proptest::collection::vec(".*", 0..64)) {
            let mut p = ReplyParser::new();
            for line in &lines {
                let _ = p.feed(line);
            }
        }

        /// Well-formed generated replies parse to the expected code/lines.
        #[test]
        fn generated_replies_roundtrip(
            code in 200u16..600,
            tail in "[A-Za-z0-9=_ -]{0,40}",
            mid_count in 0usize..4,
        ) {
            let mut p = ReplyParser::new();
            for i in 0..mid_count {
                let line = format!("{code}-mid{i}=v{i}");
                prop_assert!(p.feed(&line).unwrap().is_none());
            }
            let reply = p.feed(&format!("{code} {tail}")).unwrap().expect("complete");
            prop_assert_eq!(reply.code, code);
            prop_assert_eq!(reply.lines.len(), mid_count + 1);
        }
    }
}
