//! Inbound path.
//!
//! A localhost TCP listener per hosted service target (the onion service's
//! `Port=127.0.0.1:<port>` forwards here). Bounded decode via
//! [`framing`], per-connection budgets, frame-hash dedup via
//! [`SeenRing`], and the alert flag surfaced as an "arrival" event.
//!
//! TB1/TB2 by types: this module produces [`OpaqueFrame`]s — bytes, never
//! plaintext. Decryption lives across the vault gate in later phases.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, info, warn};

use super::error::TransportError;
use super::framing::{self, OpaqueFrame, MAX_CONN_BYTES, MAX_CONN_PACKETS};
use super::seen::SeenRing;
use crate::limits::rate;
use crate::ratelimit::{Surface, TokenBucket};

// Caps declared in the bounds catalog; re-exported so
// `inbound::MAX_CONNECTIONS` etc. keep working.
pub use crate::limits::transport::{ACCEPT_BACKLOG, MAX_CONNECTIONS, RECV_BUFFER_BYTES};

pub const FIRST_PACKET_TIMEOUT: Duration = Duration::from_secs(90);
pub const READ_TIMEOUT: Duration = Duration::from_secs(16 * 60);

/// What the inbound path tells the rest of the core.
#[derive(Clone, Debug)]
pub struct InboundDrop {
    pub service_id: String,
    pub frame: OpaqueFrame,
    /// True exactly once per unique frame (SeenRing): drive the client's
    /// arrival notification from this, never from raw frame receipt.
    pub first_sight: bool,
}

/// Wall-clock seconds for the flood bucket (the transport layer has no
/// store clock; this limit is wall-time by nature).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One bounded connection decode. Enforces packet/byte budgets and read
/// timeouts; malformed input ends the connection (fail closed).
///
/// `flood` is the per-service token bucket shared by all
/// connections of one hosted service. Frames past the budget are
/// dropped **before** the seen-ring and before any crypto — a peer
/// flood costs us a bounded decode only. The connection stays open;
/// honest bursts sit far below the budget (notes/rate-limits.md).
async fn read_connection(
    service_id: &str,
    stream: TcpStream,
    seen: Arc<tokio::sync::Mutex<SeenRing>>,
    flood: Arc<std::sync::Mutex<TokenBucket>>,
    sink: &mpsc::Sender<InboundDrop>,
) -> Result<(), TransportError> {
    let mut reader = BufReader::with_capacity(RECV_BUFFER_BYTES, stream);
    let mut packets: u32 = 0;
    let mut bytes: u64 = 0;
    loop {
        let timeout = if packets == 0 {
            FIRST_PACKET_TIMEOUT
        } else {
            READ_TIMEOUT
        };
        let next = tokio::time::timeout(timeout, framing::read_frame(&mut reader)).await;
        let frame = match next {
            Ok(Ok(Some(f))) => f,
            Ok(Ok(None)) => return Ok(()), // clean EOF
            Ok(Err(e)) => {
                // Malformed: drop the connection, log the reason, never panic.
                warn!(service_id, error = %e, "dropping malformed inbound stream");
                return Err(e);
            }
            Err(_) => {
                debug!(service_id, "inbound read timeout; closing");
                return Ok(());
            }
        };
        packets += 1;
        bytes += frame.frame.len() as u64
            + frame.intro.as_ref().map(|i| i.len() as u64).unwrap_or(0)
            + 3;
        if packets > MAX_CONN_PACKETS || bytes > MAX_CONN_BYTES {
            warn!(
                service_id,
                packets, bytes, "connection budget exceeded; dropping"
            );
            return Err(TransportError::MalformedFrame(
                "connection budget exceeded".into(),
            ));
        }
        // Flood gate: after the bounded decode, before the
        // seen-ring and everything downstream (crypto included).
        {
            let allowed = flood
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .check(now_secs());
            if !allowed {
                crate::ratelimit::note_limited(Surface::InboundFrame, service_id);
                continue;
            }
        }
        let first_sight = {
            let mut ring = seen.lock().await;
            !ring.seen_or_mark(&frame.frame)
        };
        let drop = InboundDrop {
            service_id: service_id.to_string(),
            frame,
            first_sight,
        };
        if sink.send(drop).await.is_err() {
            return Ok(()); // core is shutting down
        }
    }
}

/// A running inbound listener.
pub struct InboundListener {
    task: tokio::task::JoinHandle<()>,
    port: u16,
}

impl InboundListener {
    /// Bind `127.0.0.1:port` (0 = ephemeral) and accept until `shutdown` is
    /// notified or the returned handle is dropped.
    pub async fn bind(
        service_id: String,
        port: u16,
        seen: Arc<tokio::sync::Mutex<SeenRing>>,
        sink: mpsc::Sender<InboundDrop>,
    ) -> Result<Self, TransportError> {
        let listener = TcpListener::bind(("127.0.0.1", port)).await?;
        let port = listener.local_addr()?.port();
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let flood = Arc::new(std::sync::Mutex::new(TokenBucket::new(
            rate::INBOUND_FRAME_BURST,
            rate::INBOUND_FRAME_PER_SEC,
            now_secs(),
        )));
        info!(service_id, port, "inbound listener up");
        let task = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "inbound accept failed; listener exit");
                        break;
                    }
                };
                // try_acquire: no queueing — full means close immediately.
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    debug!(%peer, "connection cap reached; closing");
                    drop(stream);
                    continue;
                };
                let service_id = service_id.clone();
                let seen = seen.clone();
                let flood = flood.clone();
                let sink = sink.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = read_connection(&service_id, stream, seen, flood, &sink).await;
                });
            }
        });
        Ok(Self { task, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for InboundListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn record(bucket: usize) -> Vec<u8> {
        let mut r = vec![0u8; bucket];
        r[0] = framing::VERSION_V2;
        r
    }

    async fn setup() -> (
        InboundListener,
        mpsc::Receiver<InboundDrop>,
        Arc<tokio::sync::Mutex<SeenRing>>,
    ) {
        let seen = Arc::new(tokio::sync::Mutex::new(SeenRing::default()));
        let (tx, rx) = mpsc::channel(64);
        let listener = InboundListener::bind("inbox".into(), 0, seen.clone(), tx)
            .await
            .unwrap();
        (listener, rx, seen)
    }

    /// Replay of a captured v2 stream: sized quiet + sized alert + intro.
    #[tokio::test]
    async fn replays_valid_v2_stream() {
        let (listener, mut rx, _seen) = setup().await;
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port()))
            .await
            .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&framing::pack(None, &record(256), false).unwrap());
        bytes.extend_from_slice(&framing::pack(None, &record(512), true).unwrap());
        bytes.extend_from_slice(&framing::pack(Some(b"intro"), &record(1024), false).unwrap());
        stream.write_all(&bytes).await.unwrap();

        let d1 = rx.recv().await.unwrap();
        assert!(!d1.frame.alert);
        assert_eq!(d1.frame.frame.len(), 256);
        assert!(d1.first_sight);

        let d2 = rx.recv().await.unwrap();
        assert!(d2.frame.alert);
        assert_eq!(d2.frame.frame.len(), 512);

        let d3 = rx.recv().await.unwrap();
        assert_eq!(d3.frame.intro.as_deref(), Some(b"intro".as_slice()));
    }

    #[tokio::test]
    async fn duplicate_frames_flagged_not_first_sight() {
        let (listener, mut rx, _seen) = setup().await;
        let frame = framing::pack(None, &record(256), true).unwrap();
        let mut s1 = TcpStream::connect(("127.0.0.1", listener.port()))
            .await
            .unwrap();
        s1.write_all(&frame).await.unwrap();
        let d1 = rx.recv().await.unwrap();
        assert!(d1.first_sight);

        // Retransmission (new connection, identical bytes).
        let mut s2 = TcpStream::connect(("127.0.0.1", listener.port()))
            .await
            .unwrap();
        s2.write_all(&frame).await.unwrap();
        let d2 = rx.recv().await.unwrap();
        assert!(!d2.first_sight);
    }

    #[tokio::test]
    async fn malformed_stream_dropped_without_panic() {
        let (listener, mut rx, _seen) = setup().await;
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port()))
            .await
            .unwrap();
        // Legacy fixed-size flag: dropped under the breaking-change rule.
        stream.write_all(&[0x04u8]).await.unwrap();
        stream.write_all(&[0u8; 100]).await.unwrap();
        // Nothing is delivered; the connection is closed.
        let got = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(got.is_err(), "no frame may be delivered from garbage");
    }

    #[tokio::test]
    async fn unknown_flag_drops_connection() {
        let (listener, mut rx, _seen) = setup().await;
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port()))
            .await
            .unwrap();
        stream.write_all(&[0x99u8, 0, 1, 2]).await.unwrap();
        let got = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn truncated_frame_dropped() {
        let (listener, mut rx, _seen) = setup().await;
        let mut stream = TcpStream::connect(("127.0.0.1", listener.port()))
            .await
            .unwrap();
        // Declares a 256 record, sends 10 bytes, then closes.
        stream
            .write_all(&[framing::FLAG_SIZED_QUIET, 0x01, 0x00])
            .await
            .unwrap();
        stream.write_all(&[2u8; 10]).await.unwrap();
        stream.shutdown().await.unwrap();
        let got = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(got.is_err());
    }

    /// A frame flood across many connections hits the per-service
    /// pre-crypto bucket; honest traffic after the flood still passes.
    #[tokio::test]
    async fn frame_flood_throttled_pre_crypto() {
        use crate::ratelimit::{self, Surface};
        let (listener, mut rx, _seen) = setup().await;
        let before = ratelimit::limited(Surface::InboundFrame);

        // Drain concurrently so the sink channel never back-pressures.
        let counter = tokio::spawn(async move {
            let mut n = 0u64;
            while let Some(_d) = rx.recv().await {
                n += 1;
            }
            n
        });

        let frame = framing::pack(None, &record(256), false).unwrap();
        let mut chunk = Vec::new();
        // 1000 frames per connection stays under the per-connection
        // packet budget (1025); five connections exceed the service
        // flood burst (4096).
        for _ in 0..1000 {
            chunk.extend_from_slice(&frame);
        }
        const CONNS: u64 = 5;
        const PER_CONN: u64 = 1000;
        for _ in 0..CONNS {
            let mut s = TcpStream::connect(("127.0.0.1", listener.port()))
                .await
                .unwrap();
            s.write_all(&chunk).await.unwrap();
            s.shutdown().await.unwrap();
        }
        // Let the listener chew through the backlog, then drop the
        // listener so the counter task's channel closes.
        tokio::time::sleep(Duration::from_secs(2)).await;
        drop(listener);
        let delivered = counter.await.unwrap();

        let total = CONNS * PER_CONN;
        let dropped = ratelimit::limited(Surface::InboundFrame) - before;
        assert_eq!(
            delivered + dropped,
            total,
            "every frame either delivered or counted: delivered={delivered} dropped={dropped}"
        );
        assert!(
            dropped
                >= total
                    - rate::INBOUND_FRAME_BURST as u64
                    - rate::INBOUND_FRAME_PER_SEC as u64 * 3,
            "flood mostly throttled: dropped={dropped}"
        );
        assert!(delivered >= rate::INBOUND_FRAME_BURST as u64);
    }
}
