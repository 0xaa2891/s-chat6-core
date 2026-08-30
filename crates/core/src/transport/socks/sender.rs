//! Per-destination pooled sender. Connects when a frame is queued,
//! batches whatever is already waiting, then holds the stream for
//! [`CONVERSATION_HOLD`] so a follow-up reuses the circuit. After that the
//! stream drops; the worker parks until the next real frame.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::transport::error::TransportError;
use crate::transport::onion;

use super::handshake::socks_connect;
use super::{
    connect_backoff, CONVERSATION_HOLD, MAX_CONNECT_FAILS, MAX_LIVE_SESSIONS, MAX_WRITE_RETRIES,
    PURPOSE_CHAT, WRITE_COALESCE_MAX, WRITE_COALESCE_MIN,
};

struct QueuedWrite {
    bytes: Vec<u8>,
    done: tokio::sync::oneshot::Sender<Result<(), TransportError>>,
}

struct DestWorker {
    tx: mpsc::Sender<QueuedWrite>,
}

pub struct Sender {
    proxy: SocketAddr,
    dest_port: u16,
    kill_switch: Arc<AtomicBool>,
    online: Arc<AtomicBool>,
    dests: Mutex<HashMap<String, DestWorker>>,
    hold: Duration,
}

impl Sender {
    pub fn new(
        proxy: SocketAddr,
        dest_port: u16,
        kill_switch: Arc<AtomicBool>,
        online: Arc<AtomicBool>,
    ) -> Arc<Self> {
        Self::with_hold(proxy, dest_port, kill_switch, online, CONVERSATION_HOLD)
    }

    pub fn with_hold(
        proxy: SocketAddr,
        dest_port: u16,
        kill_switch: Arc<AtomicBool>,
        online: Arc<AtomicBool>,
        hold: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            proxy,
            dest_port,
            kill_switch,
            online,
            dests: Mutex::new(HashMap::new()),
            hold,
        })
    }

    /// Queue `bytes` for `dest`. The returned future resolves when the bytes
    /// have been written to the SOCKS socket ("transmitted", not "delivered").
    pub async fn send(self: &Arc<Self>, dest: &str, bytes: Vec<u8>) -> Result<(), TransportError> {
        if self.kill_switch.load(Ordering::SeqCst) {
            return Err(TransportError::KillSwitch);
        }
        if !self.online.load(Ordering::SeqCst) {
            return Err(TransportError::Offline);
        }
        let dest = onion::normalize_hostname(dest)?;
        let (done, rx) = tokio::sync::oneshot::channel();
        let tx = {
            let mut dests = self.dests.lock().await;
            match dests.get(&dest) {
                Some(w) => w.tx.clone(),
                None => {
                    self.evict_if_full(&mut dests).await;
                    let (tx, rx) = mpsc::channel::<QueuedWrite>(256);
                    dests.insert(dest.clone(), DestWorker { tx: tx.clone() });
                    let this = self.clone();
                    let d = dest.clone();
                    tokio::spawn(async move {
                        this.run_dest(d, rx).await;
                    });
                    tx
                }
            }
        };
        tx.send(QueuedWrite { bytes, done })
            .await
            .map_err(|_| TransportError::Socks("destination worker gone".into()))?;
        rx.await
            .map_err(|_| TransportError::Socks("destination worker dropped write".into()))?
    }

    /// Number of queued destinations (for status).
    pub async fn dest_count(&self) -> usize {
        self.dests.lock().await.len()
    }

    async fn evict_if_full(&self, dests: &mut HashMap<String, DestWorker>) {
        if dests.len() >= MAX_LIVE_SESSIONS {
            // Evict an arbitrary worker; its queued writes error out to the
            // caller (structured, logged) instead of silently dropping.
            if let Some(key) = dests.keys().next().cloned() {
                warn!(dest = %key, "evicting destination worker (MAX_LIVE_SESSIONS)");
                dests.remove(&key);
            }
        }
    }

    async fn run_dest(self: Arc<Self>, dest: String, mut rx: mpsc::Receiver<QueuedWrite>) {
        let mut stream: Option<TcpStream> = None;
        let mut connect_fails: u32 = 0;

        // Wait for the first write.
        let Some(mut pending) = rx.recv().await else {
            self.dests.lock().await.remove(&dest);
            return;
        };

        'outer: loop {
            // Kill switch / offline gate: refuse, don't silently drop.
            if self.kill_switch.load(Ordering::SeqCst) || !self.online.load(Ordering::SeqCst) {
                let err = if self.kill_switch.load(Ordering::SeqCst) {
                    TransportError::KillSwitch
                } else {
                    TransportError::Offline
                };
                fail_all(&dest, err, drain(pending, &mut rx));
                break;
            }

            // Ensure a connection, with backoff. The pending write is
            // parked across retries — never dropped on a transient failure.
            while stream.is_none() {
                match socks_connect(self.proxy, &dest, self.dest_port, PURPOSE_CHAT).await {
                    Ok(s) => {
                        connect_fails = 0;
                        stream = Some(s);
                    }
                    Err(e) => {
                        connect_fails += 1;
                        let reason = e.to_string();
                        warn!(dest = %dest, fails = connect_fails, %reason, "connect failed");
                        if connect_fails >= MAX_CONNECT_FAILS {
                            let err = TransportError::ConnectFailed {
                                dest: dest.clone(),
                                attempts: connect_fails,
                                reason,
                            };
                            fail_all(&dest, err, drain(pending, &mut rx));
                            break 'outer;
                        }
                        let jitter_ms = rand::rng().random_range(0..1000u64);
                        tokio::time::sleep(connect_backoff(connect_fails, jitter_ms)).await;
                    }
                }
            }

            // Coalesce: pending write plus whatever is queued, up to a random
            // budget in [512 KiB, 2 MiB].
            let budget = rand::rng().random_range(WRITE_COALESCE_MIN..=WRITE_COALESCE_MAX);
            let mut batch: Vec<QueuedWrite> = vec![pending];
            let mut batch_bytes = batch[0].bytes.len();
            while batch_bytes < budget {
                match rx.try_recv() {
                    Ok(w) => {
                        batch_bytes += w.bytes.len();
                        batch.push(w);
                    }
                    Err(_) => break,
                }
            }

            let mut payload = Vec::with_capacity(batch_bytes);
            for w in &batch {
                payload.extend_from_slice(&w.bytes);
            }

            // Write; on mid-write failure reconnect and retry the whole batch
            // (duplicates are acceptable).
            let mut write_retries = 0;
            let write_result: Result<(), TransportError> = loop {
                let s = stream.as_mut().expect("connected");
                match s.write_all(&payload).await {
                    Ok(()) => break Ok(()),
                    Err(e) => {
                        write_retries += 1;
                        warn!(dest = %dest, retry = write_retries, error = %e, "write failed; reconnecting");
                        if write_retries >= MAX_WRITE_RETRIES {
                            break Err(TransportError::Io(e));
                        }
                        match socks_connect(self.proxy, &dest, self.dest_port, PURPOSE_CHAT).await {
                            Ok(new_s) => stream = Some(new_s),
                            Err(e) => break Err(e),
                        }
                    }
                }
            };

            match write_result {
                Ok(()) => {
                    for w in batch {
                        let _ = w.done.send(Ok(()));
                    }
                }
                Err(e) => {
                    fail_all(&dest, e, batch);
                    break;
                }
            }

            // Reuse the circuit for a short conversation window, then drop
            // it. The worker stays parked (no SOCKS) until the next frame.
            // While holding, watch the read side: the protocol is one-way,
            // so any read result (EOF, data, error) means the circuit died
            // (e.g. the peer's tor restarted). Drop the stream so the next
            // write reconnects instead of blackholing into a dead circuit —
            // TCP writes to the local tor client keep succeeding at the OS
            // level even after the rendezvous circuit is gone.
            let next = {
                let s = stream.as_mut().expect("connected");
                let mut buf = [0u8; 64];
                tokio::select! {
                    w = tokio::time::timeout(self.hold, rx.recv()) => match w {
                        Ok(Some(w)) => Some(w),
                        Ok(None) => break,
                        Err(_) => {
                            debug!(dest = %dest, "conversation hold expired; dropping socks");
                            stream = None;
                            rx.recv().await
                        }
                    },
                    r = s.read(&mut buf) => {
                        match r {
                            Ok(0) => debug!(dest = %dest, "socks stream EOF; dropping dead circuit"),
                            Ok(n) => debug!(dest = %dest, n, "unexpected data on one-way stream; dropping"),
                            Err(e) => debug!(dest = %dest, error = %e, "socks stream read error; dropping"),
                        }
                        stream = None;
                        rx.recv().await
                    }
                }
            };
            match next {
                Some(w) => pending = w,
                None => break,
            }
        }
        self.dests.lock().await.remove(&dest);
        debug!(dest = %dest, "destination worker exit");
    }
}

fn drain(first: QueuedWrite, rx: &mut mpsc::Receiver<QueuedWrite>) -> Vec<QueuedWrite> {
    let mut out = vec![first];
    while let Ok(w) = rx.try_recv() {
        out.push(w);
    }
    out
}

fn fail_all(dest: &str, err: TransportError, writes: Vec<QueuedWrite>) {
    let msg = err.to_string();
    let mut writes = writes.into_iter();
    if let Some(w) = writes.next() {
        let _ = w.done.send(Err(clone_error(&err, &msg)));
    }
    for w in writes {
        let _ = w.done.send(Err(TransportError::Socks(msg.clone())));
    }
    info!(dest = %dest, error = %msg, "failed queued writes");
}

fn clone_error(err: &TransportError, msg: &str) -> TransportError {
    match err {
        TransportError::KillSwitch => TransportError::KillSwitch,
        TransportError::Offline => TransportError::Offline,
        TransportError::ConnectFailed {
            dest,
            attempts,
            reason,
        } => TransportError::ConnectFailed {
            dest: dest.clone(),
            attempts: *attempts,
            reason: reason.clone(),
        },
        _ => TransportError::Socks(msg.to_string()),
    }
}
