//! Async Tor control-port client (replaces `jtorctl`).
//!
//! Covers exactly what s//chat6 uses — nothing else:
//! `AUTHENTICATE` (cookie + hashed-password), `SETCONF`, `RESETCONF`,
//! `SIGNAL RELOAD|NEWNYM`, `ADD_ONION`, `DEL_ONION`,
//! `GETINFO status/bootstrap-phase` / `status/circuit-established`, and
//! `SETEVENTS HS_DESC STATUS_GENERAL CIRC`.
//!
//! Protocol: control-spec.txt. Replies are `CCC[ -+]` lines; `+` introduces a
//! data block terminated by a lone `.`; a reply is complete at the first
//! line with a space separator. Asynchronous `650` events may arrive at any
//! time, including between the lines of a multi-line reply, and are dispatched
//! to the event broadcast channel instead of the pending command.
//!
//! **Client contract:** on Android the client shell starts
//! tor-android, reads the cookie file itself, and passes the bytes through
//! `SchatCore.attach_tor(...)` as [`ControlAuth::Cookie`]. The core never
//! assumes it can see the daemon's filesystem in production; reading the
//! cookie from `DataDirectory` directly (as [`ControlAuth::cookie_from_file`]
//! does) is the desktop/testnet path only. A test double lives in
//! `tests::attach_contract_double`.

mod events;
mod reply;

pub use events::{parse_event, TorEvent};
pub use reply::{Reply, ReplyParser};

#[cfg(test)]
mod tests;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, oneshot, Mutex};
use tracing::{debug, warn};

use super::error::TransportError;

/// How to authenticate to the control port.
#[derive(Clone, Debug, uniffi::Enum)]
pub enum ControlAuth {
    /// `AUTHENTICATE` with no credential (only valid when the daemon runs
    /// with `CookieAuthentication 0`, e.g. some embedded setups).
    NoAuth,
    /// Cookie bytes (contents of `DataDirectory/control_auth_cookie`).
    Cookie { bytes: Vec<u8> },
    /// `HashedControlPassword` cleartext password.
    Password { password: String },
}

impl ControlAuth {
    /// Desktop/testnet path: read the cookie from the daemon's data dir.
    pub fn cookie_from_file(data_dir: &Path) -> Result<Self, TransportError> {
        let bytes = std::fs::read(data_dir.join("control_auth_cookie"))?;
        Ok(ControlAuth::Cookie { bytes })
    }
}

struct Shared {
    write: OwnedWriteHalf,
    pending: VecDeque<oneshot::Sender<Result<Reply, TransportError>>>,
}

/// One control connection. Commands are serialized (the control port answers
/// in order); events flow on a broadcast channel.
pub struct ControlClient {
    shared: Arc<Mutex<Shared>>,
    events: broadcast::Sender<TorEvent>,
    reader_task: tokio::task::JoinHandle<()>,
    /// Supervisor loop guard: a wedged heal loop must not hammer
    /// the control port. Far above honest use (boot ≈ 20 commands).
    cmd_budget: std::sync::Mutex<crate::ratelimit::TokenBucket>,
}

impl ControlClient {
    pub async fn connect(addr: SocketAddr, auth: ControlAuth) -> Result<Arc<Self>, TransportError> {
        let stream = TcpStream::connect(addr).await?;
        let (read, write) = stream.into_split();
        let events = broadcast::channel(256).0;
        let shared = Arc::new(Mutex::new(Shared {
            write,
            pending: VecDeque::new(),
        }));
        let reader_task = tokio::spawn(reader_loop(read, shared.clone(), events.clone()));
        let client = Arc::new(Self {
            shared,
            events,
            reader_task,
            cmd_budget: std::sync::Mutex::new(crate::ratelimit::TokenBucket::new(
                crate::limits::rate::CONTROL_CMD_BURST,
                crate::limits::rate::CONTROL_CMD_PER_SEC,
                now_secs(),
            )),
        });
        client.authenticate(auth).await?;
        Ok(client)
    }

    async fn authenticate(&self, auth: ControlAuth) -> Result<(), TransportError> {
        let cmd = match &auth {
            ControlAuth::NoAuth => "AUTHENTICATE".to_string(),
            ControlAuth::Cookie { bytes } => format!("AUTHENTICATE {}", hex_encode(bytes)),
            ControlAuth::Password { password } => {
                format!(
                    "AUTHENTICATE \"{}\"",
                    password.replace('\\', "\\\\").replace('"', "\\\"")
                )
            }
        };
        self.cmd_ok(&cmd).await
    }

    pub fn events(&self) -> broadcast::Receiver<TorEvent> {
        self.events.subscribe()
    }

    async fn cmd(&self, command: &str) -> Result<Reply, TransportError> {
        // Supervisor guard: fail fast (the heal ladder surfaces this as
        // an error it can act on) instead of queueing unbounded work
        // onto a possibly-wedged daemon.
        {
            let allowed = self
                .cmd_budget
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .check(now_secs());
            if !allowed {
                crate::ratelimit::note_limited(crate::ratelimit::Surface::ControlCmd, "control");
                return Err(TransportError::Control(
                    "control command rate limited (supervisor guard)".into(),
                ));
            }
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut sh = self.shared.lock().await;
            sh.write.write_all(command.as_bytes()).await.map_err(|e| {
                sh.pending.pop_back();
                TransportError::Io(e)
            })?;
            sh.write.write_all(b"\r\n").await.map_err(|e| {
                sh.pending.pop_back();
                TransportError::Io(e)
            })?;
            sh.pending.push_back(tx);
        }
        // Bounded wait: a wedged control connection must surface as an
        // error so the supervisor can heal, never hang the health loop.
        let reply = tokio::time::timeout(Duration::from_secs(30), rx)
            .await
            .map_err(|_| TransportError::Timeout(format!("control command: {command}")))?
            .map_err(|_| TransportError::ControlClosed)??;
        if reply.is_ok() {
            Ok(reply)
        } else {
            Err(TransportError::ControlReply {
                code: reply.code,
                message: reply.lines.join(" | "),
            })
        }
    }

    async fn cmd_ok(&self, command: &str) -> Result<(), TransportError> {
        self.cmd(command).await.map(|_| ())
    }

    pub async fn setconf(&self, pairs: &[(String, String)]) -> Result<(), TransportError> {
        if pairs.is_empty() {
            return Ok(());
        }
        let args = pairs
            .iter()
            .map(|(k, v)| format!("{k}=\"{v}\""))
            .collect::<Vec<_>>()
            .join(" ");
        self.cmd_ok(&format!("SETCONF {args}")).await
    }

    pub async fn resetconf(&self, keys: &[&str]) -> Result<(), TransportError> {
        if keys.is_empty() {
            return Ok(());
        }
        self.cmd_ok(&format!("RESETCONF {}", keys.join(" "))).await
    }

    /// `SIGNAL RELOAD` / `SIGNAL NEWNYM`.
    pub async fn signal(&self, signal: &str) -> Result<(), TransportError> {
        self.cmd_ok(&format!("SIGNAL {signal}")).await
    }

    pub async fn getinfo(&self, key: &str) -> Result<String, TransportError> {
        let reply = self.cmd(&format!("GETINFO {key}")).await?;
        reply
            .get(key)
            .map(|s| s.to_string())
            .ok_or_else(|| TransportError::Control(format!("GETINFO {key}: key missing in reply")))
    }

    /// Bootstrap percentage from `status/bootstrap-phase` (0–100).
    pub async fn bootstrap_progress(&self) -> Result<u8, TransportError> {
        let phase = self.getinfo("status/bootstrap-phase").await?;
        for token in phase.split_whitespace() {
            if let Some(v) = token.strip_prefix("PROGRESS=") {
                return v
                    .parse()
                    .map_err(|_| TransportError::Control(format!("bad PROGRESS in {phase:?}")));
            }
        }
        Err(TransportError::Control(format!(
            "no PROGRESS in bootstrap phase {phase:?}"
        )))
    }

    /// `true` when `status/circuit-established` reports 1.
    pub async fn circuit_established(&self) -> Result<bool, TransportError> {
        Ok(self.getinfo("status/circuit-established").await?.trim() == "1")
    }

    pub async fn setevents(&self, events: &[&str]) -> Result<(), TransportError> {
        self.cmd_ok(&format!("SETEVENTS {}", events.join(" ")))
            .await
    }

    /// `ADD_ONION` for a v3 service. `key_blob` is the opaque
    /// `ED25519-V3:<base64>` string tor returned on first creation; pass
    /// `None` to generate a fresh key (the reply then contains the blob to
    /// persist). `client_auth_v3` is a list of base32 x25519 public keys
    /// (restricted discovery).
    pub async fn add_onion(
        &self,
        key_blob: Option<&str>,
        target: &str,
        client_auth_v3: &[String],
    ) -> Result<AddOnionResult, TransportError> {
        let key = match key_blob {
            Some(blob) => format!("ED25519-V3:{blob}"),
            None => "NEW:ED25519-V3".to_string(),
        };
        let mut cmd = format!("ADD_ONION {key}");
        if !client_auth_v3.is_empty() {
            cmd.push_str(" Flags=V3Auth");
        }
        // Per-service PoW defenses (a static torrc sets this globally next
        // to its HiddenServiceDir; ephemeral services take it here). Intro-DoS
        // rates and intro-point counts are torrc-only knobs and stay at tor
        // defaults for ephemeral services.
        cmd.push_str(" PoWDefensesEnabled=1");
        cmd.push_str(&format!(" Port=80,{target}"));
        for pk in client_auth_v3 {
            cmd.push_str(&format!(" ClientAuthV3={pk}"));
        }
        let reply = self.cmd(&cmd).await?;
        let service_id = reply
            .get("ServiceID")
            .ok_or_else(|| TransportError::Control("ADD_ONION reply missing ServiceID".into()))?
            .to_string();
        let private_key = reply.get("PrivateKey").map(|s| s.to_string());
        Ok(AddOnionResult {
            service_id,
            private_key,
        })
    }

    pub async fn del_onion(&self, service_id: &str) -> Result<(), TransportError> {
        self.cmd_ok(&format!("DEL_ONION {service_id}")).await
    }
}

impl Drop for ControlClient {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

pub struct AddOnionResult {
    /// 56-char service id (no `.onion` suffix).
    pub service_id: String,
    /// `ED25519-V3:<base64>` blob to persist, when a key was generated.
    pub private_key: Option<String>,
}

async fn reader_loop(
    read: OwnedReadHalf,
    shared: Arc<Mutex<Shared>>,
    events: broadcast::Sender<TorEvent>,
) {
    let mut lines = BufReader::new(read).lines();
    let mut parser = ReplyParser::new();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let line = line.trim_end_matches('\r').to_string();
                if line.starts_with("650") {
                    let event = parse_event(&line);
                    debug!(?event, "tor event");
                    let _ = events.send(event);
                    continue;
                }
                match parser.feed(&line) {
                    Ok(Some(reply)) => {
                        let mut sh = shared.lock().await;
                        if let Some(tx) = sh.pending.pop_front() {
                            let _ = tx.send(Ok(reply));
                        } else {
                            warn!(?reply, "unsolicited control reply; dropping");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        warn!(error = %e, "control reply parse failure; closing");
                        break;
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                debug!(error = %e, "control reader io error");
                break;
            }
        }
    }
    // Fail every pending command so waiters don't hang.
    let mut sh = shared.lock().await;
    while let Some(tx) = sh.pending.pop_front() {
        let _ = tx.send(Err(TransportError::ControlClosed));
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}
