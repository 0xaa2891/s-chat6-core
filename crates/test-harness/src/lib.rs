//! Headless harness crate.
//!
//! [`TestInstance`] — one headless s//chat6 instance (subprocess tor
//! + transport) for Chutney testnet tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use schat_core::transport::daemon::{chutney_extra_torrc_lines, SubprocessTor};
use schat_core::transport::error::TransportError;
use schat_core::transport::framing;
use schat_core::transport::inbound::InboundDrop;
use schat_core::transport::status::TorState;
use schat_core::transport::Transport;
use tokio::sync::broadcast;

pub mod latency;
pub mod reliability;

pub fn core_ping() -> String {
    schat_core::ping()
}

/// Path to a configured Chutney nodes dir, or `None` when the testnet is
/// not up. Tests skip in that case (never touch the real Tor network).
pub fn chutney_nodes() -> Option<PathBuf> {
    let dir = std::env::var_os("SCHAT_CHUTNEY_NODES").map(PathBuf::from)?;
    // A configured network has at least one node torrc with DirAuthority.
    chutney_extra_torrc_lines(&dir).ok()?;
    Some(dir)
}

pub fn tor_binary() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SCHAT_TOR") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Some(path);
        }
    }
    let name = if cfg!(windows) { "tor.exe" } else { "tor" };
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            candidate.is_file().then_some(candidate)
        })
    })
}

/// One headless instance: own data dir, own tor subprocess on the Chutney
/// network, own transport.
pub struct TestInstance {
    pub name: String,
    pub transport: Arc<Transport>,
    pub daemon: Arc<SubprocessTor>,
    pub data_dir: PathBuf,
    // Keeps the temp dir alive.
    _tmp: tempfile::TempDir,
}

impl TestInstance {
    pub async fn new(name: &str, nodes: &Path) -> Result<Self, TransportError> {
        let tmp = tempfile::tempdir()?;
        let data_dir = tmp.path().join(name);
        let extra = chutney_extra_torrc_lines(nodes)?;
        let daemon = SubprocessTor::new(
            tor_binary().ok_or_else(|| TransportError::Control("no tor binary".into()))?,
            data_dir.join("tor"),
            SubprocessTor::free_port()?,
            SubprocessTor::free_port()?,
            extra,
        );
        let transport = Transport::new(&data_dir);
        transport.set_daemon(daemon.clone()).await;
        transport.start().await?;
        Ok(Self {
            name: name.to_string(),
            transport,
            daemon,
            data_dir,
            _tmp: tmp,
        })
    }

    pub async fn host(&self, service_id: &str, restricted: bool) -> Result<String, TransportError> {
        self.transport.host_service(service_id, restricted).await
    }

    /// Build a bucket-256 v2 record carrying a text tag (test payload).
    pub fn text_record(text: &str) -> Vec<u8> {
        let mut rec = vec![0u8; framing::RECORD_BUCKETS[0]];
        rec[0] = framing::VERSION_V2;
        let bytes = text.as_bytes();
        let len = bytes.len().min(250);
        rec[1..3].copy_from_slice(&(len as u16).to_be_bytes());
        rec[3..3 + len].copy_from_slice(&bytes[..len]);
        rec
    }

    pub async fn send_text(
        &self,
        dest_onion: &str,
        text: &str,
        alert: bool,
    ) -> Result<(), TransportError> {
        self.transport
            .send_frame(dest_onion, &Self::text_record(text), alert)
            .await
    }

    pub fn drops(&self) -> broadcast::Receiver<InboundDrop> {
        self.transport.subscribe_drops()
    }

    pub async fn wait_online(&self, timeout: Duration) -> bool {
        let mut rx = self.transport.subscribe();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if matches!(rx.borrow().tor, TorState::Online) {
                return true;
            }
            if std::time::Instant::now() > deadline {
                return false;
            }
            let _ = tokio::time::timeout(Duration::from_secs(5), rx.changed()).await;
        }
    }

    /// Wait for an inbound drop whose frame carries `tag`.
    pub async fn wait_for_drop(
        &self,
        rx: &mut broadcast::Receiver<InboundDrop>,
        tag: &str,
        timeout: Duration,
    ) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(drop)) => {
                    let f = &drop.frame.frame;
                    if f.len() >= 3 {
                        let len = u16::from_be_bytes([f[1], f[2]]) as usize;
                        if 3 + len <= f.len() {
                            if let Ok(s) = std::str::from_utf8(&f[3..3 + len]) {
                                if s == tag {
                                    return true;
                                }
                            }
                        }
                    }
                }
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                _ => return false,
            }
        }
    }

    pub async fn stop(self) {
        self.transport.stop().await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn core_ping_roundtrip() {
        assert_eq!(crate::core_ping(), "pong");
    }
}
