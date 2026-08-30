//! Tor daemon lifecycle, platform-split behind a trait.
//!
//! Production: the client shell starts the daemon and calls
//! `attach_tor(...)` — the core never spawns processes on a phone.
//! Desktop/CI: [`SubprocessTor`] spawns the `tor` binary with a generated
//! torrc. Everything below the trait is shared code; `transport/` only ever
//! sees `socks_addr` + `control_addr` + auth.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use super::control::ControlAuth;
use super::error::TransportError;
use super::onion::{base_torrc, TorrcParams};

/// What the supervisor needs from a daemon.
#[async_trait]
pub trait TorDaemon: Send + Sync {
    fn socks_addr(&self) -> SocketAddr;
    fn control_addr(&self) -> SocketAddr;
    fn control_auth(&self) -> ControlAuth;
    /// Start the daemon (idempotent). No-op for client-attached daemons.
    async fn start(&self) -> Result<(), TransportError>;
    /// Restart the daemon process (heal ladder rung 3).
    async fn restart(&self) -> Result<(), TransportError>;
    async fn stop(&self) -> Result<(), TransportError>;
    /// True once the daemon process died on its own (crash / kill -9).
    /// The supervisor checks this every health tick: a dead process fails
    /// every heal rung below Restart, so it is restarted directly instead
    /// of walking the ladder against a corpse. Always false for
    /// client-attached daemons (the client owns the process).
    async fn unexpected_exit(&self) -> bool {
        false
    }
    /// Where `.auth_private` files for restricted discovery live
    /// (`ClientOnionAuthDir`).
    fn client_auth_dir(&self) -> PathBuf;
}

/// A client-attached daemon (Android shell, or a test double): the process
/// lifecycle belongs to the client, so restart is a no-op the supervisor
/// treats as "reconnect control".
pub struct AttachedDaemon {
    pub socks_addr: SocketAddr,
    pub control_addr: SocketAddr,
    pub auth: ControlAuth,
    pub client_auth_dir: PathBuf,
}

#[async_trait]
impl TorDaemon for AttachedDaemon {
    fn socks_addr(&self) -> SocketAddr {
        self.socks_addr
    }
    fn control_addr(&self) -> SocketAddr {
        self.control_addr
    }
    fn control_auth(&self) -> ControlAuth {
        self.auth.clone()
    }
    async fn start(&self) -> Result<(), TransportError> {
        Ok(())
    }
    async fn restart(&self) -> Result<(), TransportError> {
        // The client owns the process; "restart" means the supervisor drops
        // and re-establishes the control connection.
        Ok(())
    }
    async fn stop(&self) -> Result<(), TransportError> {
        Ok(())
    }
    fn client_auth_dir(&self) -> PathBuf {
        self.client_auth_dir.clone()
    }
}

/// Desktop/CI daemon: spawn `tor` as a subprocess with a generated torrc.
pub struct SubprocessTor {
    tor_binary: PathBuf,
    work_dir: PathBuf,
    socks_port: u16,
    control_port: u16,
    extra_torrc: Vec<String>,
    child: tokio::sync::Mutex<Option<tokio::process::Child>>,
}

impl SubprocessTor {
    pub fn new(
        tor_binary: PathBuf,
        work_dir: PathBuf,
        socks_port: u16,
        control_port: u16,
        extra_torrc: Vec<String>,
    ) -> Arc<Self> {
        Arc::new(Self {
            tor_binary,
            work_dir,
            socks_port,
            control_port,
            extra_torrc,
            child: tokio::sync::Mutex::new(None),
        })
    }

    /// Pick a currently-free localhost port (test/dev helper).
    pub fn free_port() -> Result<u16, TransportError> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        Ok(listener.local_addr()?.port())
    }

    pub fn data_dir(&self) -> PathBuf {
        self.work_dir.join("data")
    }

    fn write_torrc(&self) -> Result<PathBuf, TransportError> {
        std::fs::create_dir_all(self.data_dir())?;
        std::fs::create_dir_all(self.work_dir.join("client_auth"))?;
        let torrc = self.work_dir.join("torrc");
        let body = base_torrc(&TorrcParams {
            data_dir: self.data_dir(),
            control_port: self.control_port,
            socks_port: self.socks_port,
            client_auth_dir: self.work_dir.join("client_auth"),
            log_file: Some(self.work_dir.join("tor.log")),
            extra: self.extra_torrc.clone(),
        });
        std::fs::write(&torrc, body)?;
        Ok(torrc)
    }

    pub async fn start(&self) -> Result<(), TransportError> {
        let mut guard = self.child.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let torrc = self.write_torrc()?;
        info!(torrc = %torrc.display(), "spawning tor subprocess");
        let child = tokio::process::Command::new(&self.tor_binary)
            .arg("-f")
            .arg(&torrc)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| {
                TransportError::Control(format!("spawn {}: {e}", self.tor_binary.display()))
            })?;
        *guard = Some(child);
        drop(guard);
        self.wait_for_control(Duration::from_secs(30)).await
    }

    /// Test-only kill -9: SIGKILL the subprocess but keep the handle
    /// unreaped, exactly like an external crash. The supervisor's
    /// `unexpected_exit` poll then owns detection and restart.
    pub async fn simulate_crash(&self) -> Result<(), TransportError> {
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            child
                .kill()
                .await
                .map_err(|e| TransportError::Control(format!("simulate_crash kill: {e}")))?;
        }
        Ok(())
    }

    async fn wait_for_control(&self, timeout: Duration) -> Result<(), TransportError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if tokio::net::TcpStream::connect(self.control_addr())
                .await
                .is_ok()
                && self.data_dir().join("control_auth_cookie").is_file()
            {
                return Ok(());
            }
            if std::time::Instant::now() > deadline {
                return Err(TransportError::Timeout(
                    "tor control port did not come up".into(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

#[async_trait]
impl TorDaemon for SubprocessTor {
    fn socks_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.socks_port))
    }
    fn control_addr(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.control_port))
    }
    fn control_auth(&self) -> ControlAuth {
        ControlAuth::cookie_from_file(&self.data_dir()).unwrap_or(ControlAuth::NoAuth)
    }
    async fn start(&self) -> Result<(), TransportError> {
        SubprocessTor::start(self).await
    }
    async fn restart(&self) -> Result<(), TransportError> {
        self.stop().await?;
        // Give tor a moment to release ports.
        tokio::time::sleep(Duration::from_millis(500)).await;
        self.start().await
    }
    async fn stop(&self) -> Result<(), TransportError> {
        let mut guard = self.child.lock().await;
        if let Some(mut child) = guard.take() {
            debug!("stopping tor subprocess");
            match child.kill().await {
                Ok(()) => {}
                Err(e) => warn!(error = %e, "tor kill failed"),
            }
            let _ = child.wait().await;
        }
        Ok(())
    }
    async fn unexpected_exit(&self) -> bool {
        let mut guard = self.child.lock().await;
        let Some(child) = guard.as_mut() else {
            return false;
        };
        match child.try_wait() {
            // Reap and clear the handle so the restart spawns fresh.
            Ok(Some(status)) => {
                warn!(%status, "tor subprocess exited unexpectedly");
                *guard = None;
                true
            }
            Ok(None) => false,
            Err(e) => {
                warn!(error = %e, "tor subprocess wait failed");
                false
            }
        }
    }
    fn client_auth_dir(&self) -> PathBuf {
        self.work_dir.join("client_auth")
    }
}

/// Extract the Chutney testing-network lines a *client* torrc needs from a
/// configured Chutney nodes dir: the rapid-bootstrap options plus the
/// `DirAuthority` lines. Used by the CLI and the test harness; never touches
/// the real Tor network.
pub fn chutney_extra_torrc_lines(nodes_dir: &Path) -> Result<Vec<String>, TransportError> {
    // Any node torrc carries the full DirAuthority set; prefer a client node.
    let mut entries: Vec<PathBuf> = std::fs::read_dir(nodes_dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    entries.sort();
    let client_first = |a: &PathBuf, b: &PathBuf| {
        let ac = a.file_name().map(|n| n.to_string_lossy().ends_with('c'));
        let bc = b.file_name().map(|n| n.to_string_lossy().ends_with('c'));
        bc.cmp(&ac)
    };
    entries.sort_by(client_first);
    const KEEP_PREFIXES: [&str; 6] = [
        "TestingTorNetwork",
        "PathsNeededToBuildCircuits",
        "TestingDirAuthVoteExit",
        "TestingDirAuthVoteHSDir",
        "TestingDirAuthVoteGuard",
        "TestingMinExitFlagThreshold",
    ];
    for node in entries {
        let torrc = node.join("torrc");
        let Ok(body) = std::fs::read_to_string(&torrc) else {
            continue;
        };
        let mut out = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.starts_with("DirAuthority")
                || KEEP_PREFIXES
                    .iter()
                    .any(|p| line.starts_with(&format!("{p} ")))
            {
                out.push(line.to_string());
            }
        }
        if out.iter().any(|l| l.starts_with("DirAuthority")) {
            return Ok(out);
        }
    }
    Err(TransportError::Control(format!(
        "no DirAuthority lines found under {}",
        nodes_dir.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chutney_lines_extracted() {
        let tmp = tempfile::tempdir().unwrap();
        let node = tmp.path().join("000a");
        std::fs::create_dir_all(&node).unwrap();
        std::fs::write(
            node.join("torrc"),
            "TestingTorNetwork 1\n\
             DataDirectory /somewhere\n\
             SocksPort 19000\n\
             PathsNeededToBuildCircuits 0.67\n\
             DirAuthority test000a orport=15000 no-v2 v3ident=AAAA 127.0.0.1:17000 BBBB\n\
             Log notice stdout\n",
        )
        .unwrap();
        let lines = chutney_extra_torrc_lines(tmp.path()).unwrap();
        assert!(lines.contains(&"TestingTorNetwork 1".to_string()));
        assert!(lines.iter().any(|l| l.starts_with("DirAuthority test000a")));
        assert!(!lines.iter().any(|l| l.starts_with("DataDirectory")));
        assert!(!lines.iter().any(|l| l.starts_with("SocksPort")));
    }

    #[test]
    fn chutney_lines_missing_dir_errors() {
        assert!(chutney_extra_torrc_lines(Path::new("/nonexistent")).is_err());
    }
}
