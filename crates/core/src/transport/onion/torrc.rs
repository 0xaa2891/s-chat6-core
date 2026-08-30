//! Base torrc template.
//!
//! `HiddenService*` DoS/PoW tuning cannot live in the base torrc: tor
//! rejects those options without a preceding
//! HiddenServiceDir, so with ephemeral `ADD_ONION` hosting they move to
//! per-service `ADD_ONION` parameters (see `OnionServiceManager`).

use std::path::PathBuf;

pub struct TorrcParams {
    pub data_dir: PathBuf,
    pub control_port: u16,
    pub socks_port: u16,
    pub client_auth_dir: PathBuf,
    pub log_file: Option<PathBuf>,
    /// Extra lines appended at the end (testnet authority lines, etc.).
    pub extra: Vec<String>,
}

pub fn base_torrc(p: &TorrcParams) -> String {
    let mut s = String::new();
    s.push_str("ClientOnly 1\n");
    s.push_str("SafeLogging 1\n");
    s.push_str(&format!("DataDirectory {}\n", p.data_dir.display()));
    s.push_str(&format!("ControlPort 127.0.0.1:{}\n", p.control_port));
    s.push_str("CookieAuthentication 1\n");
    s.push_str(&format!(
        "SocksPort 127.0.0.1:{} IsolateSOCKSAuth IsolateDestAddr IsolateClientProtocol\n",
        p.socks_port
    ));
    s.push_str(&format!(
        "ClientOnionAuthDir {}\n",
        p.client_auth_dir.display()
    ));
    match &p.log_file {
        Some(f) => s.push_str(&format!("Log notice file {}\n", f.display())),
        None => s.push_str("Log notice stdout\n"),
    }
    s.push_str("KeepalivePeriod 60\n");
    s.push_str("MaxClientCircuitsPending 48\n");
    s.push_str("VanguardsLiteEnabled 1\n");
    for line in &p.extra {
        s.push_str(line);
        s.push('\n');
    }
    s
}
