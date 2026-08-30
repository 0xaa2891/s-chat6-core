//! Structured transport errors. No silent drops: every failure path in
//! `transport/` ends up here, and every heal/retry logs the reason.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("control port: {0}")]
    Control(String),

    #[error("control port replied {code}: {message}")]
    ControlReply { code: u16, message: String },

    #[error("control connection closed")]
    ControlClosed,

    #[error("socks: {0}")]
    Socks(String),

    #[error("connect to {dest} failed after {attempts} attempts: {reason}")]
    ConnectFailed {
        dest: String,
        attempts: u32,
        reason: String,
    },

    #[error("kill switch engaged; send refused")]
    KillSwitch,

    #[error("daemon is dead: {0}")]
    DaemonDead(String),

    #[error("transport is not online")]
    Offline,

    #[error("timeout: {0}")]
    Timeout(String),

    #[error("invalid onion address: {0}")]
    InvalidOnion(String),

    #[error("key store: {0}")]
    KeyStore(String),

    #[error("malformed frame: {0}")]
    MalformedFrame(String),
}

impl From<schat_wire_types::WireError> for TransportError {
    fn from(e: schat_wire_types::WireError) -> Self {
        TransportError::MalformedFrame(e.to_string())
    }
}
