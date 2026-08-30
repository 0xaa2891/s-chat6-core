//! SOCKS5 send path.
//!
//! - CONNECT with ATYP=domain — `.onion` names are **never** resolved locally.
//! - Username/password auth where both are the per-purpose token
//!   ([`PURPOSE_CHAT`]); combined with `IsolateSOCKSAuth` in the torrc this
//!   yields per-destination circuits.
//! - Per-destination connect-on-send, ~25 s connect timeout, exponential
//!   backoff with cap, coalesced writes of already-queued frames, structured
//!   `TransportError`s instead of silent drops. After a write the SOCKS
//!   stream stays up for [`CONVERSATION_HOLD`] so a follow-up message reuses
//!   the circuit; then it drops. No 5–15 min idle, no dummy frames.

mod handshake;
mod sender;

pub use handshake::{socks_connect, socks_handshake};
pub use sender::Sender;

#[cfg(test)]
mod tests;

use std::time::Duration;

/// RFC1929 username **and** password for chat traffic.
pub const PURPOSE_CHAT: &str = "chat";

pub const SOCKS_TCP_TIMEOUT: Duration = Duration::from_millis(3_000);
pub const SOCKS_CONNECT_TIMEOUT: Duration = Duration::from_millis(25_000);

pub const CONNECT_RETRY_MS: u64 = 1_500;
pub const CONNECT_RETRY_MAX_MS: u64 = 24_000;
pub const MAX_CONNECT_FAILS: u32 = 8;
pub const MAX_WRITE_RETRIES: u32 = 3;

pub const WRITE_COALESCE_MIN: usize = 512 * 1024;
pub const WRITE_COALESCE_MAX: usize = 2 * 1024 * 1024;
pub const MAX_LIVE_SESSIONS: usize = 8;

/// Keep the SOCKS stream (and thus the onion circuit) after a real send so
/// the next message in the same conversation does not pay a new CONNECT.
/// 60 s is long enough for a reply without holding circuits for minutes.
pub const CONVERSATION_HOLD: Duration = Duration::from_secs(60);

/// Backoff after `fails` consecutive connect failures (1-based):
/// `1500 << min(fails-1, 4)`, capped at 24 s, plus 0–999 ms jitter.
pub fn connect_backoff(fails: u32, jitter_ms: u64) -> Duration {
    let shift = fails.saturating_sub(1).min(4);
    let base = CONNECT_RETRY_MS
        .checked_shl(shift)
        .unwrap_or(u64::MAX)
        .min(CONNECT_RETRY_MAX_MS);
    Duration::from_millis(base + jitter_ms % 1000)
}
