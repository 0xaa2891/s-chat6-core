//! `sent_at` handling (clamp to local now, hardened to fail closed on
//! abuse).
//!
//! The sender's clock is untrusted:
//! - Mildly-future timestamps are **clamped** to local now — a peer must
//!   not pin a message to the top of the thread by dating it next week.
//! - Grossly-future timestamps (past [`MAX_FUTURE_SKEW_SECS`]) are
//!   **rejected**: that's not clock skew, it's a hostile or broken peer.

use super::SyncError;

/// Tolerance for honest clock skew: five minutes.
pub const MAX_FUTURE_SKEW_SECS: u64 = 300;

/// Validate and normalize an inbound envelope's `sent_at`. Returns the
/// clamped timestamp to store.
pub fn clamp_sent_at(sent_at: u64, now: u64) -> Result<u64, SyncError> {
    if sent_at > now + MAX_FUTURE_SKEW_SECS {
        return Err(SyncError::FutureTimestamp { sent_at, now });
    }
    Ok(sent_at.min(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_and_present_pass_through() {
        assert_eq!(clamp_sent_at(500, 1000).unwrap(), 500);
        assert_eq!(clamp_sent_at(1000, 1000).unwrap(), 1000);
    }

    #[test]
    fn mildly_future_clamps_to_now() {
        assert_eq!(clamp_sent_at(1000 + 299, 1000).unwrap(), 1000);
        assert_eq!(
            clamp_sent_at(1000 + MAX_FUTURE_SKEW_SECS, 1000).unwrap(),
            1000
        );
    }

    #[test]
    fn grossly_future_rejected() {
        assert!(matches!(
            clamp_sent_at(1000 + MAX_FUTURE_SKEW_SECS + 1, 1000),
            Err(SyncError::FutureTimestamp { .. })
        ));
    }
}
