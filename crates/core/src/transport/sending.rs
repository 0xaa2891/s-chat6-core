//! Outbound send path on the transport (framing + the pooled SOCKS
//! sender).

use super::error::TransportError;
use super::framing;
use super::Transport;

impl Transport {
    /// Send one framed record to a peer onion. `payload` must already be a
    /// bucket-sized v2 record (see [`framing::pack`]).
    pub async fn send_frame(
        &self,
        dest_onion: &str,
        payload: &[u8],
        alert: bool,
    ) -> Result<(), TransportError> {
        self.send_record(dest_onion, None, payload, alert).await
    }

    /// `send_frame` with an intro block riding outside the record (the
    /// pairing payload on a relationship's first frames).
    pub async fn send_record(
        &self,
        dest_onion: &str,
        intro: Option<&[u8]>,
        payload: &[u8],
        alert: bool,
    ) -> Result<(), TransportError> {
        if self.kill_switch.is_on() {
            return Err(TransportError::KillSwitch);
        }
        let packed = framing::pack(intro, payload, alert)?;
        let sender = self.sender.read().await.clone();
        let sender = sender.ok_or(TransportError::Offline)?;
        sender.send(dest_onion, packed).await
    }
}
