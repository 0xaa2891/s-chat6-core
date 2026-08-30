//! Transport at the boundary: daemon handoff, lifecycle, kill switch,
//! circumvention, raw frame send, and the event subscription.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::transport::circumvention::CircumventionConfig;
use crate::transport::control::ControlAuth;
use crate::transport::status::{OnionMode, TransportStatus};
use crate::transport::TransportEvent;

use super::{CoreError, SchatCore, SchatEvent, SchatEventListener};

#[uniffi::export]
impl SchatCore {
    /// Client-side daemon handoff: the shell started the
    /// Tor daemon itself and passes SOCKS addr, control addr, and auth (e.g.
    /// cookie bytes it read) in here. The core never starts processes on a
    /// client OS.
    pub fn attach_tor(
        &self,
        socks_addr: String,
        control_addr: String,
        auth: ControlAuth,
    ) -> Result<(), CoreError> {
        let socks: SocketAddr = socks_addr
            .parse()
            .map_err(|e| CoreError::Other(format!("bad socks addr: {e}")))?;
        let control: SocketAddr = control_addr
            .parse()
            .map_err(|e| CoreError::Other(format!("bad control addr: {e}")))?;
        self.rt
            .block_on(self.transport.attach_tor(socks, control, auth))?;
        Ok(())
    }

    pub fn start_transport(&self) -> Result<(), CoreError> {
        self.rt.block_on(self.transport.start())?;
        Ok(())
    }

    pub fn stop_transport(&self) {
        self.rt.block_on(self.transport.stop());
    }

    pub fn transport_status(&self) -> TransportStatus {
        self.transport.status()
    }

    pub fn set_kill_switch(&self, on: bool) -> Result<(), CoreError> {
        self.rt.block_on(self.transport.set_kill_switch(on))?;
        Ok(())
    }

    pub fn set_onion_mode(&self, mode: OnionMode) {
        self.transport.set_mode(mode);
    }

    /// Apply a circumvention config. Returns the honest "no PT binary"
    /// warning when one applies (the client decides how to show it).
    pub fn apply_circumvention(
        &self,
        config: CircumventionConfig,
    ) -> Result<Option<String>, CoreError> {
        Ok(self
            .rt
            .block_on(self.transport.apply_circumvention(&config))?)
    }

    /// Network-change entry point. Rust runs the `DisableNetwork` roaming
    /// reset; the client only reports "path / no path".
    pub fn on_network_changed(&self, has_path: bool) {
        let transport = self.transport.clone();
        self.rt.spawn(async move {
            if let Err(e) = transport.on_network_changed(has_path).await {
                tracing::warn!(error = %e, "on_network_changed failed");
            }
        });
    }

    /// Host an onion service; returns the onion hostname. `restricted`
    /// enables v3 client authorization (restricted discovery).
    pub fn host_service(&self, service_id: String, restricted: bool) -> Result<String, CoreError> {
        Ok(self
            .rt
            .block_on(self.transport.host_service(&service_id, restricted))?)
    }

    pub fn remove_service(&self, service_id: String) -> Result<(), CoreError> {
        self.rt
            .block_on(self.transport.remove_service(&service_id))?;
        Ok(())
    }

    /// Send one framed record to a peer onion. `payload` must be a
    /// bucket-sized v2 record (256/512/1024/4096/16384/32768 bytes, first
    /// byte 0x02). Bytes on the wire are the transport's concern; higher
    /// layers fill the record.
    pub fn send_frame(
        &self,
        dest_onion: String,
        payload: Vec<u8>,
        alert: bool,
    ) -> Result<(), CoreError> {
        self.rt
            .block_on(self.transport.send_frame(&dest_onion, &payload, alert))?;
        Ok(())
    }

    pub fn subscribe_events(&self, listener: Arc<dyn SchatEventListener>) {
        let mut rx = self.transport.subscribe_events();
        self.rt.spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(TransportEvent::Status(status)) => {
                        listener.on_event(SchatEvent::Transport(status));
                    }
                    Ok(TransportEvent::Arrival { service_id }) => {
                        listener.on_event(SchatEvent::Arrival { service_id });
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        });
    }
}
