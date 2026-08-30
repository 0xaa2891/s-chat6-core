//! Policy knobs on the transport: kill switch, circumvention (bridges /
//! pluggable transports), and the Briar-style roaming reset on network
//! changes.

use std::sync::atomic::Ordering;
use std::time::Duration;

use tracing::{debug, info};

use super::circumvention::{self, CircumventionConfig};
use super::error::TransportError;
use super::status::TorState;
use super::Transport;

impl Transport {
    pub async fn set_kill_switch(&self, on: bool) -> Result<(), TransportError> {
        self.kill_switch.set(on)?;
        self.update_status(|s| s.kill_switch = on);
        info!(on, "kill switch toggled");
        if let Some(control) = self.control.read().await.clone() {
            // Fail-closed: DisableNetwork follows the kill switch.
            control
                .setconf(&[("DisableNetwork".into(), if on { "1" } else { "0" }.into())])
                .await?;
        }
        if !on {
            // Resume: nudge the supervisor to re-check reachability.
            self.set_tor_state(TorState::Starting);
        }
        Ok(())
    }

    pub async fn apply_circumvention(
        &self,
        config: &CircumventionConfig,
    ) -> Result<Option<String>, TransportError> {
        config.validate()?;
        let warning = config.pt_warning();
        let control = self.control().await?;
        // Clear stale bridge lines first, then apply the batch.
        control
            .resetconf(&circumvention::MANAGED_KEYS)
            .await
            .or_else(|e| {
                debug!(error = %e, "RESETCONF before circumvention failed (continuing)");
                Ok::<(), TransportError>(())
            })?;
        control.setconf(&config.setconf_pairs()).await?;
        info!(?config, "circumvention applied");
        Ok(warning)
    }

    /// Network change entry point.
    /// Briar-style roaming reset: on regain, bounce `DisableNetwork`
    /// 1 → wait 1 s → 0.
    pub async fn on_network_changed(&self, has_path: bool) -> Result<(), TransportError> {
        let Some(control) = self.control.read().await.clone() else {
            debug!(has_path, "network changed before control attach");
            return Ok(());
        };
        if !has_path {
            info!("network path lost; DisableNetwork 1");
            control
                .setconf(&[("DisableNetwork".into(), "1".into())])
                .await?;
            self.online.store(false, Ordering::SeqCst);
            self.set_tor_state(TorState::Degraded {
                reason: "network path lost".into(),
            });
            return Ok(());
        }
        info!("network regained; roaming reset (DisableNetwork 1 → 0)");
        control
            .setconf(&[("DisableNetwork".into(), "1".into())])
            .await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        control
            .setconf(&[("DisableNetwork".into(), "0".into())])
            .await?;
        Ok(())
    }
}
