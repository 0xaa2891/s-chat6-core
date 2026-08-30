//! Service manager: drives `ADD_ONION` / `DEL_ONION` for hosted services.

use std::sync::Arc;

use crate::transport::control::ControlClient;
use crate::transport::error::TransportError;

use super::KeyStore;

pub const ONION_KEY_PREFIX: &str = "onion-key/";

pub struct OnionServiceManager {
    control: Arc<ControlClient>,
    keys: Arc<dyn KeyStore>,
}

pub struct HostedService {
    pub service_id: String,
    pub onion: String,
}

impl OnionServiceManager {
    pub fn new(control: Arc<ControlClient>, keys: Arc<dyn KeyStore>) -> Self {
        Self { control, keys }
    }

    /// Host a service for `service_id` forwarding virtual port 80 to
    /// `target` (e.g. `127.0.0.1:4001`). Reuses the persisted key blob or
    /// generates and persists a new one. `client_auth_v3` restricts
    /// discovery to holders of the matching private keys.
    pub async fn host_service(
        &self,
        service_id: &str,
        target: &str,
        client_auth_v3: &[String],
    ) -> Result<HostedService, TransportError> {
        let store_key = format!("{ONION_KEY_PREFIX}{service_id}");
        let existing = self.keys.get(&store_key).await?;
        if let Some(blob) = existing.as_deref() {
            // ADD_ONION has no replace semantics: a live ephemeral service
            // with the same key makes tor reject the add ("private key
            // collides"), leaving tor forwarding to the STALE target port
            // while our entry points at the new listener. Delete first so
            // re-hosting (auth update, boot restore) actually rebinds.
            // Best-effort: the service usually doesn't exist yet.
            if let Ok(hostname) = super::hostname_from_key_blob(blob) {
                let _ = self.control.del_onion(&hostname).await;
            }
        }
        let result = self
            .control
            .add_onion(existing.as_deref(), target, client_auth_v3)
            .await?;
        if existing.is_none() {
            let blob = result.private_key.clone().ok_or_else(|| {
                TransportError::Control("ADD_ONION NEW: reply missing PrivateKey".into())
            })?;
            // Reply is "ED25519-V3:<blob>"; persist only the blob half.
            let blob = blob
                .strip_prefix("ED25519-V3:")
                .unwrap_or(&blob)
                .to_string();
            self.keys.put(&store_key, &blob).await?;
        }
        Ok(HostedService {
            onion: format!("{}.onion", result.service_id),
            service_id: result.service_id,
        })
    }

    pub async fn remove_service(&self, service_id: &str) -> Result<(), TransportError> {
        self.control.del_onion(service_id).await?;
        Ok(())
    }

    /// Re-add every persisted service on boot (keys survive; ephemeral
    /// services do not).
    pub async fn restore_services(
        &self,
        target_for: impl Fn(&str) -> String,
    ) -> Result<Vec<HostedService>, TransportError> {
        let mut out = Vec::new();
        for key in self.keys.keys_with_prefix(ONION_KEY_PREFIX).await? {
            let service_id = key.trim_start_matches(ONION_KEY_PREFIX).to_string();
            let hosted = self
                .host_service(&service_id, &target_for(&service_id), &[])
                .await?;
            out.push(hosted);
        }
        Ok(out)
    }
}
