//! Onion service hosting on the transport: bind the inbound listener,
//! get-or-create the v3 key, defer `ADD_ONION` until tor is online, and
//! manage v3 client authorization.

use std::sync::Arc;

use tracing::{debug, info};

use super::error::TransportError;
use super::inbound::{InboundDrop, InboundListener};
use super::onion::{self, ClientAuthKeys, OnionServiceManager};
use super::status::ServiceState;
use super::{HostedEntry, Transport, TransportEvent};

impl Transport {
    /// Host an onion service for `service_id`. The key is generated
    /// locally, so the onion address is returned synchronously; the actual
    /// `ADD_ONION` is deferred until tor is online (see `published` on
    /// `HostedEntry`). With `restricted`, a fresh x25519 client-auth
    /// keypair is generated; the public half restricts discovery, the
    /// private half is persisted for the peer to use (pairing hands it
    /// over).
    pub async fn host_service(
        self: &Arc<Self>,
        service_id: &str,
        restricted: bool,
    ) -> Result<String, TransportError> {
        let client_auth = if restricted {
            let keys = ClientAuthKeys::generate();
            self.keys
                .put(&format!("client-auth/{service_id}"), &keys.private_b32)
                .await?;
            vec![keys.public_b32]
        } else {
            Vec::new()
        };
        self.host_service_with_auth(service_id, &client_auth).await
    }

    /// Host a service with an explicit v3 client-auth list (empty = open).
    /// Pairing uses this: the accepter's service is restricted to the
    /// inviter's key from the moment it exists, and the inviter's
    /// invitation service becomes restricted when the request is accepted.
    /// Re-hosting an existing service updates its auth list and
    /// re-publishes (`ADD_ONION` with the same key blob replaces the
    /// ephemeral service).
    pub async fn host_service_with_auth(
        self: &Arc<Self>,
        service_id: &str,
        client_auth: &[String],
    ) -> Result<String, TransportError> {
        let listener = InboundListener::bind(service_id.to_string(), 0, self.seen.clone(), {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundDrop>(256);
            let drops = self.drops.clone();
            let events = self.events.clone();
            let this = Arc::downgrade(self);
            tokio::spawn(async move {
                while let Some(drop) = rx.recv().await {
                    let alert = drop.frame.alert;
                    let first = drop.first_sight;
                    let service_id = drop.service_id.clone();
                    let _ = drops.send(drop);
                    if let Some(this) = this.upgrade() {
                        this.note_inbound();
                    }
                    if alert && first {
                        let _ = events.send(TransportEvent::Arrival { service_id });
                    }
                }
            });
            tx
        })
        .await?;
        let target = format!("127.0.0.1:{}", listener.port());
        // Get-or-create the service key locally; the address never depends
        // on tor being reachable.
        let store_key = format!("{}{service_id}", onion::ONION_KEY_PREFIX);
        let onion = match self.keys.get(&store_key).await? {
            Some(blob) => format!("{}.onion", onion::hostname_from_key_blob(&blob)?),
            None => {
                let (blob, hostname) = onion::generate_v3_key_blob();
                self.keys.put(&store_key, &blob).await?;
                format!("{hostname}.onion")
            }
        };
        self.services.lock().await.insert(
            service_id.to_string(),
            HostedEntry {
                onion: onion.clone(),
                state: ServiceState::Publishing,
                target,
                client_auth: client_auth.to_vec(),
                published: false,
                listener: Arc::new(listener),
            },
        );
        self.refresh_services_status().await;
        info!(service_id, %onion, restricted = !client_auth.is_empty(), "hosting onion service");
        self.publish_pending().await;
        Ok(onion)
    }

    pub async fn remove_service(&self, service_id: &str) -> Result<(), TransportError> {
        // DEL_ONION takes tor's ServiceID (the onion hostname), not our
        // logical service id — and only makes sense if the service was
        // published to this daemon.
        let tor_id = self.services.lock().await.get(service_id).and_then(|e| {
            e.published
                .then(|| e.onion.trim_end_matches(".onion").to_string())
        });
        if let Some(tor_id) = tor_id {
            let control = self.control().await?;
            let manager = OnionServiceManager::new(control, self.keys.clone());
            manager.remove_service(&tor_id).await?;
        }
        self.services.lock().await.remove(service_id);
        self.refresh_services_status().await;
        Ok(())
    }

    /// Write a `.auth_private` file for a peer's restricted service and
    /// reload tor so it takes effect (an explicit RELOAD, not a
    /// side-effect reload). With no daemon
    /// attached the file is still written: tor reads `ClientOnionAuthDir`
    /// at boot, so the install is simply deferred until then.
    pub async fn install_client_auth(
        &self,
        peer_onion: &str,
        private_b32: &str,
    ) -> Result<(), TransportError> {
        let dir = match self.daemon.read().await.clone() {
            Some(daemon) => daemon.client_auth_dir(),
            None => self.client_auth_dir.clone(),
        };
        onion::write_client_auth_file(&dir, peer_onion, private_b32)?;
        if let Ok(control) = self.control().await {
            control
                .setconf(&[(
                    "ClientOnionAuthDir".into(),
                    dir.to_string_lossy().to_string(),
                )])
                .await?;
            control.signal("RELOAD").await?;
        } else {
            debug!(
                peer_onion,
                "client auth installed (deferred until daemon attach)"
            );
        }
        Ok(())
    }

    /// The persisted client-auth private key for a hosted restricted
    /// service (pairing hands this to the peer).
    pub async fn client_auth_private(
        &self,
        service_id: &str,
    ) -> Result<Option<String>, TransportError> {
        self.keys.get(&format!("client-auth/{service_id}")).await
    }
}
