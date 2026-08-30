//! Transport lifecycle: bring-up, shutdown, and the background health
//! supervisor (bootstrap watch, HS_DESC health, heal ladder, control
//! reconnect, deferred `ADD_ONION` publish).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use super::control::{ControlClient, TorEvent};
use super::daemon::TorDaemon;
use super::error::TransportError;
use super::heal::{self, HealAction, HealLadder, HsHealth, RestartBudget};
use super::onion::{self, OnionServiceManager};
use super::socks::Sender;
use super::status::{now_secs, InboxStatus, OutboxStatus, ServiceState, TorState};
use super::Transport;

impl Transport {
    /// Bring the transport up: start the daemon, attach the control
    /// connection, build the sender, re-host services, then spawn the
    /// background health loop. Returns only once the transport is usable
    /// (or the bring-up fails), so callers never race the attach.
    pub async fn start(self: &Arc<Self>) -> Result<(), TransportError> {
        let mut guard = self.supervisor.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        self.shutdown.send_replace(false);

        let daemon = self
            .daemon
            .read()
            .await
            .clone()
            .ok_or_else(|| TransportError::Control("no daemon configured".into()))?;

        self.set_tor_state(TorState::Starting);
        daemon.start().await?;
        let control = self.connect_control(daemon.clone()).await?;
        control
            .setevents(&["HS_DESC", "STATUS_GENERAL", "CIRC"])
            .await?;

        // Kill switch engaged at boot: the daemon runs with the network
        // disabled and all sends refused until release.
        if self.kill_switch.is_on() {
            self.update_status(|s| s.kill_switch = true);
            control
                .setconf(&[("DisableNetwork".into(), "1".into())])
                .await?;
            self.set_tor_state(TorState::Off);
        }

        self.publish_pending().await;

        // Event pump: HS_DESC health feeds the heal ladder. Re-subscribes
        // when the control connection is replaced by a heal reconnect.
        let (hs_tx, hs_rx) = tokio::sync::mpsc::channel::<bool>(64);
        {
            let this = self.clone();
            tokio::spawn(async move {
                loop {
                    if *this.shutdown.borrow() {
                        return;
                    }
                    let Some(ctrl) = this.control.read().await.clone() else {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    };
                    let mut events = ctrl.events();
                    loop {
                        match events.recv().await {
                            Ok(TorEvent::HsDesc { action, .. }) => {
                                let failed = action.contains("FAILED");
                                let uploaded = action == "UPLOADED";
                                if (failed || uploaded) && hs_tx.send(!failed).await.is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                debug!(n, "tor event lag");
                            }
                            Err(broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            });
        }

        let this = self.clone();
        *guard = Some(tokio::spawn(async move {
            this.health_loop(daemon, control, hs_rx).await;
        }));
        Ok(())
    }

    pub async fn stop(&self) {
        self.shutdown.send_replace(true);
        if let Some(task) = self.supervisor.lock().await.take() {
            task.abort();
        }
        if let Some(daemon) = self.daemon.read().await.clone() {
            let _ = daemon.stop().await;
        }
        self.online.store(false, Ordering::SeqCst);
        self.set_tor_state(TorState::Off);
    }

    /// Ongoing bootstrap/health supervision. Bring-up lives in `start()`;
    /// this loop only watches and heals.
    async fn health_loop(
        self: &Arc<Self>,
        daemon: Arc<dyn TorDaemon>,
        mut control: Arc<ControlClient>,
        mut hs_rx: tokio::sync::mpsc::Receiver<bool>,
    ) {
        let mut ladder = HealLadder::system();
        let mut restarts = RestartBudget::system();
        let mut hs_health = HsHealth::default();
        let mut hs_window_start = now_secs() * 1000;
        let mut connect_fails: u32 = 0;

        // Bootstrap + health loop.
        let mut boot_pct: u8 = 0;
        loop {
            if *self.shutdown.borrow() {
                return;
            }
            debug!("health tick");
            if self.kill_switch.is_on() {
                self.online.store(false, Ordering::SeqCst);
                self.set_tor_state(TorState::Off);
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }

            // A dead tor subprocess fails every ladder rung below Restart
            // (Reload/Newnym signal a process that no longer exists), so
            // detect the exit directly and restart straight away instead
            // of burning minutes on control-poll escalation.
            if daemon.unexpected_exit().await {
                warn!("tor subprocess exited unexpectedly; restarting");
                self.online.store(false, Ordering::SeqCst);
                self.set_tor_state(TorState::Degraded {
                    reason: "tor subprocess exited".into(),
                });
                connect_fails = 0;
                if !restarts.record_restart() {
                    let msg = "restart budget exhausted (tor subprocess exited)".to_string();
                    warn!(%msg);
                    self.set_tor_state(TorState::Dead { reason: msg });
                    return;
                }
                if let Err(e) = daemon.restart().await {
                    warn!(error = %e, "subprocess restart failed");
                }
                match self.connect_control(daemon.clone()).await {
                    Ok(new_control) => {
                        let _ = new_control
                            .setevents(&["HS_DESC", "STATUS_GENERAL", "CIRC"])
                            .await;
                        control = new_control;
                    }
                    Err(e) => warn!(error = %e, "control reconnect failed"),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }

            // Drain HS_DESC health events.
            while let Ok(uploaded) = hs_rx.try_recv() {
                if uploaded {
                    hs_health.record_uploaded();
                } else {
                    hs_health.record_failed();
                }
            }
            let now_ms = now_secs() * 1000;
            if now_ms.saturating_sub(hs_window_start) >= heal::HS_WINDOW_MS {
                let (escalate, healthy) = hs_health.evaluate();
                hs_health.clear();
                hs_window_start = now_ms;
                if healthy {
                    ladder.reset();
                }
                if escalate {
                    self.run_heal(
                        &mut ladder,
                        &mut restarts,
                        daemon.clone(),
                        "hs_desc failures",
                    )
                    .await;
                }
            }

            match control.bootstrap_progress().await {
                Ok(pct) => {
                    connect_fails = 0;
                    if pct != boot_pct {
                        boot_pct = pct;
                        debug!(pct, "bootstrap progress");
                    }
                    if pct >= 100 {
                        let circuit = control.circuit_established().await.unwrap_or(false);
                        let _ = circuit; // socks listener presence is implied on subprocess
                        if !self.online.load(Ordering::SeqCst) {
                            info!("transport online");
                            self.online.store(true, Ordering::SeqCst);
                            ladder.reset();
                        }
                        // Reconcile every tick, not just on the online-flag
                        // transition: set_kill_switch(false) moves the state
                        // to Starting even when the loop never observed the
                        // on-window (flag still true), and a transition-only
                        // check would leave the status stuck at Starting.
                        if !matches!(self.status().tor, TorState::Online) {
                            self.set_tor_state(TorState::Online);
                        }
                        self.publish_pending().await;
                    } else {
                        self.online.store(false, Ordering::SeqCst);
                        self.set_tor_state(TorState::Bootstrapping { pct });
                    }
                }
                Err(e) => {
                    connect_fails += 1;
                    let reason = e.to_string();
                    warn!(connect_fails, %reason, "control poll failed");
                    self.online.store(false, Ordering::SeqCst);
                    self.set_tor_state(TorState::Degraded {
                        reason: reason.clone(),
                    });
                    if connect_fails >= heal::HEAL_CONNECT_FAILS {
                        self.run_heal(
                            &mut ladder,
                            &mut restarts,
                            daemon.clone(),
                            &format!("control poll failures: {reason}"),
                        )
                        .await;
                        connect_fails = 0;
                        // Reconnect control after healing.
                        match self.connect_control(daemon.clone()).await {
                            Ok(new_control) => {
                                let _ = new_control
                                    .setevents(&["HS_DESC", "STATUS_GENERAL", "CIRC"])
                                    .await;
                                self.publish_pending().await;
                                control = new_control;
                            }
                            Err(e) => {
                                warn!(error = %e, "control reconnect failed");
                            }
                        }
                    }
                }
            }

            // Outbox/inbox rollup.
            let queued = match self.sender.read().await.as_ref() {
                Some(s) => s.dest_count().await as u32,
                None => 0,
            };
            let drain_age = self.last_drain_secs_ago(now_secs());
            self.update_status(|s| {
                s.outbox = OutboxStatus {
                    queued,
                    oldest_age_secs: 0,
                    next_retry_secs: None,
                };
                s.inbox = InboxStatus {
                    pending: s.inbox.pending,
                    last_drain_secs_ago: drain_age,
                };
            });

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// `ADD_ONION` every hosted service not yet live on the current
    /// control connection. No-op while offline: tor must have directory
    /// info before a service is added, otherwise it computes a broken
    /// initial descriptor upload schedule. Persisted key blobs bring the
    /// same onion addresses back after a daemon restart (descriptor
    /// republish).
    pub(super) async fn publish_pending(self: &Arc<Self>) {
        if !self.online.load(Ordering::SeqCst) {
            return;
        }
        let entries: Vec<(String, String, Vec<String>)> = self
            .services
            .lock()
            .await
            .iter()
            .filter(|(_, e)| !e.published)
            .map(|(id, e)| (id.clone(), e.target.clone(), e.client_auth.clone()))
            .collect();
        if entries.is_empty() {
            return;
        }
        let Ok(control) = self.control().await else {
            return;
        };
        let manager = OnionServiceManager::new(control, self.keys.clone());
        for (service_id, target, client_auth) in entries {
            match manager
                .host_service(&service_id, &target, &client_auth)
                .await
            {
                Ok(hosted) => {
                    info!(service_id, onion = %hosted.onion, "service published");
                    if let Some(entry) = self.services.lock().await.get_mut(&service_id) {
                        entry.published = true;
                        entry.state = ServiceState::Reachable;
                    }
                }
                Err(e) => {
                    warn!(service_id, error = %e, "publish failed");
                    self.update_status(|s| {
                        s.last_error = Some(format!("publish {service_id}: {e}"));
                    });
                }
            }
        }
        self.refresh_services_status().await;
    }

    /// One heal-ladder rung, always logged with its reason (standing rule 6).
    async fn run_heal(
        &self,
        ladder: &mut HealLadder,
        restarts: &mut RestartBudget,
        daemon: Arc<dyn TorDaemon>,
        reason: &str,
    ) {
        let Some(action) = ladder.escalate() else {
            debug!(%reason, "heal cooldown active; skipping");
            return;
        };
        warn!(?action, %reason, "self-heal triggered");
        self.update_status(|s| {
            s.last_error = Some(format!("heal {action:?}: {reason}"));
        });
        match action {
            HealAction::Reload => {
                if let Some(control) = self.control.read().await.clone() {
                    if let Err(e) = control.signal("RELOAD").await {
                        warn!(error = %e, "heal RELOAD failed");
                    }
                }
            }
            HealAction::Newnym => {
                if let Some(control) = self.control.read().await.clone() {
                    if let Err(e) = control.signal("NEWNYM").await {
                        warn!(error = %e, "heal NEWNYM failed");
                    }
                }
            }
            HealAction::Restart => {
                if !restarts.record_restart() {
                    let msg = format!("restart budget exhausted ({reason})");
                    warn!(%msg);
                    self.set_tor_state(TorState::Dead { reason: msg });
                    return;
                }
                if let Err(e) = daemon.restart().await {
                    warn!(error = %e, "heal restart failed");
                }
            }
        }
    }

    /// (Re)establish the control connection and rebuild the sender.
    async fn connect_control(
        &self,
        daemon: Arc<dyn TorDaemon>,
    ) -> Result<Arc<ControlClient>, TransportError> {
        // Attach poll: 400 ms.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let control = loop {
            match ControlClient::connect(daemon.control_addr(), daemon.control_auth()).await {
                Ok(c) => break c,
                Err(e) => {
                    if std::time::Instant::now() > deadline {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
            }
        };
        *self.control.write().await = Some(control.clone());
        // Ephemeral services are tied to the control connection: every new
        // connection invalidates published state; the health loop
        // re-publishes once online.
        for entry in self.services.lock().await.values_mut() {
            entry.published = false;
        }
        let sender = Sender::new(
            daemon.socks_addr(),
            onion::VIRTUAL_PORT,
            self.kill_switch.flag(),
            self.online.clone(),
        );
        *self.sender.write().await = Some(sender);
        Ok(control)
    }
}
