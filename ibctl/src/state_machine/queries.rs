//! Query handling and JSON response builders for the command server.
//!
//! Hot-path queries (STATUS, STATE, CONFIG) are served via a `watch` channel
//! snapshot — the command server reads the latest value directly without going
//! through the state machine's mpsc. Only WINDOWS (which requires async agent
//! I/O) still uses the mpsc/oneshot path.

use std::sync::Arc;

use crate::types::{Query, QuerySnapshot};

use super::types::{client_advisory, State, StateMachine};

impl StateMachine {
    /// Publish a fresh query snapshot to the watch channel.
    ///
    /// Called after state transitions, command handling, and at the top of
    /// the main loop. The command server reads this snapshot directly for
    /// STATUS/STATE/CONFIG — no mpsc round-trip needed.
    pub(super) fn publish_snapshot(&mut self) {
        self.snapshot_version += 1;
        let snapshot = Arc::new(QuerySnapshot {
            status_json: self.build_status_json(),
            state_json: self.build_state_json(),
            config_json: self.build_config_json(),
            published_at: std::time::Instant::now(),
            version: self.snapshot_version,
            start_time: self.start_time,
            connected_since: self.connected_since,
        });
        // Ignore error — means no receivers exist (command server not started)
        let _ = self.snapshot_tx.send(snapshot);
    }

    /// Process pending queries that require async I/O (WINDOWS only).
    ///
    /// STATUS/STATE/CONFIG are handled by the command server directly
    /// via the watch snapshot. This method drains WINDOWS and LOGS queries
    /// that need the state machine's async capabilities or stub responses.
    pub(super) async fn process_queries(&mut self) {
        loop {
            match self.query_rx.try_recv() {
                Ok(query) => self.handle_query(query).await,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Handle a single query. Only WINDOWS needs async processing here;
    /// STATUS/STATE/CONFIG are answered from the watch snapshot by the
    /// command server, but we handle them as fallback if they arrive.
    async fn handle_query(&mut self, query: Query) {
        match query {
            // These should be served from the watch snapshot by the command
            // server. If they arrive here, answer them directly as fallback.
            Query::Status(tx) => {
                let _ = tx.send(self.build_status_json());
            }
            Query::State(tx) => {
                let _ = tx.send(self.build_state_json());
            }
            Query::Config(tx) => {
                let _ = tx.send(self.build_config_json());
            }
            Query::Logs(limit, tx) => {
                let json = serde_json::json!({
                    "error": "not_implemented",
                    "message": "LOGS command is not yet implemented — use container logs instead",
                    "limit": limit,
                }).to_string();
                let _ = tx.send(json);
            }
            Query::Windows(tx) => {
                let json = self.build_windows_json().await;
                let _ = tx.send(json);
            }
        }
    }

    /// Build the full STATUS JSON response for the dashboard.
    ///
    /// All data is read from in-memory fields, no agent I/O.
    /// Client IDs are refreshed every 30s in do_connected() and cached.
    fn build_status_json(&mut self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let connected_uptime = self.connected_since.map(|t| t.elapsed().as_secs());
        let socat_running = self.socat_process.as_mut()
            .map(|c| c.try_wait().ok().flatten().is_none())
            .unwrap_or(false);
        let socat_pid = self.socat_process.as_ref().map(|c| c.id());

        let is_connected = matches!(self.state, State::Connected(_));
        let (should_connect, should_wait, wait_reason, client_id_likely_stale) =
            client_advisory(&self.state);

        let jvm = self.supervisor.jvm_info();

        // Use cached client IDs (refreshed every 30s in do_connected)
        let client_ids = &self.cached_client_ids;

        serde_json::json!({
            "version": env!("IBCTL_VERSION"),
            "ready": is_connected && socat_running,
            "state": self.state.to_string(),
            "trading_mode": self.config.auth.trading_mode.to_string(),
            "uptime_secs": uptime,
            "connected_uptime_secs": connected_uptime,
            "jvm": {
                "pid": jvm.pid,
                "alive": jvm.alive,
                "uptime_secs": jvm.started_at,
                "config_dir": jvm.config_dir,
                "agent_socket": jvm.agent_socket,
            },
            "socat": {
                "running": socat_running,
                "pid": socat_pid,
            },
            "clients": {
                "count": client_ids.len(),
                "ids": client_ids,
            },
            "ib_system": {
                "available": self.ib_status.available,
                "status": self.ib_status.status,
                "reason": if self.ib_status.reason.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(self.ib_status.reason.clone()) },
                "expires_in_secs": self.ib_status.last_updated.map(|t| {
                    let ttl = 600u64; // TODO: from config
                    ttl.saturating_sub(t.elapsed().as_secs())
                }),
            },
            "site": {
                "role": self.config.site.role.to_string(),
                "auto_launch": self.config.site.auto_launch,
            },
            "paused": self.pause.paused,
            "ceiling_state": self.pause.ceiling_state.as_ref().map(|s| s.to_string()),
            "stats": self.stats,
            "client_advisory": {
                "should_connect": should_connect && socat_running,
                "should_wait": should_wait,
                "wait_reason": wait_reason,
                "client_id_likely_stale": client_id_likely_stale,
            }
        }).to_string()
    }

    /// Build the STATE JSON response.
    fn build_state_json(&self) -> String {
        serde_json::json!({
            "current": self.state.to_string(),
            "history": self.transition_history,
        }).to_string()
    }

    /// Build the CONFIG JSON response (passwords masked).
    fn build_config_json(&self) -> String {
        serde_json::json!({
            "auth": {
                "username": self.config.auth.username,
                "trading_mode": self.config.auth.trading_mode.to_string(),
                "password": "********",
            },
            "gateway": {
                "tws_path": self.config.gateway.tws_path,
                "settings_path": self.config.gateway.settings_path,
                "version": self.config.gateway.version,
                "java_heap_mb": self.config.gateway.java_heap_mb,
                "program": self.config.gateway.program.to_string(),
            },
            "session": {
                "action": self.config.session.action.to_string(),
                "accept_incoming": self.config.session.accept_incoming.to_string(),
            },
            "command_server": {
                "enabled": self.config.command_server.enabled,
                "port": self.config.command_server.port,
                "bind_address": self.config.command_server.bind_address,
            },
            "timing": {
                "ui_tick_ms": self.config.timing.ui_tick_ms,
                "agent_tick_ms": self.config.timing.agent_tick_ms,
                "post_login_delay_ms": self.config.timing.post_login_delay_ms,
                "popup_quiet_secs": self.config.timing.popup_quiet_secs,
            },
            "agent": {
                "socket_path": self.config.agent.socket_path,
            },
            "site": {
                "role": self.config.site.role.to_string(),
                "auto_launch": self.config.site.auto_launch,
            },
        }).to_string()
    }

    /// Build the WINDOWS JSON response including client tabs.
    async fn build_windows_json(&self) -> String {
        let windows = self.agent_client.list_windows().await.unwrap_or_default();

        let mut windows_json = Vec::new();
        for w in &windows {
            let tabs: Vec<serde_json::Value> = if let Ok(dump) = self.agent_client.dump_components(w.id).await {
                dump.get("tabs").and_then(|t| t.as_array()).cloned().unwrap_or_default()
            } else {
                Vec::new()
            };

            windows_json.push(serde_json::json!({
                "id": w.id,
                "title": w.title,
                "class": w.class,
                "tabs": tabs,
            }));
        }

        serde_json::json!({
            "windows": windows_json,
        }).to_string()
    }
}
