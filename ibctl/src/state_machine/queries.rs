//! Query handling and JSON response builders for the command server.

use crate::command_server::Query;

use super::types::{client_advisory, State, StateMachine};

impl StateMachine {
    /// Process any pending queries from the command server (non-blocking).
    pub(super) async fn process_queries(&mut self) {
        loop {
            match self.query_rx.try_recv() {
                Ok(query) => self.handle_query(query).await,
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Handle a single query by building the JSON response and sending it back.
    async fn handle_query(&mut self, query: Query) {
        match query {
            Query::Status(tx) => {
                let json = self.build_status_json().await;
                let _ = tx.send(json);
            }
            Query::State(tx) => {
                let json = self.build_state_json();
                let _ = tx.send(json);
            }
            Query::Config(tx) => {
                let json = self.build_config_json();
                let _ = tx.send(json);
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
    async fn build_status_json(&mut self) -> String {
        let uptime = self.start_time.elapsed().as_secs();
        let connected_uptime = self.connected_since.map(|t| t.elapsed().as_secs());
        let socat_running = self.socat_process.as_mut()
            .map(|c| c.try_wait().ok().flatten().is_none())
            .unwrap_or(false);

        let is_connected = self.state == State::Connected;
        let (should_connect, should_wait, wait_reason, client_id_likely_stale) =
            client_advisory(&self.state);

        serde_json::json!({
            "ready": is_connected && socat_running,
            "state": self.state.to_string(),
            "trading_mode": self.config.auth.trading_mode.to_string(),
            "uptime_secs": uptime,
            "connected_uptime_secs": connected_uptime,
            "socat_running": socat_running,
            "jvm_running": self.supervisor.is_running(),
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
