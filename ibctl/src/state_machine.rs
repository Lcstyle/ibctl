//! Enum-based state machine driving the IB Gateway login and session lifecycle.
//!
//! States: Init -> Launching -> WaitingForAgent -> WaitingForLogin -> Authenticating
//!       -> WaitingFor2fa -> HandlingSessionConflict -> DismissingPopups -> Connected
//!       -> Restarting -> Shutdown
//!
//! The main loop calls `transition()` which matches on the current state and
//! calls the appropriate handler method. Each handler returns the next state.

use std::path::Path;

use thiserror::Error;
use tokio::sync::mpsc;

use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::agent_client::AgentClient;
use crate::cold_restart::ColdRestartSignal;
use crate::command_server::{Command, Query};
use crate::config::Config;
use crate::handlers::DialogHandlerRegistry;
use crate::signals::Signal;
use crate::supervisor::Supervisor;

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("supervisor error: {0}")]
    Supervisor(#[from] crate::supervisor::SupervisorError),
    #[error("agent error: {0}")]
    Agent(#[from] crate::agent_client::AgentError),
    #[error("handler error: {0}")]
    Handler(#[from] crate::handlers::HandlerError),
    #[error("fatal error in state {state}: {reason}")]
    Fatal { state: String, reason: String },
}

/// All possible states in the ibctl lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Initial state: parse config, validate environment
    Init,
    /// Launching the JVM with -javaagent
    Launching,
    /// Polling the agent's /health endpoint until it responds
    WaitingForAgent,
    /// Waiting for the login window to appear
    WaitingForLogin,
    /// Filling in credentials and clicking login
    Authenticating,
    /// Waiting for 2FA dialog (if TOTP configured)
    WaitingFor2fa,
    /// Handling an "existing session detected" dialog
    HandlingSessionConflict,
    /// Dismissing startup popups (tip of day, version notice, paper warning)
    DismissingPopups,
    /// Applying post-login API configuration (master client ID, read-only, etc.)
    ConfiguringApi,
    /// Fully connected and monitoring for new dialogs
    Connected,
    /// Restarting the Gateway JVM
    Restarting,
    /// Shutting down cleanly
    Shutdown,
    /// Unrecoverable error state
    Error(String),
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Error(msg) => write!(f, "Error({})", msg),
            other => write!(f, "{:?}", other),
        }
    }
}

/// Runtime statistics collected by the state machine.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Stats {
    pub restarts_today: u32,
    pub relogins_today: u32,
    pub dialogs_dismissed: u32,
    pub last_2fa_duration_secs: Option<f64>,
    pub config_apply_duration_secs: Option<f64>,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            restarts_today: 0,
            relogins_today: 0,
            dialogs_dismissed: 0,
            last_2fa_duration_secs: None,
            config_apply_duration_secs: None,
        }
    }
}

/// A recorded state transition.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Transition {
    pub timestamp: String,
    pub from: String,
    pub to: String,
}

/// The main state machine that orchestrates the IB Gateway lifecycle.
pub struct StateMachine {
    state: State,
    config: Config,
    agent_client: AgentClient,
    supervisor: Supervisor,
    handler_registry: DialogHandlerRegistry,
    signal_rx: mpsc::Receiver<Signal>,
    command_rx: mpsc::Receiver<Command>,
    query_rx: mpsc::Receiver<Query>,
    cold_restart_rx: mpsc::Receiver<ColdRestartSignal>,
    socat_process: Option<std::process::Child>,
    // Dashboard state tracking
    start_time: Instant,
    connected_since: Option<Instant>,
    transition_history: VecDeque<Transition>,
    pub stats: Stats,
}

impl StateMachine {
    pub fn new(
        config: Config,
        agent_client: AgentClient,
        supervisor: Supervisor,
        handler_registry: DialogHandlerRegistry,
        signal_rx: mpsc::Receiver<Signal>,
        command_rx: mpsc::Receiver<Command>,
        query_rx: mpsc::Receiver<Query>,
        cold_restart_rx: mpsc::Receiver<ColdRestartSignal>,
    ) -> Self {
        Self {
            state: State::Init,
            config,
            agent_client,
            supervisor,
            handler_registry,
            signal_rx,
            command_rx,
            query_rx,
            cold_restart_rx,
            socat_process: None,
            start_time: Instant::now(),
            connected_since: None,
            transition_history: VecDeque::with_capacity(100),
            stats: Stats::default(),
        }
    }

    /// Start socat to forward external port to Gateway's localhost port.
    /// Called only after configuration is complete — no race condition possible.
    fn start_socat(&mut self, api_port: u16, socat_port: u16) {
        // Kill any existing socat first
        self.stop_socat();

        log::info!("Starting socat: 0.0.0.0:{} -> 127.0.0.1:{}", socat_port, api_port);
        match std::process::Command::new("socat")
            .arg(format!("TCP-LISTEN:{},fork,reuseaddr", socat_port))
            .arg(format!("TCP:127.0.0.1:{}", api_port))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => {
                log::info!("socat started (PID {}): port {} -> {}", child.id(), socat_port, api_port);
                self.socat_process = Some(child);
            }
            Err(e) => {
                log::error!("Failed to start socat: {} — clients won't be able to connect externally", e);
            }
        }
    }

    /// Stop socat if running.
    fn stop_socat(&mut self) {
        if let Some(ref mut child) = self.socat_process {
            log::info!("Stopping socat (PID {})", child.id());
            let _ = child.kill();
            let _ = child.wait();
            self.socat_process = None;
        }
    }

    /// Record a state transition in the history ring buffer.
    fn record_transition(&mut self, from: &State, to: &State) {
        if self.transition_history.len() >= 100 {
            self.transition_history.pop_front();
        }
        self.transition_history.push_back(Transition {
            timestamp: chrono_timestamp(),
            from: from.to_string(),
            to: to.to_string(),
        });
    }

    /// Process any pending queries from the command server (non-blocking).
    async fn process_queries(&mut self) {
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
                // TODO: implement log buffer
                let json = serde_json::json!({
                    "logs": [],
                    "note": "log buffer not yet implemented",
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

        // Client advisory
        let (should_connect, should_wait, wait_reason) = match &self.state {
            State::Init | State::Launching | State::WaitingForAgent => (false, true, Some("launching")),
            State::WaitingForLogin | State::Authenticating => (false, true, Some("logging_in")),
            State::WaitingFor2fa => (false, true, Some("2fa_pending")),
            State::HandlingSessionConflict => (false, true, Some("session_conflict")),
            State::DismissingPopups | State::ConfiguringApi => (false, true, Some("configuring")),
            State::Connected => (true, false, None),
            State::Restarting => (false, true, Some("restarting")),
            State::Shutdown => (false, false, None),
            State::Error(_) => (false, false, None),
        };

        let client_id_likely_stale = matches!(self.state, State::Restarting);

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
            // Try to get tabs for this window
            let tabs: Vec<serde_json::Value> = if let Ok(dump) = self.agent_client.dump_components(w.id).await {
                // Extract tabs from dump if available
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

    /// Run the state machine until shutdown or fatal error.
    ///
    /// This is the main loop: repeatedly call `transition()` to advance
    /// through states, checking for signals and commands between transitions.
    pub async fn run(&mut self) -> Result<(), StateMachineError> {
        log::info!("State machine starting in state: {}", self.state);

        loop {
            // Check for signals or commands before each transition
            if let Some(signal_or_cmd) = self.check_interrupts().await {
                match signal_or_cmd {
                    Interrupt::Signal(Signal::Terminate | Signal::Interrupt) => {
                        log::info!("Received shutdown signal, transitioning to Shutdown");
                        self.state = State::Shutdown;
                    }
                    Interrupt::Command(Command::Stop | Command::Exit) => {
                        log::info!("Received stop command, transitioning to Shutdown");
                        self.state = State::Shutdown;
                    }
                    Interrupt::Command(Command::Restart) => {
                        log::info!("Received restart command");
                        self.state = State::Restarting;
                    }
                    Interrupt::Command(cmd) => {
                        log::info!("Received command {:?} in state {}", cmd, self.state);
                        self.handle_command(cmd).await?;
                    }
                    Interrupt::ColdRestart => {
                        log::info!("Sunday cold restart — full re-authentication required");
                        self.state = State::Restarting;
                    }
                }
            }

            let next = self.transition().await?;
            log::info!("State transition: {} -> {}", self.state, next);

            // Record transition in history for dashboard
            self.record_transition(&self.state.clone(), &next);

            // Track connected_since
            if next == State::Connected && self.state != State::Connected {
                self.connected_since = Some(Instant::now());
            } else if next != State::Connected {
                self.connected_since = None;
            }

            // Process any pending queries (non-blocking)
            self.process_queries().await;

            if next == State::Shutdown {
                self.do_shutdown().await?;
                break;
            }

            if let State::Error(ref msg) = next {
                log::error!("State machine entered error state: {}", msg);
                self.do_shutdown().await?;
                return Err(StateMachineError::Fatal {
                    state: self.state.to_string(),
                    reason: msg.clone(),
                });
            }

            self.state = next;
        }

        Ok(())
    }

    /// Execute the transition for the current state, returning the next state.
    async fn transition(&mut self) -> Result<State, StateMachineError> {
        match &self.state {
            State::Init => self.do_init().await,
            State::Launching => self.do_launch().await,
            State::WaitingForAgent => self.do_wait_for_agent().await,
            State::WaitingForLogin => self.do_wait_for_login().await,
            State::Authenticating => self.do_authenticate().await,
            State::WaitingFor2fa => self.do_wait_for_2fa().await,
            State::HandlingSessionConflict => self.do_handle_session_conflict().await,
            State::DismissingPopups => self.do_dismiss_popups().await,
            State::ConfiguringApi => self.do_configure_api().await,
            State::Connected => self.do_connected().await,
            State::Restarting => self.do_restart().await,
            State::Shutdown => Ok(State::Shutdown),
            State::Error(msg) => Ok(State::Error(msg.clone())),
        }
    }

    // --- State handler methods ---

    async fn do_init(&mut self) -> Result<State, StateMachineError> {
        log::info!("Initializing: validating configuration");

        let tws = Path::new(&self.config.gateway.tws_path);
        if !tws.exists() {
            return Ok(State::Error(format!(
                "TWS path does not exist: {}",
                tws.display()
            )));
        }

        // Check oathtool if TOTP is configured
        if self.config.twofa.provider == crate::config::TotpProvider::Oathtool {
            if let Ok(status) = std::process::Command::new("which")
                .arg("oathtool")
                .stdout(std::process::Stdio::null())
                .status()
            {
                if !status.success() {
                    log::warn!("oathtool not found — 2FA via oathtool will fail if needed");
                }
            }
        }

        Ok(State::Launching)
    }

    async fn do_launch(&mut self) -> Result<State, StateMachineError> {
        log::info!("Launching IB Gateway JVM");
        self.supervisor.launch()?;
        Ok(State::WaitingForAgent)
    }

    async fn do_wait_for_agent(&mut self) -> Result<State, StateMachineError> {
        log::info!("Waiting for agent to become healthy");
        let max_wait = std::time::Duration::from_secs(60);
        let poll_interval = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();

        loop {
            // Check if JVM crashed
            if !self.supervisor.is_running() {
                return Ok(State::Error("JVM process exited before agent became ready".into()));
            }

            // Try health check
            match self.agent_client.health().await {
                Ok(true) => {
                    log::info!("Agent is healthy");
                    return Ok(State::WaitingForLogin);
                }
                Ok(false) | Err(_) => {
                    if start.elapsed() > max_wait {
                        return Ok(State::Error("Timed out waiting for agent health check".into()));
                    }
                    tokio::time::sleep(poll_interval).await;
                }
            }
        }
    }

    async fn do_wait_for_login(&mut self) -> Result<State, StateMachineError> {
        log::info!("Waiting for login window to appear");
        let max_wait = std::time::Duration::from_secs(120);
        let poll_interval = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();

        loop {
            if !self.supervisor.is_running() {
                return Ok(State::Error("JVM process exited while waiting for login window".into()));
            }

            match self.agent_client.list_windows().await {
                Ok(windows) => {
                    for w in &windows {
                        let title_lower = w.title.to_lowercase();
                        // Check for session conflict first
                        if title_lower.contains("existing session") {
                            log::info!("Session conflict dialog detected: {}", w.title);
                            return Ok(State::HandlingSessionConflict);
                        }
                        // Check for login window
                        if title_lower.contains("ib gateway")
                            || title_lower.contains("ibkr gateway")
                            || title_lower.contains("login")
                        {
                            log::info!("Login window detected: {}", w.title);
                            return Ok(State::Authenticating);
                        }
                    }
                }
                Err(e) => {
                    log::debug!("Agent not ready yet: {}", e);
                }
            }

            if start.elapsed() > max_wait {
                return Ok(State::Error("Timed out waiting for login window".into()));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn do_authenticate(&mut self) -> Result<State, StateMachineError> {
        log::info!("Authenticating with IB Gateway");

        // Find the login window and dispatch to LoginHandler
        // This mirrors IBC's approach: LoginFrameHandler.handleWindow()
        let windows = self.agent_client.list_windows().await?;
        let login_window = windows.iter().find(|w| {
            let t = w.title.to_lowercase();
            t.contains("ib gateway") || t.contains("ibkr gateway") || t.contains("login")
        });

        let win = match login_window {
            Some(w) => w,
            None => return Ok(State::WaitingForLogin), // Window disappeared, go back
        };

        // Dispatch to the LoginHandler via the registry
        // The LoginHandler fills credentials and clicks login,
        // then sets its login_submitted flag to prevent re-dispatch
        match self.handler_registry.dispatch(&self.agent_client, win).await {
            Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                log::info!("Login submitted via handler");
            }
            Some(Ok(crate::handlers::HandlerResult::Error(msg))) => {
                log::error!("Login handler reported error: {}", msg);
                // Reset so we can retry
                self.handler_registry.reset();
                return Ok(State::WaitingForLogin);
            }
            Some(Ok(crate::handlers::HandlerResult::NotApplicable)) => {
                log::warn!("Login handler didn't recognize window — retrying");
                return Ok(State::WaitingForLogin);
            }
            Some(Err(e)) => {
                log::error!("Login handler failed: {}", e);
                self.handler_registry.reset();
                return Ok(State::WaitingForLogin);
            }
            None => {
                log::warn!("No handler matched login window");
                return Ok(State::WaitingForLogin);
            }
        }

        // Wait for Gateway to process credentials, then check what appeared.
        // IBC's flow: after clicking login, poll for either:
        //   - 2FA dialog (Second Factor Authentication) -> handle it
        //   - Session conflict dialog -> handle it
        //   - Login error -> report it
        //   - Main window (login succeeded) -> proceed
        // We always go to WaitingFor2fa which handles all cases:
        //   - If TOTP secret is set: enters the code
        //   - If IB Key (mobile push): waits for user to approve on mobile
        //   - If no 2FA required: dialog won't appear, we move on quickly
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::WaitingFor2fa)
    }

    async fn do_wait_for_2fa(&mut self) -> Result<State, StateMachineError> {
        // This state handles three scenarios after login is submitted:
        //
        // 1. TOTP configured (TWOFACTOR_CODE set): detect 2FA dialog, enter code, submit
        // 2. IB Key / mobile push (no TOTP): detect 2FA dialog, wait for user to approve
        //    on mobile, dialog disappears when approved
        // 3. No 2FA required (paper accounts): no 2FA dialog appears, move on quickly
        //
        // Mirrors IBC's SecondFactorAuthenticationDialogHandler which handles all cases.

        let has_totp = crate::config::env_or_file("TWOFACTOR_CODE")
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        let timeout_secs = self.config.twofa.timeout_seconds;
        let max_wait = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(1);
        let start = std::time::Instant::now();
        let mut twofa_seen = false;
        let mut device_selected = false;

        // Short initial grace period — if no 2FA dialog appears within 10s,
        // assume 2FA is not required (paper accounts, etc.)
        let grace_period = std::time::Duration::from_secs(10);

        let mut consecutive_agent_failures: u32 = 0;

        log::info!("Checking for 2FA dialog (timeout={}s, totp={})",
            timeout_secs, if has_totp { "configured" } else { "not configured (IB Key/mobile)" });

        loop {
            if !self.supervisor.is_running() {
                return Ok(State::Error("JVM exited during 2FA wait".into()));
            }

            match self.agent_client.list_windows().await {
                Ok(windows) => {
                    consecutive_agent_failures = 0;
                    // Check for session conflict (can appear instead of 2FA)
                    let has_conflict = windows.iter().any(|w| {
                        w.title.to_lowercase().contains("existing session")
                    });
                    if has_conflict {
                        return Ok(State::HandlingSessionConflict);
                    }

                    // Check if 2FA dialog is present
                    let twofa = windows.iter().find(|w| {
                        w.title.to_lowercase().contains("second factor")
                    });

                    if let Some(win) = twofa {
                        if !twofa_seen {
                            twofa_seen = true;
                            log::info!("2FA dialog detected: {}", win.title);
                        }

                        // IBC's SecondFactorDevice handling:
                        // First appearance of the 2FA dialog may be a device selection list.
                        // Select the configured device and click OK, then the actual
                        // 2FA challenge dialog appears.
                        if !device_selected {
                            let twofa_device = std::env::var("TWOFA_DEVICE")
                                .unwrap_or_default();
                            if !twofa_device.is_empty() {
                                log::info!("Selecting 2FA device: {}", twofa_device);
                                match self.agent_client.select_list_item(win.id, &twofa_device).await {
                                    Ok(true) => {
                                        log::info!("Selected '{}' in device list", twofa_device);
                                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                        let _ = self.agent_client.click_button(win.id, "OK").await;
                                        log::info!("Clicked OK on device selection — waiting for 2FA challenge");
                                        device_selected = true;
                                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                        continue;
                                    }
                                    _ => {
                                        log::debug!("No device list found — this is the actual 2FA challenge");
                                        device_selected = true; // Skip future attempts
                                    }
                                }
                            } else {
                                device_selected = true; // No device configured, skip
                            }
                        }

                        if has_totp {
                            // TOTP mode: enter the code via handler
                            match self.handler_registry.dispatch(&self.agent_client, win).await {
                                Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                                    log::info!("TOTP code submitted, waiting for verification");
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    return Ok(State::DismissingPopups);
                                }
                                Some(Ok(crate::handlers::HandlerResult::Error(msg))) => {
                                    log::error!("TOTP entry failed: {} — will retry on next loop", msg);
                                    // Don't fall through — wait and retry
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    continue;
                                }
                                Some(Err(e)) => {
                                    log::error!("TOTP handler error: {} — will retry", e);
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    continue;
                                }
                                _ => {
                                    log::debug!("No TOTP handler matched — may be IB Key dialog");
                                }
                            }
                        } else {
                            // IB Key / mobile push: just wait for user to approve
                            // The dialog will disappear when approved on mobile
                            log::debug!("Waiting for 2FA approval on mobile device...");
                        }
                    } else if twofa_seen {
                        // 2FA dialog was present but now gone — user approved on mobile
                        log::info!("2FA completed (approved on mobile device)");
                        return Ok(State::DismissingPopups);
                    } else if !twofa_seen && start.elapsed() > grace_period {
                        // No 2FA dialog appeared within grace period — not required
                        log::info!("No 2FA dialog appeared — proceeding without 2FA");
                        return Ok(State::DismissingPopups);
                    }
                }
                Err(e) => {
                    consecutive_agent_failures += 1;
                    if consecutive_agent_failures >= 10 {
                        log::error!("Agent unreachable after {} consecutive failures — JVM may have crashed", consecutive_agent_failures);
                        return Ok(State::Error("Agent unreachable during 2FA wait".into()));
                    }
                    log::debug!("Agent poll failed ({}x): {}", consecutive_agent_failures, e);
                }
            }

            if start.elapsed() > max_wait {
                // IBC's behavior on 2FA timeout:
                // - ReloginAfterSecondFactorAuthenticationTimeout=yes -> restart login sequence
                // - TWOFA_TIMEOUT_ACTION=restart -> restart the whole login flow
                // - TWOFA_TIMEOUT_ACTION=exit -> shut down
                //
                // The "restart" action re-initiates the login sequence, giving the user
                // another chance to approve on mobile. This can repeat indefinitely.
                let relogin = std::env::var("RELOGIN_AFTER_TWOFA_TIMEOUT")
                    .map(|v| matches!(v.to_lowercase().as_str(), "yes" | "true" | "1"))
                    .unwrap_or(false);

                if relogin || self.config.twofa.timeout_action == crate::config::TwoFaTimeoutAction::Restart {
                    log::warn!(
                        "2FA timed out after {}s — restarting login sequence (will retry until approved)",
                        timeout_secs
                    );
                    // Reset the LoginHandler so it can fill credentials again
                    // The handler's login_submitted flag needs to be cleared for re-login
                    // For now, transition to Restarting which kills and relaunches the JVM
                    // (matching IBC's cold restart behavior)
                    return Ok(State::Restarting);
                } else {
                    log::error!("2FA timed out after {}s — shutting down", timeout_secs);
                    return Ok(State::Shutdown);
                }
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn do_handle_session_conflict(&mut self) -> Result<State, StateMachineError> {
        log::info!("Handling session conflict dialog");

        let windows = self.agent_client.list_windows().await?;
        let conflict = windows.iter().find(|w| {
            w.title.to_lowercase().contains("existing session")
        });

        if let Some(win) = conflict {
            match self.handler_registry.dispatch(&self.agent_client, win).await {
                Some(Ok(_)) => log::info!("Session conflict resolved"),
                Some(Err(e)) => log::error!("Session conflict handling failed: {}", e),
                None => log::warn!("No handler matched session conflict dialog"),
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::DismissingPopups)
    }

    async fn do_dismiss_popups(&mut self) -> Result<State, StateMachineError> {
        log::info!("Dismissing startup popups");
        let quiet_threshold = std::time::Duration::from_secs(5);
        let max_wait = std::time::Duration::from_secs(30);
        let poll_interval = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();
        let mut last_popup = std::time::Instant::now();

        loop {
            if !self.supervisor.is_running() {
                return Ok(State::Error("JVM exited during popup dismissal".into()));
            }

            let mut found_popup = false;

            if let Ok(windows) = self.agent_client.list_windows().await {
                for win in &windows {
                    if let Some(Ok(_)) = self.handler_registry.dispatch(&self.agent_client, win).await {
                        log::info!("Dismissed popup: {}", win.title);
                        found_popup = true;
                        last_popup = std::time::Instant::now();
                    }
                }
            }

            if !found_popup && last_popup.elapsed() > quiet_threshold {
                log::info!("No popups for {:?} — proceeding to API configuration", quiet_threshold);
                return Ok(State::ConfiguringApi);
            }

            if start.elapsed() > max_wait {
                log::info!("Max popup dismissal time reached, proceeding to API configuration");
                return Ok(State::ConfiguringApi);
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn do_configure_api(&mut self) -> Result<State, StateMachineError> {
        log::info!("Applying post-login API configuration");

        let settings = crate::handlers::api_config::ApiConfigSettings::from_config(&self.config);

        match crate::handlers::api_config::apply_api_config(&self.agent_client, &settings, self.config.timing.ui_tick_ms).await {
            Ok(()) => {
                log::info!("API configuration complete");
                Ok(State::Connected)
            }
            Err(e) => {
                log::error!("API configuration FAILED: {} — will retry", e);
                // Wait before retrying to let any lingering dialogs/menus close
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                // Stay in ConfiguringApi — the state machine loop will call us again
                Ok(State::ConfiguringApi)
            }
        }
    }

    async fn do_connected(&mut self) -> Result<State, StateMachineError> {
        log::info!("Gateway connected — entering monitoring loop");

        // Start socat port forwarding NOW — configuration is complete,
        // Read-Only API is unchecked, all settings applied.
        // ibctl owns socat directly, no race conditions possible.
        let (api_port, socat_port) = if self.config.auth.trading_mode == crate::config::TradingMode::Paper {
            (4002, 4004)
        } else {
            (4001, 4003)
        };
        self.start_socat(api_port, socat_port);

        let poll_interval = std::time::Duration::from_secs(5);

        loop {
            // Check if JVM is still running
            if !self.supervisor.is_running() {
                log::warn!("JVM process exited unexpectedly");
                return Ok(State::Restarting);
            }

            // Poll for new dialogs that need handling
            if let Ok(windows) = self.agent_client.list_windows().await {
                for win in &windows {
                    let title_lower = win.title.to_lowercase();

                    // Re-login dialog: "RE-LOGIN IS REQUIRED"
                    // Clicking Re-login doesn't work reliably — IB Key keeps failing.
                    // Instead click Cancel, which returns to the login form with
                    // username/API type/trading mode pre-filled and cursor in password.
                    // Then we re-enter password and click Login for a fresh auth cycle.
                    if title_lower.contains("re-login") || title_lower.contains("login is required") {
                        log::info!("Connection lost — clicking Cancel to return to login form");
                        let _ = self.agent_client.click_button(win.id, "Cancel").await;
                        self.handler_registry.reset();
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        return Ok(State::WaitingForLogin);
                    }

                    // Handle other dialogs normally (accept connection, etc.)
                    let _ = self.handler_registry.dispatch(&self.agent_client, win).await;
                }
            }

            // Process any pending dashboard queries
            self.process_queries().await;

            // Check for signals/commands
            if let Some(interrupt) = self.check_interrupts().await {
                match interrupt {
                    Interrupt::Signal(Signal::Terminate | Signal::Interrupt) => {
                        return Ok(State::Shutdown);
                    }
                    Interrupt::Command(Command::Stop | Command::Exit) => {
                        return Ok(State::Shutdown);
                    }
                    Interrupt::Command(Command::Restart) => {
                        return Ok(State::Restarting);
                    }
                    Interrupt::Command(cmd) => {
                        self.handle_command(cmd).await?;
                    }
                    Interrupt::ColdRestart => {
                        log::info!("Sunday cold restart — restarting with full re-authentication");
                        return Ok(State::Restarting);
                    }
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    async fn do_restart(&mut self) -> Result<State, StateMachineError> {
        log::info!("Restarting IB Gateway");

        // Stop socat first — no new client connections during restart
        self.stop_socat();

        // Kill and WAIT for the JVM to fully exit before launching a new one.
        // Without waiting, the old process can linger and cause "EXISTING SESSION DETECTED"
        // when the new instance tries to log in with the same account.
        if self.supervisor.is_running() {
            log::info!("Sending SIGTERM to JVM");
            if let Err(e) = self.supervisor.kill().await {
                log::error!("Failed to kill JVM: {}", e);
            }
        }

        // Block until the child process is fully reaped
        match self.supervisor.wait() {
            Ok(status) => log::info!("JVM exited with status: {}", status),
            Err(e) => log::warn!("JVM wait failed: {} (may already be dead)", e),
        }

        // Extra safety: sleep to let the OS fully clean up the process
        // and release any ports/sockets held by the JVM
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // Verify the old process is truly gone
        if self.supervisor.is_running() {
            log::error!("JVM still running after kill+wait — forcing SIGKILL");
            let _ = self.supervisor.kill().await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        // Clean up agent socket
        let socket = &self.config.agent.socket_path;
        let _ = std::fs::remove_file(socket);

        // Reset all handler state so LoginHandler can fire again
        self.handler_registry.reset();
        log::info!("Handler state reset for fresh login");

        Ok(State::Launching)
    }

    async fn do_shutdown(&mut self) -> Result<(), StateMachineError> {
        log::info!("Shutting down");
        // Stop socat
        self.stop_socat();
        // Kill the JVM if it's running
        if self.supervisor.is_running() {
            log::info!("Stopping JVM process");
            if let Err(e) = self.supervisor.kill().await {
                log::error!("Failed to kill JVM: {}", e);
            }
        }
        // Clean up the agent socket
        let socket = &self.config.agent.socket_path;
        if std::path::Path::new(socket).exists() {
            if let Err(e) = std::fs::remove_file(socket) {
                log::warn!("Failed to remove agent socket {}: {}", socket, e);
            }
        }
        log::info!("Shutdown complete");
        Ok(())
    }

    // --- Interrupt handling ---

    /// Non-blocking check for pending signals or commands.
    async fn check_interrupts(&mut self) -> Option<Interrupt> {
        use tokio::sync::mpsc::error::TryRecvError;

        // Check signals first (higher priority)
        match self.signal_rx.try_recv() {
            Ok(sig) => return Some(Interrupt::Signal(sig)),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                log::warn!("Signal channel disconnected");
            }
        }

        // Check commands
        match self.command_rx.try_recv() {
            Ok(cmd) => return Some(Interrupt::Command(cmd)),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {}
        }

        // Check cold restart (Sunday weekly)
        match self.cold_restart_rx.try_recv() {
            Ok(_) => return Some(Interrupt::ColdRestart),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {}
        }

        None
    }

    /// Handle a command received while in the Connected state.
    async fn handle_command(&mut self, cmd: Command) -> Result<(), StateMachineError> {
        match cmd {
            Command::ReconnectData => {
                log::info!("Sending reconnect data keystroke (Ctrl+F)");
                if let Ok(windows) = self.agent_client.list_windows().await {
                    if let Some(win) = windows.first() {
                        let _ = self.agent_client.send_key(win.id, "ctrl+f").await;
                    }
                }
                Ok(())
            }
            Command::ReconnectAccount => {
                log::info!("Sending reconnect account keystroke (Ctrl+R)");
                if let Ok(windows) = self.agent_client.list_windows().await {
                    if let Some(win) = windows.first() {
                        let _ = self.agent_client.send_key(win.id, "ctrl+r").await;
                    }
                }
                Ok(())
            }
            Command::EnableApi => {
                log::info!("EnableApi command received (not yet implemented)");
                Ok(())
            }
            // Stop, Exit, Restart are handled in the main loop
            _ => Ok(()),
        }
    }
}

/// Internal enum for interrupt sources.
enum Interrupt {
    Signal(Signal),
    Command(Command),
    ColdRestart,
}

/// Simple UTC timestamp string (avoids chrono dependency).
fn chrono_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Format as ISO-ish: just use epoch seconds for now
    // A proper implementation would format as "2026-03-29T17:05:02Z"
    format!("{}", secs)
}
