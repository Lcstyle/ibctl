//! Enum-based state machine driving the IB Gateway login and session lifecycle.
//!
//! States: Init -> Launching -> WaitingForAgent -> WaitingForLogin -> Authenticating
//!       -> WaitingFor2fa -> HandlingSessionConflict -> DismissingPopups -> Connected
//!       -> Restarting -> Shutdown
//!
//! The main loop calls `transition()` which matches on the current state and
//! calls the appropriate handler method. Each handler returns the next state.

mod queries;
mod socat;
mod types;

// Re-export public API
pub use types::{Channels, State, StateMachine, StateMachineError};

use std::path::Path;
use std::time::Instant;

use crate::command_server::Command;
use crate::signals::Signal;

use types::Interrupt;

impl StateMachine {
    /// Run the state machine until shutdown or fatal error.
    pub async fn run(&mut self) -> Result<(), StateMachineError> {
        log::info!("State machine starting in state: {}", self.state);

        loop {
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

            self.record_transition(&self.state.clone(), &next);

            if next == State::Connected && self.state != State::Connected {
                self.connected_since = Some(Instant::now());
            } else if next != State::Connected {
                self.connected_since = None;
            }

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
            if !self.supervisor.is_running() {
                return Ok(State::Error("JVM process exited before agent became ready".into()));
            }

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
                        if title_lower.contains("existing session") {
                            log::info!("Session conflict dialog detected: {}", w.title);
                            return Ok(State::HandlingSessionConflict);
                        }
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

        let windows = self.agent_client.list_windows().await?;
        let login_window = windows.iter().find(|w| {
            let t = w.title.to_lowercase();
            t.contains("ib gateway") || t.contains("ibkr gateway") || t.contains("login")
        });

        let win = match login_window {
            Some(w) => w,
            None => return Ok(State::WaitingForLogin),
        };

        match self.handler_registry.dispatch(&self.agent_client, win).await {
            Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                log::info!("Login submitted via handler");
            }
            Some(Ok(crate::handlers::HandlerResult::Error(msg))) => {
                log::error!("Login handler reported error: {}", msg);
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

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::WaitingFor2fa)
    }

    async fn do_wait_for_2fa(&mut self) -> Result<State, StateMachineError> {
        let has_totp = self.config.twofa.has_secret;

        let timeout_secs = self.config.twofa.timeout_seconds;
        let max_wait = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(1);
        let start = std::time::Instant::now();
        let mut twofa_seen = false;
        let mut device_selected = false;
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
                    let has_conflict = windows.iter().any(|w| {
                        w.title.to_lowercase().contains("existing session")
                    });
                    if has_conflict {
                        return Ok(State::HandlingSessionConflict);
                    }

                    let twofa = windows.iter().find(|w| {
                        w.title.to_lowercase().contains("second factor")
                    });

                    if let Some(win) = twofa {
                        if !twofa_seen {
                            twofa_seen = true;
                            log::info!("2FA dialog detected: {}", win.title);
                        }

                        if !device_selected {
                            let twofa_device = &self.config.twofa.device;
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
                                        device_selected = true;
                                    }
                                }
                            } else {
                                device_selected = true;
                            }
                        }

                        if has_totp {
                            match self.handler_registry.dispatch(&self.agent_client, win).await {
                                Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                                    log::info!("TOTP code submitted, waiting for verification");
                                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                    return Ok(State::DismissingPopups);
                                }
                                Some(Ok(crate::handlers::HandlerResult::Error(msg))) => {
                                    log::error!("TOTP entry failed: {} — will retry on next loop", msg);
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
                            log::debug!("Waiting for 2FA approval on mobile device...");
                        }
                    } else if twofa_seen {
                        log::info!("2FA completed (approved on mobile device)");
                        return Ok(State::DismissingPopups);
                    } else if !twofa_seen && start.elapsed() > grace_period {
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
                if self.config.twofa.relogin_after_timeout
                    || self.config.twofa.timeout_action == crate::config::TwoFaTimeoutAction::Restart
                {
                    log::warn!(
                        "2FA timed out after {}s — restarting login sequence (will retry until approved)",
                        timeout_secs
                    );
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
        const MAX_CONFIG_RETRIES: u32 = 10;

        self.config_retries += 1;
        log::info!(
            "Applying post-login API configuration (attempt {}/{})",
            self.config_retries, MAX_CONFIG_RETRIES
        );

        let settings = crate::handlers::api_config::ApiConfigSettings::from_env();

        match crate::handlers::api_config::apply_api_config(&self.agent_client, &settings, self.config.timing.ui_tick_ms).await {
            Ok(()) => {
                log::info!("API configuration complete");
                self.config_retries = 0;
                Ok(State::Connected)
            }
            Err(e) => {
                if self.config_retries >= MAX_CONFIG_RETRIES {
                    log::error!(
                        "API configuration failed {} times — restarting Gateway: {}",
                        MAX_CONFIG_RETRIES, e
                    );
                    self.config_retries = 0;
                    Ok(State::Restarting)
                } else {
                    log::error!("API configuration FAILED: {} — will retry ({}/{})", e, self.config_retries, MAX_CONFIG_RETRIES);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    Ok(State::ConfiguringApi)
                }
            }
        }
    }

    async fn do_connected(&mut self) -> Result<State, StateMachineError> {
        log::info!("Gateway connected — entering monitoring loop");

        let (api_port, socat_port) = if self.config.auth.trading_mode == crate::config::TradingMode::Paper {
            (self.config.gateway.paper_api_port, self.config.gateway.paper_socat_port)
        } else {
            (self.config.gateway.live_api_port, self.config.gateway.live_socat_port)
        };
        self.start_socat(api_port, socat_port);

        let poll_interval = std::time::Duration::from_secs(5);

        loop {
            if !self.supervisor.is_running() {
                log::warn!("JVM process exited unexpectedly");
                return Ok(State::Restarting);
            }

            // Check socat health — restart if it died
            let socat_alive = self.socat_process.as_mut()
                .map(|c| c.try_wait().ok().flatten().is_none())
                .unwrap_or(false);
            if !socat_alive {
                log::warn!("Socat process died — restarting port forwarding");
                self.start_socat(api_port, socat_port);
            }

            if let Ok(windows) = self.agent_client.list_windows().await {
                for win in &windows {
                    let title_lower = win.title.to_lowercase();

                    if title_lower.contains("re-login") || title_lower.contains("login is required") {
                        log::info!("Connection lost — clicking Cancel to return to login form");
                        let _ = self.agent_client.click_button(win.id, "Cancel").await;
                        self.handler_registry.reset();
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        return Ok(State::WaitingForLogin);
                    }

                    let _ = self.handler_registry.dispatch(&self.agent_client, win).await;
                }
            }

            self.process_queries().await;

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

        self.stop_socat();

        if self.supervisor.is_running() {
            log::info!("Sending SIGTERM to JVM");
            if let Err(e) = self.supervisor.kill().await {
                log::error!("Failed to kill JVM: {}", e);
            }
        }

        match self.supervisor.wait().await {
            Ok(status) => log::info!("JVM exited with status: {}", status),
            Err(e) => log::warn!("JVM wait failed: {} (may already be dead)", e),
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        if self.supervisor.is_running() {
            log::error!("JVM still running after kill+wait — forcing SIGKILL");
            let _ = self.supervisor.kill().await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        let socket = &self.config.agent.socket_path;
        let _ = std::fs::remove_file(socket);

        self.handler_registry.reset();
        log::info!("Handler state reset for fresh login");

        Ok(State::Launching)
    }

    async fn do_shutdown(&mut self) -> Result<(), StateMachineError> {
        log::info!("Shutting down");
        self.stop_socat();
        if self.supervisor.is_running() {
            log::info!("Stopping JVM process");
            if let Err(e) = self.supervisor.kill().await {
                log::error!("Failed to kill JVM: {}", e);
            }
        }
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

    async fn check_interrupts(&mut self) -> Option<Interrupt> {
        use tokio::sync::mpsc::error::TryRecvError;

        match self.signal_rx.try_recv() {
            Ok(sig) => return Some(Interrupt::Signal(sig)),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                log::warn!("Signal channel disconnected");
            }
        }

        match self.command_rx.try_recv() {
            Ok(cmd) => return Some(Interrupt::Command(cmd)),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {}
        }

        match self.cold_restart_rx.try_recv() {
            Ok(_) => return Some(Interrupt::ColdRestart),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {}
        }

        None
    }

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
            _ => Ok(()),
        }
    }
}
