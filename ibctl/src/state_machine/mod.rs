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

            // IB System Status TTL expiry — fail-open if no recent push
            if let Some(last) = self.ib_system_last_updated {
                let ttl = std::time::Duration::from_secs(600); // 10 min default TTL
                if last.elapsed() > ttl && !self.ib_system_available {
                    log::info!("IB system status TTL expired — assuming available (fail-open)");
                    self.ib_system_available = true;
                    self.ib_system_status = "available".to_string();
                    self.ib_system_reason.clear();
                }
            }

            // If IB system unavailable and not already in WaitingForIB, transition there
            if !self.ib_system_available && self.state != State::WaitingForIB && self.state != State::Shutdown {
                log::warn!("IB system unavailable: {} — transitioning to WaitingForIB", self.ib_system_reason);
                self.ib_system_return_state = Some(Box::new(self.state.clone()));
                let old = self.state.clone();
                self.state = State::WaitingForIB;
                self.record_transition(&old, &State::WaitingForIB);
            }

            // Pause mode: skip transitions but keep processing queries/interrupts
            if self.paused {
                self.process_queries().await;
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }

            let next = self.transition().await?;

            // Ceiling check: if the next state matches the ceiling, auto-pause
            if let Some(ref ceiling) = self.ceiling_state {
                if &next == ceiling {
                    log::info!("State machine reached ceiling state {} — auto-pausing", next);
                    self.paused = true;
                    self.ceiling_state = None;
                }
            }

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
            State::WaitingForIB => self.do_waiting_for_ib().await,
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
        // Check for warm restart: if the autorestart token exists, pass it
        // to Gateway via -Drestart so it resumes the session without 2FA.
        if self.warm_restart_pending {
            if let Some(restart_hash) = self.supervisor.find_autorestart_path() {
                log::info!("Warm restart: launching with -Drestart={}", restart_hash);
                self.supervisor.launch_with_restart(Some(&restart_hash))?;
                // Keep warm_restart_pending=true through the auth flow so
                // do_wait_for_login and do_authenticate don't touch the login window.
                // Gateway handles session resumption itself.
                return Ok(State::WaitingForAgent);
            }
            log::warn!("Warm restart requested but no autorestart token found — doing cold launch");
            self.warm_restart_pending = false;
        }

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
        // Warm restart: Gateway handles its own re-authentication via -Drestart.
        // Don't touch the login window — just wait for Gateway to reach the main
        // trading window. This mirrors IBC's SessionManager.isRestart() behavior.
        if self.warm_restart_pending {
            log::info!("Warm restart: waiting for Gateway to self-authenticate (not touching login)");
            let max_wait = std::time::Duration::from_secs(120);
            let poll_interval = std::time::Duration::from_secs(2);
            let start = std::time::Instant::now();

            loop {
                if !self.supervisor.is_running() {
                    self.warm_restart_pending = false;
                    return Ok(State::Error("JVM exited during warm restart login".into()));
                }

                if let Ok(windows) = self.agent_client.list_windows().await {
                    for w in &windows {
                        let t = w.title.to_lowercase();
                        // Main Gateway window with API status = warm restart succeeded
                        if (t.contains("ib gateway") || t.contains("ibkr gateway"))
                            && !t.contains("login")
                            && !t.contains("configuration")
                        {
                            // Check if it has the connection status bar (main window, not login)
                            if w.bounds.as_ref().map(|b| b.width > 400).unwrap_or(false) {
                                log::info!("Warm restart: Gateway self-authenticated — main window detected");
                                self.warm_restart_pending = false;
                                return Ok(State::DismissingPopups);
                            }
                        }
                    }
                }

                self.process_queries().await;

                if start.elapsed() > max_wait {
                    log::warn!("Warm restart: Gateway did not self-authenticate within {}s — falling back to cold auth", max_wait.as_secs());
                    self.warm_restart_pending = false;
                    return Ok(State::WaitingForLogin); // recurse as cold
                }
                tokio::time::sleep(poll_interval).await;
            }
        }

        log::info!("Waiting for login window to appear");
        let max_wait = std::time::Duration::from_secs(120);
        let poll_interval = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();

        loop {
            if !self.supervisor.is_running() {
                return Ok(State::Error("JVM process exited while waiting for login window".into()));
            }

            // Check for blocking dialogs (re-login, 2FA) before looking for login window
            if let Some(next_state) = self.check_blocking_dialog().await {
                log::info!("Blocking dialog detected while waiting for login — transitioning to {}", next_state);
                return Ok(next_state);
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

        // Check for blocking dialogs (re-login, 2FA) before attempting login
        if let Some(next_state) = self.check_blocking_dialog().await {
            log::info!("Blocking dialog detected during authentication — transitioning to {}", next_state);
            return Ok(next_state);
        }

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
                log::debug!("Login handler didn't recognize window — waiting for login form");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                return Ok(State::WaitingForLogin);
            }
            Some(Err(e)) => {
                log::error!("Login handler failed: {}", e);
                self.handler_registry.reset();
                return Ok(State::WaitingForLogin);
            }
            None => {
                // Window exists but no handler matched — Gateway may be in a transitional
                // state (e.g. "Authenticating..." screen). Wait before retrying.
                log::debug!("No handler matched login window — waiting for Gateway to settle");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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

            // Check for blocking dialogs (re-login, authenticating splash)
            if let Some(next_state) = self.check_blocking_dialog().await {
                if next_state == State::WaitingForLogin {
                    log::info!("Blocking dialog detected during 2FA wait — transitioning to {}", next_state);
                    return Ok(next_state);
                }
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
                                match self.agent_client.select_list_item(win.id, twofa_device).await {
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
                        // 2FA dialog was visible but now gone — confirm it's really gone
                        // (not just a redraw) by waiting and re-checking
                        log::info!("2FA dialog disappeared — confirming...");
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                        // Re-check: is the 2FA dialog really gone?
                        let still_gone = match self.agent_client.list_windows().await {
                            Ok(wins) => !wins.iter().any(|w| {
                                let t = w.title.to_lowercase();
                                t.contains("second factor") || t.contains("authentication")
                            }),
                            Err(_) => false, // Agent error — assume not gone
                        };

                        if still_gone {
                            log::info!("2FA completed (confirmed — dialog gone for 3s)");
                            return Ok(State::DismissingPopups);
                        } else {
                            log::warn!("2FA dialog reappeared after brief disappearance — still waiting");
                            continue;
                        }
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

            // Check for blocking dialogs that require state changes (re-login, 2FA)
            if let Some(next_state) = self.check_blocking_dialog().await {
                log::info!("Blocking dialog detected during popup dismissal — transitioning to {}", next_state);
                self.handler_registry.reset();
                return Ok(next_state);
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

        // Guard: check for any blocking dialog (re-login, 2FA, session conflict)
        // These prevent the Settings dialog from opening
        if let Some(next_state) = self.check_blocking_dialog().await {
            log::warn!("Blocking dialog detected — cannot configure API, transitioning to {}", next_state);
            self.config_retries = 0;
            return Ok(next_state);
        }

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

        // Spawn background task for client ID refresh (slow agent calls, must not block main loop)
        // Uses tokio::sync::watch — lock-free, change-driven updates
        let (ids_tx, mut ids_rx) = tokio::sync::watch::channel(Vec::<String>::new());
        let socket_path = self.config.agent.socket_path.clone();
        let client_id_task = tokio::spawn(async move {
            loop {
                let mut ids = Vec::new();
                let client = crate::agent_client::AgentClient::new(&socket_path);
                if let Ok(windows) = client.list_windows().await {
                    for w in &windows {
                        if let Ok(tabs_data) = client.list_tabs(w.id).await {
                            if let Some(tabs) = tabs_data.get("tabs").and_then(|t| t.as_array()) {
                                for tab in tabs {
                                    if let Some(title) = tab.get("title").and_then(|t| t.as_str()) {
                                        ids.push(title.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                let _ = ids_tx.send(ids);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });

        let poll_interval = std::time::Duration::from_secs(5);

        loop {
            if !self.supervisor.is_running() {
                log::info!("JVM exited — waiting for warm restart (install4j auto-restart)");
                self.stop_socat();

                // Grace period: wait up to 30s for install4j to spawn a new JVM
                let grace = std::time::Duration::from_secs(30);
                let poll = std::time::Duration::from_secs(2);
                let start = std::time::Instant::now();
                let mut warm_restart_pid: Option<u32> = None;

                while start.elapsed() < grace {
                    if let Some(pid) = self.supervisor.find_gateway_pid() {
                        log::info!("Warm restart detected — install4j spawned new JVM at PID {}", pid);
                        warm_restart_pid = Some(pid);
                        break;
                    }

                    if let Some(interrupt) = self.check_interrupts().await {
                        match interrupt {
                            Interrupt::Signal(Signal::Terminate | Signal::Interrupt) => {
                                client_id_task.abort();
                                return Ok(State::Shutdown);
                            }
                            Interrupt::Command(Command::Stop | Command::Exit) => {
                                client_id_task.abort();
                                return Ok(State::Shutdown);
                            }
                            Interrupt::Command(Command::Restart) => {
                                log::info!("Restart command during warm restart wait — doing cold restart");
                                client_id_task.abort();
                                return Ok(State::Restarting);
                            }
                            _ => {}
                        }
                    }

                    self.process_queries().await;
                    tokio::time::sleep(poll).await;
                }

                if let Some(pid) = warm_restart_pid {
                    // install4j spawned a new JVM but without our -javaagent.
                    // Kill it and relaunch with the agent attached. The session
                    // cookies in jts.ini are still valid from the warm restart,
                    // so Gateway will skip 2FA on the next launch.
                    log::info!("Killing install4j JVM (PID {}) — will relaunch with agent", pid);
                    unsafe { libc::kill(pid as i32, libc::SIGKILL); }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }

                // Relaunch — either after killing install4j's JVM (warm restart
                // with preserved session) or after grace period timeout (cold restart).
                // Both paths go through Launching → WaitingForAgent → WaitingForLogin.
                // If session cookies are valid, Gateway skips login/2FA automatically.
                log::info!("Relaunching Gateway with agent attached");
                self.warm_restart_pending = true;
                client_id_task.abort();
                let _ = std::fs::remove_file(&self.config.agent.socket_path);
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
                        client_id_task.abort();
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        return Ok(State::WaitingForLogin);
                    }

                    let _ = self.handler_registry.dispatch(&self.agent_client, win).await;
                }
            }

            // Sync client IDs from background task (lock-free watch channel)
            if ids_rx.has_changed().unwrap_or(false) {
                let ids = ids_rx.borrow_and_update().clone();
                if !ids.is_empty() {
                    self.cached_client_ids = ids;
                }
            }

            self.process_queries().await;

            if let Some(interrupt) = self.check_interrupts().await {
                match interrupt {
                    Interrupt::Signal(Signal::Terminate | Signal::Interrupt) => {
                        client_id_task.abort();
                        return Ok(State::Shutdown);
                    }
                    Interrupt::Command(Command::Stop | Command::Exit) => {
                        client_id_task.abort();
                        return Ok(State::Shutdown);
                    }
                    Interrupt::Command(Command::Restart) => {
                        client_id_task.abort();
                        return Ok(State::Restarting);
                    }
                    Interrupt::Command(cmd) => {
                        self.handle_command(cmd).await?;
                    }
                    Interrupt::ColdRestart => {
                        log::info!("Sunday cold restart — restarting with full re-authentication");
                        client_id_task.abort();
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

    async fn do_waiting_for_ib(&mut self) -> Result<State, StateMachineError> {
        log::info!("Waiting for IB system to become available ({})", self.ib_system_reason);

        // Process queries so STATUS requests still return
        self.process_queries().await;

        // Check if IB became available
        if self.ib_system_available {
            log::info!("IB system is now available — resuming");
            if let Some(return_state) = self.ib_system_return_state.take() {
                return Ok(*return_state);
            }
            return Ok(State::Init);
        }

        // Sleep and check again
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        Ok(State::WaitingForIB)
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

    /// Check if any visible window is a blocking dialog that requires a state change.
    /// Clicks the appropriate button to dismiss the dialog, then returns the next state.
    async fn check_blocking_dialog(&self) -> Option<State> {
        if let Ok(windows) = self.agent_client.list_windows().await {
            for w in &windows {
                if let Some(state) = Self::classify_blocking_dialog(&w.title) {
                    // Dismiss the blocking dialog before transitioning
                    let t = w.title.to_lowercase();
                    if t.contains("re-login") || t.contains("relogin") || t.contains("login is required") {
                        log::info!("Connection lost — clicking Cancel to return to login form");
                        let _ = self.agent_client.click_button(w.id, "Cancel").await;
                    }
                    return Some(state);
                }
            }
        }
        None
    }

    /// Pure function: classify a window title as a blocking dialog.
    /// Returns the state to transition to, or None.
    fn classify_blocking_dialog(title: &str) -> Option<State> {
        let t = title.to_lowercase();
        // Re-login dialog: "RE-LOGIN IS REQUIRED" / "Your connection was lost"
        if t.contains("re-login") || t.contains("relogin") || t.contains("login is required") {
            return Some(State::WaitingForLogin);
        }
        // 2FA dialog: "Second Factor Authentication" / "IB Key Authentication"
        if t.contains("second factor") || t.contains("ib key authenticat") {
            return Some(State::WaitingFor2fa);
        }
        // Note: "Attempt N: Authenticating..." is a splash screen, NOT a blocking dialog.
        // It's Gateway's normal login progress window and should not trigger a state change.
        None
    }

    async fn handle_command(&mut self, cmd: Command) -> Result<(), StateMachineError> {
        match cmd {
            Command::IbStatus(ref status, ref reason) => {
                let available = status == "available";
                log::info!("IB system status update: {} ({})", status, if reason.is_empty() { "no reason" } else { reason });
                self.ib_system_available = available;
                self.ib_system_status = status.clone();
                self.ib_system_reason = reason.clone();
                self.ib_system_last_updated = Some(std::time::Instant::now());
                Ok(())
            }
            Command::RestartSocat => {
                log::info!("Restarting socat port forwarding");
                let (api_port, socat_port) = if self.config.auth.trading_mode == crate::config::TradingMode::Paper {
                    (self.config.gateway.paper_api_port, self.config.gateway.paper_socat_port)
                } else {
                    (self.config.gateway.live_api_port, self.config.gateway.live_socat_port)
                };
                self.stop_socat();
                self.start_socat(api_port, socat_port);
                Ok(())
            }
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
            Command::Pause => {
                log::info!("State machine PAUSED — transitions frozen");
                self.paused = true;
                self.ceiling_state = None;
                Ok(())
            }
            Command::PauseAt(ref name) => {
                if let Some(target) = State::from_name(name) {
                    log::info!("State machine ceiling set: will pause at {}", target);
                    self.ceiling_state = Some(target);
                    // If already at the ceiling state, pause immediately
                    if self.ceiling_state.as_ref() == Some(&self.state) {
                        log::info!("Already at ceiling state — pausing now");
                        self.paused = true;
                        self.ceiling_state = None;
                    }
                } else {
                    log::error!("PAUSE: unknown state '{}'", name);
                }
                Ok(())
            }
            Command::Resume => {
                log::info!("State machine RESUMED — transitions active");
                self.paused = false;
                self.ceiling_state = None;
                Ok(())
            }
            Command::SetState(ref name) => {
                if let Some(new_state) = State::from_name(name) {
                    log::warn!("GOD MODE: forcing state to {}", new_state);
                    let old = self.state.clone();
                    self.state = new_state.clone();
                    self.record_transition(&old, &new_state);
                    Ok(())
                } else {
                    log::error!("SETSTATE: unknown state '{}'", name);
                    Ok(())
                }
            }
            Command::SetRestartTime(ref time_str) => {
                log::info!("SETRESTART: setting auto-restart time to {} (UTC)", time_str);
                let settings = crate::handlers::api_config::ApiConfigSettings {
                    master_client_id: None,
                    read_only_api: None,
                    bypass_order_precautions: None,
                    allow_blind_trading: None,
                    auto_restart_time: Some(time_str.clone()),
                    auto_logoff_time: None,
                };
                let tick_ms = self.config.timing.ui_tick_ms;
                match crate::handlers::api_config::apply_api_config(
                    &self.agent_client, &settings, tick_ms,
                ).await {
                    Ok(()) => log::info!("SETRESTART: auto-restart time set to {}", time_str),
                    Err(e) => log::error!("SETRESTART failed: {}", e),
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relogin_dialog_detected() {
        // The exact title from the screenshot
        assert_eq!(
            StateMachine::classify_blocking_dialog("RE-LOGIN IS REQUIRED"),
            Some(State::WaitingForLogin),
        );
    }

    #[test]
    fn test_relogin_dialog_lowercase() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("re-login is required"),
            Some(State::WaitingForLogin),
        );
    }

    #[test]
    fn test_login_is_required_variant() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("Login is required"),
            Some(State::WaitingForLogin),
        );
    }

    #[test]
    fn test_2fa_dialog_detected() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("Second Factor Authentication"),
            Some(State::WaitingFor2fa),
        );
    }

    #[test]
    fn test_authentication_dialog() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("IB Key Authentication"),
            Some(State::WaitingFor2fa),
        );
    }

    #[test]
    fn test_authenticating_splash_not_blocking() {
        // "Attempt N: Authenticating..." is a splash screen, NOT a blocking dialog.
        // It's Gateway's normal login progress and should not trigger state changes.
        assert_eq!(
            StateMachine::classify_blocking_dialog("Attempt 2: Authenticating..."),
            None,
        );
        assert_eq!(
            StateMachine::classify_blocking_dialog("Attempt 1: Authenticating..."),
            None,
        );
    }

    #[test]
    fn test_normal_window_not_blocking() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("IBKR Gateway"),
            None,
        );
    }

    #[test]
    fn test_config_dialog_not_blocking() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("Trader Workstation Configuration"),
            None,
        );
    }

    #[test]
    fn test_paper_warning_not_blocking() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("Warning"),
            None,
        );
    }
}
