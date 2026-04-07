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

use tokio::sync::mpsc;

use crate::types::{Command, Signal};

use types::Interrupt;

/// Select result: either an interrupt from a channel, or a completed
/// state transition.
enum SelectOutcome {
    Interrupted(Interrupt),
    Transitioned(Result<State, StateMachineError>),
}

impl StateMachine {
    /// Run the state machine until shutdown or fatal error.
    ///
    /// Uses `tokio::select!` with `biased;` to ensure signals (SIGTERM/SIGINT)
    /// are handled with priority over state transitions. This means a SIGTERM
    /// during a 60s+ agent wait will be caught immediately instead of being
    /// delayed until the transition completes — critical for Docker's 10s
    /// stop grace period.
    ///
    /// Architecture: the channel receivers are temporarily moved out of `self`
    /// for the select (and restored afterward) to avoid conflicting `&mut self`
    /// borrows between the interrupt channels and `transition()`. This is safe
    /// because `transition()` never accesses the channel receivers.
    pub async fn run(&mut self) -> Result<(), StateMachineError> {
        // If auto_launch is disabled, start in dormant WaitingForLaunch state
        if !self.config.site.auto_launch && self.state == State::Init {
            log::info!(
                "Site role={}, auto_launch=false — starting in WaitingForLaunch (JVM will not launch until START command)",
                self.config.site.role,
            );
            self.state = State::WaitingForLaunch;
        }

        log::info!("State machine starting in state: {}", self.state);

        loop {
            // Pre-transition bookkeeping (cheap, no I/O)
            self.check_ib_status_ttl();
            self.check_ib_system_availability();
            self.process_queries().await;

            // Temporarily take receivers out of self so we can select between
            // them and self.transition() without borrow conflicts.
            let mut sig_rx = std::mem::replace(
                &mut self.signal_rx,
                mpsc::channel(1).1, // dummy receiver, never polled
            );
            let mut cmd_rx = std::mem::replace(
                &mut self.command_rx,
                mpsc::channel(1).1,
            );
            let mut cold_rx = std::mem::replace(
                &mut self.cold_restart_rx,
                mpsc::channel(1).1,
            );

            let outcome = if self.pause.paused {
                // Pause mode: wait for interrupt or timeout
                tokio::select! {
                    biased;

                    Some(sig) = sig_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::Signal(sig))
                    }
                    Some(c) = cmd_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::Command(c))
                    }
                    Some(_) = cold_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::ColdRestart)
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                        SelectOutcome::Transitioned(Ok(self.state.clone()))
                    }
                }
            } else {
                // Main select: interrupts race against the state transition.
                // `biased;` ensures signals get priority when multiple branches
                // are ready simultaneously.
                //
                // All recv() branches use `Some(_) =` pattern guards so that a
                // closed channel (sender dropped) is treated as "branch not ready"
                // rather than firing. Without this, a dropped sender causes an
                // immediate-resolving branch that busy-loops or triggers spurious
                // interrupts. See: https://github.com/Lcstyle/ibctl/issues/1
                tokio::select! {
                    biased;

                    Some(sig) = sig_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::Signal(sig))
                    }

                    Some(c) = cmd_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::Command(c))
                    }

                    Some(_) = cold_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::ColdRestart)
                    }

                    // State transition — cancellation-safe because:
                    // 1. Agent HTTP calls are atomic (complete or don't)
                    // 2. self.state is only updated AFTER transition returns
                    // 3. Internal timers reset on re-entry, which is acceptable
                    //    since cancellation only happens on signal/command (rare)
                    next = self.transition() => {
                        SelectOutcome::Transitioned(next)
                    }
                }
            };

            // Restore receivers back into self
            self.signal_rx = sig_rx;
            self.command_rx = cmd_rx;
            self.cold_restart_rx = cold_rx;

            // Process the outcome
            match outcome {
                SelectOutcome::Interrupted(interrupt) => {
                    self.handle_interrupt(interrupt).await?;
                    if matches!(self.state, State::Shutdown) {
                        self.do_shutdown().await?;
                        break;
                    }
                }
                SelectOutcome::Transitioned(result) => {
                    let next = result?;
                    if next != self.state {
                        self.apply_transition(next).await?;
                    }
                    if matches!(self.state, State::Shutdown) {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Apply a transition result: record history, check ceiling, handle
    /// terminal states (Shutdown, Error).
    async fn apply_transition(&mut self, next: State) -> Result<(), StateMachineError> {
        // Ceiling check: if the next state matches the ceiling, auto-pause
        if let Some(ref ceiling) = self.pause.ceiling_state {
            if &next == ceiling {
                log::info!("State machine reached ceiling state {} — auto-pausing", next);
                self.pause.paused = true;
                self.pause.ceiling_state = None;
            }
        }

        log::info!("State transition: {} -> {}", self.state, next);
        self.record_transition(&self.state.clone(), &next);

        if next == State::Connected && self.state != State::Connected {
            self.connected_since = Some(Instant::now());
            self.relogin_attempts = 0;
        } else if next != State::Connected {
            self.connected_since = None;
        }

        self.process_queries().await;

        if next == State::Shutdown {
            self.abort_client_id_task();
            self.do_shutdown().await?;
            self.state = State::Shutdown;
            return Ok(());
        }

        if let State::Error(ref msg) = next {
            log::error!("State machine error: {} — will restart after delay", msg);
            // Error is recoverable: restart the JVM instead of killing the process.
            // Fatal errors (actual bugs) will panic; transient errors (connection loss,
            // login timeout) should retry with the configurable restart delay.
            self.state = State::Restarting;
            return Ok(());
        }

        self.state = next;
        Ok(())
    }

    /// Dispatch a command received from the command server.
    /// Handles stop/exit/start/restart specially; delegates the rest to handle_command.
    async fn dispatch_command(&mut self, cmd: Command) -> Result<(), StateMachineError> {
        match cmd {
            Command::Stop => {
                if matches!(self.state, State::WaitingForLaunch) {
                    log::info!("STOP received but already in WaitingForLaunch — no-op");
                } else {
                    log::info!("Received STOP — killing JVM, transitioning to WaitingForLaunch");
                    self.abort_client_id_task();
                    self.stop_socat();
                    if self.supervisor.is_running() {
                        if let Err(e) = self.supervisor.kill().await {
                            log::error!("Failed to kill JVM: {}", e);
                        }
                        match self.supervisor.wait().await {
                            Ok(status) => log::info!("JVM exited with status: {}", status),
                            Err(e) => log::warn!("JVM wait failed: {} (may already be dead)", e),
                        }
                    }
                    let socket = &self.config.agent.socket_path.clone();
                    let _ = std::fs::remove_file(socket);
                    self.handler_registry.reset();
                    let old = self.state.clone();
                    self.state = State::WaitingForLaunch;
                    self.record_transition(&old, &State::WaitingForLaunch);
                }
            }
            Command::Exit => {
                log::info!("Received EXIT command, transitioning to Shutdown");
                self.abort_client_id_task();
                self.state = State::Shutdown;
            }
            Command::Start => {
                if matches!(self.state, State::WaitingForLaunch) {
                    log::info!("Received START — launching JVM");
                    let old = self.state.clone();
                    self.state = State::Init;
                    self.record_transition(&old, &State::Init);
                } else {
                    log::info!("START received but not in WaitingForLaunch (state={}) — ignoring", self.state);
                }
            }
            Command::Restart => {
                log::info!("Received restart command");
                self.abort_client_id_task();
                self.state = State::Restarting;
            }
            other => {
                log::info!("Received command {:?} in state {}", other, self.state);
                self.handle_command(other).await?;
            }
        }
        Ok(())
    }

    /// Drain pending commands non-blockingly. Used inside state handler loops
    /// (like do_wait_for_login) to process IBSTATUS updates that arrive via the
    /// command channel without waiting for the main select loop.
    async fn process_commands_nonblocking(&mut self) {
        loop {
            match self.command_rx.try_recv() {
                Ok(cmd) => {
                    // Only handle non-state-changing commands (like IBSTATUS).
                    // Stop/Restart/Exit are handled by the main select loop.
                    match cmd {
                        Command::IbStatus(_, _) | Command::SetRestartTime(_) => {
                            let _ = self.handle_command(cmd).await;
                        }
                        _ => {
                            // Put it back? Can't with mpsc. Log and skip —
                            // these commands will be processed when we return
                            // to the main loop.
                            log::debug!("Deferring command {:?} until main loop", cmd);
                        }
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }
    }

    /// Handle an interrupt received via the select loop.
    async fn handle_interrupt(&mut self, interrupt: Interrupt) -> Result<(), StateMachineError> {
        match interrupt {
            Interrupt::Signal(Signal::Terminate | Signal::Interrupt) => {
                log::info!("Received shutdown signal, transitioning to Shutdown");
                self.abort_client_id_task();
                self.state = State::Shutdown;
            }
            Interrupt::Command(cmd) => {
                self.dispatch_command(cmd).await?;
            }
            Interrupt::ColdRestart => {
                log::info!("Sunday cold restart — full re-authentication required");
                self.abort_client_id_task();
                self.state = State::Restarting;
            }
        }
        Ok(())
    }

    /// IB System Status TTL expiry — fail-open if no recent push.
    fn check_ib_status_ttl(&mut self) {
        if let Some(last) = self.ib_status.last_updated {
            let ttl = std::time::Duration::from_secs(600); // 10 min default TTL
            if last.elapsed() > ttl && !self.ib_status.available {
                log::info!("IB system status TTL expired — assuming available (fail-open)");
                self.ib_status.available = true;
                self.ib_status.status = "available".to_string();
                self.ib_status.reason.clear();
            }
        }
    }

    /// If IB system unavailable and not already in WaitingForIB, transition there.
    fn check_ib_system_availability(&mut self) {
        if !self.ib_status.available && self.state != State::WaitingForIB && self.state != State::Shutdown && self.state != State::WaitingForLaunch {
            log::warn!("IB system unavailable: {} — transitioning to WaitingForIB", self.ib_status.reason);
            self.ib_status.return_state = Some(Box::new(self.state.clone()));
            let old = self.state.clone();
            self.state = State::WaitingForIB;
            self.record_transition(&old, &State::WaitingForIB);
        }
    }

    /// Abort the background client ID refresh task if running.
    fn abort_client_id_task(&mut self) {
        if let Some(handle) = self.client_id_task.take() {
            handle.abort();
        }
        self.client_id_rx = None;
    }

    /// Execute the transition for the current state, returning the next state.
    async fn transition(&mut self) -> Result<State, StateMachineError> {
        match &self.state {
            State::WaitingForLaunch => self.do_waiting_for_launch().await,
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

    /// Dormant standby mode: process is running but JVM is NOT launched.
    /// Only processes queries. Waits for a START command to transition to Init.
    async fn do_waiting_for_launch(&mut self) -> Result<State, StateMachineError> {
        log::info!("Standby mode — waiting for START command (JVM not launched)");

        // Process any pending queries so STATUS/STATE/CONFIG still respond
        self.process_queries().await;

        // Sleep and loop — commands/signals are handled by the outer select! in run()
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(State::WaitingForLaunch)
    }

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
        // Check for warm restart: use the captured autorestart hash to pass
        // -Drestart so Gateway resumes the session without 2FA.
        if let Some(ref restart_hash) = self.warm_restart_pending {
            log::info!("Warm restart: launching with -Drestart={}", restart_hash);
            self.supervisor.launch_with_restart(Some(restart_hash))?;
            // Keep warm_restart_pending set through the auth flow so
            // do_wait_for_login doesn't touch the login window.
            return Ok(State::WaitingForAgent);
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
        if self.warm_restart_pending.is_some() {
            log::info!("Warm restart: waiting for Gateway to self-authenticate (not touching login)");
            let max_wait = std::time::Duration::from_secs(120);
            let poll_interval = std::time::Duration::from_secs(2);
            let start = std::time::Instant::now();

            loop {
                if !self.supervisor.is_running() {
                    self.warm_restart_pending = None;
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
                                self.warm_restart_pending = None;
                                return Ok(State::DismissingPopups);
                            }
                        }
                    }
                }

                self.process_queries().await;

                if start.elapsed() > max_wait {
                    log::warn!("Warm restart: Gateway did not self-authenticate within {}s — falling back to cold auth", max_wait.as_secs());
                    self.warm_restart_pending = None;
                    return Ok(State::WaitingForLogin); // recurse as cold
                }
                tokio::time::sleep(poll_interval).await;
            }
        }

        let timeout_secs = self.config.timing.login_dialog_timeout_secs;
        let wait_indefinitely = timeout_secs == 0;
        if wait_indefinitely {
            log::info!("Waiting for login window (no timeout — will wait indefinitely)");
        } else {
            log::info!("Waiting for login window (timeout={}s)", timeout_secs);
        }

        let max_wait = std::time::Duration::from_secs(timeout_secs);
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
                    let mut has_login_form = false;
                    let mut has_main_window = false;

                    for w in &windows {
                        let title_lower = w.title.to_lowercase();
                        let class_lower = w.class.to_lowercase();

                        if title_lower.contains("existing session") {
                            log::info!("Session conflict dialog detected: {}", w.title);
                            return Ok(State::HandlingSessionConflict);
                        }

                        // Login form: class contains "login" (jclient.login.as)
                        if class_lower.contains("login") {
                            has_login_form = true;
                        }

                        // Main Gateway window: title matches but class is NOT login
                        if (title_lower.contains("ib gateway") || title_lower.contains("ibkr gateway"))
                            && !class_lower.contains("login")
                        {
                            has_main_window = true;
                        }
                    }

                    if has_login_form {
                        log::info!("Login form detected — proceeding to authenticate");
                        return Ok(State::Authenticating);
                    }

                    if has_main_window && !has_login_form {
                        // Gateway already authenticated (e.g., paper auto-login).
                        // The main window is showing but no login form exists.
                        log::info!("Gateway already authenticated — main window present, no login form");
                        return Ok(State::DismissingPopups);
                    }
                }
                Err(e) => {
                    log::debug!("Agent not ready yet: {}", e);
                }
            }

            if !wait_indefinitely && start.elapsed() > max_wait {
                return Ok(State::Error("Timed out waiting for login window".into()));
            }

            // Process pending commands (IBSTATUS updates arrive via command channel)
            // and queries (STATUS requests should still respond during wait)
            self.process_commands_nonblocking().await;
            self.process_queries().await;

            // If dashboard scraper pushed IBSTATUS unavailable, exit to main loop
            // which will transition to WaitingForIB
            if !self.ib_status.available {
                log::info!("IB system unavailable during login wait — returning to main loop");
                return Ok(State::WaitingForLogin); // main loop will catch and go to WaitingForIB
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

        // Find the login form by class (not title — the main window also says "IBKR Gateway")
        let login_window = windows.iter().find(|w| w.class.to_lowercase().contains("login"));

        // If no login form exists but the main Gateway window is showing,
        // Gateway already authenticated (e.g., paper auto-login without 2FA)
        if login_window.is_none() {
            let has_main = windows.iter().any(|w| {
                let t = w.title.to_lowercase();
                (t.contains("ib gateway") || t.contains("ibkr gateway")) && !w.class.to_lowercase().contains("login")
            });
            if has_main {
                log::info!("No login form but main Gateway window present — already authenticated");
                return Ok(State::DismissingPopups);
            }
            return Ok(State::WaitingForLogin);
        }

        // Safety: login_window.is_none() was checked above and returned early
        let Some(win) = login_window else { return Ok(State::WaitingForLogin) };

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
                // Handler couldn't interact with the window — might be a transient
                // state where the login form is closing. Check again shortly.
                log::debug!("Login handler didn't recognize window — retrying");
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

        // Close any stale Configure menu from a previous failed attempt.
        // An open menu covers dialogs and interferes with detection.
        self.dismiss_menus().await;

        // Guard: check for any blocking dialog (re-login, 2FA, session conflict)
        if let Some(next_state) = self.check_blocking_dialog().await {
            log::warn!("Blocking dialog detected — cannot configure API, transitioning to {}", next_state);
            self.config_retries = 0;
            return Ok(next_state);
        }

        // Guard: JVM must still be running
        if !self.supervisor.is_running() {
            log::warn!("JVM not running — cannot configure API");
            self.config_retries = 0;
            return Ok(State::Restarting);
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
                // Close any menu left open by the failed attempt
                self.dismiss_menus().await;

                if self.config_retries >= MAX_CONFIG_RETRIES {
                    // Configuration is best-effort — don't restart Gateway for config failures.
                    // Proceed to Connected and let the user configure manually if needed.
                    log::warn!(
                        "API configuration failed {} times — proceeding without config: {}",
                        MAX_CONFIG_RETRIES, e
                    );
                    self.config_retries = 0;
                    Ok(State::Connected)
                } else {
                    log::error!("API configuration FAILED: {} — will retry ({}/{})", e, self.config_retries, MAX_CONFIG_RETRIES);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    Ok(State::ConfiguringApi)
                }
            }
        }
    }

    async fn do_connected(&mut self) -> Result<State, StateMachineError> {
        log::info!("Gateway connected — monitoring loop tick");

        let (api_port, socat_port) = if self.config.auth.trading_mode == crate::config::TradingMode::Paper {
            (self.config.gateway.paper_api_port, self.config.gateway.paper_socat_port)
        } else {
            (self.config.gateway.live_api_port, self.config.gateway.live_socat_port)
        };

        // Start socat if not already running
        let socat_alive = self.socat_process.as_mut()
            .map(|c| c.try_wait().ok().flatten().is_none())
            .unwrap_or(false);
        if !socat_alive {
            self.start_socat(api_port, socat_port);
        }

        // Spawn client ID refresh task if not already running.
        // Stored in struct fields so it survives cancellation by tokio::select!
        if self.client_id_task.is_none() {
            let (ids_tx, ids_rx) = tokio::sync::watch::channel(Vec::<String>::new());
            let socket_path = self.config.agent.socket_path.clone();
            let handle = tokio::spawn(async move {
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
            self.client_id_task = Some(handle);
            self.client_id_rx = Some(ids_rx);
        }

        // Check JVM health
        if !self.supervisor.is_running() {
            log::info!("JVM exited — checking for autorestart token");
            let autorestart_hash = self.supervisor.find_autorestart_path();
            if let Some(ref hash) = autorestart_hash {
                log::info!("Found autorestart token: {} — warm restart", hash);
            } else {
                log::info!("No autorestart token — crash or unexpected exit");
            }

            self.stop_socat();
            self.warm_restart_pending = autorestart_hash;
            self.abort_client_id_task();
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

        // Check windows for re-login dialogs and dismiss popups
        if let Ok(windows) = self.agent_client.list_windows().await {
            for win in &windows {
                let title_lower = win.title.to_lowercase();

                if title_lower.contains("re-login") || title_lower.contains("login is required") {
                    self.relogin_attempts += 1;
                    log::info!(
                        "RE-LOGIN dialog detected (attempt {}) — connection lost",
                        self.relogin_attempts
                    );

                    if self.relogin_attempts <= self.config.timing.relogin_max_attempts {
                        // First occurrence: wait 30s for transient recovery, then click Re-login
                        log::info!("Waiting 30s before attempting re-login...");
                        for _ in 0..15 { self.process_queries().await; tokio::time::sleep(std::time::Duration::from_secs(2)).await; }

                        // Check if dialog is still there (Gateway may have self-recovered)
                        if let Ok(current_windows) = self.agent_client.list_windows().await {
                            let still_showing = current_windows.iter().any(|w| {
                                let t = w.title.to_lowercase();
                                t.contains("re-login") || t.contains("login is required")
                            });
                            if !still_showing {
                                log::info!("RE-LOGIN dialog disappeared during wait — Gateway self-recovered");
                                continue;
                            }
                            // Still showing — click Re-login to attempt reconnection
                            if let Some(dialog) = current_windows.iter().find(|w| {
                                let t = w.title.to_lowercase();
                                t.contains("re-login") || t.contains("login is required")
                            }) {
                                log::info!("Clicking Re-login to attempt reconnection");
                                let _ = self.agent_client.click_button(dialog.id, "Re-login").await;
                                self.handler_registry.reset();
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                                return Ok(State::WaitingForLogin);
                            }
                        }
                    } else {
                        // Second+ occurrence: re-login failed, cancel and restart JVM
                        log::warn!(
                            "RE-LOGIN failed after {} attempts — cancelling and restarting JVM",
                            self.relogin_attempts
                        );
                        let _ = self.agent_client.click_button(win.id, "Cancel").await;
                        self.handler_registry.reset();
                        self.abort_client_id_task();
                        log::info!("Waiting 60s before restarting JVM...");
                        for _ in 0..30 { self.process_queries().await; tokio::time::sleep(std::time::Duration::from_secs(2)).await; }
                        return Ok(State::Restarting);
                    }
                }

                let _ = self.handler_registry.dispatch(&self.agent_client, win).await;
            }
        }

        // Sync client IDs from background task (lock-free watch channel)
        if let Some(ref mut ids_rx) = self.client_id_rx {
            if ids_rx.has_changed().unwrap_or(false) {
                let ids = ids_rx.borrow_and_update().clone();
                if !ids.is_empty() {
                    self.cached_client_ids = ids;
                }
            }
        }

        // Signal/command/cold-restart handling is done by the outer
        // tokio::select! in run() — no need to check_interrupts() here.

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        Ok(State::Connected)
    }

    async fn do_restart(&mut self) -> Result<State, StateMachineError> {
        let delay = self.config.timing.restart_delay_secs;
        if delay > 0 {
            log::info!("Waiting {}s before restarting Gateway (giving time to self-recover)", delay);
            let start = std::time::Instant::now();
            while start.elapsed().as_secs() < delay {
                self.process_queries().await;
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        log::info!("Restarting IB Gateway");

        self.abort_client_id_task();
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
        log::info!("Waiting for IB system to become available ({})", self.ib_status.reason);

        // Process queries and commands so dashboard stays responsive
        self.process_queries().await;
        self.process_commands_nonblocking().await;

        // Check if IB became available
        if self.ib_status.available {
            log::info!("IB system is now available — resuming");
            if let Some(return_state) = self.ib_status.return_state.take() {
                return Ok(*return_state);
            }
            return Ok(State::Init);
        }

        // Poll with query processing so dashboard stays responsive
        for _ in 0..5 {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            self.process_queries().await;
            self.process_commands_nonblocking().await;
        }
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

    // check_interrupts() removed — signal/command/cold-restart handling is now
    // done directly in the tokio::select! loop in run(), giving immediate
    // responsiveness instead of polling between transitions.

    /// Dismiss any open menus by pressing Escape on the main Gateway window.
    /// Open menus (Configure > Settings) cover dialogs and interfere with detection.
    async fn dismiss_menus(&self) {
        if let Ok(windows) = self.agent_client.list_windows().await {
            for w in &windows {
                let t = w.title.to_lowercase();
                if t.contains("ib gateway") || t.contains("ibkr gateway") {
                    let _ = self.agent_client.send_key(w.id, "escape").await;
                    return;
                }
            }
        }
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
                self.ib_status.available = available;
                self.ib_status.status = status.clone();
                self.ib_status.reason = reason.clone();
                self.ib_status.last_updated = Some(std::time::Instant::now());
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
                self.pause.paused = true;
                self.pause.ceiling_state = None;
                Ok(())
            }
            Command::PauseAt(ref name) => {
                if let Some(target) = State::from_name(name) {
                    log::info!("State machine ceiling set: will pause at {}", target);
                    self.pause.ceiling_state = Some(target);
                    // If already at the ceiling state, pause immediately
                    if self.pause.ceiling_state.as_ref() == Some(&self.state) {
                        log::info!("Already at ceiling state — pausing now");
                        self.pause.paused = true;
                        self.pause.ceiling_state = None;
                    }
                } else {
                    log::error!("PAUSE: unknown state '{}'", name);
                }
                Ok(())
            }
            Command::Resume => {
                log::info!("State machine RESUMED — transitions active");
                self.pause.paused = false;
                self.pause.ceiling_state = None;
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
    use crate::types::{ColdRestartSignal, Command, Signal};

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

    // --- Channel closure tests (issue #1: closed channel busy-loop) ---
    // These verify that `Some(_) = rx.recv()` in tokio::select! correctly
    // skips branches when the sender is dropped (channel closed).

    #[tokio::test]
    async fn test_closed_cold_restart_channel_does_not_fire() {
        // Simulate: TWS_COLD_RESTART not set → sender dropped → receiver closed
        let (_tx, mut rx) = tokio::sync::mpsc::channel::<ColdRestartSignal>(1);
        drop(_tx); // sender dropped, channel closed

        // recv() on closed channel returns None immediately
        assert!(rx.recv().await.is_none());

        // In select!, Some(_) pattern should NOT match None → branch skipped
        let result = tokio::select! {
            Some(_) = rx.recv() => "cold_restart_fired",
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => "timeout",
        };
        assert_eq!(result, "timeout", "closed cold_restart channel must not fire");
    }

    #[tokio::test]
    async fn test_closed_command_channel_does_not_fire() {
        // Simulate: command server disabled → sender dropped
        let (_tx, mut rx) = tokio::sync::mpsc::channel::<Command>(1);
        drop(_tx);

        let result = tokio::select! {
            Some(_) = rx.recv() => "command_fired",
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => "timeout",
        };
        assert_eq!(result, "timeout", "closed command channel must not fire");
    }

    #[tokio::test]
    async fn test_closed_signal_channel_does_not_fire() {
        let (_tx, mut rx) = tokio::sync::mpsc::channel::<Signal>(1);
        drop(_tx);

        let result = tokio::select! {
            Some(_) = rx.recv() => "signal_fired",
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => "timeout",
        };
        assert_eq!(result, "timeout", "closed signal channel must not fire");
    }

    #[tokio::test]
    async fn test_live_channel_still_works_with_closed_siblings() {
        // One channel alive (cold_restart), two closed (signal, command)
        // The live channel should still deliver messages
        let (cold_tx, mut cold_rx) = tokio::sync::mpsc::channel::<ColdRestartSignal>(1);
        let (_sig_tx, mut sig_rx) = tokio::sync::mpsc::channel::<Signal>(1);
        let (_cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<Command>(1);
        drop(_sig_tx);
        drop(_cmd_tx);

        // Send a cold restart signal
        cold_tx.send(ColdRestartSignal).await.unwrap();

        let result = tokio::select! {
            biased;
            Some(_) = sig_rx.recv() => "signal",
            Some(_) = cmd_rx.recv() => "command",
            Some(_) = cold_rx.recv() => "cold_restart",
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => "timeout",
        };
        assert_eq!(result, "cold_restart", "live channel must still deliver with closed siblings");
    }

    #[tokio::test]
    async fn test_biased_select_no_starvation_with_closed_channels() {
        // Verify that closed channels don't starve later branches.
        // With the old `_ = rx.recv()` pattern, this would spin on the
        // closed channel and never reach the transition branch.
        let (_tx1, mut rx1) = tokio::sync::mpsc::channel::<Signal>(1);
        let (_tx2, mut rx2) = tokio::sync::mpsc::channel::<Command>(1);
        let (_tx3, mut rx3) = tokio::sync::mpsc::channel::<ColdRestartSignal>(1);
        drop(_tx1);
        drop(_tx2);
        drop(_tx3);

        // All channels closed — the sleep (simulating transition) must win
        let result = tokio::select! {
            biased;
            Some(_) = rx1.recv() => "signal",
            Some(_) = rx2.recv() => "command",
            Some(_) = rx3.recv() => "cold_restart",
            _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => "transition",
        };
        assert_eq!(result, "transition", "closed channels must not starve transition branch");
    }

    // --- Login timeout configuration tests ---

    #[test]
    fn test_login_timeout_default_is_120() {
        let config = crate::config::Config::default();
        assert_eq!(config.timing.login_dialog_timeout_secs, 120);
    }

    #[test]
    fn test_login_timeout_zero_means_indefinite() {
        let toml_str = r#"
[timing]
login_dialog_timeout_secs = 0
"#;
        let config: crate::config::Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.timing.login_dialog_timeout_secs, 0);
    }

    // --- IB status + command processing interaction tests ---

    #[tokio::test]
    async fn test_ibstatus_command_received_via_try_recv() {
        // Simulate: IBSTATUS command arrives on command channel
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Command>(32);
        tx.send(Command::IbStatus("maintenance".into(), "weekend reset".into())).await.unwrap();

        // try_recv should get it without blocking
        match rx.try_recv() {
            Ok(Command::IbStatus(status, reason)) => {
                assert_eq!(status, "maintenance");
                assert_eq!(reason, "weekend reset");
            }
            other => panic!("expected IbStatus, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_closed_command_channel_try_recv_is_disconnected() {
        // When command server disabled, sender dropped, try_recv returns Disconnected
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Command>(32);
        drop(tx);

        match rx.try_recv() {
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {} // expected
            other => panic!("expected Disconnected, got {:?}", other),
        }
    }
}
