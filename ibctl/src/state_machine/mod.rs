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
mod verifier;

// Re-export public API
pub use types::{Channels, State, StateMachine, StateMachineError};
#[allow(unused_imports)] // surfaced in later phases
pub(super) use verifier::{ConnectedProof, EvidenceKinds, RevocationSource, RevocationTracker};

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
            self.publish_snapshot();
            self.process_queries().await; // WINDOWS queries only

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
            // Event stream is optional — create a dummy if not connected.
            // During action states (Authenticating, ConfiguringApi), events
            // should NOT interrupt the transition — they'd cancel in-progress
            // UI automation. Instead, drain events after the transition completes.
            let action_in_progress = matches!(
                self.state,
                State::Authenticating | State::ConfiguringApi | State::HandlingSessionConflict
            );
            let mut evt_rx = if action_in_progress { None } else { self.event_rx.take() };

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
                    Some(event) = async { match evt_rx.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                        SelectOutcome::Interrupted(Interrupt::AgentEvent(event))
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
                // Priority order (per GPT-5.4 review):
                //   Signal/shutdown > ColdRestart > Command > AgentEvent > transition
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

                    Some(_) = cold_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::ColdRestart)
                    }

                    Some(c) = cmd_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::Command(c))
                    }

                    // Agent events — update observation cache, trigger re-evaluation.
                    // Uses Option<Receiver>: if event stream is not connected,
                    // this branch is permanently pending (never fires).
                    Some(event) = async { match evt_rx.as_mut() { Some(rx) => rx.recv().await, None => std::future::pending().await } } => {
                        SelectOutcome::Interrupted(Interrupt::AgentEvent(event))
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
            if !action_in_progress {
                self.event_rx = evt_rx;
            }

            // Drain any pending events (including those that arrived during action states).
            // Collect first to avoid double-borrow of self.
            if let Some(ref mut rx) = self.event_rx {
                let mut pending = Vec::new();
                while let Ok(event) = rx.try_recv() {
                    pending.push(event);
                }
                for event in pending {
                    self.handle_agent_event(event).await;
                }
            }

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

        // Reset per-state tracking on every transition
        self.state_entered_at = Instant::now();
        self.consecutive_agent_failures = 0;

        let next_is_connected = matches!(next, State::Connected(_));
        let curr_is_connected = matches!(self.state, State::Connected(_));
        if next_is_connected && !curr_is_connected {
            self.connected_since = Some(Instant::now());
            self.relogin_attempts = 0;
        } else if !next_is_connected {
            self.connected_since = None;
            // Leaving Connected — reset per-source revocation debounce state
            // so the next Connected session starts with a clean slate.
            self.revocation.clear_all();
        }

        // Reset 2FA device state when starting a new login or 2FA cycle
        if matches!(next, State::WaitingForLogin | State::WaitingFor2fa | State::Launching | State::Restarting) {
            self.twofa_device_selected = false;
        }

        // State-specific entry initialization
        match &next {
            State::Restarting | State::Launching => {
                // JVM is being killed or started — all window data is stale.
                // Clear observation cache so WaitingForLogin doesn't trust
                // old "no login button" data from the dead JVM.
                self.observation = crate::agent_events::AgentObservation::new();
            }
            State::WaitingFor2fa => {
                self.twofa_seen = false;
                self.twofa_gone_at = None;
            }
            State::DismissingPopups => {
                self.popup_last_dismissed = None;
            }
            State::ReconnectingSession => {
                self.relogin_attempts += 1;
            }
            _ => {}
        }

        // Clear stale login button flags when leaving the login phase.
        // IB Gateway morphs the login window in place (no close/reopen),
        // so window events may carry stale has_login_button=true during
        // the authentication animation.
        if matches!(next, State::DismissingPopups | State::WaitingFor2fa
            | State::WaitingForApiReady | State::ConfiguringApi | State::Connected(_))
        {
            self.observation.clear_login_buttons();
        }

        self.publish_snapshot();
        self.process_queries().await; // WINDOWS queries only

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
                log::debug!("Received command {:?} in state {}", other, self.state);
                self.handle_command(other).await?;
            }
        }
        self.publish_snapshot();
        Ok(())
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
            Interrupt::AgentEvent(event) => {
                self.handle_agent_event(event).await;
            }
        }
        Ok(())
    }

    /// Process an agent event — update the observation cache.
    /// Does NOT directly change controller state. The next transition()
    /// call reads the updated observation and decides the transition.
    async fn handle_agent_event(&mut self, event: crate::agent_events::AgentEvent) {
        use crate::agent_events::AgentEvent;

        match event {
            AgentEvent::Hello { protocol_version, .. } => {
                log::info!("Agent event stream connected (protocol v{})", protocol_version);
            }
            AgentEvent::Snapshot { seq, windows, .. } => {
                self.observation.apply_snapshot(windows, seq);
            }
            AgentEvent::WindowOpened { seq, window_id, ref window_title, ref window_class, has_login_button, .. } => {
                self.observation.window_opened(
                    window_id,
                    window_title.clone(),
                    window_class.clone(),
                    has_login_button,
                    seq,
                );
                log::info!("Event: window opened '{}' (has_login_button={})", window_title, has_login_button);
            }
            AgentEvent::WindowClosed { seq, window_id, ref window_title, .. } => {
                self.observation.window_closed(window_id, seq);
                log::info!("Event: window closed '{}'", window_title);
            }
            AgentEvent::Overflow { .. } => {
                log::warn!("Agent event queue overflow — marking observation as desynced");
                self.observation.mark_desync();
            }
            AgentEvent::Keepalive { .. } => {
                log::debug!("Agent event keepalive");
            }
            // Wave 3: semantic events — log for observability, state machine
            // uses these for richer context but core transitions still rely
            // on window_opened + has_login_button.
            AgentEvent::LoginFormReady { login_button, selected_mode, text_field_count, password_field_count, .. } => {
                log::info!(
                    "Event: login_form_ready (button={:?}, mode={:?}, fields={}/{})",
                    login_button, selected_mode, text_field_count, password_field_count
                );
            }
            AgentEvent::TwofaPrompt { prompt_type, ref devices, .. } => {
                log::info!("Event: twofa_prompt (type={}, devices={:?})", prompt_type, devices);
            }
            AgentEvent::ErrorDialog { ref window_title, ref message, ref buttons, .. } => {
                log::info!(
                    "Event: error_dialog '{}' (message={:?}, buttons={:?})",
                    window_title, message, buttons
                );
            }
            AgentEvent::ConnectionStatusChanged { ref from, ref to, .. } => {
                // Informational only — do NOT drive state changes from this event.
                // Events can arrive with stale "disconnected" state while the state
                // machine is still in Launching/Login, and would trigger false-positive
                // restarts on first Connected entry. Match IBC's reactive model:
                // disconnect detection happens via error dialog handling + active
                // label inspection during Connected state.
                log::warn!("Event: connection_status_changed {} -> {}", from, to);
            }
        }

        // Re-publish snapshot so dashboard sees latest state
        self.publish_snapshot();
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
            State::WaitingForApiReady => self.do_wait_for_api_ready().await,
            State::ConfiguringApi => self.do_configure_api().await,
            State::Connected(_) => self.do_connected().await,
            State::ReconnectingSession => self.do_reconnecting_session().await,
            State::Restarting => self.do_restart().await,
            State::WaitingForIB => self.do_waiting_for_ib().await,
            State::Shutdown => Ok(State::Shutdown),
            State::Error(msg) => Ok(State::Error(msg.clone())),
        }
    }

    // --- State handler methods ---

    /// Dormant standby mode: process is running but JVM is NOT launched.
    /// Single-step: sleep and return same state. START command handled by outer select!.
    async fn do_waiting_for_launch(&mut self) -> Result<State, StateMachineError> {
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

    /// Single-step: one health check per tick. Deadline tracked via state_entered_at.
    async fn do_wait_for_agent(&mut self) -> Result<State, StateMachineError> {
        if !self.supervisor.is_running() {
            return Ok(State::Error("JVM process exited before agent became ready".into()));
        }

        match self.agent_client.health().await {
            Ok(true) => {
                log::info!("Agent is healthy");
                Ok(State::WaitingForLogin)
            }
            _ => {
                if self.state_entered_at.elapsed() > std::time::Duration::from_secs(60) {
                    return Ok(State::Error("Timed out waiting for agent health check".into()));
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                Ok(State::WaitingForAgent)
            }
        }
    }

    /// Single-step: check observation cache / HTTP once, return immediately.
    /// Deadlines tracked via state_entered_at. Events trigger re-evaluation via select!.
    async fn do_wait_for_login(&mut self) -> Result<State, StateMachineError> {
        // --- Warm restart path ---
        // Gateway handles its own re-authentication via -Drestart.
        // Don't touch the login window — just wait for the main trading window.
        if self.warm_restart_pending.is_some() {
            if !self.supervisor.is_running() {
                self.warm_restart_pending = None;
                return Ok(State::Error("JVM exited during warm restart login".into()));
            }

            // Check for authenticated main window
            if let Ok(windows) = self.agent_client.list_windows().await {
                for w in &windows {
                    let t = w.title.to_lowercase();
                    if (t.contains("ib gateway") || t.contains("ibkr gateway"))
                        && !t.contains("login")
                        && !t.contains("configuration")
                        && w.bounds.as_ref().is_some_and(|b| b.width > 400)
                    {
                        log::info!("Warm restart: Gateway self-authenticated — main window detected");
                        self.warm_restart_pending = None;
                        return Ok(State::DismissingPopups);
                    }
                }
            }

            if self.state_entered_at.elapsed() > std::time::Duration::from_secs(120) {
                log::warn!("Warm restart timeout — falling back to cold auth");
                self.warm_restart_pending = None;
                self.state_entered_at = Instant::now(); // reset for cold auth deadline
                // Fall through to cold auth below
            } else {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                return Ok(State::WaitingForLogin);
            }
        }

        // --- Cold auth path ---
        if !self.supervisor.is_running() {
            return Ok(State::Error("JVM process exited while waiting for login window".into()));
        }

        // Event-driven fast path (observation cache, no I/O)
        if self.observation.synced {
            if self.observation.has_session_conflict() {
                log::info!("Session conflict detected via observation cache");
                return Ok(State::HandlingSessionConflict);
            }
            if self.observation.has_2fa_dialog() {
                log::info!("2FA dialog detected via observation cache while waiting for login");
                return Ok(State::WaitingFor2fa);
            }
            if self.observation.has_relogin_dialog() {
                log::info!("Re-login dialog detected via observation cache");
                return Ok(State::ReconnectingSession);
            }
            if let Some(main) = self.observation.main_gateway_window() {
                if main.has_login_button {
                    log::info!("Login form detected via observation cache (has_login_button=true)");
                    return Ok(State::Authenticating);
                } else {
                    log::info!("Gateway already authenticated via observation cache (no login button)");
                    return Ok(State::DismissingPopups);
                }
            }
        }

        // HTTP fallback (when observation cache is not synced)
        if !self.observation.synced {
            if let Some(next_state) = self.check_blocking_dialog().await {
                log::info!("Blocking dialog detected while waiting for login — transitioning to {}", next_state);
                return Ok(next_state);
            }

            if let Ok(windows) = self.agent_client.list_windows().await {
                for w in &windows {
                    if w.title.to_lowercase().contains("existing session") {
                        log::info!("Session conflict dialog detected: {}", w.title);
                        return Ok(State::HandlingSessionConflict);
                    }
                }

                let main_window = windows.iter().find(|w| {
                    let t = w.title.to_lowercase();
                    t.contains("ib gateway") || t.contains("ibkr gateway")
                });

                if let Some(main) = main_window {
                    use crate::types::WindowId;
                    let has_login_fields = if let Ok(components) = self.agent_client.dump_components(WindowId(main.id.0)).await {
                        components.get("textfields")
                            .and_then(|t| t.as_array())
                            .map(|a| !a.is_empty())
                            .unwrap_or(false)
                    } else {
                        true
                    };

                    if has_login_fields {
                        log::info!("Login form detected (text fields present, HTTP fallback)");
                        return Ok(State::Authenticating);
                    } else {
                        log::info!("Gateway already authenticated (HTTP fallback, no text fields)");
                        return Ok(State::DismissingPopups);
                    }
                }
            }
        }

        // Deadline check
        let timeout_secs = self.config.timing.login_dialog_timeout_secs;
        if timeout_secs > 0 && self.state_entered_at.elapsed() > std::time::Duration::from_secs(timeout_secs) {
            return Ok(State::Error("Timed out waiting for login window".into()));
        }

        // Nothing detected yet — sleep and return same state.
        // Events interrupt this sleep via select!, providing instant wakeup.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(State::WaitingForLogin)
    }

    async fn do_authenticate(&mut self) -> Result<State, StateMachineError> {
        log::info!("Authenticating with IB Gateway");

        // Check for blocking dialogs (re-login, 2FA) before attempting login
        if let Some(next_state) = self.check_blocking_dialog().await {
            log::info!("Blocking dialog detected during authentication — transitioning to {}", next_state);
            return Ok(next_state);
        }

        let windows = self.agent_client.list_windows().await?;

        // Find the main Gateway window by title (class is unreliable across versions)
        let main_window = windows.iter().find(|w| {
            let t = w.title.to_lowercase();
            t.contains("ib gateway") || t.contains("ibkr gateway")
        });

        let Some(win) = main_window else {
            return Ok(State::WaitingForLogin);
        };

        // Check if this window has text fields (login form) or not (already connected).
        // Some Gateway versions use the same class for both states.
        use crate::types::WindowId;
        let has_login_fields = if let Ok(components) = self.agent_client.dump_components(WindowId(win.id.0)).await {
            components.get("textfields")
                .and_then(|t| t.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
        } else {
            false
        };

        if !has_login_fields {
            log::info!("Main Gateway window present but no text fields — already authenticated");
            return Ok(State::DismissingPopups);
        }

        match self.handler_registry.dispatch(&self.agent_client, win).await {
            Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                log::info!("Login submitted via handler");
                // The login window will morph into the connected window without
                // closing/reopening (IB Gateway mutates in place). Clear the cached
                // has_login_button flag so do_connected() doesn't see a stale "login form".
                self.observation.clear_login_buttons();
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

    /// Single-step: check for 2FA dialog, handle TOTP/device selection, return.
    /// State tracked via twofa_seen, twofa_gone_at, twofa_device_selected fields.
    /// Deadline tracked via state_entered_at.
    async fn do_wait_for_2fa(&mut self) -> Result<State, StateMachineError> {
        if !self.supervisor.is_running() {
            return Ok(State::Error("JVM exited during 2FA wait".into()));
        }

        // Observation cache checks (instant, no I/O)
        if self.observation.has_relogin_dialog() {
            log::info!("Re-login dialog detected via observation during 2FA wait");
            return Ok(State::WaitingForLogin);
        }
        if self.observation.has_session_conflict() {
            log::info!("Session conflict detected via observation during 2FA wait");
            return Ok(State::HandlingSessionConflict);
        }

        // HTTP blocking dialog check
        if let Some(next_state) = self.check_blocking_dialog().await {
            if next_state == State::WaitingForLogin {
                log::info!("Blocking dialog detected during 2FA wait — transitioning to {}", next_state);
                return Ok(next_state);
            }
        }

        // One window check per tick
        match self.agent_client.list_windows().await {
            Ok(windows) => {
                self.consecutive_agent_failures = 0;

                if windows.iter().any(|w| w.title.to_lowercase().contains("existing session")) {
                    return Ok(State::HandlingSessionConflict);
                }

                let twofa = windows.iter().find(|w| {
                    w.title.to_lowercase().contains("second factor")
                });

                if let Some(win) = twofa {
                    // 2FA dialog is visible — reset gone timer
                    self.twofa_gone_at = None;

                    if !self.twofa_seen {
                        self.twofa_seen = true;
                        log::info!("2FA dialog detected: {}", win.title);
                    }

                    // Device selection (one-shot action)
                    if !self.twofa_device_selected {
                        let twofa_device = &self.config.twofa.device.clone();
                        if !twofa_device.is_empty() {
                            log::info!("Selecting 2FA device: {}", twofa_device);
                            match self.agent_client.select_list_item(win.id, twofa_device).await {
                                Ok(true) => {
                                    log::info!("Selected '{}' in device list", twofa_device);
                                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                    let _ = self.agent_client.click_button(win.id, "OK").await;
                                    log::info!("Clicked OK on device selection — waiting for 2FA challenge");
                                    self.twofa_device_selected = true;
                                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                                    return Ok(State::WaitingFor2fa);
                                }
                                _ => {
                                    log::debug!("No device list found — this is the actual 2FA challenge");
                                    self.twofa_device_selected = true;
                                }
                            }
                        } else {
                            self.twofa_device_selected = true;
                        }
                    }

                    // TOTP submission
                    if self.config.twofa.has_secret {
                        match self.handler_registry.dispatch(&self.agent_client, win).await {
                            Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                                log::info!("TOTP code submitted, waiting for verification");
                                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                                return Ok(State::DismissingPopups);
                            }
                            Some(Ok(crate::handlers::HandlerResult::Error(msg))) => {
                                log::error!("TOTP entry failed: {} — will retry next tick", msg);
                            }
                            Some(Err(e)) => {
                                log::error!("TOTP handler error: {} — will retry next tick", e);
                            }
                            _ => {
                                log::debug!("No TOTP handler matched — may be IB Key dialog");
                            }
                        }
                    }
                } else if self.twofa_seen {
                    // FAIL-CLOSED 2FA verification (L4 architectural fix).
                    //
                    // 2FA dialog was seen but is now absent. This can mean:
                    //   a) Device selection closed → challenge dialog about to open
                    //   b) 2FA succeeded → Gateway is authenticated
                    //   c) 2FA failed/cancelled → login form appeared
                    //
                    // We require POSITIVE CONFIRMATION of authentication:
                    // the main Gateway window must exist with ZERO text fields
                    // (no login form). We do NOT use timing-based checks or
                    // absence-of-bad-state as proof of success.

                    // First: check if 2FA dialog reappeared (case a — dialog swap)
                    // Reset gone timer if dialog comes back within check window
                    if self.twofa_gone_at.is_none() {
                        self.twofa_gone_at = Some(Instant::now());
                        log::info!("2FA dialog absent — waiting for positive auth confirmation...");
                    }

                    // Wait at least 5 seconds for dialog swap to settle
                    // (device selection → challenge dialog transition takes 1-3s)
                    if self.twofa_gone_at.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(5)) {
                        // Still in settling window — don't decide yet
                    } else {
                        // Settling window passed. Require POSITIVE CONFIRMATION via
                        // active object inspection — not observation cache, not timers.
                        let mut confirmed_authenticated = false;
                        let mut confirmed_login_form = false;

                        for w in &windows {
                            let t = w.title.to_lowercase();
                            if t.contains("ib gateway") || t.contains("ibkr gateway") {
                                if let Ok(components) = self.agent_client.dump_components(w.id).await {
                                    let has_textfields = components.get("textfields")
                                        .and_then(|t| t.as_array())
                                        .is_some_and(|a| !a.is_empty());
                                    if has_textfields {
                                        confirmed_login_form = true;
                                    } else {
                                        confirmed_authenticated = true;
                                    }
                                }
                            }
                        }

                        if confirmed_login_form {
                            log::warn!("2FA FAILED — login form detected via object inspection");
                            self.handler_registry.reset();
                            return Ok(State::WaitingForLogin);
                        }

                        if confirmed_authenticated {
                            log::info!("2FA SUCCEEDED — Gateway authenticated (positive confirmation via object inspection)");
                            return Ok(State::DismissingPopups);
                        }

                        // Neither confirmed — gateway window might not be visible yet.
                        // Stay in WaitingFor2fa (will be caught by timeout if stuck).
                        log::debug!("2FA verification inconclusive — no gateway window found, retrying");
                    }
                } else {
                    // Never seen 2FA dialog — check grace period
                    let grace_period = std::time::Duration::from_secs(10);
                    if self.state_entered_at.elapsed() > grace_period {
                        log::info!("No 2FA dialog appeared within {}s — proceeding without 2FA", grace_period.as_secs());
                        return Ok(State::DismissingPopups);
                    }
                }
            }
            Err(e) => {
                self.consecutive_agent_failures += 1;
                if self.consecutive_agent_failures >= 10 {
                    log::error!("Agent unreachable after {} consecutive failures", self.consecutive_agent_failures);
                    return Ok(State::Error("Agent unreachable during 2FA wait".into()));
                }
                log::debug!("Agent poll failed ({}x): {}", self.consecutive_agent_failures, e);
            }
        }

        // Timeout check
        let timeout_secs = self.config.twofa.timeout_seconds;
        if self.state_entered_at.elapsed() > std::time::Duration::from_secs(timeout_secs) {
            if self.config.twofa.relogin_after_timeout
                || self.config.twofa.timeout_action == crate::config::TwoFaTimeoutAction::Restart
            {
                log::warn!("2FA timed out after {}s — restarting", timeout_secs);
                return Ok(State::Restarting);
            } else {
                log::error!("2FA timed out after {}s — shutting down", timeout_secs);
                return Ok(State::Shutdown);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(State::WaitingFor2fa)
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

    /// Single-step: dispatch popups once, check quiet period, return.
    /// Quiet period tracked via popup_last_dismissed. Deadline via state_entered_at.
    async fn do_dismiss_popups(&mut self) -> Result<State, StateMachineError> {
        if !self.supervisor.is_running() {
            return Ok(State::Error("JVM exited during popup dismissal".into()));
        }

        // Event-driven blocking dialog detection (no I/O)
        if self.observation.has_2fa_dialog() {
            log::info!("2FA dialog detected via observation during popup dismissal");
            return Ok(State::WaitingFor2fa);
        }
        if self.observation.has_relogin_dialog() {
            log::info!("Re-login dialog detected via observation during popup dismissal");
            self.handler_registry.reset();
            return Ok(State::ReconnectingSession);
        }
        if self.observation.has_session_conflict() {
            log::info!("Session conflict detected via observation during popup dismissal");
            self.handler_registry.reset();
            return Ok(State::HandlingSessionConflict);
        }

        // HTTP fallback for blocking dialogs (if observation not synced)
        if !self.observation.synced {
            if let Some(next_state) = self.check_blocking_dialog().await {
                log::info!("Blocking dialog detected during popup dismissal — transitioning to {}", next_state);
                if !matches!(next_state, State::WaitingFor2fa) {
                    self.handler_registry.reset();
                }
                return Ok(next_state);
            }
        }

        // One pass: dispatch popups via HTTP
        let mut found_popup = false;
        if let Ok(windows) = self.agent_client.list_windows().await {
            for win in &windows {
                if let Some(Ok(_)) = self.handler_registry.dispatch(&self.agent_client, win).await {
                    log::info!("Dismissed popup: {}", win.title);
                    found_popup = true;
                    self.popup_last_dismissed = Some(Instant::now());
                }
            }
        }

        // Quiet period check: no popups for 5s means we're done
        let quiet_threshold = std::time::Duration::from_secs(5);
        if !found_popup {
            let quiet_since = self.popup_last_dismissed.unwrap_or(self.state_entered_at);
            if quiet_since.elapsed() > quiet_threshold {
                log::info!("No popups for {:?} — waiting for API readiness", quiet_threshold);
                return Ok(State::WaitingForApiReady);
            }
        }

        // Max wait deadline
        if self.state_entered_at.elapsed() > std::time::Duration::from_secs(30) {
            log::info!("Max popup dismissal time reached, waiting for API readiness");
            return Ok(State::WaitingForApiReady);
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        Ok(State::DismissingPopups)
    }

    /// Single-step: check observation cache / HTTP for API readiness, return.
    /// Deadline tracked via state_entered_at.
    async fn do_wait_for_api_ready(&mut self) -> Result<State, StateMachineError> {
        if !self.supervisor.is_running() {
            log::warn!("JVM exited while waiting for API readiness");
            return Ok(State::Restarting);
        }

        // Check for blocking dialogs (2FA, re-login, session conflict)
        if self.observation.has_2fa_dialog() {
            log::info!("2FA dialog detected via observation while waiting for API ready");
            return Ok(State::WaitingFor2fa);
        }
        if self.observation.has_relogin_dialog() {
            log::info!("Re-login detected via observation while waiting for API ready");
            return Ok(State::ReconnectingSession);
        }
        if self.observation.has_session_conflict() {
            log::info!("Session conflict detected via observation while waiting for API ready");
            return Ok(State::HandlingSessionConflict);
        }
        if self.observation.has_login_form() {
            log::warn!("Login form detected while waiting for API ready — session lost");
            return Ok(State::WaitingForLogin);
        }

        if let Some(next_state) = self.check_blocking_dialog().await {
            log::info!("Blocking dialog detected while waiting for API — transitioning to {}", next_state);
            return Ok(next_state);
        }

        // POSITIVE CONFIRMATION: Inspect Gateway window's Connection Status table.
        // The definitive signal is "Interactive Brokers API Server: connected"
        // visible in the JTable. Not absence of login form, not TCP probe.
        if let Ok(windows) = self.agent_client.list_windows().await {
            for w in &windows {
                let t = w.title.to_lowercase();
                if t.contains("ib gateway") || t.contains("ibkr gateway") {
                    if let Ok(components) = self.agent_client.dump_components(w.id).await {
                        // Check for login form (textfields present = not authenticated)
                        let has_textfields = components.get("textfields")
                            .and_then(|t| t.as_array())
                            .is_some_and(|a| !a.is_empty());
                        // Log component counts for diagnostics
                        let n_labels = components.get("labels").and_then(|l| l.as_array()).map(|a| a.len()).unwrap_or(0);
                        let n_tables = components.get("tables").and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(0);
                        let n_buttons = components.get("buttons").and_then(|b| b.as_array()).map(|a| a.len()).unwrap_or(0);
                        log::info!(
                            "WaitingForApiReady: inspecting gateway window — {} textfields, {} labels, {} tables, {} buttons",
                            if has_textfields { "HAS" } else { "0" }, n_labels, n_tables, n_buttons
                        );

                        if has_textfields {
                            log::debug!("Login form still visible — not ready");
                            break;
                        }

                        // Positive confirmation via label inspection.
                        // See components_indicate_connected for label shape details.
                        if components_indicate_connected(&components) {
                            log::info!("Gateway API Server: connected (confirmed via label inspection)");
                            return Ok(State::ConfiguringApi);
                        }
                    }
                }
            }
        }

        // Deadline — fail-CLOSED: if we never saw "connected" after 120s, the
        // Gateway is in an unknown state. Proceeding to ConfiguringApi pretending
        // the session is valid produces a false-Connected state where the dashboard
        // lies to the user. Restart the JVM for a clean slate instead.
        if self.state_entered_at.elapsed() > std::time::Duration::from_secs(120) {
            log::warn!("Gateway API not ready after 120s — restarting JVM (fail-closed)");
            self.abort_client_id_task();
            return Ok(State::Restarting);
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::WaitingForApiReady)
    }

    async fn do_configure_api(&mut self) -> Result<State, StateMachineError> {
        const MAX_CONFIG_RETRIES: u32 = 3;

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
                // Phase 0: use forced sentinel so the enum-shape change is a
                // no-op behavior change. Phase 2 replaces this with a real
                // `try_enter_connected(...)` call backed by the verifier.
                Ok(State::Connected(verifier::ConnectedProof::forced()))
            }
            Err(e) => {
                // Close any menu left open by the failed attempt
                self.dismiss_menus().await;

                if self.config_retries >= MAX_CONFIG_RETRIES {
                    // Configuration dialog not being reachable after 3 attempts means
                    // Gateway is not in the expected Connected-with-UI state — likely
                    // still at login form or showing an error. Fail-CLOSED: restart
                    // the JVM instead of pretending we're Connected.
                    log::warn!(
                        "API configuration failed {} times — restarting JVM (fail-closed): {}",
                        MAX_CONFIG_RETRIES, e
                    );
                    self.config_retries = 0;
                    self.abort_client_id_task();
                    Ok(State::Restarting)
                } else {
                    log::error!("API configuration FAILED: {} — will retry ({}/{})", e, self.config_retries, MAX_CONFIG_RETRIES);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    Ok(State::ConfiguringApi)
                }
            }
        }
    }

    /// Single-step: check observation cache for dialogs, manage socat/client IDs.
    /// Events provide instant wakeup for dialog detection. Reconciliation poll at 10s.
    async fn do_connected(&mut self) -> Result<State, StateMachineError> {

        // Record the main window class on first entry — used to detect silent session loss.
        // Uses observation cache (event-driven) with HTTP fallback.
        if self.connected_window_class.is_none() {
            if let Some(main) = self.observation.main_gateway_window() {
                log::info!("Recording connected window class: {} (from observation cache)", main.class);
                self.connected_window_class = Some(main.class.clone());
            } else if let Ok(windows) = self.agent_client.list_windows().await {
                // Fallback: observation cache not populated yet
                if let Some(main) = windows.iter().find(|w| {
                    let t = w.title.to_lowercase();
                    t.contains("ib gateway") || t.contains("ibkr gateway")
                }) {
                    log::info!("Recording connected window class: {} (from HTTP fallback)", main.class);
                    self.connected_window_class = Some(main.class.clone());
                }
            }
        }

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

        // ================================================================
        // Revocation bus: every contradiction source funnels through
        // self.revocation.observe(RevocationSource::X). Sources with zero
        // debounce (JvmDied, ReloginDialog, SessionConflict) fire on first
        // observation; debounced sources (LoginFormVisible, DisconnectedLabel,
        // ErrorDialog) require sustained contradiction. On maturation, we
        // log a structured "proof revoked" line + perform per-source cleanup
        // + return the source's designated next_state(). See verifier.rs.
        // ================================================================

        // --- JVM health (immediate) ---
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
            // Record & fire — zero debounce ⇒ matures immediately.
            let src = verifier::RevocationSource::JvmDied;
            let next = src.next_state();
            if self.revocation.observe(src).is_some() {
                log::warn!("proof revoked source=jvm_died next={}", next);
            }
            return Ok(next);
        }

        // --- Socat health (not a revocation — just self-heal) ---
        let socat_alive = self.socat_process.as_mut()
            .map(|c| c.try_wait().ok().flatten().is_none())
            .unwrap_or(false);
        if !socat_alive {
            log::warn!("Socat process died — restarting port forwarding");
            self.start_socat(api_port, socat_port);
        }

        // --- Re-login dialog (immediate) ---
        if self.observation.has_relogin_dialog() {
            let src = verifier::RevocationSource::ReloginDialog;
            if self.revocation.observe(src.clone()).is_some() {
                let next = src.next_state();
                log::warn!("proof revoked source=relogin_dialog next={}", next);
                self.abort_client_id_task();
                self.stop_socat();
                return Ok(next);
            }
        } else {
            self.revocation.clear("relogin_dialog");
        }

        // --- Session conflict dialog (immediate) ---
        if self.observation.has_session_conflict() {
            let src = verifier::RevocationSource::SessionConflict;
            if self.revocation.observe(src.clone()).is_some() {
                let next = src.next_state();
                log::warn!("proof revoked source=session_conflict next={}", next);
                self.abort_client_id_task();
                self.stop_socat();
                return Ok(next);
            }
        } else {
            self.revocation.clear("session_conflict");
        }

        // --- Error dialog on Gateway window (500 ms debounce) ---
        // Match non-config "IBKR Gateway"-titled dialogs that aren't the main
        // window itself. We also opportunistically click OK on them (benign
        // recovery action, orthogonal to revocation).
        let error_dialog_title = self.observation.windows.iter().find_map(|w| {
            let t = w.title.to_lowercase();
            let is_error = (t.contains("ibkr gateway") || t.contains("ib gateway"))
                && !t.contains("configuration")
                && w.id != self.observation.main_gateway_window().map(|m| m.id).unwrap_or(0);
            is_error.then(|| w.title.clone())
        });
        if let Some(title) = error_dialog_title {
            // Click OK (idempotent recovery action — separate from revocation)
            if let Ok(windows) = self.agent_client.list_windows().await {
                for w in &windows {
                    let t = w.title.to_lowercase();
                    if (t.contains("ibkr gateway") || t.contains("ib gateway"))
                        && !t.contains("configuration")
                    {
                        let _ = self.agent_client.click_button(w.id, "OK").await;
                    }
                }
            }
            let src = verifier::RevocationSource::ErrorDialog(title);
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!("proof revoked source=error_dialog next={}", next);
                self.connected_window_class = None;
                self.handler_registry.reset();
                self.abort_client_id_task();
                self.stop_socat();
                return Ok(next);
            }
        } else {
            self.revocation.clear("error_dialog");
        }

        // --- Login form via observation cache (1s debounce) ---
        // Event-driven detection: the agent's has_login_button flag is set
        // when window_opened/dump events detect login textfields.
        let observed_login_button = self.observation.main_gateway_window()
            .map(|m| m.has_login_button)
            .unwrap_or(false);

        // Track class changes (informational; not a revocation source in Phase 1)
        if let Some(main) = self.observation.main_gateway_window() {
            if let Some(ref expected_class) = self.connected_window_class {
                if main.class != *expected_class && !main.has_login_button {
                    log::info!(
                        "Window class changed {} → {} (no login form — benign UI update)",
                        expected_class, main.class
                    );
                    self.connected_window_class = Some(main.class.clone());
                }
            }
        }

        // --- Active probe: dump_components on main window ---
        // Runs every do_connected tick (not gated by modulo timer anymore) so
        // debounce timers can mature on schedule. Per-source clear() resets
        // the debounce when the contradiction stops.
        let mut probe_login_form = false;
        let mut probe_disconnected_label = false;
        let mut probe_twofa = false;
        if let Ok(windows) = self.agent_client.list_windows().await {
            for w in &windows {
                let t = w.title.to_lowercase();
                if t.contains("second factor") {
                    probe_twofa = true;
                }
                if t.contains("ib gateway") || t.contains("ibkr gateway") {
                    if let Ok(components) = self.agent_client.dump_components(w.id).await {
                        if components_have_login_form(&components) {
                            probe_login_form = true;
                        }
                        if components_indicate_disconnected(&components) {
                            probe_disconnected_label = true;
                        }
                    }
                }
            }

            // Reconciliation: dispatch handlers for any unprocessed windows.
            // Preserves the existing behavior of letting dialog handlers
            // auto-dismiss popups, etc.
            for win in &windows {
                let _ = self.handler_registry.dispatch(&self.agent_client, win).await;
            }
        }

        // 2FA dialog during Connected — unusual but possible. Not strictly a
        // revocation; we transition to WaitingFor2fa and the proof is dropped
        // when we leave Connected (apply_transition.clear_all()).
        if probe_twofa {
            log::warn!("2FA dialog observed during Connected — transitioning to WaitingFor2fa");
            return Ok(State::WaitingFor2fa);
        }

        // --- Login form revocation (1s debounce) ---
        let login_form_observed = observed_login_button || probe_login_form;
        if login_form_observed {
            let src = verifier::RevocationSource::LoginFormVisible;
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!("proof revoked source=login_form_visible next={}", next);
                self.connected_window_class = None;
                self.handler_registry.reset();
                self.abort_client_id_task();
                self.stop_socat();
                return Ok(next);
            }
        } else {
            self.revocation.clear("login_form_visible");
        }

        // --- Disconnected label revocation (2s debounce) ---
        if probe_disconnected_label {
            let src = verifier::RevocationSource::DisconnectedLabelStable;
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!("proof revoked source=disconnected_label next={}", next);
                self.connected_window_class = None;
                self.handler_registry.reset();
                self.abort_client_id_task();
                self.stop_socat();
                return Ok(next);
            }
        } else {
            self.revocation.clear("disconnected_label");
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

        // Signal/command/cold-restart/event handling is done by the outer
        // tokio::select! in run(). Events provide instant dialog detection.
        // This sleep is now just a reconciliation tick — events handle the fast path.

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        // Phase 0: stay-Connected self-return. Phase 1 will replace this path
        // entirely — the revocation bus drives demotion; otherwise the existing
        // proof is retained without re-verification.
        Ok(State::Connected(verifier::ConnectedProof::forced()))
    }

    /// Single-step graduated session recovery.
    /// Phase 1 (elapsed < 30s): wait for transient recovery.
    /// Phase 2 (elapsed >= 30s): check dialog, click Re-login.
    /// Phase 3 (attempts > max): click Cancel, reauth or restart.
    /// relogin_attempts incremented in apply_transition() on state entry.
    async fn do_reconnecting_session(&mut self) -> Result<State, StateMachineError> {
        let max = self.config.timing.relogin_max_attempts;

        // Phase 3: exhausted attempts — cancel and fallback
        if self.relogin_attempts > max {
            log::warn!(
                "Re-login failed after {} attempts — cancelling",
                self.relogin_attempts
            );
            if let Ok(windows) = self.agent_client.list_windows().await {
                for w in &windows {
                    let t = w.title.to_lowercase();
                    if t.contains("re-login") || t.contains("login is required") {
                        let _ = self.agent_client.click_button(w.id, "Cancel").await;
                    }
                }
            }
            self.handler_registry.reset();
            self.abort_client_id_task();
            self.relogin_attempts = 0;

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            use crate::config::ReloginFailureAction;
            match self.config.timing.relogin_failure_action {
                ReloginFailureAction::Restart => {
                    log::info!("relogin_failure_action=restart — restarting JVM");
                    return Ok(State::Restarting);
                }
                ReloginFailureAction::Reauth => {
                    if self.observation.has_login_form() {
                        log::info!("Login form available after Cancel — re-authenticating");
                        return Ok(State::WaitingForLogin);
                    }
                    if let Ok(windows) = self.agent_client.list_windows().await {
                        let has_gateway = windows.iter().any(|w| {
                            let t = w.title.to_lowercase();
                            t.contains("ib gateway") || t.contains("ibkr gateway")
                        });
                        if has_gateway {
                            log::info!("Gateway window present after Cancel — re-authenticating");
                            return Ok(State::WaitingForLogin);
                        }
                    }
                    log::warn!("No Gateway window after Cancel — restarting JVM");
                    return Ok(State::Restarting);
                }
            }
        }

        // Phase 1: transient recovery wait (first 30s)
        if self.state_entered_at.elapsed() < std::time::Duration::from_secs(30) {
            log::debug!(
                "ReconnectingSession: waiting for transient recovery ({:.0}s/30s, attempt {}/{})",
                self.state_entered_at.elapsed().as_secs_f64(),
                self.relogin_attempts, max
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            return Ok(State::ReconnectingSession);
        }

        // Phase 2: check dialog, click Re-login
        if let Ok(windows) = self.agent_client.list_windows().await {
            let dialog = windows.iter().find(|w| {
                let t = w.title.to_lowercase();
                t.contains("re-login") || t.contains("login is required")
            });

            if dialog.is_none() {
                // FAIL-CLOSED re-login verification (L4 architectural fix).
                //
                // Re-login dialog is gone. Require POSITIVE CONFIRMATION that
                // Gateway is authenticated before returning to Connected.
                // Check for 2FA dialog (auth still in progress) or login form
                // (session lost). Only declare recovery if main Gateway window
                // has zero text fields (authenticated state).
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;

                // Check for 2FA dialog (re-login triggered new auth)
                if self.observation.has_2fa_dialog() {
                    log::info!("RE-LOGIN dialog gone, 2FA dialog visible — waiting for auth");
                    self.handler_registry.reset();
                    self.relogin_attempts = 0;
                    return Ok(State::WaitingFor2fa);
                }

                // Active object inspection on main gateway window
                let mut confirmed_authenticated = false;
                let mut confirmed_login_form = false;

                if let Ok(win_list) = self.agent_client.list_windows().await {
                    // Check for 2FA dialog via window list
                    let has_2fa = win_list.iter().any(|w| {
                        w.title.to_lowercase().contains("second factor")
                    });
                    if has_2fa {
                        log::info!("RE-LOGIN dialog gone, 2FA dialog found — waiting for auth");
                        self.handler_registry.reset();
                        self.relogin_attempts = 0;
                        return Ok(State::WaitingFor2fa);
                    }

                    for w in &win_list {
                        let t = w.title.to_lowercase();
                        if t.contains("ib gateway") || t.contains("ibkr gateway") {
                            if let Ok(components) = self.agent_client.dump_components(w.id).await {
                                let has_textfields = components.get("textfields")
                                    .and_then(|t| t.as_array())
                                    .is_some_and(|a| !a.is_empty());
                                if has_textfields {
                                    confirmed_login_form = true;
                                } else {
                                    confirmed_authenticated = true;
                                }
                            }
                        }
                    }
                }

                if confirmed_login_form {
                    log::warn!("RE-LOGIN: login form detected — session NOT recovered");
                    self.handler_registry.reset();
                    self.relogin_attempts = 0;
                    return Ok(State::WaitingForLogin);
                }

                if confirmed_authenticated {
                    log::info!("RE-LOGIN: Gateway authenticated (positive confirmation)");
                    self.relogin_attempts = 0;
                    // Phase 0 sentinel — Phase 2 routes through verifier.
                    return Ok(State::Connected(verifier::ConnectedProof::forced()));
                }

                // Inconclusive — stay in ReconnectingSession (retry next tick)
                log::debug!("RE-LOGIN verification inconclusive — no gateway window confirmed, retrying");
            }

            if let Some(d) = dialog {
                log::info!("Clicking Re-login (attempt {}/{})", self.relogin_attempts, max);
                let _ = self.agent_client.click_button(d.id, "Re-login").await;
                self.handler_registry.reset();
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                return Ok(State::WaitingForLogin);
            }
        }

        // Couldn't check windows — retry next tick
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::ReconnectingSession)
    }

    /// Single-step: wait for restart delay (deadline-based), then kill and relaunch.
    async fn do_restart(&mut self) -> Result<State, StateMachineError> {
        let delay = self.config.timing.restart_delay_secs;

        // Phase 1: delay before restart (dashboard stays responsive via outer loop)
        if delay > 0 && self.state_entered_at.elapsed().as_secs() < delay {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            return Ok(State::Restarting);
        }

        // Phase 2: kill and restart
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

    /// Single-step: check IB status, return. Commands/queries handled by outer loop.
    async fn do_waiting_for_ib(&mut self) -> Result<State, StateMachineError> {
        if self.ib_status.available {
            log::info!("IB system is now available — resuming");
            if let Some(return_state) = self.ib_status.return_state.take() {
                return Ok(*return_state);
            }
            return Ok(State::Init);
        }

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
                    // Re-login dialogs: route to ReconnectingSession for graduated recovery.
                    // Do NOT click Cancel here — ReconnectingSession owns the re-login flow.
                    let t = w.title.to_lowercase();
                    if t.contains("re-login") || t.contains("relogin") || t.contains("login is required") {
                        log::info!("RE-LOGIN dialog detected — transitioning to ReconnectingSession");
                        return Some(State::ReconnectingSession);
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
        // Routes to ReconnectingSession for graduated recovery (wait → re-login → retry → restart)
        if t.contains("re-login") || t.contains("relogin") || t.contains("login is required") {
            return Some(State::ReconnectingSession);
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
                // Only log when status actually changes
                if self.ib_status.status != *status || self.ib_status.reason != *reason {
                    log::info!("IB system status update: {} ({})", status, if reason.is_empty() { "no reason" } else { reason });
                }
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

// --- Pure helpers for component inspection ---
//
// Extracted as free functions so they can be unit-tested against real JSON
// fixtures captured from the Java agent's `/windows/<id>/dump` endpoint.
// Gateway's Connection Status is rendered as adjacent JLabels
// (`["Purpose","Status","API Server","disconnected","IBKR GATEWAY"]`),
// NOT as JTable rows — so we must inspect the labels array.

/// Returns true if the component dump shows "API Server: disconnected" in labels.
/// Requires BOTH "api server" (case-insensitive) and "disconnected" as labels
/// to avoid false-positives on benign windows that happen to contain one term.
fn components_indicate_disconnected(components: &serde_json::Value) -> bool {
    let labels = match components.get("labels").and_then(|l| l.as_array()) {
        Some(arr) => arr,
        None => return false,
    };
    let texts: Vec<String> = labels.iter()
        .filter_map(|l| l.as_str())
        .map(|s| s.to_lowercase())
        .collect();
    let has_api_server = texts.iter().any(|s| s.contains("api server"));
    let has_disconnected = texts.iter().any(|s| s == "disconnected");
    has_api_server && has_disconnected
}

/// Returns true if the component dump shows "connected" as a standalone label.
/// Used by WaitingForApiReady to positively confirm the Gateway is ready.
fn components_indicate_connected(components: &serde_json::Value) -> bool {
    components.get("labels")
        .and_then(|l| l.as_array())
        .is_some_and(|labels| {
            labels.iter().any(|l| {
                l.as_str().is_some_and(|s| s.to_lowercase() == "connected")
            })
        })
}

/// Returns true if the component dump indicates a login form (non-empty textfields).
fn components_have_login_form(components: &serde_json::Value) -> bool {
    components.get("textfields")
        .and_then(|t| t.as_array())
        .is_some_and(|a| !a.is_empty())
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
            Some(State::ReconnectingSession),
        );
    }

    #[test]
    fn test_relogin_dialog_lowercase() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("re-login is required"),
            Some(State::ReconnectingSession),
        );
    }

    #[test]
    fn test_login_is_required_variant() {
        assert_eq!(
            StateMachine::classify_blocking_dialog("Login is required"),
            Some(State::ReconnectingSession),
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

    // --- Liveness check label inspection tests (incident 2026-04-16) ---
    //
    // Gateway renders the Connection Status info as JLabels, not JTable. A prior
    // version of the liveness check inspected `components["tables"]` for
    // "API Server: disconnected" — but the tables array was always empty on
    // the main Gateway window. This allowed the state machine to stay in
    // Connected for an hour while Gateway was actually at the login form.
    //
    // These tests use real JSON captured from the `/windows/<id>/dump` endpoint
    // on zion during the incident. Regression guards:
    //
    //   1. MUST detect "API Server: disconnected" from labels alone
    //   2. MUST NOT false-positive when Gateway is in a benign no-connection-status state
    //   3. MUST detect login form via non-empty textfields
    //   4. MUST confirm "connected" when labels say so

    /// Real zion dump of the main Gateway window in the disconnected state
    /// (captured 2026-04-16 ~06:00 UTC during the incident).
    const FIXTURE_MAIN_DISCONNECTED: &str = r#"{
        "buttons": [
            {"class":"trader.common.tag.r","text":"Show log","visible":true,"enabled":false,"selected":false,"type":"r"},
            {"class":"trader.common.tag.r","text":"Show API messages","visible":true,"enabled":false,"selected":false,"type":"r"},
            {"class":"jtscomponents.in","text":"File","visible":true,"enabled":true,"selected":false,"type":"in"}
        ],
        "textfields": [],
        "trees": [],
        "labels": ["Purpose","Status","API Server","disconnected","IBKR GATEWAY"],
        "tables": []
    }"#;

    /// Hypothetical but faithfully-shaped "connected" dump — same labels array
    /// except the status word differs.
    const FIXTURE_MAIN_CONNECTED: &str = r#"{
        "buttons": [{"class":"jtscomponents.in","text":"File","visible":true,"enabled":true,"selected":false,"type":"in"}],
        "textfields": [],
        "trees": [],
        "labels": ["Purpose","Status","API Server","connected","IBKR GATEWAY"],
        "tables": []
    }"#;

    /// Dump of the login-form window — has populated textfields. Labels contain
    /// neither "api server" nor "disconnected", so the disconnect check must
    /// NOT false-positive on this case (the login-form check catches it instead).
    const FIXTURE_LOGIN_FORM: &str = r#"{
        "buttons": [
            {"class":"javax.swing.JButton","text":"Log In","visible":true,"enabled":false,"selected":false,"type":"JButton"},
            {"class":"twslaunch.jtscomponents.V","text":"Live Trading","visible":true,"enabled":true,"selected":true,"type":"V"}
        ],
        "textfields": [
            {"class":"javax.swing.JTextField","text":"fake","visible":true,"enabled":true,"type":"JTextField"}
        ],
        "labels": ["Username","Password"],
        "tables": []
    }"#;

    fn parse(json: &str) -> serde_json::Value {
        serde_json::from_str(json).expect("fixture is valid JSON")
    }

    #[test]
    fn test_label_check_detects_disconnected_in_real_dump() {
        let components = parse(FIXTURE_MAIN_DISCONNECTED);
        assert!(
            components_indicate_disconnected(&components),
            "must detect 'API Server: disconnected' from real zion dump"
        );
    }

    #[test]
    fn test_label_check_does_not_trigger_on_connected() {
        let components = parse(FIXTURE_MAIN_CONNECTED);
        assert!(
            !components_indicate_disconnected(&components),
            "must NOT false-positive on a connected Gateway"
        );
    }

    #[test]
    fn test_label_check_does_not_trigger_on_login_form() {
        let components = parse(FIXTURE_LOGIN_FORM);
        assert!(
            !components_indicate_disconnected(&components),
            "must NOT false-positive on login form (login-form check catches this case)"
        );
    }

    #[test]
    fn test_label_check_handles_missing_labels_array() {
        let components = serde_json::json!({"buttons": [], "textfields": []});
        assert!(
            !components_indicate_disconnected(&components),
            "must NOT panic or false-positive when labels array is absent"
        );
    }

    #[test]
    fn test_label_check_requires_both_markers() {
        // "disconnected" alone without "API Server" context — shouldn't fire.
        // (e.g. some other label that happens to equal "disconnected" in a
        // benign window)
        let components = serde_json::json!({
            "labels": ["Some Other Thing", "disconnected"]
        });
        assert!(
            !components_indicate_disconnected(&components),
            "must require both 'api server' AND 'disconnected' labels"
        );
    }

    #[test]
    fn test_label_check_detects_connected_when_label_present() {
        let components = parse(FIXTURE_MAIN_CONNECTED);
        assert!(
            components_indicate_connected(&components),
            "must detect 'connected' label for positive confirmation"
        );
    }

    #[test]
    fn test_label_check_does_not_confirm_connected_on_disconnected() {
        let components = parse(FIXTURE_MAIN_DISCONNECTED);
        assert!(
            !components_indicate_connected(&components),
            "must not confirm connected when label says disconnected"
        );
    }

    #[test]
    fn test_login_form_detected_via_textfields() {
        let components = parse(FIXTURE_LOGIN_FORM);
        assert!(
            components_have_login_form(&components),
            "must detect login form via non-empty textfields array"
        );
    }

    #[test]
    fn test_login_form_not_detected_on_main_window() {
        let components = parse(FIXTURE_MAIN_DISCONNECTED);
        assert!(
            !components_have_login_form(&components),
            "must not flag main Gateway window as login form (textfields is empty)"
        );
    }

    // ================================================================
    // Integration tests — fail-closed state transitions
    // ================================================================
    //
    // Incident 2026-04-16 regression guard. The state machine must NEVER
    // transition into Connected without positive evidence the Gateway API
    // server is actually connected. These tests wire up a minimal StateMachine
    // with a mocked AgentClient and exercise the specific transition-decision
    // paths that were previously fail-open.

    use crate::agent_client::{AgentClient, MockAgent, WindowInfo};
    use crate::config::{Config, ValidConfig};
    use crate::handlers::DialogHandlerRegistry;
    use crate::supervisor::Supervisor;
    use crate::types::{QuerySnapshot, WindowId};
    use secrecy::SecretString;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::{mpsc, watch};

    /// Construct a minimal StateMachine for transition-decision tests.
    ///
    /// The supervisor is constructed but never launched (no JVM spawned). The
    /// AgentClient wraps the supplied MockAgent. All channels are created but
    /// left unused — tests drive state transitions directly via `do_*` methods.
    fn make_test_state_machine(mock: MockAgent) -> StateMachine {
        // Build a minimally-valid config (values irrelevant to the tests).
        let mut cfg = Config::default();
        {
            let u: String = ['x'; 3].iter().collect();
            let p: String = ['x'; 3].iter().collect();
            cfg.auth.username = u;
            cfg.auth.password = SecretString::from(p);
        }
        let config = ValidConfig::new_unchecked(cfg);

        let agent_client = AgentClient::mock(mock);
        let supervisor = Supervisor::new(
            config.gateway.clone(),
            std::path::PathBuf::from("/dev/null/not-used-in-tests.jar"),
            "/dev/null/not-used.sock".to_string(),
            5,
        );
        let handler_registry = DialogHandlerRegistry::new();

        let (_sig_tx, sig_rx) = mpsc::channel(1);
        let (_cmd_tx, cmd_rx) = mpsc::channel(1);
        let (_q_tx, q_rx) = mpsc::channel(1);
        let (_cr_tx, cr_rx) = mpsc::channel(1);
        let channels = Channels {
            signals: sig_rx,
            commands: cmd_rx,
            queries: q_rx,
            cold_restart: cr_rx,
            agent_events: None,
        };

        let (snapshot_tx, _snapshot_rx) = watch::channel(Arc::new(QuerySnapshot::initializing()));

        let mut sm = StateMachine::new(
            config,
            agent_client,
            supervisor,
            handler_registry,
            channels,
            snapshot_tx,
        );
        // Pretend the JVM is running so state handlers don't early-return
        // to Restarting on the `supervisor.is_running()` check.
        sm.supervisor.set_test_force_running(true);
        sm
    }

    /// A Gateway main window matching how it shows up in /windows responses.
    fn gateway_window() -> WindowInfo {
        WindowInfo {
            id: WindowId(1),
            title: "IBKR Gateway".into(),
            class: "ibgateway.ay".into(),
            bounds: None,
            visible: true,
        }
    }

    // ----------------------------------------------------------------
    // WaitingForApiReady: fail-closed when label never shows "connected"
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_wait_for_api_ready_times_out_to_restarting_when_disconnected() {
        // Arrange: Gateway shows "disconnected" label (simulates the incident scenario).
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "disconnected", "IBKR GATEWAY"],
                "textfields": [],
                "buttons": [],
                "tables": []
            }),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        // Simulate 121s having already elapsed — past the 120s deadline.
        sm.state_entered_at = Instant::now() - Duration::from_secs(121);
        sm.state = State::WaitingForApiReady;

        // Act
        let result = sm.do_wait_for_api_ready().await.expect("handler should not error");

        // Assert: MUST fail-closed to Restarting, not fabricate progress to ConfiguringApi.
        assert_eq!(
            result, State::Restarting,
            "fail-closed: after 120s without 'connected' label, must restart JVM not proceed to ConfiguringApi"
        );
    }

    #[tokio::test]
    async fn test_wait_for_api_ready_advances_to_configuring_when_connected() {
        // Arrange: Gateway shows "connected" label — positive confirmation.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "connected", "IBKR GATEWAY"],
                "textfields": [],
                "buttons": [],
                "tables": []
            }),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state_entered_at = Instant::now(); // fresh entry
        sm.state = State::WaitingForApiReady;

        // Act
        let result = sm.do_wait_for_api_ready().await.expect("handler should not error");

        // Assert: positive label confirmation → advance to ConfiguringApi
        assert_eq!(
            result, State::ConfiguringApi,
            "with 'connected' label confirmed, must advance to ConfiguringApi"
        );
    }

    #[tokio::test]
    async fn test_wait_for_api_ready_stays_when_no_signal_yet() {
        // Arrange: Gateway shows no textfields, no "connected", no "disconnected" labels —
        // transient mid-connect state. Not timed out yet.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status"],
                "textfields": [],
                "buttons": [],
                "tables": []
            }),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state_entered_at = Instant::now(); // fresh
        sm.state = State::WaitingForApiReady;

        let result = sm.do_wait_for_api_ready().await.expect("handler should not error");
        assert_eq!(
            result, State::WaitingForApiReady,
            "transient state: keep waiting, don't fabricate progress"
        );
    }

    // ----------------------------------------------------------------
    // Connected liveness check: detects disconnected label
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_connected_liveness_catches_disconnected_label() {
        // Arrange: Gateway was Connected but now shows "disconnected" in its labels
        // (the exact incident scenario — previously went undetected because the check
        // was looking at tables instead of labels).
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "disconnected", "IBKR GATEWAY"],
                "textfields": [],
                "buttons": [],
                "tables": []
            }),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state = State::Connected(verifier::ConnectedProof::forced());
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;
        // Seed the revocation tracker as if the disconnected label were first
        // observed 3s ago — past its 2s debounce — so the next `observe()`
        // call matures immediately. Without this seed, the test would need
        // two calls to `do_connected()` with a real 2s wait between them.
        sm.revocation.seed_first_seen_for_tests(
            verifier::RevocationSource::DisconnectedLabelStable,
            Duration::from_secs(3),
        );

        // Act
        let result = sm.do_connected().await.expect("handler should not error");

        // Assert: label-based liveness catches the disconnect, transitions to WaitingForLogin.
        assert_eq!(
            result, State::WaitingForLogin,
            "Connected state liveness check must detect 'API Server: disconnected' label and transition to WaitingForLogin once debounce matures"
        );
    }

    // ----------------------------------------------------------------
    // ConfiguringApi: skip-to-Connected when no settings to apply
    //
    // Note: the fail-closed path for ConfiguringApi (retry exhaustion ⇒
    // Restarting) is exercised by production logs during the 2026-04-16
    // incident and by manual reproduction. Wiring it up as an automated
    // test requires either (a) env-var mutation (not thread-safe under
    // parallel tests), or (b) injecting ApiConfigSettings via the config
    // struct rather than env::var. Tracked as follow-up — for now the
    // other fail-closed tests in this module cover the regression surface.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_configure_api_no_settings_advances_to_connected() {
        // Behavior contract: when there are no API settings to apply, skip the
        // config dialog entirely and advance to Connected. This is the correct
        // "no-op success" path — distinct from the fail-open we removed.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state = State::ConfiguringApi;

        let result = sm.do_configure_api().await.expect("handler should not error");
        assert!(
            matches!(result, State::Connected(_)),
            "no API settings configured ⇒ skip dialog ⇒ Connected (valid no-op path), got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_connected_liveness_respects_debounce_on_first_tick() {
        // Arrange: Gateway shows "disconnected" label but this is the first
        // observation — the 2s debounce must NOT have matured yet, so the
        // state machine stays Connected on this tick. This guards against
        // transient label-refresh glitches where a single-frame "disconnected"
        // reading during a window morph would otherwise cause a false demotion.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "disconnected", "IBKR GATEWAY"],
                "textfields": [],
                "buttons": [],
                "tables": []
            }),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state = State::Connected(verifier::ConnectedProof::forced());
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;
        // No seed — this is the FIRST observation.

        let result = sm.do_connected().await.expect("handler should not error");

        assert!(
            matches!(result, State::Connected(_)),
            "single-tick 'disconnected' observation must NOT fire the 2s-debounced revocation; got {:?}",
            result
        );
        assert!(
            sm.revocation.is_pending("disconnected_label"),
            "the disconnected_label source should be in its debounce window"
        );
    }

    #[tokio::test]
    async fn test_connected_liveness_transient_disconnect_does_not_revoke() {
        // Arrange: first tick sees "disconnected" — debounce starts. Second
        // tick sees "connected" — debounce must be cleared. No revocation.
        let mut dump = serde_json::json!({
            "labels": ["Purpose", "Status", "API Server", "disconnected", "IBKR GATEWAY"],
            "textfields": [], "buttons": [], "tables": []
        });
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: dump.clone(),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state = State::Connected(verifier::ConnectedProof::forced());
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;

        // Tick 1: disconnected observed — pending, stays Connected.
        let r1 = sm.do_connected().await.unwrap();
        assert!(matches!(r1, State::Connected(_)), "tick 1 still Connected");
        assert!(sm.revocation.is_pending("disconnected_label"));

        // Now the "disconnect" clears — Gateway's labels refresh to "connected".
        dump["labels"] = serde_json::json!(
            ["Purpose", "Status", "API Server", "connected", "IBKR GATEWAY"]
        );
        // Swap in the healed dump via a fresh mock (MockAgent.dump_response
        // is read-only per AgentApi trait, so we rebuild the state machine).
        let healed_mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: dump,
            ..Default::default()
        };
        sm.agent_client = AgentClient::mock(healed_mock);

        // Tick 2: healthy — debounce must clear, still Connected.
        let r2 = sm.do_connected().await.unwrap();
        assert!(matches!(r2, State::Connected(_)), "tick 2 still Connected after heal");
        assert!(
            !sm.revocation.is_pending("disconnected_label"),
            "debounce must clear when contradiction stops (transient disconnect resolved)"
        );
    }

    #[tokio::test]
    async fn test_connected_stays_connected_when_labels_show_connected() {
        // Arrange: Gateway is genuinely connected — labels show "connected".
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "connected", "IBKR GATEWAY"],
                "textfields": [],
                "buttons": [],
                "tables": []
            }),
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state = State::Connected(verifier::ConnectedProof::forced());
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;

        // Act
        let result = sm.do_connected().await.expect("handler should not error");

        // Assert: no transition — stays Connected (handler returns next state to loop back).
        // Uses matches! rather than assert_eq! because proof instances differ by issued_at.
        assert!(
            matches!(result, State::Connected(_)),
            "healthy Connected state must not self-transition just because a liveness tick fired, got {:?}",
            result
        );
    }
}
