//! Enum-based state machine driving the IB Gateway login and session lifecycle.
//!
//! States: Init -> Launching -> WaitingForAgent -> WaitingForLogin -> Authenticating
//!       -> WaitingFor2fa -> HandlingSessionConflict -> DismissingPopups -> Connected
//!       -> Restarting -> Shutdown
//!
//! The main loop calls `transition()` which matches on the current state and
//! calls the appropriate handler method. Each handler returns the next state.

mod markers;
mod queries;
pub mod recovery;
mod socat;
mod types;
mod revocation;

// Re-export public API
pub use markers::write_cold_restart_equivalent_marker;
pub use types::{Channels, State, StateMachine, StateMachineError};

use std::path::Path;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::types::{ColdRestartSignal, ColdRestartSkipReason, Command, Signal};

use types::{ColdRestartSkipRecord, Interrupt};

/// Select result: either an interrupt from a channel, or a completed
/// state transition.
enum SelectOutcome {
    Interrupted(Interrupt),
    Transitioned(Result<State, StateMachineError>),
}

/// Number of consecutive observation ticks where login form is visible
/// AND no 2FA dialog before demoting out of WaitingForHitl2fa. At a 2s
/// tick interval, 3 ticks = 6s minimum dwell — wide enough to bridge
/// the JVM's brief "(no dialog yet)" window during a real 2FA timeout,
/// narrow enough that an actual wedge unblocks quickly.
const HITL_DEMOTE_TICK_THRESHOLD: u8 = 3;

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

        // PR-C stage 3 fail-safe gate: if `RecoveryCoordinator::boot`
        // observed a corrupt-marker + sidecar=given_up sequence, it
        // refused to auto-reset and set `blocked_awaiting_resume=true`.
        // Park the SM in `WaitingForLaunch` so no reconnect attempt fires
        // until either (a) the operator taps the ntfy resume link
        // (`RESUME_RECONNECT <token>`) or (b) the operator restarts with
        // `IBCTL_RECOVERY_FORCE_RESET=1`. Without this gate the SM would
        // walk the standard Init → Launching → login flow on every boot
        // — the exact behaviour the fail-safe existed to prevent.
        if self.recovery.is_blocked_awaiting_resume() && self.state != State::WaitingForLaunch {
            log::warn!(
                "recovery.blocked_boot_gate state={} — parking SM in WaitingForLaunch \
                 pending RESUME_RECONNECT or IBCTL_RECOVERY_FORCE_RESET=1 restart",
                self.state,
            );
            let old = self.state.clone();
            self.state = State::WaitingForLaunch;
            self.record_transition(&old, &State::WaitingForLaunch);
        }

        log::info!("State machine starting in state: {}", self.state);

        loop {
            // Pre-transition bookkeeping (cheap, no I/O)
            self.check_ib_status_ttl();
            self.check_ib_system_availability();
            self.tick_recovery().await;
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
                    Some(sig) = cold_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::ColdRestart(sig))
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

                    Some(sig) = cold_rx.recv() => {
                        SelectOutcome::Interrupted(Interrupt::ColdRestart(sig))
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

        // Track "did the operator actually answer a 2FA challenge this JVM
        // lifecycle?" so the cold-restart-equivalent marker only fires for
        // real cold-restart-equivalents — not for warm restarts that bypass
        // 2FA (IBC's daily -Drestart= pattern) or revoke flap loops.
        // Set BEFORE the Connected-entry block so the predicate sees the
        // updated value on the same transition.
        //
        // WaitingFor2fa -> {DismissingPopups, WaitingForApiReady, ConfiguringApi,
        // Connected} sets the flag ONLY when twofa_seen == true. Without the
        // twofa_seen gate, the grace-period escape at do_wait_for_2fa
        // line 1188 (no dialog appeared within the grace period -> proceed to
        // DismissingPopups) would falsely set the flag even though no
        // challenge was ever presented or answered.
        if self.state == State::WaitingFor2fa
            && self.twofa_seen
            && matches!(
                next,
                State::DismissingPopups
                    | State::WaitingForApiReady
                    | State::ConfiguringApi
                    | State::Connected,
            )
        {
            self.cold_restart_equivalent_pending = true;
        }
        // WaitingForHitl2fa -> WaitingForApiReady is the positive-direction
        // probe at do_waiting_for_hitl_2fa (commit 7a7bb5d). NOT set on
        // - WaitingForHitl2fa -> WaitingForLogin (negative stale-form demote,
        //   commit bce5832: 2FA dialog timed out without being answered)
        // - WaitingForHitl2fa -> Restarting (preempt / auto-retry deadline /
        //   HITL_RESUME: Launching reset will clear the flag anyway)
        if self.state == State::WaitingForHitl2fa && next == State::WaitingForApiReady {
            self.cold_restart_equivalent_pending = true;
        }

        let next_is_connected = next == State::Connected;
        let curr_is_connected = self.state == State::Connected;
        // PR-C stage 3 dwell timer: on entering Connected, spawn a task that
        // sleeps `min_success_dwell_secs` then sends a DwellSuccess. On
        // leaving, drop the AbortOnDrop guard which aborts the task. This
        // is the single source of truth for "we've held Connected long
        // enough for a success" — the wall/mono anchors are sampled by
        // the task itself so the delta stays coherent.
        if next_is_connected && !curr_is_connected {
            let dwell_secs = self.recovery.config_min_success_dwell_secs();
            let tx = self.dwell_success_tx.clone();
            let handle = tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(dwell_secs)).await;
                let _ = tx.send(crate::state_machine::recovery::DwellSuccess {
                    recorded_at_wall: jiff::Zoned::now(),
                    recorded_at_mono: Instant::now(),
                });
            });
            self.dwell_guard = Some(crate::state_machine::recovery::AbortOnDrop::new(
                handle.abort_handle(),
            ));
        } else if curr_is_connected && !next_is_connected {
            // Drop the guard — this aborts the pending timer so it can
            // never fire `record_success` on a phase we've already left.
            self.dwell_guard = None;
        }
        if next_is_connected && !curr_is_connected {
            // Write the cold-restart-equivalent marker ONLY when both
            // conditions hold:
            //   (a) we got here via a credential-gathering / login-flow
            //       path (skips the Connected->revoke->Connected flap),
            //   (b) a 2FA challenge was answered successfully this JVM
            //       lifecycle (skips warm restarts that bypass 2FA).
            // The is_credential_gathering check is necessary-but-not-
            // sufficient; cold_restart_equivalent_pending is the second
            // mandatory gate.
            if self.state.is_credential_gathering() && self.cold_restart_equivalent_pending {
                if let Err(e) =
                    write_cold_restart_equivalent_marker(&self.cold_restart_equivalent_marker_path)
                {
                    log::warn!("Failed to write cold-restart-equivalent marker: {}", e);
                } else {
                    log::info!(
                        "Cold-restart-equivalent marker written ({}) — Sunday cold restart may skip if scheduled today",
                        self.cold_restart_equivalent_marker_path.display()
                    );
                }
            } else if self.state.is_credential_gathering() {
                log::debug!(
                    "Connected entry from credential-gathering state ({}) but no 2FA challenge \
                     answered this JVM lifecycle — not writing cold-restart-equivalent marker",
                    self.state
                );
            }
            // Consume the flag immediately after the write decision so a
            // subsequent Connected->revoke->ReconnectingSession->Connected
            // loop doesn't double-write or carry stale truth.
            self.cold_restart_equivalent_pending = false;
            self.connected_since = Some(Instant::now());
            self.relogin_attempts = 0;
            self.connected_continuously_since = Some(Instant::now());
            // Counter reset: "any_reach" resets immediately; "stable" defers
            // to a check in do_connected once connected_continuously_since
            // exceeds stable_secs. Here we seed the timer either way.
            if matches!(
                self.config.twofa.backoff.counter_reset,
                crate::config::CounterResetScope::AnyReach
            ) {
                if self.consecutive_2fa_timeouts > 0 {
                    log::info!(
                        "Connected reached — resetting 2FA attempt counter (was {})",
                        self.consecutive_2fa_timeouts
                    );
                }
                self.consecutive_2fa_timeouts = 0;
            }
            // Start the TCP probe task on Connected entry.
            self.start_api_port_probe();
        } else if curr_is_connected && !next_is_connected {
            // Leaving Connected → the single, authoritative cleanup site.
            // Previously these calls were scattered across five revocation
            // branches inside do_connected, with subtle asymmetries (e.g.
            // ReloginDialog didn't reset the handler registry, SessionConflict
            // didn't clear connected_window_class). Centralizing here makes
            // the lifecycle explicit and covers every future exit path — any
            // new command or handler that sets `self.state` to a non-Connected
            // variant will now clean up correctly without having to remember
            // to call these five methods.
            self.connected_since = None;
            self.connected_continuously_since = None;
            self.stop_api_port_probe();
            self.revocation.clear_all();
            self.abort_client_id_task();
            self.connected_window_class = None;
            self.handler_registry.reset();
            self.stop_socat();
        } else if !next_is_connected {
            // Not-Connected → not-Connected. `connected_since` is already None
            // in this case but set defensively; everything else was already
            // reset the last time we left Connected.
            self.connected_since = None;
            self.connected_continuously_since = None;
        }

        // Clear HITL bookkeeping when leaving WaitingForHitl2fa. Everything
        // allocated at HITL entry (timer, ntfy state) becomes stale
        // once we transition out.
        if self.state == State::WaitingForHitl2fa && next != State::WaitingForHitl2fa {
            log::info!(
                "Leaving HITL 2FA after {:?}s",
                self.hitl_entered_at
                    .map(|t| t.elapsed().as_secs())
                    .unwrap_or(0)
            );
            self.hitl_entered_at = None;
            self.hitl_next_retry_at = None;
            self.hitl_intervals_index = 0;
            self.hitl_ntfy_attempts = 0;
            self.hitl_ntfy_sent = false;
            self.hitl_login_form_observation_ticks = 0;
            self.hitl_connected_observation_ticks = 0;
        }

        // Reset 2FA device state when starting a new login or 2FA cycle
        if matches!(next, State::WaitingForLogin | State::WaitingFor2fa | State::Launching | State::Restarting) {
            self.twofa_device_selected = false;
        }

        // Drop any pending warm-restart token when we enter a clean lifecycle
        // boundary. Without this, an operator-triggered `STOP -> START` after
        // a prior unplanned `Restarting` would try to warm-restart using a
        // hash from a JVM exit that happened minutes ago — stale by the time
        // we relaunch. Restarting itself sets the field legitimately in
        // do_connected before transitioning, so this clear must NOT overwrite
        // it during that path; we only clear on Shutdown and WaitingForLaunch,
        // which are both operator-initiated idle states.
        if matches!(next, State::Shutdown | State::WaitingForLaunch) {
            self.warm_restart_pending = None;
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
        if next == State::Launching {
            // Defensive blanket reset of the cold-restart-equivalent flag —
            // covers every JVM (re)start: warm restart, cold restart, error
            // recovery, HITL auto-retry. The RAM flag only governs marker
            // writes during one process lifetime; the persistent marker on
            // disk is the durable cross-process truth, so resetting here is
            // correct (and matches what the constructor does).
            self.cold_restart_equivalent_pending = false;
        }

        // Clear stale login button flags when leaving the login phase.
        // IB Gateway morphs the login window in place (no close/reopen),
        // so window events may carry stale has_login_button=true during
        // the authentication animation.
        if matches!(next, State::DismissingPopups | State::WaitingFor2fa
            | State::WaitingForApiReady | State::ConfiguringApi | State::Connected)
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
            Interrupt::Signal(Signal::RecoveryGaveUp { mode, phase_entered_at }) => {
                // The recovery coordinator publishes RecoveryGaveUp on its
                // own giveup_signal_tx channel (installed via
                // `set_giveup_signal_sender`), which routes to external
                // subscribers (SSE bus, dashboard) — NOT into the main
                // interrupt select loop. Reaching this arm means a caller
                // wired the coordinator's sender into the OS-signal path;
                // that would be a wiring bug. Log at warn and no-op so the
                // in-line halt behaviour (JVM kill + WaitingForLaunch park
                // handled by the coordinator's own apply() branch) remains
                // authoritative.
                log::warn!(
                    "recovery.signal_misrouted mode={} phase_entered_at={} — \
                     RecoveryGaveUp routed into main interrupt channel; ignoring",
                    mode,
                    phase_entered_at,
                );
            }
            Interrupt::Command(cmd) => {
                self.dispatch_command(cmd).await?;
            }
            Interrupt::ColdRestart(signal) => match signal {
                ColdRestartSignal::Fire => {
                    // Dormant states have no running Gateway to restart. Firing
                    // a cold-restart here would spawn a Gateway JVM from scratch
                    // and log into IBKR — the exact failure mode observed on
                    // 2026-04-19 when a standby VPS's cold-restart scheduler
                    // fired on Sunday 9 AM while the site was correctly sitting
                    // in WaitingForLaunch awaiting a failover-coordinator START. The dormant
                    // standby launched Gateway anyway and raced the primary for
                    // the same IBKR account for hours.
                    //
                    // Invariant: ibctl only acts on a cold-restart when there's
                    // actually something to restart. Dormant signals: stamp the
                    // skip record so the dashboard can render the standby case
                    // distinctly from "fresh auth already happened", then no-op.
                    //
                    //   WaitingForLaunch — standby awaiting failover-coordinator activation
                    //   Shutdown         — operator exit in progress
                    //   Error            — recovery path; don't short-circuit it
                    //   WaitingForHitl2fa — JVM is up but operator gate unlifted;
                    //                      cycling would waste a pending 2FA token
                    if matches!(
                        self.state,
                        State::WaitingForLaunch
                            | State::Shutdown
                            | State::Error(_)
                            | State::WaitingForHitl2fa
                    ) {
                        log::info!(
                            "Sunday cold restart ignored — site is dormant (state={})",
                            self.state
                        );
                        self.last_cold_restart_skip = Some(ColdRestartSkipRecord {
                            recorded_at: jiff::Zoned::now(),
                            reason: ColdRestartSkipReason::DormantSite,
                        });
                        self.publish_snapshot();
                        return Ok(());
                    }
                    // A non-dormant fire is being accepted. Any prior skip
                    // record is necessarily stale — clear it so STATUS JSON
                    // consumers don't see "skip happened a week ago" forever.
                    self.last_cold_restart_skip = None;
                    log::info!("Sunday cold restart — full re-authentication required");
                    self.abort_client_id_task();
                    self.state = State::Restarting;
                }
                ColdRestartSignal::Skipped(reason) => {
                    // The scheduler suppressed the fire (typically because a
                    // fresh login already happened earlier today). Record the
                    // skip so the dashboard can surface it (and dedup against
                    // a same-day re-auth notification) — but do NOT change state.
                    match &reason {
                        ColdRestartSkipReason::FreshAuthToday { at } => {
                            log::info!(
                                "Sunday cold restart skipped — fresh auth already happened today at {}",
                                at
                            );
                        }
                        ColdRestartSkipReason::DormantSite => {
                            log::info!(
                                "Sunday cold restart skipped — site is dormant"
                            );
                        }
                    }
                    self.last_cold_restart_skip = Some(ColdRestartSkipRecord {
                        recorded_at: jiff::Zoned::now(),
                        reason,
                    });
                    self.publish_snapshot();
                }
            },
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
    ///
    /// IBSTATUS is a retry-gate, not a session killer. When we are in a
    /// post-auth state (Connected / DismissingPopups / WaitingForApiReady /
    /// ConfiguringApi) we stay put regardless of what the scraper says.
    /// Gateway's own label inspection (driven by the revocation bus) is the
    /// authoritative source for "is this session still healthy?" — not the
    /// public status page, which can be wrong (CDN blips, slow updates).
    ///
    /// Opt in to the historical kick-on-unavailable behavior via
    /// `[ib_status] kick_active_session = true`.
    fn check_ib_system_availability(&mut self) {
        if self.ib_status.available {
            return;
        }
        if matches!(
            self.state,
            State::WaitingForIB | State::Shutdown | State::WaitingForLaunch
        ) {
            return;
        }
        // Post-auth states are never interrupted unless explicit opt-in.
        let is_post_auth = matches!(
            self.state,
            State::Connected
                | State::DismissingPopups
                | State::WaitingForApiReady
                | State::ConfiguringApi
        );
        if is_post_auth && !self.config.ib_status.kick_active_session {
            return;
        }
        log::warn!(
            "IB system unavailable: {} — transitioning to WaitingForIB",
            self.ib_status.reason
        );
        self.ib_status.return_state = Some(Box::new(self.state.clone()));
        let old = self.state.clone();
        self.state = State::WaitingForIB;
        self.record_transition(&old, &State::WaitingForIB);
    }

    /// PR-C stage 3: per-tick recovery coordinator drive.
    ///
    /// Called at the top of each main-loop iteration. Responsibilities:
    ///   1. Drain any pending `DwellSuccess` from the dwell-timer task
    ///      channel and commit via `RecoveryCoordinator::record_success`.
    ///      This is where a full Connected dwell resets the phase timer
    ///      (or promotes Backoff → Aggressive).
    ///   2. Take the pending resume token (if any) and drive one
    ///      `compute` → `apply` cycle. `Sleep`/`Deferred` outcomes are
    ///      no-ops; only phase transitions rewrite the marker.
    ///
    /// Gating: only ticks in states that are actively trying to
    /// reconnect (or are Connected, so a Connected-dwell success can
    /// still land). Dormant / user-gated / shutdown states are skipped
    /// because the coordinator's phase timer must not age while the SM
    /// has no opportunity to reconnect — a weekend spent in
    /// `WaitingForLaunch` would otherwise deliver a `FireGiveUpAlert`
    /// on Monday morning's first START.
    ///
    /// Applied actions do throttle the SM: `FiredGiveUpAlert` halts
    /// active reconnection by transitioning to `WaitingForLaunch` (the
    /// resume-token gate is the only exit until the operator taps the
    /// ntfy link). `ResumedToAggressive` unblocks by dropping the SM
    /// back into `Init` when it was previously parked.
    async fn tick_recovery(&mut self) {
        // 1. Defensive drain of DwellSuccess. Only credit success to
        //    the coordinator when the SM is actually in Connected —
        //    the seven direct `self.state = ...` bypass sites in this
        //    module (Stop / Exit / Restart / HitlResume / signal
        //    handlers / ColdRestart::Fire / check_ib_system_availability)
        //    don't run apply_transition's dwell_guard cleanup, so a
        //    stale timer can still fire after we've left Connected.
        //    Belt-and-suspenders: drop the guard here if the SM has
        //    left Connected, and only commit successes drained while
        //    the SM is still Connected.
        let sm_connected = self.state == State::Connected;
        if !sm_connected && self.dwell_guard.is_some() {
            // Direct-assign bypass site left the guard alive; clear
            // it now so the pending task cannot deliver a phantom
            // success against the new phase.
            self.dwell_guard = None;
        }
        while let Ok(dwell) = self.dwell_success_rx.try_recv() {
            if !sm_connected {
                log::debug!(
                    "recovery.dwell_success_dropped state={} — SM left Connected \
                     between dwell fire and tick drain",
                    self.state,
                );
                continue;
            }
            if self.recovery.phase() == crate::state_machine::recovery::RecoveryPhase::GivenUp {
                // Guard's fallback: if the coordinator escalated into
                // GivenUp inside apply() (via its own compute-decision
                // path) while a dwell task was in flight, the wrapper
                // never had a chance to abort the task. Drop the
                // record_success rather than surfacing an error every
                // tick, and clear the guard.
                log::debug!(
                    "recovery.dwell_success_dropped phase=given_up — \
                     coordinator escalated during dwell window",
                );
                self.dwell_guard = None;
                continue;
            }
            if let Err(e) = self
                .recovery
                .record_success(dwell.recorded_at_wall, dwell.recorded_at_mono)
            {
                log::error!("recovery.record_success failed: {}", e);
            }
        }

        // Gate: skip the coordinator's compute/apply cycle in dormant
        // or user-gated states. The phase timer must not accrue time
        // while the SM has no opportunity to reconnect.
        //
        // Connected: kept in the tick set so record_success from a
        // Connected dwell can land immediately without a state change
        // (already drained above; compute here is a no-op tick).
        let active_recovery = matches!(
            self.state,
            State::Init
                | State::Launching
                | State::WaitingForAgent
                | State::WaitingForLogin
                | State::Authenticating
                | State::WaitingFor2fa
                | State::HandlingSessionConflict
                | State::DismissingPopups
                | State::WaitingForApiReady
                | State::ConfiguringApi
                | State::Connected
                | State::ReconnectingSession
                | State::Restarting
        );
        if !active_recovery {
            // Silently drop any pending resume token in a dormant state
            // — the operator taps but the coordinator isn't running.
            // Leave the token parked; a subsequent transition back to
            // an active state will pick it up on the next tick.
            return;
        }

        // 2. Compute + apply one recovery action. `Sleep`/`Deferred`
        //    are idempotent — safe to call every tick.
        let now_wall = jiff::Zoned::now();
        let now_mono = Instant::now();
        // TODO(PR-C stage 4): sample cold-restart FireEligible from the
        // scheduler. Passing false for now means the recovery arc runs
        // even when a cold restart is imminent — worst case, coordinator
        // escalates one phase early and the marker gets rewritten twice
        // (once here, once after the cold-restart re-auth completes).
        let cold_pending = false;
        // TODO(PR-C stage 3B): fingerprint tracking. Passing 0 means the
        // fingerprint tripwire never fires from stage 3 — only time-based
        // escalation is active until stage 3B lands.
        let fingerprint_streak: u32 = 0;
        let resume_token = self.pending_resume_token.take();
        let had_token = resume_token.is_some();

        let action = self.recovery.compute(
            &now_wall,
            now_mono,
            cold_pending,
            resume_token.clone(),
            fingerprint_streak,
        );
        // Log tick evaluations at debug so a running system doesn't
        // spam INFO with per-tick Sleep decisions.
        log::debug!(
            "recovery.tick_evaluated phase={} next_action={:?}",
            self.recovery.phase().as_str(),
            action,
        );
        let phase_before = self.recovery.phase();
        match self
            .recovery
            .apply(action, now_wall, now_mono, resume_token)
        {
            Ok(applied) => {
                use crate::state_machine::recovery::AppliedAction;
                match applied {
                    AppliedAction::NoChange | AppliedAction::Deferred => {
                        // Surface silently-consumed tokens: the operator
                        // tapped the ntfy link but the coordinator's
                        // current phase couldn't act on it. Without this
                        // log, the tap disappears with no forensic trail.
                        if had_token && phase_before != crate::state_machine::recovery::RecoveryPhase::GivenUp {
                            log::warn!(
                                "recovery.resume_token_discarded phase={} — \
                                 RESUME_RECONNECT taken but coordinator not in given_up",
                                phase_before.as_str(),
                            );
                        }
                    }
                    AppliedAction::EscalatedToBackoff => {
                        // apply() emits the phase_changed log line;
                        // nothing further to do here until stage 4/5
                        // wire per-phase throttling of the reconnect
                        // cadence.
                    }
                    AppliedAction::FiredGiveUpAlert => {
                        // Halt active reconnection: park the SM in
                        // WaitingForLaunch. Only the resume-token gate
                        // (RESUME_RECONNECT command → Aggressive) or
                        // IBCTL_RECOVERY_FORCE_RESET=1 restart can
                        // exit. Kills the JVM so it isn't hammering IB
                        // while the operator is asleep.
                        //
                        // Abort the dwell timer if any (Connected → GivenUp
                        // during dwell window). Also clear the dwell guard
                        // so the pending task is aborted before the state
                        // transition — the drain above cannot see this
                        // guard until the next tick.
                        self.dwell_guard = None;
                        if !matches!(
                            self.state,
                            State::WaitingForLaunch | State::Shutdown | State::Error(_)
                        ) {
                            log::error!(
                                "recovery.giveup_halt state={} — parking SM in \
                                 WaitingForLaunch (JVM will be killed)",
                                self.state,
                            );
                            let old = self.state.clone();
                            self.abort_client_id_task();
                            self.stop_socat();
                            if self.supervisor.is_running() {
                                if let Err(e) = self.supervisor.kill().await {
                                    log::error!(
                                        "recovery.giveup_halt kill failed: {}", e,
                                    );
                                }
                                match self.supervisor.wait().await {
                                    Ok(status) => log::info!(
                                        "JVM exited after giveup halt: {}", status,
                                    ),
                                    Err(e) => log::warn!(
                                        "JVM wait failed after giveup halt: {}", e,
                                    ),
                                }
                            }
                            let socket = &self.config.agent.socket_path.clone();
                            let _ = std::fs::remove_file(socket);
                            self.handler_registry.reset();
                            self.state = State::WaitingForLaunch;
                            self.record_transition(&old, &State::WaitingForLaunch);
                        }
                    }
                    AppliedAction::ResumedToAggressive => {
                        // Unblock: if we were parked in WaitingForLaunch
                        // by a prior GivenUp, transition to Init to
                        // resume the normal launch flow. Other states
                        // (Connected, in-flight reconnect) are left
                        // alone — the resume clears the coordinator's
                        // block flag, and the SM's own flow handles the
                        // rest.
                        log::info!(
                            "recovery.giveup_resumed prior_state={} — resuming SM",
                            self.state,
                        );
                        if matches!(self.state, State::WaitingForLaunch) {
                            let old = self.state.clone();
                            self.state = State::Init;
                            self.record_transition(&old, &State::Init);
                        }
                    }
                }
            }
            Err(e) => log::error!("recovery.apply failed: {}", e),
        }
    }

    /// Abort the background client ID refresh task if running.
    fn abort_client_id_task(&mut self) {
        if let Some(handle) = self.client_id_task.take() {
            handle.abort();
        }
        self.client_id_rx = None;
    }

    /// Start the TCP probe task — pings Gateway's API port every
    /// `api_port_probe_interval_secs` seconds. Sets the shared
    /// `api_port_probe_failed` AtomicBool to true after
    /// `api_port_probe_fails_before_revoke` consecutive failures.
    ///
    /// No-op when interval is 0 (disabled).
    /// Safe to call when a task is already running — cancels the old one first.
    fn start_api_port_probe(&mut self) {
        self.stop_api_port_probe();
        let interval = self.config.timing.api_port_probe_interval_secs;
        if interval == 0 {
            return;
        }
        let threshold = self.config.timing.api_port_probe_fails_before_revoke;
        // Choose the API port based on trading mode.
        let api_port = match self.config.auth.trading_mode {
            crate::config::TradingMode::Paper => self.config.gateway.paper_api_port,
            // Live and Both use the live port (each dual-mode process is
            // spawned per-mode with its own state machine).
            _ => self.config.gateway.live_api_port,
        };
        let failed_flag = self.api_port_probe_failed.clone();
        failed_flag.store(false, std::sync::atomic::Ordering::Relaxed);
        let handle = tokio::spawn(async move {
            let addr = format!("127.0.0.1:{}", api_port);
            let mut consecutive_failures: u32 = 0;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                let connect_result = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await;
                let ok = matches!(connect_result, Ok(Ok(_)));
                if ok {
                    if consecutive_failures > 0 {
                        log::debug!(
                            "API port probe recovered after {} failures (addr={})",
                            consecutive_failures, addr
                        );
                    }
                    consecutive_failures = 0;
                } else {
                    consecutive_failures = consecutive_failures.saturating_add(1);
                    log::debug!(
                        "API port probe failed ({}/{}): addr={}",
                        consecutive_failures, threshold, addr
                    );
                    if consecutive_failures >= threshold {
                        log::warn!(
                            "API port probe: {} consecutive failures on {} — signaling revocation",
                            consecutive_failures, addr
                        );
                        failed_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                        // Once we've signaled, don't spam — keep ticking but the
                        // state machine will transition away shortly and cancel us.
                    }
                }
            }
        });
        self.api_port_probe_task = Some(handle);
    }

    /// Cancel the TCP probe task, if running.
    fn stop_api_port_probe(&mut self) {
        if let Some(handle) = self.api_port_probe_task.take() {
            handle.abort();
        }
        self.api_port_probe_failed
            .store(false, std::sync::atomic::Ordering::Relaxed);
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
            State::Connected => self.do_connected().await,
            State::ReconnectingSession => self.do_reconnecting_session().await,
            State::Restarting => self.do_restart().await,
            State::WaitingForIB => self.do_waiting_for_ib().await,
            State::WaitingForHitl2fa => self.do_waiting_for_hitl_2fa().await,
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
                                    if let Err(e) = self.agent_client.click_button(win.id, "OK").await {
                                        log::debug!("click OK on device selection failed: {}", e);
                                    }
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
            // If the configured action is exit (legacy), honor that.
            if !self.config.twofa.relogin_after_timeout
                && self.config.twofa.timeout_action == crate::config::TwoFaTimeoutAction::Exit
            {
                log::error!("2FA timed out after {}s — shutting down", timeout_secs);
                return Ok(State::Shutdown);
            }

            // HITL backoff policy
            self.consecutive_2fa_timeouts = self.consecutive_2fa_timeouts.saturating_add(1);
            let backoff = &self.config.twofa.backoff;
            let next = match backoff.on_timeout {
                crate::config::TwoFaOnTimeout::RestartForever => {
                    log::warn!(
                        "2FA timed out after {}s — restarting (legacy mode, attempt {})",
                        timeout_secs, self.consecutive_2fa_timeouts
                    );
                    State::Restarting
                }
                crate::config::TwoFaOnTimeout::HitlImmediately => {
                    log::warn!(
                        "2FA timed out after {}s — entering HITL immediately (hitl_immediately)",
                        timeout_secs
                    );
                    State::WaitingForHitl2fa
                }
                crate::config::TwoFaOnTimeout::RestartThenHitl => {
                    if self.consecutive_2fa_timeouts >= backoff.max_immediate_attempts {
                        log::warn!(
                            "2FA timed out after {}s — attempts exhausted ({}/{}), entering HITL",
                            timeout_secs,
                            self.consecutive_2fa_timeouts,
                            backoff.max_immediate_attempts
                        );
                        State::WaitingForHitl2fa
                    } else {
                        log::warn!(
                            "2FA timed out after {}s — restarting (attempt {}/{})",
                            timeout_secs,
                            self.consecutive_2fa_timeouts,
                            backoff.max_immediate_attempts
                        );
                        State::Restarting
                    }
                }
            };
            return Ok(next);
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
            Ok(report) => {
                log::info!("API configuration complete");
                self.stats.precaution_labels_not_found = self
                    .stats
                    .precaution_labels_not_found
                    .saturating_add(report.precaution_labels_not_found);
                self.stats.read_only_api_label_not_found = self
                    .stats
                    .read_only_api_label_not_found
                    .saturating_add(report.read_only_api_label_not_found);
                self.config_retries = 0;
                // Config success implies UI is responsive (we just drove the
                // Configure → Settings dialog) and JVM is alive. Ongoing
                // verification is the job of the revocation bus in
                // do_connected, not a gate here.
                log::info!("Entered Connected via ConfiguringApi (post-config success)");
                Ok(State::Connected)
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

        // Spawn client-refresh task if not already running.
        // Stored in struct fields so it survives cancellation by tokio::select!
        //
        // Pulls truth from inside the JVM via the agent's `/clients` endpoint:
        //   * `api_client_row_status` — connection-status table's API Client
        //     row reflects the JVM's aggregate notion of "any client live".
        //   * `tabs` — JTabbedPane tab titles ("Client 1"…). Gateway keeps
        //     these as a historical log view, so they persist after a client
        //     disconnects.
        //
        // Derivation: if the row says "disconnected" or the row is absent
        // (no client has ever connected this session), report empty. If the
        // row says "connected", report the tab titles — the JVM is telling
        // us ≥1 client is live, and the tab list is the best identity signal
        // available without bytecode-instrumenting Gateway. Per-client
        // disconnect tracking when count > 1 requires deeper introspection
        // and is left for a follow-up.
        if self.client_id_task.is_none() {
            let (ids_tx, ids_rx) = tokio::sync::watch::channel(Vec::<String>::new());
            let socket_path = self.config.agent.socket_path.clone();
            const MAX_CLIENT_IDS: usize = 256;
            let handle = tokio::spawn(async move {
                loop {
                    let client = crate::agent_client::AgentClient::new(&socket_path);
                    let mut ids: Vec<String> = Vec::new();
                    if let Ok(windows) = client.list_windows().await {
                        // Find the main Gateway window: title contains
                        // "ib gateway"/"ibkr gateway" and is NOT a
                        // configuration / dialog window.
                        let main = windows.iter().find(|w| {
                            let t = w.title.to_lowercase();
                            (t.contains("ib gateway") || t.contains("ibkr gateway"))
                                && !t.contains("configuration")
                        });
                        if let Some(main) = main {
                            if let Ok(view) = client.list_clients(main.id).await {
                                ids = derive_client_ids(&view, MAX_CLIENT_IDS);
                            }
                        }
                    }
                    let _ = ids_tx.send(ids);
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
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

            // stop_socat / abort_client_id_task / connected_window_class /
            // handler_registry.reset are handled centrally in apply_transition
            // when we leave Connected — see the curr_is_connected branch.
            self.warm_restart_pending = autorestart_hash;
            let _ = std::fs::remove_file(&self.config.agent.socket_path);
            // Record & fire — zero debounce ⇒ matures immediately.
            let src = revocation::RevocationSource::JvmDied;
            let next = src.next_state();
            if self.revocation.observe(src).is_some() {
                log::warn!("proof revoked source=jvm_died next={}", next);
            }
            return Ok(next);
        }

        // --- API port listener ---
        // Ground-truth TCP probe to Gateway's listener. The probe task tracks
        // consecutive failures independently; we just consume the signal here.
        if self.api_port_probe_failed.load(std::sync::atomic::Ordering::Relaxed) {
            let src = revocation::RevocationSource::ApiPortListenerLost;
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!(
                    "proof revoked source=api_port_listener_lost next={}",
                    next
                );
                // Clear the flag so if we come back to Connected later we start fresh.
                self.api_port_probe_failed
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Ok(next);
            }
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
        // Cleanup is centralized in apply_transition — every revocation
        // branch below just logs and returns the next state.
        if self.observation.has_relogin_dialog() {
            let src = revocation::RevocationSource::ReloginDialog;
            if self.revocation.observe(src.clone()).is_some() {
                let next = src.next_state();
                log::warn!("proof revoked source=relogin_dialog next={}", next);
                return Ok(next);
            }
        } else {
            self.revocation.clear(revocation::RevocationTag::ReloginDialog);
        }

        // --- Session conflict dialog (immediate) ---
        if self.observation.has_session_conflict() {
            let src = revocation::RevocationSource::SessionConflict;
            if self.revocation.observe(src.clone()).is_some() {
                let next = src.next_state();
                log::warn!("proof revoked source=session_conflict next={}", next);
                return Ok(next);
            }
        } else {
            self.revocation.clear(revocation::RevocationTag::SessionConflict);
        }

        // --- Fetch window list once per tick ---
        // Previously this HTTP round-trip happened twice: once in the error-
        // dialog OK-click loop, once in the active probe. That doubled tick
        // latency AND created a race window where the two fetches could see
        // different Gateway state. Fetch once, reuse everywhere.
        let windows_snapshot = self.agent_client.list_windows().await.ok();
        let main_id: Option<u64> = self.observation.main_gateway_window().map(|m| m.id);

        // --- Error dialog revocation: deliberately not wired ---
        // The old title-scan predicate matched any non-main "IBKR Gateway"
        // titled dialog and treated it as a session-loss signal. That
        // conflates "unexpected dialog exists" with "Gateway session has
        // failed" — they are different things. Benign cases we've hit
        // in practice: "Restart in progress" during Gateway's own warm
        // restart, the BBO-warning post-config notification ("Note: You
        // can enable precaution…"), and the generic "IBKR Gateway" modal
        // from GatewayNotificationHandler's view. Every one of those
        // produced a false revocation that forced an unneeded full
        // re-auth cycle (and a second IB Key prompt for the operator).
        //
        // Canonical session-loss signals live in two other sources:
        //   * DisconnectedLabelStable — "API Server: disconnected" label
        //     on the Connection Status panel (Gateway's own truth).
        //   * LoginFormVisible — main window reverted to the login form.
        //
        // Specific dialog handlers (GatewayNotificationHandler,
        // PaperWarningHandler, AutoRestartConfirmationDialog, …) dismiss
        // known benign dialogs via the handler_registry dispatch later
        // in this tick. Unknown unexpected dialogs are informational via
        // the AgentEvent::ErrorDialog stream; they do NOT revoke.
        //
        // Keep the clear() call so any in-flight debounce from earlier
        // versions drops cleanly on upgrade.
        self.revocation.clear(revocation::RevocationTag::ErrorDialog);

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
                    // Benign morphs (e.g. `ibgateway.ay` → `ibgateway.az`) happen
                    // several times per day during normal Gateway operation.
                    // Keep it at debug so production logs don't drown in them;
                    // a morph paired with a login form is caught separately by
                    // the LoginFormVisible revocation source.
                    log::debug!(
                        "Window class changed {} → {} (no login form — benign UI update)",
                        expected_class, main.class
                    );
                    self.connected_window_class = Some(main.class.clone());
                }
            }
        }

        // --- Active probe: dump_components on main window ---
        // The dump_components loop is the expensive part of the tick — one
        // HTTP round-trip per matching window, each returning the full UI
        // tree. Gate it so it only runs when:
        //   1. a revocation source is already pending (debounce must tick),
        //   2. or the observation cache shows a login button / error dialog
        //      (event-driven signal suggesting we should look),
        //   3. or periodically (3s out of every 30s window) as a fallback
        //      so that label-only disconnects — where Gateway updates the
        //      "API Server: connected" label to "disconnected" without any
        //      event firing — are eventually detected within 30s.
        //
        // In steady healthy state (no dialogs, no login-button, no pending
        // debounce) this skips ~90% of probes except the periodic fallback.
        let cache_suggests_probe = observed_login_button
            || self.observation.windows.iter().any(|w| {
                let t = w.title.to_lowercase();
                (t.contains("ibkr gateway") || t.contains("ib gateway"))
                    && !t.contains("configuration")
                    && Some(w.id) != main_id
            });
        let periodic_fallback =
            self.state_entered_at.elapsed().as_secs() % 30 < 3;
        let probe_needed = self.revocation.any_pending()
            || cache_suggests_probe
            || periodic_fallback;

        let mut probe_login_form = false;
        let mut probe_disconnected_label = false;
        let mut probe_twofa = false;
        if let Some(ref windows) = windows_snapshot {
            if probe_needed {
                for w in windows {
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
            }

            // Reconciliation: dispatch handlers for any unprocessed windows.
            // Preserves the existing behavior of letting dialog handlers
            // auto-dismiss popups, etc. Runs every tick regardless of
            // probe_needed because handlers are cheap and this is our
            // popup-auto-dismiss path during Connected.
            for win in windows {
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
            let src = revocation::RevocationSource::LoginFormVisible;
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!("proof revoked source=login_form_visible next={}", next);
                return Ok(next);
            }
        } else {
            self.revocation.clear(revocation::RevocationTag::LoginFormVisible);
        }

        // --- Disconnected label revocation (2s debounce) ---
        if probe_disconnected_label {
            let src = revocation::RevocationSource::DisconnectedLabelStable;
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!("proof revoked source=disconnected_label next={}", next);
                return Ok(next);
            }
        } else {
            self.revocation.clear(revocation::RevocationTag::DisconnectedLabelStable);
        }

        // Sync client IDs from background task (lock-free watch channel).
        // Trust the kernel-derived count; empty is a valid steady-state
        // value (zero connected clients). The previous version skipped
        // empty updates as a "transient zero" filter, which combined with
        // tab-title polling to leave the cache stale forever.
        if let Some(ref mut ids_rx) = self.client_id_rx {
            if ids_rx.has_changed().unwrap_or(false) {
                self.cached_client_ids = ids_rx.borrow_and_update().clone();
            }
        }

        // Counter reset under stable policy: only reset after Connected has been
        // sustained for stable_secs. Prevents flapping sessions from "laundering"
        // the failure counter. any_reach resets immediately in apply_transition.
        if matches!(
            self.config.twofa.backoff.counter_reset,
            crate::config::CounterResetScope::Stable
        ) && self.consecutive_2fa_timeouts > 0
        {
            if let Some(connected_since) = self.connected_continuously_since {
                let stable_threshold = std::time::Duration::from_secs(
                    self.config.twofa.backoff.stable_secs,
                );
                if connected_since.elapsed() >= stable_threshold {
                    log::info!(
                        "Connected stable for {}s — resetting 2FA attempt counter (was {})",
                        self.config.twofa.backoff.stable_secs,
                        self.consecutive_2fa_timeouts,
                    );
                    self.consecutive_2fa_timeouts = 0;
                }
            }
        }

        // Signal/command/cold-restart/event handling is done by the outer
        // tokio::select! in run(). Events provide instant dialog detection.
        // This sleep is now just a reconciliation tick — events handle the fast path.

        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        // Stay-Connected self-return. The revocation bus decides when to
        // demote; until it does, keep returning the same state.
        Ok(State::Connected)
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
                        if let Err(e) = self.agent_client.click_button(w.id, "Cancel").await {
                            log::debug!("click Cancel on re-login dialog failed: {}", e);
                        }
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
                    log::info!("RE-LOGIN: Gateway authenticated (positive confirmation) → Connected");
                    self.relogin_attempts = 0;
                    return Ok(State::Connected);
                }

                // Inconclusive — stay in ReconnectingSession (retry next tick)
                log::debug!("RE-LOGIN verification inconclusive — no gateway window confirmed, retrying");
            }

            if let Some(d) = dialog {
                log::info!("Clicking Re-login (attempt {}/{})", self.relogin_attempts, max);
                if let Err(e) = self.agent_client.click_button(d.id, "Re-login").await {
                    log::debug!("click Re-login failed: {}", e);
                }
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
    ///
    /// Warm restart fast-path: when we arrived here via Gateway's own clean
    /// shutdown + autorestart token (`warm_restart_pending = Some(hash)`),
    /// skip the `restart_delay_secs` backoff entirely. That delay exists to
    /// give IBKR's backend time to forget a crashed/bad-auth session before
    /// we hammer it with a reconnect — the backend already knows a planned
    /// warm restart ended cleanly, so waiting 90s here is pure outage time.
    /// Observed: a full warm-restart cycle takes ~20s without the delay vs
    /// ~110s with it.
    async fn do_restart(&mut self) -> Result<State, StateMachineError> {
        let delay = self.config.timing.restart_delay_secs;
        let is_warm_restart = self.warm_restart_pending.is_some();

        // Phase 1: delay before restart (dashboard stays responsive via outer loop)
        // Skipped for warm restart — planned Gateway exit, no backend backoff needed.
        if !is_warm_restart && delay > 0 && self.state_entered_at.elapsed().as_secs() < delay {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            return Ok(State::Restarting);
        }

        // Phase 2: kill and restart
        if is_warm_restart {
            log::info!("Warm restart: skipping restart_delay ({}s) — Gateway already exited cleanly", delay);
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

    /// Human-in-the-loop 2FA wait. Exits on:
    ///   - HITL_RESUME command (consumed by command handler → sets a flag)
    ///   - scheduled auto-retry (intervals_minutes)
    ///   - cold restart preempting (if cold_restart_preempts_hitl = true)
    ///
    /// On entry (first tick): logs arrival, ntfy-send attempt (if ntfy strategy),
    /// schedules the first auto-retry deadline.
    async fn do_waiting_for_hitl_2fa(&mut self) -> Result<State, StateMachineError> {
        let backoff = self.config.twofa.backoff.clone();

        // First tick of this HITL entry — initialize bookkeeping.
        if self.hitl_entered_at.is_none() {
            self.hitl_entered_at = Some(Instant::now());
            self.hitl_intervals_index = 0;
            self.hitl_ntfy_attempts = 0;
            self.hitl_ntfy_sent = false;
            self.hitl_login_form_observation_ticks = 0;
            self.hitl_connected_observation_ticks = 0;
            // Schedule the first auto-retry deadline if strategy involves a timer.
            self.hitl_next_retry_at = Self::compute_next_hitl_deadline(
                &backoff.strategy,
                &backoff.intervals_minutes,
                0,
            );
            log::warn!(
                "HITL 2FA entered: strategy={:?} next_retry_at={:?} callback_valid_hours={} attempts_exhausted={}",
                backoff.strategy,
                self.hitl_next_retry_at.map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
                backoff.callback_valid_hours,
                self.consecutive_2fa_timeouts,
            );
        }

        // Cold restart preemption.
        if backoff.cold_restart_preempts_hitl {
            // Only drain the cold-restart channel when we're going to act on it.
            // Under preempt=false, a cold restart signal sits in the channel and
            // will be consumed by the main event loop once we exit HITL.
            if let Ok(reason) = self.cold_restart_rx.try_recv() {
                log::warn!(
                    "HITL preempted by cold restart ({:?}) — exiting to Restarting",
                    reason
                );
                return Ok(State::Restarting);
            }
        }

        // World-state truth check (debounced over HITL_DEMOTE_TICK_THRESHOLD
        // consecutive ticks to bridge the JVM's brief "no dialog yet" window
        // during a real 2FA timeout). If the 2FA dialog is gone AND the login
        // form is visible, IBKR has timed out the 2FA prompt on their side
        // and dropped the JVM back to login. Don't wait forever — demote so
        // credentials can be re-submitted via the normal Authenticating path.
        // The existing consecutive_2fa_timeouts counter still gates how
        // aggressively the system re-cycles.
        if self.observation.has_login_form() && !self.observation.has_2fa_dialog() {
            self.hitl_login_form_observation_ticks =
                self.hitl_login_form_observation_ticks.saturating_add(1);
            if self.hitl_login_form_observation_ticks >= HITL_DEMOTE_TICK_THRESHOLD {
                log::warn!(
                    "HITL stale: login form visible / no 2FA dialog for {} ticks — \
                     demoting to WaitingForLogin (consecutive_2fa_timeouts={})",
                    self.hitl_login_form_observation_ticks,
                    self.consecutive_2fa_timeouts,
                );
                return Ok(State::WaitingForLogin);
            }
        } else {
            self.hitl_login_form_observation_ticks = 0;
        }

        // World-state truth check (positive direction, debounced).
        // If the main Gateway window is present and its connection-status
        // panel shows "API Server: connected" — with no 2FA dialog and no
        // login form — then the user's 2FA push approval arrived in flight
        // during the attempt-3 timeout race, the JVM completed auth, and
        // the Gateway has reached steady connected state. Don't wait for
        // the next retry slot; transition to WaitingForApiReady so the
        // standard handler completes the post-auth path (API config detect
        // or skip, then Connected setup including socat start).
        if !self.observation.has_2fa_dialog()
            && !self.observation.has_login_form()
        {
            let main_window_id = self.observation.main_gateway_window().map(|w| w.id);

            if let Some(window_id) = main_window_id {
                // Probe the connection-status panel labels for "API Server:
                // connected" using the existing predicate that the Connected-
                // state liveness check uses (components_indicate_connected).
                let probe_says_connected = match self
                    .agent_client
                    .dump_components(crate::types::WindowId(window_id))
                    .await
                {
                    Ok(components) => components_indicate_connected(&components),
                    Err(e) => {
                        log::debug!(
                            "HITL positive probe: dump_components failed: {} — \
                             treating as not-connected",
                            e
                        );
                        false
                    }
                };

                if probe_says_connected {
                    self.hitl_connected_observation_ticks =
                        self.hitl_connected_observation_ticks.saturating_add(1);
                    if self.hitl_connected_observation_ticks >= HITL_DEMOTE_TICK_THRESHOLD {
                        log::warn!(
                            "HITL stale: JVM reached \"API Server: connected\" \
                             for {} ticks — transitioning to WaitingForApiReady \
                             (consecutive_2fa_timeouts={})",
                            self.hitl_connected_observation_ticks,
                            self.consecutive_2fa_timeouts,
                        );
                        return Ok(State::WaitingForApiReady);
                    }
                } else {
                    self.hitl_connected_observation_ticks = 0;
                }
            } else {
                self.hitl_connected_observation_ticks = 0;
            }
        } else {
            self.hitl_connected_observation_ticks = 0;
        }

        // Scheduled auto-retry deadline check.
        if let Some(deadline) = self.hitl_next_retry_at {
            if Instant::now() >= deadline {
                self.hitl_intervals_index = self
                    .hitl_intervals_index
                    .saturating_add(1);
                self.hitl_next_retry_at = Self::compute_next_hitl_deadline(
                    &backoff.strategy,
                    &backoff.intervals_minutes,
                    self.hitl_intervals_index,
                );
                log::warn!(
                    "HITL auto-retry firing (interval index {}), next retry scheduled in {:?}s",
                    self.hitl_intervals_index,
                    self.hitl_next_retry_at
                        .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
                );
                return Ok(State::Restarting);
            }
        }

        // Note: HITL_RESUME dispatch happens in the command handler (mod.rs:
        // process_commands) which sets `self.state = State::Restarting`
        // directly and the main loop picks it up next tick.

        // Sleep briefly then come back — we want to remain responsive to
        // commands, cold restart, and the periodic deadline.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        self.process_queries().await;
        Ok(State::WaitingForHitl2fa)
    }

    /// Compute the next auto-retry absolute deadline given the strategy +
    /// intervals list + current index. Returns `None` when the strategy does
    /// not include a timer, or when intervals is empty.
    fn compute_next_hitl_deadline(
        strategy: &crate::config::HitlStrategy,
        intervals: &[u32],
        index: usize,
    ) -> Option<Instant> {
        if !matches!(
            strategy,
            crate::config::HitlStrategy::Periodic | crate::config::HitlStrategy::Both
        ) {
            return None;
        }
        if intervals.is_empty() {
            return None;
        }
        // Traverse the list, then hold at the last element.
        let minutes = if index < intervals.len() {
            intervals[index]
        } else {
            intervals[intervals.len() - 1]
        };
        Some(Instant::now() + std::time::Duration::from_secs(u64::from(minutes) * 60))
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
            Command::HitlResume => {
                if matches!(self.state, State::WaitingForHitl2fa) {
                    log::warn!("HITL_RESUME received — transitioning to Restarting");
                    let old = self.state.clone();
                    self.state = State::Restarting;
                    self.record_transition(&old, &State::Restarting);
                } else {
                    log::warn!(
                        "HITL_RESUME ignored — not in WaitingForHitl2fa (current={})",
                        self.state
                    );
                }
                Ok(())
            }
            Command::ResumeReconnect(ref token_str) => {
                // PR-C stage 3: park the resume token; the recovery tick
                // in the main loop will pass it through
                // `RecoveryCoordinator::compute` → `::apply` on the next
                // iteration. Stage 3 accepts any non-empty token string
                // (parser rejects empty in `command_server::parse_command`);
                // stage 5 wires HMAC verification against the dashboard-
                // signed URL.
                //
                // The operator-supplied token STRING is threaded into
                // `ResumeToken.nonce_material` so `hash_token` incorporates
                // it — without this, every `RESUME_RECONNECT <anything>`
                // in the same wall-second collapses to the same hash and
                // the single-use nonce invariant reduces to a per-second
                // rate limit. See `test_resume_token_hash_incorporates_nonce_material`.
                //
                // Reject the token outright when the coordinator is not
                // in a resumable state — accepting it here would silently
                // consume the operator's tap with no visible state change.
                let phase = self.recovery.phase();
                let blocked = self.recovery.is_blocked_awaiting_resume();
                if phase != crate::state_machine::recovery::RecoveryPhase::GivenUp && !blocked {
                    log::warn!(
                        "RESUME_RECONNECT ignored — coordinator not in given_up \
                         (phase={}, blocked_awaiting_resume={})",
                        phase.as_str(),
                        blocked,
                    );
                    return Ok(());
                }
                log::info!(
                    "RESUME_RECONNECT received — parking token for next recovery tick"
                );
                let token = crate::state_machine::recovery::ResumeToken {
                    mode: self.recovery_mode_tag.clone(),
                    minted_at: jiff::Timestamp::now(),
                    nonce_material: token_str.clone(),
                };
                self.pending_resume_token = Some(token);
                Ok(())
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
                    // SETRESTART only touches the auto-restart-time field —
                    // it doesn't loop precaution labels, so the report's
                    // counters are always zero here. Log the outcome and move on.
                    Ok(_report) => log::info!("SETRESTART: auto-restart time set to {}", time_str),
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
/// Derive the live API client ID list from the agent's `/clients` response.
///
/// The connection-status panel's API Client row reports its status as
/// either `"disconnected"` (no clients live) or `"N connected"` (N is the
/// live count). On a fresh session before any client has connected, the
/// row is absent and the agent returns `null`.
///
/// Rules:
///   * Status tokenizes to include the word `"connected"` exactly (not
///     "disconnected" — which would falsely match a substring search):
///     - If the preceding token parses as an integer N, take the first
///       N tab titles. The status string IS the count; tab order
///       approximates active-first.
///     - Otherwise (just `"connected"` with no count), take all tab
///       titles — the JVM told us ≥1 is live, the tab list is the only
///       per-client identity signal we have.
///   * Status missing, null, `"disconnected"`, or anything else → empty.
///
/// Caps results at `max` to guard against pathological responses.
fn derive_client_ids(view: &serde_json::Value, max: usize) -> Vec<String> {
    let status = view
        .get("api_client_row_status")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let lower = status.to_lowercase();
    // Tokenize and look for "connected" as an exact token — guards
    // against substring-matching against "disconnected".
    let tokens: Vec<&str> = lower.split_whitespace().collect();
    let connected_idx = match tokens.iter().position(|t| *t == "connected") {
        Some(i) => i,
        None => return Vec::new(),
    };
    // Preceding token, if a number, is the live count. Otherwise fall
    // back to the tab list length (we know ≥1, tabs is best-effort).
    let count_hint = if connected_idx > 0 {
        tokens[connected_idx - 1].parse::<usize>().ok()
    } else {
        None
    };
    let tabs = match view.get("tabs").and_then(|t| t.as_array()) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let target = count_hint.unwrap_or(tabs.len()).min(max);
    if target == 0 {
        return Vec::new();
    }
    if count_hint.is_none() && tabs.len() >= max {
        log::warn!("derive_client_ids: hit {} entries, capping", max);
    }
    tabs.iter()
        .take(target)
        .filter_map(|tab| tab.get("title").and_then(|t| t.as_str()).map(String::from))
        .collect()
}

/// Returns true if the API Server row of the Gateway connection-status table
/// shows status "disconnected". The dump is row-major: each table row
/// contributes its purpose cell followed by its status cell, so the API
/// Server row's status sits at index+1 of the "api server" purpose label.
///
/// We only consider the API Server row, not the API Client row. They are
/// orthogonal: API Server is the Gateway↔broker connection (what we care
/// about); API Client tracks whether an external program has hooked into
/// the Gateway's local socket (normal to be disconnected right after login).
fn components_indicate_disconnected(components: &serde_json::Value) -> bool {
    api_server_row_status(components)
        .is_some_and(|s| s == "disconnected")
}

/// Returns true if the API Server row's status shows "connected".
/// Used by WaitingForApiReady to positively confirm the Gateway is ready.
fn components_indicate_connected(components: &serde_json::Value) -> bool {
    api_server_row_status(components)
        .is_some_and(|s| s == "connected")
}

/// Returns the lowercased status label paired with the "API Server" purpose
/// label in a row-major JTable dump, if any.
fn api_server_row_status(components: &serde_json::Value) -> Option<String> {
    let labels = components.get("labels").and_then(|l| l.as_array())?;
    let texts: Vec<String> = labels
        .iter()
        .filter_map(|l| l.as_str())
        .map(|s| s.to_lowercase())
        .collect();
    for (i, text) in texts.iter().enumerate() {
        if text.contains("api server") {
            if let Some(status) = texts.get(i + 1) {
                return Some(status.clone());
            }
        }
    }
    None
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
    use crate::state_machine::types::ColdRestartSkipRecord;
    use crate::types::{ColdRestartSignal, ColdRestartSkipReason, Command, Signal};

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
        cold_tx.send(ColdRestartSignal::Fire).await.unwrap();

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
    // on our build host during the incident. Regression guards:
    //
    //   1. MUST detect "API Server: disconnected" from labels alone
    //   2. MUST NOT false-positive when Gateway is in a benign no-connection-status state
    //   3. MUST detect login form via non-empty textfields
    //   4. MUST confirm "connected" when labels say so

    /// Real production dump of the main Gateway window in the disconnected state
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

    /// Real dump captured live from the running paper Gateway once the
    /// connection-status JTable fully populates after login. The broker
    /// connection is solidly up (row 1: API Server / connected) but no
    /// external API client has connected yet (row 4: API Client / disconnected).
    /// This is the *normal* steady state on a fresh restart. The dump is row-
    /// major: row N's status sits at index 2N+1, paired with the purpose at
    /// index 2N. The old flat-OR predicate falsely fired on this dump because
    /// it saw both "Interactive Brokers API Server" and "disconnected" labels
    /// anywhere in the window — that caused a ~10s reconfiguration loop.
    const FIXTURE_API_SERVER_UP_API_CLIENT_DOWN: &str = r#"{
        "buttons": [],
        "textfields": [],
        "trees": [],
        "labels": ["Purpose","Status",
                   "Interactive Brokers API Server","connected",
                   "Market Data Farm","ON: usfarm",
                   "Historical Data Farm","ON: ushmds",
                   "API Client","disconnected",
                   "IBKR GATEWAY [PAPER]"],
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
            "must detect 'API Server: disconnected' from real production dump"
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

    // ─── client-list derivation ──────────────────────────────────────────

    #[test]
    fn test_derive_clients_empty_when_row_status_missing() {
        // Main window has never seen a client this session: the connection
        // status panel has no "API Client" row. Agent reports null. Tabs may
        // also be empty; result must be empty regardless.
        let view = serde_json::json!({
            "api_client_row_status": serde_json::Value::Null,
            "tabs": [],
        });
        assert!(derive_client_ids(&view, 256).is_empty());
    }

    #[test]
    fn test_derive_clients_empty_when_row_status_disconnected() {
        // Clients have connected at some point (tabs persist) but no client
        // is currently connected — the API Client row's aggregate status is
        // "disconnected". Tabs are historical; must not be reported as live.
        // Note: "disconnected" contains "connected" as a substring; this
        // case guards against a naïve substring-match.
        let view = serde_json::json!({
            "api_client_row_status": "disconnected",
            "tabs": [
                {"index": 0, "title": "Client 1", "selected": false},
                {"index": 1, "title": "Client 50", "selected": false},
            ],
        });
        assert!(derive_client_ids(&view, 256).is_empty());
    }

    #[test]
    fn test_derive_clients_n_connected_takes_first_n_tabs() {
        // The real Gateway status string when 3 clients are live: "3 connected".
        // Status carries the count; tabs may have more entries (historical),
        // but we trust the parsed count. Take the first N tabs in their
        // natural JTabbedPane order (which approximates active-first).
        let view = serde_json::json!({
            "api_client_row_status": "3 connected",
            "tabs": [
                {"index": 0, "title": "Client 2",  "selected": true},
                {"index": 1, "title": "Client 1",  "selected": false},
                {"index": 2, "title": "Client 50", "selected": false},
                {"index": 3, "title": "Client 5",  "selected": false},
                {"index": 4, "title": "Client 7",  "selected": false},
            ],
        });
        assert_eq!(
            derive_client_ids(&view, 256),
            vec!["Client 2", "Client 1", "Client 50"]
        );
    }

    #[test]
    fn test_derive_clients_zero_connected_is_empty() {
        let view = serde_json::json!({
            "api_client_row_status": "0 connected",
            "tabs": [{"index": 0, "title": "Client 1", "selected": false}],
        });
        assert!(derive_client_ids(&view, 256).is_empty());
    }

    #[test]
    fn test_derive_clients_plain_connected_falls_back_to_tabs_len() {
        // Tolerates the no-count form just in case Gateway ever reports it.
        let view = serde_json::json!({
            "api_client_row_status": "connected",
            "tabs": [
                {"index": 0, "title": "Client 1", "selected": false},
                {"index": 1, "title": "Client 50", "selected": false},
            ],
        });
        assert_eq!(
            derive_client_ids(&view, 256),
            vec!["Client 1", "Client 50"]
        );
    }

    #[test]
    fn test_derive_clients_status_match_is_case_insensitive() {
        let view = serde_json::json!({
            "api_client_row_status": "1 CONNECTED",
            "tabs": [{"index": 0, "title": "Client 1", "selected": false}],
        });
        assert_eq!(derive_client_ids(&view, 256), vec!["Client 1"]);
    }

    #[test]
    fn test_derive_clients_count_exceeds_tabs_takes_what_we_have() {
        // Defensive: if the agent's row count says 5 but only 3 tabs exist
        // (some transient inconsistency), return the 3 we know about.
        let view = serde_json::json!({
            "api_client_row_status": "5 connected",
            "tabs": [
                {"index": 0, "title": "Client 1", "selected": false},
                {"index": 1, "title": "Client 2", "selected": false},
                {"index": 2, "title": "Client 3", "selected": false},
            ],
        });
        assert_eq!(derive_client_ids(&view, 256).len(), 3);
    }

    #[test]
    fn test_derive_clients_caps_at_max() {
        let tabs: Vec<serde_json::Value> = (0..10)
            .map(|i| serde_json::json!({"index": i, "title": format!("Client {}", i), "selected": false}))
            .collect();
        let view = serde_json::json!({
            "api_client_row_status": "connected",
            "tabs": tabs,
        });
        assert_eq!(derive_client_ids(&view, 4).len(), 4);
    }

    #[test]
    fn test_derive_clients_empty_when_tabs_missing() {
        // Row says connected but agent returned no tabs array (shouldn't
        // happen in practice, but the helper must not panic).
        let view = serde_json::json!({"api_client_row_status": "connected"});
        assert!(derive_client_ids(&view, 256).is_empty());
    }

    #[test]
    fn test_disconnected_predicate_ignores_unrelated_rows() {
        // Live paper-mode dump: API Server row is connected, API Client row
        // is disconnected. The disconnect signal must come from the API
        // Server row only; the API Client row reports whether an external
        // program has hooked into the Gateway's API socket, which is
        // unrelated to broker connectivity.
        let components = parse(FIXTURE_API_SERVER_UP_API_CLIENT_DOWN);
        assert!(
            !components_indicate_disconnected(&components),
            "disconnected predicate must row-pair with the API Server row, \
             not match any 'disconnected' label anywhere in the window"
        );
    }

    #[test]
    fn test_connected_predicate_row_pairs_with_api_server() {
        // Same dump positively confirms Connected because the API Server
        // row's status cell is "connected".
        let components = parse(FIXTURE_API_SERVER_UP_API_CLIENT_DOWN);
        assert!(
            components_indicate_connected(&components),
            "connected predicate must positively confirm via API Server row \
             pairing, not by scanning for any 'connected' label"
        );
    }

    #[test]
    fn test_disconnected_predicate_ignores_disconnected_in_purpose_column() {
        // Defensive: if the dump order ever swapped so "disconnected" appears
        // in the purpose column (left of "API Server"), the row-pairing
        // predicate must NOT fire on it.
        let components = serde_json::json!({
            "labels": ["disconnected", "API Server", "connected"]
        });
        assert!(
            !components_indicate_disconnected(&components),
            "disconnected predicate must only consider the label immediately \
             AFTER 'api server', not before"
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
    use std::str::FromStr;
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
            agent_events: {
                // Dummy receiver — drop the sender so the channel is closed
                // from the start. The state machine's select! loop treats a
                // closed receiver as "no events" via pattern match.
                let (_tx, rx) = mpsc::channel(1);
                rx
            },
        };

        let (snapshot_tx, _snapshot_rx) = watch::channel(Arc::new(QuerySnapshot::initializing()));

        // Tests don't actually read/write the marker — just point at a
        // throw-away path under temp_dir. Tests that care about the marker
        // override this field after construction.
        let cold_restart_equivalent_marker_path = std::env::temp_dir()
            .join("ibctl-test-cold-restart-equivalent-do-not-use");
        let mut sm = StateMachine::new(
            config,
            agent_client,
            supervisor,
            handler_registry,
            channels,
            snapshot_tx,
            cold_restart_equivalent_marker_path,
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
        sm.state = State::Connected;
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;
        // Seed the revocation tracker as if the disconnected label were first
        // observed 3s ago — past its 2s debounce — so the next `observe()`
        // call matures immediately. Without this seed, the test would need
        // two calls to `do_connected()` with a real 2s wait between them.
        sm.revocation.seed_first_seen_for_tests(
            revocation::RevocationSource::DisconnectedLabelStable,
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
            result == State::Connected,
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
        sm.state = State::Connected;
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;
        // No seed — this is the FIRST observation.

        let result = sm.do_connected().await.expect("handler should not error");

        assert!(
            result == State::Connected,
            "single-tick 'disconnected' observation must NOT fire the 2s-debounced revocation; got {:?}",
            result
        );
        assert!(
            sm.revocation.is_pending(revocation::RevocationTag::DisconnectedLabelStable),
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
        sm.state = State::Connected;
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;

        // Tick 1: disconnected observed — pending, stays Connected.
        let r1 = sm.do_connected().await.unwrap();
        assert!(r1 == State::Connected, "tick 1 still Connected");
        assert!(sm.revocation.is_pending(revocation::RevocationTag::DisconnectedLabelStable));

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
        assert!(r2 == State::Connected, "tick 2 still Connected after heal");
        assert!(
            !sm.revocation.is_pending(revocation::RevocationTag::DisconnectedLabelStable),
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
        sm.state = State::Connected;
        sm.state_entered_at = Instant::now() - Duration::from_secs(30);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;

        // Act
        let result = sm.do_connected().await.expect("handler should not error");

        // Assert: no transition — stays Connected (handler returns next state to loop back).
        // Uses matches! rather than assert_eq! because proof instances differ by issued_at.
        assert!(
            result == State::Connected,
            "healthy Connected state must not self-transition just because a liveness tick fired, got {:?}",
            result
        );
    }

    // ================================================================
    // Phase 4 — property tests for the transition law
    //
    // The central architectural invariant after the proof-carrying
    // refactor is:
    //
    //   Promotion:  positive evidence → mint proof
    //   Retention:  no contradiction → retain proof
    //   Revocation: source matures past debounce → demote
    //   Silence:    timeouts may delay/restart/demote, NEVER promote
    //
    // These tests codify that law so a future regression that re-introduces
    // a fail-open path is caught by `cargo test`, not a production incident.
    // ================================================================

    /// Silence rule: a WaitingForApiReady handler that has NOT seen positive
    /// "connected" evidence must NEVER return `State::Connected(_)`, even
    /// after an arbitrary amount of elapsed time.
    #[tokio::test]
    async fn test_timeout_never_promotes_to_connected() {
        // Arrange: Gateway sitting at login form with "disconnected" label —
        // the exact incident scenario where the old code fabricated progress
        // to ConfiguringApi (and then Connected) after a 120s timeout.
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
        // Wind the clock back so the 120s timeout has "already elapsed".
        sm.state_entered_at = Instant::now() - Duration::from_secs(300);
        sm.state = State::WaitingForApiReady;

        let result = sm.do_wait_for_api_ready().await.expect("handler must not error");

        // The law: no path may reach Connected without positive evidence.
        assert!(
            result != State::Connected,
            "WaitingForApiReady timeout MUST NOT promote to Connected — got {:?}",
            result
        );
        assert_eq!(
            result,
            State::Restarting,
            "timeout with no positive signal must fail-closed to Restarting"
        );
    }

    /// Revocation rule applied to every `RevocationSource` variant.
    /// Each source, once matured past its debounce, must transition the
    /// state machine to that source's `next_state()`.
    #[tokio::test]
    async fn test_each_revocation_source_demotes_connected() {
        use revocation::RevocationSource;

        // Build a set of "this source is currently contradicting" conditions
        // by staging the observation cache / mock / revocation tracker so that
        // do_connected sees the source mature on this tick. For each source
        // we verify the resulting state equals source.next_state().

        // --- ReloginDialog (immediate) ---
        {
            let mock = MockAgent {
                windows: vec![gateway_window()],
                ..Default::default()
            };
            let mut sm = make_test_state_machine(mock);
            sm.state = State::Connected;
            sm.observation.synced = true;
            // Inject a re-login dialog into the observation cache.
            sm.observation.window_opened(
                99,
                "Re-login is required".into(),
                "dialog".into(),
                false,
                1,
            );
            let result = sm.do_connected().await.expect("handler must not error");
            assert_eq!(
                result,
                RevocationSource::ReloginDialog.next_state(),
                "ReloginDialog must demote to {}",
                RevocationSource::ReloginDialog.next_state()
            );
        }

        // --- SessionConflict (immediate) ---
        {
            let mock = MockAgent {
                windows: vec![gateway_window()],
                ..Default::default()
            };
            let mut sm = make_test_state_machine(mock);
            sm.state = State::Connected;
            sm.observation.synced = true;
            sm.observation.window_opened(
                99,
                "Existing session detected".into(),
                "dialog".into(),
                false,
                1,
            );
            let result = sm.do_connected().await.expect("handler must not error");
            assert_eq!(
                result,
                RevocationSource::SessionConflict.next_state(),
                "SessionConflict must demote to {}",
                RevocationSource::SessionConflict.next_state()
            );
        }

        // --- DisconnectedLabelStable (2s debounce) ---
        {
            let mock = MockAgent {
                windows: vec![gateway_window()],
                dump_response: serde_json::json!({
                    "labels": ["Purpose", "Status", "API Server", "disconnected", "IBKR GATEWAY"],
                    "textfields": [], "buttons": [], "tables": []
                }),
                ..Default::default()
            };
            let mut sm = make_test_state_machine(mock);
            sm.state = State::Connected;
            sm.connected_window_class = Some("ibgateway.ay".to_string());
            sm.observation.synced = true;
            sm.revocation.seed_first_seen_for_tests(
                RevocationSource::DisconnectedLabelStable,
                Duration::from_secs(3),
            );
            let result = sm.do_connected().await.expect("handler must not error");
            assert_eq!(
                result,
                RevocationSource::DisconnectedLabelStable.next_state(),
                "DisconnectedLabelStable must demote to {} once debounce elapses",
                RevocationSource::DisconnectedLabelStable.next_state()
            );
        }

        // --- LoginFormVisible (1s debounce) ---
        {
            let mock = MockAgent {
                windows: vec![gateway_window()],
                dump_response: serde_json::json!({
                    "labels": ["Username", "Password"],
                    "textfields": [
                        {"class": "javax.swing.JTextField", "text": "", "visible": true, "enabled": true, "type": "JTextField"}
                    ],
                    "buttons": [], "tables": []
                }),
                ..Default::default()
            };
            let mut sm = make_test_state_machine(mock);
            sm.state = State::Connected;
            sm.connected_window_class = Some("ibgateway.ay".to_string());
            sm.observation.synced = true;
            sm.revocation.seed_first_seen_for_tests(
                RevocationSource::LoginFormVisible,
                Duration::from_secs(2),
            );
            let result = sm.do_connected().await.expect("handler must not error");
            assert_eq!(
                result,
                RevocationSource::LoginFormVisible.next_state(),
                "LoginFormVisible must demote to {} once debounce elapses",
                RevocationSource::LoginFormVisible.next_state()
            );
        }
    }

    /// Retention rule: a debounced source that fires once then clears
    /// (transient contradiction) must NOT revoke the proof.
    ///
    /// Note: this is the same scenario as
    /// `test_connected_liveness_transient_disconnect_does_not_revoke`
    /// from Phase 1 — kept here as a parametrized law statement.
    #[tokio::test]
    async fn test_transient_contradiction_preserves_proof() {
        let mut sm = make_test_state_machine(MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "disconnected", "IBKR GATEWAY"],
                "textfields": [], "buttons": [], "tables": []
            }),
            ..Default::default()
        });
        sm.state = State::Connected;
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;

        // Tick 1: observe contradiction, debounce starts.
        assert!(sm.do_connected().await.unwrap() == State::Connected);
        assert!(sm.revocation.is_pending(revocation::RevocationTag::DisconnectedLabelStable));

        // Heal the contradiction — subsequent tick must clear the debounce.
        sm.agent_client = AgentClient::mock(MockAgent {
            windows: vec![gateway_window()],
            dump_response: serde_json::json!({
                "labels": ["Purpose", "Status", "API Server", "connected", "IBKR GATEWAY"],
                "textfields": [], "buttons": [], "tables": []
            }),
            ..Default::default()
        });
        assert!(sm.do_connected().await.unwrap() == State::Connected);
        assert!(
            !sm.revocation.is_pending(revocation::RevocationTag::DisconnectedLabelStable),
            "transient contradiction must clear the debounce"
        );

        // Sanity: explicit source variants respect the law.
        for source_tag in [
            revocation::RevocationTag::LoginFormVisible,
            revocation::RevocationTag::DisconnectedLabelStable,
            revocation::RevocationTag::ErrorDialog,
        ] {
            assert!(
                !sm.revocation.is_pending(source_tag),
                "no source should be pending after a healthy tick (got {})",
                source_tag
            );
        }
    }

    // ----------------------------------------------------------------
    // ColdRestart must no-op on dormant states
    //
    // Regression guard for the 2026-04-19 incident: standby VPS sites with
    // auto_launch=false correctly started in WaitingForLaunch, then the
    // Sunday cold-restart scheduler fired and transitioned them to
    // Restarting → Launching → login to IBKR — racing the primary for the
    // same account. Cold-restart must only fire when there's actually a
    // running Gateway to restart.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_cold_restart_noops_on_waiting_for_launch() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForLaunch;
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire)).await.expect("handler must not error");
        assert_eq!(
            sm.state,
            State::WaitingForLaunch,
            "ColdRestart on dormant standby must not transition to Restarting"
        );
    }

    #[tokio::test]
    async fn test_cold_restart_noops_on_shutdown() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Shutdown;
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire)).await.expect("handler must not error");
        assert_eq!(sm.state, State::Shutdown, "ColdRestart on Shutdown must not transition");
    }

    #[tokio::test]
    async fn test_cold_restart_noops_on_error_state() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Error("test-error".to_string());
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire)).await.expect("handler must not error");
        assert!(matches!(sm.state, State::Error(_)), "ColdRestart on Error must not short-circuit recovery");
    }

    #[tokio::test]
    async fn test_cold_restart_noops_on_waiting_for_hitl2fa() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire)).await.expect("handler must not error");
        assert_eq!(
            sm.state,
            State::WaitingForHitl2fa,
            "ColdRestart mid-HITL must not waste the pending 2FA token"
        );
    }

    #[tokio::test]
    async fn test_cold_restart_fires_on_connected() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Connected;
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire)).await.expect("handler must not error");
        assert_eq!(
            sm.state,
            State::Restarting,
            "ColdRestart on Connected must transition to Restarting (the normal path)"
        );
    }

    // ----------------------------------------------------------------
    // HITL observation-blind handler — observation cache demotion
    //
    // The wedge: IBKR times out the 2FA prompt on their side, the JVM
    // drops back to the login form, but `do_waiting_for_hitl_2fa` only
    // consulted the cold-restart channel, retry-deadline timer, and
    // HITL_RESUME command. It NEVER read the observation cache that
    // the main loop already maintains via window events.
    //
    // Observed wedge in production: 5h51min stuck in WaitingForHitl2fa
    // while the JVM had reverted to the login form hours earlier.
    //
    // Fix: handler now consults `observation.has_login_form()` and
    // `observation.has_2fa_dialog()` and demotes to WaitingForLogin
    // after HITL_DEMOTE_TICK_THRESHOLD (3) consecutive ticks of
    // "login form visible AND no 2FA dialog". Debounced to bridge the
    // brief mid-2FA-timeout window where neither form is fully drawn.
    // ----------------------------------------------------------------

    /// Helper: stage observation so it looks like the login form is visible
    /// without a 2FA dialog (the wedge condition).
    fn stage_login_form_only(sm: &mut StateMachine, seq: u64) {
        sm.observation = crate::agent_events::AgentObservation::new();
        sm.observation.window_opened(
            1,
            "IBKR Gateway".into(),
            "ibgateway.az".into(),
            true, // has_login_button
            seq,
        );
        sm.observation.synced = true;
    }

    /// Helper: stage observation so both the login form (background) AND
    /// the 2FA dialog (foreground) are visible — the legitimate HITL state.
    fn stage_login_form_and_2fa(sm: &mut StateMachine, seq: u64) {
        sm.observation = crate::agent_events::AgentObservation::new();
        sm.observation.window_opened(
            1,
            "IBKR Gateway".into(),
            "ibgateway.az".into(),
            true,
            seq,
        );
        sm.observation.window_opened(
            2,
            "Second Factor Authentication".into(),
            "dialog".into(),
            false,
            seq + 1,
        );
        sm.observation.synced = true;
    }

    /// Helper: stage observation so neither the login form nor the 2FA
    /// dialog is visible (e.g. a transient blank moment).
    fn stage_neither(sm: &mut StateMachine, seq: u64) {
        sm.observation = crate::agent_events::AgentObservation::new();
        // Just a placeholder non-gateway window so the cache isn't empty.
        sm.observation.window_opened(
            3,
            "About".into(),
            "dialog".into(),
            false,
            seq,
        );
        sm.observation.synced = true;
    }

    #[tokio::test]
    async fn test_hitl_demotes_when_login_form_persists_no_2fa() {
        // Arrange: state machine sitting in WaitingForHitl2fa; the JVM has
        // dropped back to the login form (IBKR-side 2FA timeout).
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_only(&mut sm, 1);

        // Act: three consecutive ticks of "login form visible / no 2FA dialog".
        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa, "tick 1 must hold (counter=1)");
        assert_eq!(sm.hitl_login_form_observation_ticks, 1);

        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(r2, State::WaitingForHitl2fa, "tick 2 must hold (counter=2)");
        assert_eq!(sm.hitl_login_form_observation_ticks, 2);

        let r3 = sm.do_waiting_for_hitl_2fa().await.expect("tick 3");
        assert_eq!(
            r3,
            State::WaitingForLogin,
            "tick 3 must demote to WaitingForLogin once the debounce matures"
        );
    }

    #[tokio::test]
    async fn test_hitl_holds_when_2fa_dialog_still_visible() {
        // Arrange: HITL with BOTH login window (background) AND 2FA dialog
        // (foreground) — the legitimate HITL state. Predicate is false
        // because has_2fa_dialog() returns true.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_and_2fa(&mut sm, 1);

        // Act: five ticks. Counter never increments because the predicate
        // requires `!has_2fa_dialog()`.
        for tick in 1..=5 {
            let r = sm
                .do_waiting_for_hitl_2fa()
                .await
                .unwrap_or_else(|_| panic!("tick {} must not error", tick));
            assert_eq!(
                r,
                State::WaitingForHitl2fa,
                "tick {} must hold because the 2FA dialog is still visible",
                tick,
            );
            assert_eq!(
                sm.hitl_login_form_observation_ticks, 0,
                "counter must stay 0 while the 2FA dialog is visible (tick {})",
                tick,
            );
        }
    }

    #[tokio::test]
    async fn test_hitl_resets_counter_when_neither_visible() {
        // Arrange: HITL with login form visible (no 2FA) for 2 ticks, then
        // briefly nothing visible (1 tick) which must reset the counter,
        // then login form again (1 tick). Total: 4 ticks, no demote.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;

        // Tick 1+2: login form only — counter climbs to 2.
        stage_login_form_only(&mut sm, 1);
        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_login_form_observation_ticks, 1);

        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(r2, State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_login_form_observation_ticks, 2);

        // Tick 3: neither visible — counter must reset to 0.
        stage_neither(&mut sm, 5);
        let r3 = sm.do_waiting_for_hitl_2fa().await.expect("tick 3");
        assert_eq!(r3, State::WaitingForHitl2fa);
        assert_eq!(
            sm.hitl_login_form_observation_ticks, 0,
            "counter must reset when the predicate is false (neither visible)"
        );

        // Tick 4: login form again — counter starts over at 1, not 3.
        // If the counter HADN'T reset, this would demote (3 >= threshold).
        stage_login_form_only(&mut sm, 6);
        let r4 = sm.do_waiting_for_hitl_2fa().await.expect("tick 4");
        assert_eq!(
            r4,
            State::WaitingForHitl2fa,
            "must stay HITL — the counter reset prevents premature demotion"
        );
        assert_eq!(sm.hitl_login_form_observation_ticks, 1);
    }

    #[tokio::test]
    async fn test_hitl_holds_below_threshold() {
        // Arrange: HITL with login form visible / no 2FA dialog.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_only(&mut sm, 1);

        // Act: only 2 consecutive ticks — threshold is 3, so no demote.
        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa);
        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(
            r2,
            State::WaitingForHitl2fa,
            "must stay HITL at 2 ticks — threshold is {}",
            HITL_DEMOTE_TICK_THRESHOLD,
        );
        assert_eq!(sm.hitl_login_form_observation_ticks, 2);
    }

    // ----------------------------------------------------------------
    // HITL positive-direction observation check
    //
    // The wedge: the user's IB Key push approval arrives in flight
    // during the attempt-3 timeout, the JVM completes auth and reaches
    // "API Server: connected" — but ibctl is already in WaitingForHitl2fa
    // and the negative-direction check only watches for login-form
    // reversion. Without a positive check, the handler waits indefinitely
    // for HITL_RESUME, the post-auth path never runs, and socat is
    // never started → external clients see the API bridge offline even
    // though the broker connection is alive.
    //
    // Fix: handler now also probes the main Gateway window's connection-
    // status panel each tick. After HITL_DEMOTE_TICK_THRESHOLD (3)
    // consecutive ticks of "main window present AND API Server:
    // connected AND no 2FA dialog AND no login form", the handler
    // demotes to WaitingForApiReady — same debounce shape as the
    // negative direction, opposite signal.
    // ----------------------------------------------------------------

    /// Helper: stage observation so the main Gateway window is present
    /// without a 2FA dialog and without the login button — the steady-
    /// connected world-state. Also wire the mock agent's dump_response
    /// to the canonical "API Server: connected" fixture so the predicate
    /// inside the positive check returns true.
    fn stage_main_connected(seq: u64) -> (crate::agent_events::AgentObservation, MockAgent) {
        let mut obs = crate::agent_events::AgentObservation::new();
        obs.window_opened(
            1,
            "IBKR Gateway [LIVE]".into(),
            "ibgateway.aw".into(),
            false, // no login button — we're past login
            seq,
        );
        obs.synced = true;

        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: parse(FIXTURE_API_SERVER_UP_API_CLIENT_DOWN),
            ..Default::default()
        };
        (obs, mock)
    }

    #[tokio::test]
    async fn test_hitl_demotes_when_main_connected_persists() {
        // Arrange: state machine sitting in WaitingForHitl2fa; the user's
        // 2FA push approval arrived in flight during the attempt-3 timeout,
        // the JVM has reached "API Server: connected", no 2FA dialog and
        // no login form is visible. The handler should debounce-confirm
        // and demote to WaitingForApiReady so socat finally starts.
        let (obs, mock) = stage_main_connected(1);
        let mut sm = make_test_state_machine(mock);
        sm.state = State::WaitingForHitl2fa;
        sm.observation = obs;

        // Act: three consecutive ticks of "main connected".
        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa, "tick 1 must hold (counter=1)");
        assert_eq!(sm.hitl_connected_observation_ticks, 1);

        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(r2, State::WaitingForHitl2fa, "tick 2 must hold (counter=2)");
        assert_eq!(sm.hitl_connected_observation_ticks, 2);

        let r3 = sm.do_waiting_for_hitl_2fa().await.expect("tick 3");
        assert_eq!(
            r3,
            State::WaitingForApiReady,
            "tick 3 must demote to WaitingForApiReady once the debounce matures",
        );
    }

    #[tokio::test]
    async fn test_hitl_holds_when_main_connected_only_one_tick() {
        // Arrange: HITL with main-connected for 1 tick, then a transient
        // blank moment. Counter must reset on tick 2 — no demote.
        let (obs, mock) = stage_main_connected(1);
        let mut sm = make_test_state_machine(mock);
        sm.state = State::WaitingForHitl2fa;
        sm.observation = obs;

        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_connected_observation_ticks, 1);

        // Tick 2: nothing visible — counter must reset.
        stage_neither(&mut sm, 5);
        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(r2, State::WaitingForHitl2fa);
        assert_eq!(
            sm.hitl_connected_observation_ticks, 0,
            "counter must reset when the main Gateway window is no longer present",
        );
    }

    #[tokio::test]
    async fn test_hitl_holds_when_main_connected_below_threshold() {
        // Arrange: HITL with main-connected for 2 ticks — threshold is 3,
        // so no demote yet.
        let (obs, mock) = stage_main_connected(1);
        let mut sm = make_test_state_machine(mock);
        sm.state = State::WaitingForHitl2fa;
        sm.observation = obs;

        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa);
        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(
            r2,
            State::WaitingForHitl2fa,
            "must stay HITL at 2 ticks — threshold is {}",
            HITL_DEMOTE_TICK_THRESHOLD,
        );
        assert_eq!(sm.hitl_connected_observation_ticks, 2);
    }

    #[tokio::test]
    async fn test_hitl_positive_check_subordinate_to_negative() {
        // Arrange: stage login-form-only — that fires the NEGATIVE
        // direction check. The positive check's outer condition is
        // `!has_login_form() && !has_2fa_dialog()`, so it must not even
        // increment its counter while the login form is visible.
        // The negative check demotes to WaitingForLogin (not the positive
        // check's WaitingForApiReady target).
        let mock = MockAgent {
            windows: vec![gateway_window()],
            // Even though the dump *would* say connected if probed,
            // the positive check's outer guard prevents the probe.
            dump_response: parse(FIXTURE_API_SERVER_UP_API_CLIENT_DOWN),
            ..Default::default()
        };
        let mut sm = make_test_state_machine(mock);
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_only(&mut sm, 1);

        // Act: three ticks. Negative check matures first; positive never fires.
        let r1 = sm.do_waiting_for_hitl_2fa().await.expect("tick 1");
        assert_eq!(r1, State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_login_form_observation_ticks, 1);
        assert_eq!(
            sm.hitl_connected_observation_ticks, 0,
            "positive counter must not increment while login form is visible",
        );

        let r2 = sm.do_waiting_for_hitl_2fa().await.expect("tick 2");
        assert_eq!(r2, State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_login_form_observation_ticks, 2);
        assert_eq!(sm.hitl_connected_observation_ticks, 0);

        let r3 = sm.do_waiting_for_hitl_2fa().await.expect("tick 3");
        assert_eq!(
            r3,
            State::WaitingForLogin,
            "negative direction must win — demote target is WaitingForLogin, \
             not WaitingForApiReady",
        );
    }

    #[tokio::test]
    async fn test_hitl_connected_counter_clears_on_state_entry_and_exit() {
        // Verify the counter is zeroed both on HITL entry (first-tick init
        // block guarded by `hitl_entered_at.is_none()`) and on HITL exit
        // (apply_transition cleanup block guarded by `state == HITL && next != HITL`).
        let (obs, mock) = stage_main_connected(1);
        let mut sm = make_test_state_machine(mock);
        sm.state = State::WaitingForHitl2fa;
        sm.observation = obs;

        // --- Entry: simulate a stale non-zero value before first tick ---
        sm.hitl_entered_at = None;
        sm.hitl_connected_observation_ticks = 99;
        let _ = sm.do_waiting_for_hitl_2fa().await.expect("entry tick");
        // After entry init the counter is zeroed, then the in-tick check
        // increments it back to 1. The load-bearing assertion is that the
        // stale 99 was wiped — if the entry init had not reset, we'd see
        // saturating_add(99, 1) = 100 here.
        assert_eq!(
            sm.hitl_connected_observation_ticks, 1,
            "HITL entry must zero the counter (stale 99 must not survive)",
        );

        // --- Exit: pump counter to a non-zero value, then transition away ---
        sm.hitl_connected_observation_ticks = 7;
        sm.apply_transition(State::WaitingForLogin)
            .await
            .expect("transition out of HITL must not error");
        assert_eq!(
            sm.hitl_connected_observation_ticks, 0,
            "HITL exit must zero the counter alongside the existing HITL bookkeeping",
        );
    }

    // ----------------------------------------------------------------
    // Fresh-auth marker — apply_transition writes the marker only when
    // we arrive at Connected via a credential-gathering state.
    //
    // The architect-refined filter is the load-bearing piece here: we
    // must NOT write the marker on the Connected->revoke->Connected
    // flap (e.g. ReconnectingSession self-recovery) because no human
    // pressed a 2FA prompt and Sunday's cold restart still has to fire.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_apply_transition_writes_marker_from_credential_state() {
        // Arrange: a state machine pointing its marker at a tempdir, sitting
        // in WaitingForLogin — exactly the path a fresh login takes. To
        // emulate a real cold-restart-equivalent we also set the pending
        // flag (which would have been set by WaitingFor2fa exit earlier in
        // the lifecycle).
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::WaitingForLogin;
        sm.cold_restart_equivalent_pending = true;

        // Act: simulate the actual transition that happens on a fresh login.
        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition must not error");

        // Assert: marker exists and parses as today's date.
        let raw = std::fs::read_to_string(&marker)
            .expect("marker must be written on credential-state -> Connected");
        let parsed = jiff::Zoned::from_str(raw.trim())
            .expect("marker must contain a valid ISO 8601 timestamp");
        assert_eq!(
            parsed.date(),
            jiff::Zoned::now().date(),
            "marker must record today's date",
        );
        // The flag is consumed after the write so subsequent revoke loops
        // don't double-write.
        assert!(
            !sm.cold_restart_equivalent_pending,
            "flag must be cleared immediately after marker write",
        );
    }

    #[tokio::test]
    async fn test_apply_transition_writes_marker_from_configuring_api() {
        // Arrange: the canonical cold-auth path lands in Connected from
        // ConfiguringApi after apply_api_config returns Ok. Without this
        // state classified by `State::is_credential_gathering`, the marker
        // would never fire in real production. The pending flag was set
        // when WaitingFor2fa exited to DismissingPopups earlier.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::ConfiguringApi;
        sm.cold_restart_equivalent_pending = true;

        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition must not error");

        assert!(
            marker.exists(),
            "marker must fire on the canonical ConfiguringApi -> Connected path",
        );
    }

    #[tokio::test]
    async fn test_apply_transition_skips_marker_on_revoke_loop() {
        // Arrange: a state machine in ReconnectingSession — the Connected ->
        // revoke -> Connected flap path. No credentials were gathered, so the
        // marker must NOT be written. Even if the pending flag somehow leaked
        // in (it shouldn't, since ReconnectingSession does not gather
        // credentials), the is_credential_gathering check excludes
        // ReconnectingSession.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::ReconnectingSession;

        // Act: same transition target, different source state.
        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition must not error");

        // Assert: marker file is absent.
        assert!(
            !marker.exists(),
            "marker must NOT be written on a ReconnectingSession flap",
        );
    }

    #[tokio::test]
    async fn test_apply_transition_skips_marker_on_connected_to_connected() {
        // Arrange: a no-op same-state "transition" (defensive: shouldn't
        // happen in practice, but the curr_is_connected guard must keep
        // it from writing the marker).
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::Connected;

        // Act.
        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition must not error");

        // Assert: still absent — both curr_is_connected and next_is_connected.
        assert!(
            !marker.exists(),
            "marker must NOT be written on Connected -> Connected",
        );
    }

    // ----------------------------------------------------------------
    // ColdRestartSignal::Skipped — must NOT restart, must stamp
    // last_cold_restart_skip so the dashboard sees it via STATUS JSON.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_cold_restart_skipped_signal_does_not_restart() {
        // Arrange: Connected state, then deliver a Skipped signal.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Connected;
        let last_login = jiff::Zoned::now();

        // Act.
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Skipped(
            ColdRestartSkipReason::FreshAuthToday { at: last_login.clone() },
        )))
        .await
        .expect("Skipped handler must not error");

        // Assert: state unchanged, skip stamp present.
        assert_eq!(
            sm.state,
            State::Connected,
            "Skipped must NOT transition to Restarting",
        );
        let rec = sm.last_cold_restart_skip.as_ref()
            .expect("last_cold_restart_skip must be populated");
        match &rec.reason {
            ColdRestartSkipReason::FreshAuthToday { at } => {
                assert_eq!(at, &last_login, "stamped last_login_at must match input");
            }
            other => panic!("expected FreshAuthToday, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cold_restart_skipped_keeps_dormant_states_dormant() {
        // Skipped should be a publish-only update everywhere — including
        // dormant states, where Fire would have no-op'd. This is symmetric
        // to the Fire dormant guard but achieved by the variant matching
        // (Skipped never modifies state at all).
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForLaunch;
        let last_login = jiff::Zoned::now();

        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Skipped(
            ColdRestartSkipReason::FreshAuthToday { at: last_login },
        )))
        .await
        .expect("Skipped handler must not error on dormant state");

        assert_eq!(
            sm.state,
            State::WaitingForLaunch,
            "Skipped on dormant state must remain dormant",
        );
        assert!(
            sm.last_cold_restart_skip.is_some(),
            "Skipped must still stamp the skip timestamp on dormant states",
        );
    }

    // ----------------------------------------------------------------
    // Dormant-state Fire — must record a DormantSite skip so STATUS JSON
    // distinguishes "standby skip" from "fresh auth today" skip.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_dormant_state_cold_restart_fire_publishes_skip_record() {
        // Arrange: dormant state (WaitingForLaunch) is one of the four
        // states where Fire is silently dropped. Pre-condition: no skip
        // recorded yet.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForLaunch;
        assert!(
            sm.last_cold_restart_skip.is_none(),
            "precondition: skip record must be empty before fire",
        );

        // Act: deliver a Fire against the dormant site.
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire))
            .await
            .expect("Fire on dormant site must not error");

        // Assert: state unchanged, dormant skip record stamped.
        assert_eq!(
            sm.state,
            State::WaitingForLaunch,
            "dormant Fire must not transition out of WaitingForLaunch",
        );
        let rec = sm.last_cold_restart_skip.as_ref()
            .expect("dormant Fire must publish a skip record (was invisible before)");
        assert!(
            matches!(rec.reason, ColdRestartSkipReason::DormantSite),
            "dormant Fire must record reason DormantSite, got {:?}",
            rec.reason,
        );
    }

    #[tokio::test]
    async fn test_skipped_fresh_auth_publishes_record_with_reason() {
        // Skipped(FreshAuthToday) must stamp a record whose reason carries
        // the same timestamp the scheduler observed in the marker.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Connected;
        let last_login = jiff::Zoned::now();

        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Skipped(
            ColdRestartSkipReason::FreshAuthToday { at: last_login.clone() },
        )))
        .await
        .expect("Skipped handler must not error");

        let rec = sm.last_cold_restart_skip.as_ref()
            .expect("Skipped must publish a skip record");
        match &rec.reason {
            ColdRestartSkipReason::FreshAuthToday { at } => {
                assert_eq!(at, &last_login, "FreshAuthToday must carry the input timestamp");
            }
            other => panic!("expected FreshAuthToday, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_fire_accepted_clears_prior_skip_record() {
        // A non-dormant Fire (e.g. on Connected) must clear any earlier
        // skip record so STATUS JSON doesn't show a stale skip after the
        // restart actually fires.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.last_cold_restart_skip = Some(ColdRestartSkipRecord {
            recorded_at: jiff::Zoned::now(),
            reason: ColdRestartSkipReason::DormantSite,
        });
        sm.state = State::Connected;

        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Fire))
            .await
            .expect("Fire on Connected must not error");

        assert_eq!(
            sm.state,
            State::Restarting,
            "Fire on Connected must transition to Restarting",
        );
        assert!(
            sm.last_cold_restart_skip.is_none(),
            "accepted Fire must clear the prior skip record",
        );
    }

    // ----------------------------------------------------------------
    // Bug 2 — cold_restart_equivalent_pending lifecycle.
    //
    // The flag distinguishes real cold-restart-equivalents (JVM kill +
    // answered 2FA) from warm restarts (IBC -Drestart= replay that
    // bypasses 2FA). Only the former should write the marker that the
    // Sunday cold-restart scheduler reads.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_flag_resets_on_launching_entry() {
        // Defensive reset — every JVM (re)start clears the RAM flag.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Restarting;
        sm.cold_restart_equivalent_pending = true;

        sm.apply_transition(State::Launching)
            .await
            .expect("apply_transition must not error");

        assert!(
            !sm.cold_restart_equivalent_pending,
            "Launching entry must reset the flag (defensive blanket reset)",
        );
    }

    #[tokio::test]
    async fn test_flag_set_on_waiting_for_2fa_to_dismissing_popups_with_twofa_seen() {
        // Canonical happy path: TOTP submitted, dialog gone, advance to
        // DismissingPopups. With twofa_seen=true the flag is set so the
        // eventual Connected entry writes the marker.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        assert!(!sm.cold_restart_equivalent_pending);

        sm.apply_transition(State::DismissingPopups)
            .await
            .expect("apply_transition must not error");

        assert!(
            sm.cold_restart_equivalent_pending,
            "WaitingFor2fa -> DismissingPopups with twofa_seen must set the flag",
        );
    }

    // Reviewer parameterization: the flag-set arm in apply_transition matches
    // {DismissingPopups, WaitingForApiReady, ConfiguringApi, Connected}. Only
    // the DismissingPopups branch was covered above — the other three are
    // exercised below so a future edit that drops one from the arm is caught.
    async fn assert_waiting_for_2fa_sets_flag_on_transition_to(target: State) {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        // For State::Connected, apply_transition also wants to write the
        // marker — point it at a tempdir so the on-disk write succeeds.
        let dir = tempfile::TempDir::new().unwrap();
        sm.cold_restart_equivalent_marker_path =
            dir.path().join(".ibctl-cold-restart-equivalent-today");
        assert!(!sm.cold_restart_equivalent_pending);

        sm.apply_transition(target.clone())
            .await
            .expect("apply_transition must not error");

        // When the target is Connected, the flag is consumed immediately
        // after the marker write decision (see mod.rs ~L297). For the other
        // targets, the flag stays true until the eventual Connected entry.
        if target == State::Connected {
            assert!(
                !sm.cold_restart_equivalent_pending,
                "WaitingFor2fa -> Connected: flag was set then consumed on the same transition"
            );
            assert!(
                sm.cold_restart_equivalent_marker_path.exists(),
                "WaitingFor2fa -> Connected: marker must have been written before flag consumption",
            );
        } else {
            assert!(
                sm.cold_restart_equivalent_pending,
                "WaitingFor2fa -> {} with twofa_seen must set the flag",
                target
            );
        }
    }

    #[tokio::test]
    async fn test_flag_set_on_waiting_for_2fa_to_waiting_for_api_ready_with_twofa_seen() {
        assert_waiting_for_2fa_sets_flag_on_transition_to(State::WaitingForApiReady).await;
    }

    #[tokio::test]
    async fn test_flag_set_on_waiting_for_2fa_to_configuring_api_with_twofa_seen() {
        assert_waiting_for_2fa_sets_flag_on_transition_to(State::ConfiguringApi).await;
    }

    #[tokio::test]
    async fn test_flag_set_on_waiting_for_2fa_to_connected_with_twofa_seen() {
        assert_waiting_for_2fa_sets_flag_on_transition_to(State::Connected).await;
    }

    #[tokio::test]
    async fn test_flag_not_set_on_grace_period_escape() {
        // The grace-period escape at do_wait_for_2fa line 1188: no 2FA dialog
        // ever appeared within the grace window, so the handler proceeds to
        // DismissingPopups without a challenge. twofa_seen stays false; the
        // flag must NOT be set.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = false;

        sm.apply_transition(State::DismissingPopups)
            .await
            .expect("apply_transition must not error");

        assert!(
            !sm.cold_restart_equivalent_pending,
            "grace-period escape (twofa_seen=false) must NOT set the flag",
        );
    }

    #[tokio::test]
    async fn test_flag_not_set_on_waiting_for_2fa_timeout_to_restarting() {
        // 2FA timed out; the handler routes back to Restarting (RestartForever
        // or RestartThenHitl with attempts remaining). Flag must NOT be set —
        // no challenge was answered.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true; // dialog was seen but never answered

        sm.apply_transition(State::Restarting)
            .await
            .expect("apply_transition must not error");

        assert!(
            !sm.cold_restart_equivalent_pending,
            "WaitingFor2fa -> Restarting (timeout) must NOT set the flag",
        );
    }

    #[tokio::test]
    async fn test_flag_not_set_on_waiting_for_2fa_to_waiting_for_login() {
        // Verification failed -> drop back to WaitingForLogin (line 1171). No
        // successful 2FA answer; flag stays false.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;

        sm.apply_transition(State::WaitingForLogin)
            .await
            .expect("apply_transition must not error");

        assert!(
            !sm.cold_restart_equivalent_pending,
            "WaitingFor2fa -> WaitingForLogin (failed verify) must NOT set the flag",
        );
    }

    #[tokio::test]
    async fn test_flag_set_on_hitl_to_waiting_for_api_ready() {
        // The positive-direction HITL probe (commit 7a7bb5d): the JVM reached
        // "API Server: connected" steady state — the user's push approval
        // landed in flight. This counts as a cold-restart-equivalent.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;

        sm.apply_transition(State::WaitingForApiReady)
            .await
            .expect("apply_transition must not error");

        assert!(
            sm.cold_restart_equivalent_pending,
            "WaitingForHitl2fa -> WaitingForApiReady (positive probe) must set the flag",
        );
    }

    #[tokio::test]
    async fn test_flag_not_set_on_hitl_to_waiting_for_login() {
        // The negative-direction stale-form demote (commit bce5832): the 2FA
        // dialog timed out without being answered. Flag must NOT be set.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;

        sm.apply_transition(State::WaitingForLogin)
            .await
            .expect("apply_transition must not error");

        assert!(
            !sm.cold_restart_equivalent_pending,
            "WaitingForHitl2fa -> WaitingForLogin (stale-form demote) must NOT set the flag",
        );
    }

    #[tokio::test]
    async fn test_flag_not_set_on_hitl_to_restarting() {
        // Preempt / auto-retry deadline / HITL_RESUME — all route to
        // Restarting. The subsequent Launching entry will reset the flag
        // anyway, but we don't want a stale set on this transition.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;

        sm.apply_transition(State::Restarting)
            .await
            .expect("apply_transition must not error");

        assert!(
            !sm.cold_restart_equivalent_pending,
            "WaitingForHitl2fa -> Restarting must NOT set the flag",
        );
    }

    // ----------------------------------------------------------------
    // Bug 2 gate — marker is written ONLY when the flag is true.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_apply_transition_skips_marker_when_flag_unset() {
        // A credential-gathering state transitions to Connected but no 2FA
        // was answered (e.g. warm restart that bypassed the 2FA dialog).
        // Marker must NOT be written.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::ConfiguringApi;
        // Flag is the default false — emulating a warm restart that landed
        // here without crossing WaitingFor2fa.
        assert!(!sm.cold_restart_equivalent_pending);

        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition must not error");

        assert!(
            !marker.exists(),
            "marker must NOT be written when the cold-restart-equivalent flag is false",
        );
    }

    #[tokio::test]
    async fn test_connected_revoke_connected_flap_does_not_double_write_marker() {
        // Reviewer-flagged scenario the existing tests don't cover end-to-end:
        // Connected (via cold path, marker written, flag consumed)
        //   -> ReconnectingSession (revoke)
        //   -> Connected (recovery)
        // The second Connected entry must NOT re-write the marker — the flag
        // was consumed on the first Connected entry, and ReconnectingSession
        // does not gather credentials so it can't re-arm the flag.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();

        // Step 1: cold path WaitingFor2fa -> Connected with twofa_seen=true
        // writes the marker AND consumes the flag.
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.apply_transition(State::Connected)
            .await
            .expect("first Connected entry must not error");
        assert!(marker.exists(), "first Connected entry must write the marker");
        assert!(
            !sm.cold_restart_equivalent_pending,
            "flag must be consumed by the first Connected entry",
        );
        let raw_first = std::fs::read_to_string(&marker)
            .expect("marker file must be readable after first write");

        // Step 2: Connected -> ReconnectingSession (revoke).
        sm.apply_transition(State::ReconnectingSession)
            .await
            .expect("revoke transition must not error");

        // Step 3: ReconnectingSession -> Connected (recovery). Without the
        // flag-consumption guard at mod.rs ~L297, this would re-write the
        // marker on every revoke flap, polluting Sunday's skip decision with
        // mid-week reconnects.
        sm.apply_transition(State::Connected)
            .await
            .expect("recovery Connected entry must not error");

        let raw_second = std::fs::read_to_string(&marker)
            .expect("marker file must still be readable after flap");
        assert_eq!(
            raw_first, raw_second,
            "Connected -> revoke -> Connected: second Connected entry must NOT \
             overwrite the marker (the flag was consumed on the first entry, \
             and ReconnectingSession is excluded from is_credential_gathering)",
        );
    }

    #[tokio::test]
    async fn test_apply_transition_writes_marker_from_waiting_for_api_ready_with_flag() {
        // The positive HITL probe path: WaitingForHitl2fa -> WaitingForApiReady
        // sets the flag, then WaitingForApiReady -> Connected writes the marker.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();

        // Step 1: simulate the HITL positive probe transition (sets the flag).
        sm.state = State::WaitingForHitl2fa;
        sm.apply_transition(State::WaitingForApiReady)
            .await
            .expect("apply_transition step 1 must not error");
        assert!(sm.cold_restart_equivalent_pending);

        // Step 2: WaitingForApiReady -> Connected should write the marker.
        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition step 2 must not error");

        assert!(
            marker.exists(),
            "post-HITL Connected entry must write the marker (cold-restart-equivalent confirmed)",
        );
    }

    // ---------------------------------------------------------------------
    // PR-C stage 3 review-fix tests — recovery coordinator wrapper wiring
    // ---------------------------------------------------------------------

    /// Replace `sm.recovery` with a fresh coordinator rooted in an
    /// isolated per-test settings dir. The shared `make_test_state_machine`
    /// helper uses `std::env::temp_dir()` as the coordinator's settings
    /// dir; if a prior test wrote a `.ibctl-recovery-state.paper.json`
    /// there, subsequent tests inherit that marker at boot. Isolate.
    fn reset_recovery_isolated(sm: &mut StateMachine, dir: &std::path::Path) {
        let cfg = sm.config.timing.recovery.to_runtime();
        let (fresh, _outcome) = crate::state_machine::recovery::RecoveryCoordinator::boot(
            dir.to_path_buf(),
            sm.recovery_mode_tag.clone(),
            cfg,
        );
        sm.recovery = fresh;
    }

    /// `tick_recovery` must NOT credit `record_success` when the SM has
    /// already left `State::Connected` — even if a stale dwell task
    /// delivers a `DwellSuccess` after a direct-assign bypass site (Stop /
    /// Exit / Restart / etc.) set `self.state` without running
    /// `apply_transition`'s dwell-guard cleanup.
    ///
    /// Regression for Review A H-1 / H-2 (dwell_guard leaks via seven
    /// direct-assign sites) and Review A M-3 (GivenUp-entry doesn't
    /// abort the guard either).
    #[tokio::test]
    async fn test_tick_recovery_drops_dwell_success_when_sm_left_connected() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(MockAgent::default());
        reset_recovery_isolated(&mut sm, dir.path());
        // Coordinator starts in Aggressive.
        assert_eq!(
            sm.recovery.phase(),
            crate::state_machine::recovery::RecoveryPhase::Aggressive,
        );
        assert!(sm.recovery.last_full_success_at().is_none());

        // Simulate the direct-assign bypass: SM is somewhere other than
        // Connected while a "phantom" DwellSuccess sits in the channel.
        // (Command::Restart / Command::Stop / Signal::Terminate all do
        // exactly this — `self.state = ...` without apply_transition.)
        sm.state = State::Restarting;
        // Also plant a fake dwell_guard as if we were previously Connected —
        // tick_recovery must clear it defensively.
        let dummy_handle = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        });
        sm.dwell_guard = Some(
            crate::state_machine::recovery::AbortOnDrop::new(
                dummy_handle.abort_handle(),
            ),
        );
        let _ = sm.dwell_success_tx.send(
            crate::state_machine::recovery::DwellSuccess {
                recorded_at_wall: jiff::Zoned::now(),
                recorded_at_mono: std::time::Instant::now(),
            },
        );

        // Drive one recovery tick.
        sm.tick_recovery().await;

        // The dwell success must NOT have landed as `record_success`;
        // otherwise last_full_success_at would be Some(now).
        assert!(
            sm.recovery.last_full_success_at().is_none(),
            "SM was not in Connected — the stale DwellSuccess must be dropped, \
             not credited to the coordinator's phase timer",
        );
        // The defensive drop cleared the guard.
        assert!(
            sm.dwell_guard.is_none(),
            "tick_recovery must clear the stale dwell guard when SM has left Connected",
        );
    }

    /// A pending resume token in a dormant state (Shutdown / Error /
    /// WaitingForLaunch) is retained across the tick: the coordinator's
    /// compute/apply cycle is skipped entirely, so `resume_token` stays
    /// parked for the next active-recovery tick.
    ///
    /// Regression for Review B H-4 / Review C M-4 — dormant-state tick
    /// gate.
    #[tokio::test]
    async fn test_tick_recovery_skipped_when_sm_in_shutdown_state() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(MockAgent::default());
        reset_recovery_isolated(&mut sm, dir.path());
        // Park the SM in Shutdown. Also plant a pending resume token
        // (as if RESUME_RECONNECT arrived).
        sm.state = State::Shutdown;
        sm.pending_resume_token = Some(
            crate::state_machine::recovery::ResumeToken {
                mode: sm.recovery_mode_tag.clone(),
                minted_at: jiff::Timestamp::now(),
                nonce_material: "test-nonce".to_string(),
            },
        );

        // Snapshot phase before the tick.
        let phase_before = sm.recovery.phase();
        sm.tick_recovery().await;

        // Phase unchanged (Shutdown is not an active-recovery state).
        assert_eq!(sm.recovery.phase(), phase_before);
        // Token retained (compute/apply skipped, so the token was NOT
        // taken from pending_resume_token).
        assert!(
            sm.pending_resume_token.is_some(),
            "resume token must NOT be consumed in a dormant state — the \
             coordinator's compute/apply cycle is gated off",
        );
    }

    /// `Command::ResumeReconnect` must reject the token when the
    /// coordinator is NOT in `GivenUp` and NOT `blocked_awaiting_resume`.
    /// A silently-parked-then-discarded token is a UX no-op that hides
    /// operator intent (the ntfy tap appears to succeed but produces no
    /// state change).
    ///
    /// Regression for Review B B-8 / Review C H-2.
    #[tokio::test]
    async fn test_resume_reconnect_rejects_when_coordinator_not_in_givenup() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(MockAgent::default());
        reset_recovery_isolated(&mut sm, dir.path());
        // Coordinator starts in Aggressive; not in GivenUp; not blocked.
        assert_eq!(
            sm.recovery.phase(),
            crate::state_machine::recovery::RecoveryPhase::Aggressive,
        );
        assert!(!sm.recovery.is_blocked_awaiting_resume());
        assert!(sm.pending_resume_token.is_none());

        // Fire the command.
        sm.handle_command(Command::ResumeReconnect("op-tapped".to_string()))
            .await
            .expect("handle_command must not error");

        // Token must NOT be parked — the rejection guard fired.
        assert!(
            sm.pending_resume_token.is_none(),
            "RESUME_RECONNECT in Aggressive must be rejected (not silently parked)",
        );
    }

    /// `Command::ResumeReconnect` MUST park the token when the
    /// coordinator IS in GivenUp — this is the operator's tap on the
    /// ntfy resume link, and it must reach `tick_recovery`'s
    /// compute/apply cycle.
    #[tokio::test]
    async fn test_resume_reconnect_parks_token_when_coordinator_in_givenup() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(MockAgent::default());
        reset_recovery_isolated(&mut sm, dir.path());
        // Drive the coordinator to GivenUp.
        let _ = sm.recovery.apply(
            crate::state_machine::recovery::NextAction::EscalateToBackoff,
            jiff::Zoned::now(),
            std::time::Instant::now(),
            None,
        ).expect("escalate");
        let _ = sm.recovery.apply(
            crate::state_machine::recovery::NextAction::FireGiveUpAlert,
            jiff::Zoned::now(),
            std::time::Instant::now(),
            None,
        ).expect("giveup");
        assert_eq!(
            sm.recovery.phase(),
            crate::state_machine::recovery::RecoveryPhase::GivenUp,
        );

        sm.handle_command(Command::ResumeReconnect("op-tapped-abc123".to_string()))
            .await
            .expect("handle_command must not error");

        // Token IS parked.
        let parked = sm.pending_resume_token.as_ref().expect("token must be parked");
        assert_eq!(
            parked.nonce_material, "op-tapped-abc123",
            "nonce_material must carry the operator-supplied token string \
             so hash_token distinguishes distinct taps within one wall-second",
        );
    }
}
