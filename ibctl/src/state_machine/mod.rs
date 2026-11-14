//! Enum-based state machine driving the IB Gateway login and session lifecycle.
//!
//! States: Init -> Launching -> WaitingForAgent -> WaitingForLogin -> Authenticating
//!       -> WaitingFor2fa -> HandlingSessionConflict -> DismissingPopups -> Connected
//!       -> Restarting -> Shutdown
//!
//! The main loop calls `transition()` which matches on the current state and
//! calls the appropriate handler method. Each handler returns the next state.

mod cold_restart_decision;
mod markers;
mod queries;
pub mod recovery;
mod socat;
mod types;
mod revocation;
mod session_conflict;

// Re-export public API
pub use markers::write_cold_restart_equivalent_marker;
pub use types::{Channels, State, StateMachine, StateMachineError};

use std::path::Path;
use std::time::Instant;

use tokio::sync::mpsc;

use crate::types::{ColdRestartOutcome, ColdRestartSignal, ColdRestartSkipReason, Command, Signal};

use types::{ColdRestartOutcomeRecord, HitlParkReason, Interrupt, JvmExitRecord, RelaunchReason, RelaunchRecord, RestartTimeRecord, RetryBy};

/// Select result: either an interrupt from a channel, or a completed
/// state transition.
enum SelectOutcome {
    Interrupted(Interrupt),
    Transitioned(Result<State, StateMachineError>),
}

/// Consecutive HITL ticks the Gateway must show "API Server: connected"
/// (no login form, no 2FA dialog) before the positive probe leaves
/// WaitingForHitl2fa for WaitingForApiReady. At a 2s tick interval, 3 ticks
/// = 6s minimum dwell.
const HITL_DEMOTE_TICK_THRESHOLD: u8 = 3;

/// How long after the Gateway closes an IB Key dialog an armed retry waits
/// before re-submitting the login. IBC's `LoginManager` waits the same 5 s
/// after `secondFactorAuthenticationDialogClosed` before it calls
/// `initiateLogin` on the login frame (ReloginAfterSecondFactorAuthenticationTimeout).
const RELOGIN_SETTLE_AFTER_2FA_CLOSE: std::time::Duration = std::time::Duration::from_secs(5);

/// How long a login retry in the running JVM looks for the login form
/// before concluding this Gateway will not offer one and relaunching the
/// JVM. Twelve times IBC's settle delay; also covers the ~5 s the Gateway
/// takes to reach "connected" when the old push was approved at the
/// moment the dialog closed.
const IN_JVM_RELOGIN_FORM_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

/// How long after an IB Key challenge closes ibctl waits for the Gateway to
/// report "API Server: connected" before treating the round as failed. In
/// observed approvals "connected" came 10-132 s after the close (median
/// about 10 s). The 2FA timeout does not run
/// meanwhile: the challenge is over, only its result is outstanding.
const CONFIRM_AFTER_CHALLENGE_CLOSE: std::time::Duration = std::time::Duration::from_secs(180);

/// What the Gateway shows after an IB Key prompt closed
/// (`gateway_after_prompt_closed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterPrompt {
    /// "API Server: connected": the login completed.
    Connected,
    /// Its login form is back: the round failed.
    LoginForm,
    /// Neither yet.
    Nothing,
}

/// How long an IB Key prompt may stay open before ibctl calls the Gateway
/// stuck and clicks its Cancel. The Gateway ends a round itself by
/// closing the prompt; it has been seen to keep one open for about 17 minutes.
/// Nothing shorter than this ends a round.
const STUCK_PROMPT_CEILING: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long a Cancel ibctl clicked on an IB Key prompt has to close it
/// before the JVM is relaunched — the fallback when the in-JVM recovery
/// fails. What the Gateway does on that Cancel is unverified: ibctl had
/// never clicked it before rounds ended on the Gateway's word.
const PROMPT_CANCEL_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

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

        // Fail-safe gate: if `RecoveryCoordinator::boot`
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
                // Priority order:
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
        // Credentials submitted also count, whether or not a 2FA dialog
        // follows (paper accounts get none) — set where the login handler
        // reports the submit, in `do_authenticate` and
        // `do_authenticate_in_running_jvm`. A PAPER credentials login
        // used to go unrecorded because only an
        // ANSWERED 2FA set this flag. Merely LEAVING Authenticating does not
        // count: it also leaves when it finds no form ("already
        // authenticated") or the handler fails, and neither is a login.
        //
        // An in-JVM retry lives for one stay in Authenticating: submitted,
        // found the login done, or gave up — the next Authenticating is a
        // fresh-JVM login unless `begin_in_jvm_relogin` says otherwise.
        if self.state == State::Authenticating && next != State::Authenticating {
            self.in_jvm_relogin_since = None;
            self.in_jvm_relogin_by = None;
        }
        // WaitingForHitl2fa -> WaitingForApiReady is the positive-direction
        // probe at do_waiting_for_hitl_2fa. NOT set on
        // - WaitingForHitl2fa -> WaitingForLogin (negative stale-form demote:
        //   2FA dialog timed out without being answered)
        // - WaitingForHitl2fa -> Restarting (preempt / auto-retry deadline /
        //   HITL_RESUME: Launching reset will clear the flag anyway)
        if self.state == State::WaitingForHitl2fa && next == State::WaitingForApiReady {
            self.cold_restart_equivalent_pending = true;
        }

        let next_is_connected = next == State::Connected;
        let curr_is_connected = self.state == State::Connected;
        // Dwell timer: on entering Connected, spawn a task that
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
            // A new Connected session starts with a clean slate on the agent's
            // disconnect verdict. Without this, a "disconnected" observed while
            // we were still in Launching/Login — which is routine, the Gateway
            // is genuinely disconnected then — would carry into the session and
            // revoke it 90s later for no reason. This reset is what makes
            // consuming ConnectionStatusChanged safe at all; it is the guard
            // that the original "informational only" decision was protecting.
            self.agent_reported_disconnected = false;
            self.revocation
                .clear(revocation::RevocationTag::AgentReportedDisconnect);

            // Write the cold-restart-equivalent marker ONLY when both
            // conditions hold:
            //   (a) we got here via a credential-gathering / login-flow
            //       path (skips the Connected->revoke->Connected flap),
            //   (b) this JVM lifecycle authenticated: credentials were
            //       submitted (left Authenticating) or a 2FA challenge was
            //       answered (skips warm restarts, which do neither).
            // The is_credential_gathering check is necessary-but-not-
            // sufficient; cold_restart_equivalent_pending is the second
            // mandatory gate.
            let authenticated =
                self.state.is_credential_gathering() && self.cold_restart_equivalent_pending;
            // Settle a re-authentication the Sunday fire left owed.
            if let Some(owed_since) = self.cold_restart_owed_since.clone() {
                if authenticated {
                    log::info!(
                        "Owed Sunday re-authentication (owed since {}) completed by this login",
                        owed_since
                    );
                    self.cold_restart_owed_since = None;
                    self.restart_satisfied_by_boot = false;
                    self.record_cold_restart_outcome(
                        ColdRestartOutcome::Completed { at: jiff::Zoned::now() },
                        &next,
                    );
                } else if self.restart_satisfied_by_boot {
                    log::warn!(
                        "Owed Sunday re-authentication (owed since {}) still outstanding: this \
                         Connected did not log in, but the week's restart was this process's boot \
                         — no second restart; the login stays owed",
                        owed_since
                    );
                } else {
                    log::warn!(
                        "Owed Sunday re-authentication (owed since {}) still outstanding: \
                         this Connected did not authenticate (warm restart or reconnect) \
                         — running the cold restart now",
                        owed_since
                    );
                    self.cold_restart_fire_on_connected = true;
                }
            }
            if authenticated {
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
            // A session held: whatever conflict loop there was is over.
            self.session_conflicts.clear();
            self.session_conflict_breaker_open = false;
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
            self.hitl_connected_observation_ticks = 0;
            self.hitl_relogin_armed = false;
            self.hitl_2fa_closed_at = None;
            self.hitl_cancel_requested = false;
            self.hitl_relogin_armed_by = None;
            self.hitl_park_reason = None;
            self.prompt_cancel_sent_at = None;
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

        if matches!(next, State::Restarting | State::Error(_)) {
            self.record_relaunch(&next);
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
                self.twofa_challenge_seen = false;
                self.twofa_gone_at = None;
                self.twofa_challenge_opened_at = None;
                self.twofa_overdue_logged = false;
                self.prompt_cancel_sent_at = None;
            }
            State::DismissingPopups => {
                self.popup_last_dismissed = None;
            }
            State::ReconnectingSession => {
                self.relogin_attempts += 1;
            }
            State::Connected => {
                // The one moment the state machine is unambiguously sure no
                // login form is outstanding. Without this, do_connected's
                // popup-reconciliation sweep keeps dispatching to LoginHandler
                // forever against the Gateway's main window — see
                // DialogHandler::mark_login_complete.
                self.handler_registry.mark_login_complete();
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
                    // ONE consumer, ONE decision: the main loop's
                    // select! arm is the only reader of the cold-restart
                    // channel, and `cold_restart_decision::decide` is the
                    // only place that says what the fire means for the
                    // state this mode is in. "Restart completed" and
                    // "authentication completed" are separate: a mode that
                    // already restarted and is waiting on 2FA gets its login
                    // finished, not a second restart; a login in progress is
                    // never restarted under itself.
                    let preempts_hitl = self.config.twofa.backoff.cold_restart_preempts_hitl;
                    let outcome = cold_restart_decision::decide(
                        &self.state,
                        self.observation.has_2fa_dialog(),
                        preempts_hitl,
                    );
                    if cold_restart_decision::owes_reauth(&outcome) {
                        self.cold_restart_owed_since
                            .get_or_insert_with(jiff::Zoned::now);
                    }
                    let at_state = self.state.clone();
                    self.record_cold_restart_outcome(outcome.clone(), &at_state);
                    match outcome {
                        ColdRestartOutcome::Restarted => {
                            log::info!("Sunday cold restart — full re-authentication required");
                            self.abort_client_id_task();
                            self.apply_transition(State::Restarting).await?;
                        }
                        ColdRestartOutcome::ResumedLogin => {
                            self.resume_login_from_hitl("Sunday cold restart", RetryBy::SundayReauth).await?;
                        }
                        ColdRestartOutcome::ChallengePending => {
                            log::info!(
                                "Sunday cold restart — the Gateway shows an IB Key prompt that \
                                 may still be approvable (state={}); preserving it, \
                                 re-authentication owed",
                                at_state
                            );
                            if at_state == State::WaitingForHitl2fa && preempts_hitl {
                                // Arms the retry for when the Gateway closes it.
                                self.resume_login_from_hitl("Sunday cold restart", RetryBy::SundayReauth).await?;
                            }
                        }
                        ColdRestartOutcome::AwaitingOperator => log::warn!(
                            "Sunday cold restart — waiting for the operator's 2FA and \
                             cold_restart_preempts_hitl is off; nothing started, \
                             re-authentication owed"
                        ),
                        ColdRestartOutcome::Deferred => log::info!(
                            "Sunday cold restart deferred — a login is already in progress \
                             (state={}); no second restart, re-authentication owed",
                            at_state
                        ),
                        ColdRestartOutcome::Standby => log::info!(
                            "Sunday cold restart not applicable — standby awaiting activation"
                        ),
                        ColdRestartOutcome::Stopping => log::info!(
                            "Sunday cold restart not applicable — process is exiting"
                        ),
                        ColdRestartOutcome::Failed { ref detail } => log::error!(
                            "Sunday cold restart could not run — mode is in Error: {}; \
                             re-authentication owed",
                            detail
                        ),
                        // Never produced by `decide()`: a boot-after-target is
                        // reported by the scheduler's own signal, not a fire.
                        ColdRestartOutcome::RestartedByBoot => log::error!(
                            "cold_restart_decision::decide produced RestartedByBoot — not a fire outcome"
                        ),
                        // decide() never yields these: they are the scheduler's
                        // skip and the settlement of an owed re-auth.
                        ColdRestartOutcome::AlreadySatisfied { .. }
                        | ColdRestartOutcome::Completed { .. } => {}
                    }
                    self.publish_snapshot();
                }
                ColdRestartSignal::BootedAfterTarget { auth_satisfied_at: Some(at) } => {
                    log::info!("Sunday re-auth: this process booted after the target; a fresh login today at {} already satisfies it", at);
                    self.cold_restart_owed_since = None;
                    let at_state = self.state.clone();
                    self.record_cold_restart_outcome(ColdRestartOutcome::AlreadySatisfied { at }, &at_state);
                    self.publish_snapshot();
                }
                ColdRestartSignal::BootedAfterTarget { auth_satisfied_at: None } => {
                    // The boot is the week's restart; the login is owed, and
                    // stays visibly owed (STATUS, dashboard, the HITL alert if
                    // it parks) until a login succeeds.
                    log::warn!(
                        "Sunday re-auth: this gateway started after the scheduled time — that \
                         restart counts; its login is owed until it succeeds (state={})",
                        self.state
                    );
                    self.restart_satisfied_by_boot = true;
                    self.cold_restart_owed_since.get_or_insert_with(jiff::Zoned::now);
                    let at_state = self.state.clone();
                    self.record_cold_restart_outcome(ColdRestartOutcome::RestartedByBoot, &at_state);
                    self.publish_snapshot();
                }
                ColdRestartSignal::Skipped(ColdRestartSkipReason::FreshAuthToday { at }) => {
                    // The scheduler found this week's re-auth already done
                    // earlier today. Publish-only: never changes state.
                    log::info!(
                        "Sunday cold restart skipped — fresh auth already happened today at {}",
                        at
                    );
                    self.cold_restart_owed_since = None;
                    let at_state = self.state.clone();
                    self.record_cold_restart_outcome(
                        ColdRestartOutcome::AlreadySatisfied { at },
                        &at_state,
                    );
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
                // A (re)connect means our event history has a GAP: any
                // `-> connected` emitted while the stream was down was never
                // delivered. Trusting a pre-gap "disconnected" verdict across
                // that boundary would revoke a healthy session ~90s later —
                // reintroducing, by a different door, the false-positive class
                // this event was once removed for. Assume nothing across a
                // reconnect; the next real event re-establishes truth.
                self.agent_reported_disconnected = false;
                self.revocation
                    .clear(revocation::RevocationTag::AgentReportedDisconnect);
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
            // Semantic events — log for observability, state machine
            // uses these for richer context but core transitions still rely
            // on window_opened + has_login_button.
            AgentEvent::LoginFormReady { ref login_button, ref selected_mode, text_field_count, password_field_count, .. } => {
                log::info!(
                    "Event: login_form_ready (button={:?}, mode={:?}, fields={}/{})",
                    login_button, selected_mode, text_field_count, password_field_count
                );
                // Hand it to LoginHandler, which is waiting on exactly this to
                // decide the form is composed and the mode has taken effect.
                // The agent re-emits whenever any of these four values change,
                // so a null login_button here is corrected rather than final.
                let _ = self.handler_registry.login_form_tx.send(Some(
                    crate::agent_events::LoginFormState {
                        text_field_count,
                        password_field_count,
                        login_button: login_button.clone(),
                        selected_mode: selected_mode.clone(),
                    },
                ));
            }
            AgentEvent::TwofaPrompt { prompt_type, ref devices, .. } => {
                log::info!("Event: twofa_prompt (type={}, devices={:?})", prompt_type, devices);
            }
            AgentEvent::ErrorDialog { ref window_title, ref message, ref buttons, .. } => {
                log::info!(
                    "Event: error_dialog '{}' (message={:?}, buttons={:?})",
                    window_title, message, buttons
                );
                // It names the other session's IP and login time.
                if window_title.to_lowercase().contains("existing session") {
                    self.last_conflict_message = message.clone();
                }
            }
            AgentEvent::ConnectionStatusChanged { ref from, ref to, .. } => {
                // This event does NOT drive state changes directly — that caused
                // false-positive restarts, because stale "disconnected" events
                // arrive while the machine is still in Launching/Login and would
                // fire against the session that is only just starting.
                //
                // But discarding it entirely (the earlier behaviour) left
                // Connected with only ONE way to notice a dead session: active
                // label inspection, which depends on the Gateway UI rendering a
                // readable status. Seen in production: one disconnect was revoked
                // via disconnected_label in 7ms, yet two others lasting 20s and
                // 25s produced NO revocation at all and Connected was wrongly
                // retained.
                //
                // Why the label path missed those two is NOT established — UI
                // refresh lag, a different label variant, and debounce timing are
                // all plausible and the logs do not distinguish them (label
                // inspection only logs when it fires). What matters is that the
                // agent's report is an INDEPENDENT signal that does not depend on
                // UI rendering at all, so it still holds when the label path,
                // for whatever reason, does not.
                //
                // So: record the agent's verdict here, and let `do_connected`
                // decide. Scoping consumption to Connected (plus the reset on
                // entry to Connected) preserves the original false-positive
                // guarantee while restoring the authoritative signal.
                let disconnected = to.eq_ignore_ascii_case("disconnected");
                if disconnected != self.agent_reported_disconnected {
                    self.agent_reported_disconnected = disconnected;
                    if !disconnected {
                        // Connection came back — cancel any pending debounce so
                        // the routine ~20-25s nightly blip never matures.
                        self.revocation
                            .clear(revocation::RevocationTag::AgentReportedDisconnect);
                    }
                }
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

    /// Per-tick recovery coordinator drive.
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
        // TODO: sample cold-restart FireEligible from the
        // scheduler. Passing false for now means the recovery arc runs
        // even when a cold restart is imminent — worst case, coordinator
        // escalates one phase early and the marker gets rewritten twice
        // (once here, once after the cold-restart re-auth completes).
        let cold_pending = false;
        // TODO: fingerprint tracking. Passing 0 means the
        // fingerprint tripwire never fires — only time-based
        // escalation is active until fingerprint tracking lands.
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
                        // nothing further to do here until per-phase
                        // throttling of the reconnect cadence is
                        // wired.
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

    /// Finish a login that is waiting for the operator's 2FA by retrying it
    /// in the JVM that is already running. The ONE resume path, shared by
    /// the operator's `HITL_RESUME` and the Sunday cold restart,
    /// so the two can never start competing recoveries: whichever arrives
    /// second finds the mode no longer in `WaitingForHitl2fa` (the other is
    /// `Deferred`, the command is ignored). Goes through `apply_transition`
    /// so leaving HITL clears its bookkeeping.
    ///
    /// Does NOT touch the 2FA attempt budget: a resume grants the one
    /// attempt its login makes; a timeout lands back in HITL with a fresh
    /// page to the operator.
    async fn resume_login_from_hitl(&mut self, source: &str, by: RetryBy) -> Result<(), StateMachineError> {
        let next = self.begin_in_jvm_relogin(source, by);
        if next == self.state {
            return Ok(());
        }
        self.apply_transition(next).await
    }

    /// Decide how a login parked in `WaitingForHitl2fa` is retried, and set
    /// up that retry. Returns the state to move to.
    ///
    /// * `Authenticating`, in the running JVM: the login handler's submit
    ///   guard is reset and `do_authenticate` re-submits the credentials
    ///   into the Gateway's login form. The JVM that restarted overnight
    ///   already did the restart; what is outstanding is the login.
    ///   IBC does the same with
    ///   `ReloginAfterSecondFactorAuthenticationTimeout=yes`.
    /// * `WaitingForHitl2fa`, armed, while the Gateway still shows the IB
    ///   Key dialog: that push may still be approvable, and a second login
    ///   under it would replace it. The HITL tick re-submits once the
    ///   Gateway closes the dialog.
    /// * `Restarting` only when the JVM has exited: there is no login form
    ///   left to re-submit into. The Gateway does exit on its own after some
    ///   failed 2FA rounds (with exit status 0).
    fn begin_in_jvm_relogin(&mut self, source: &str, by: RetryBy) -> State {
        if !self.supervisor.is_running() {
            log::error!(
                "{} — cannot retry the login in the running Gateway: the JVM has exited, \
                 so there is no login form to re-submit into; relaunching it \
                 (2FA attempts used so far: {})",
                source,
                self.consecutive_2fa_timeouts,
            );
            return self.relaunch(RelaunchReason::JvmExited);
        }
        if self.observation.has_2fa_dialog() {
            if self.hitl_cancel_requested {
                log::warn!(
                    "{} — the Gateway still shows an IB Key prompt; closing it with its \
                     Cancel, then re-submitting the login in the running Gateway (no JVM restart)",
                    source,
                );
            } else if !self.hitl_relogin_armed {
                log::warn!(
                    "{} — the Gateway still shows an IB Key prompt, which may still be \
                     approvable; the login will be re-submitted in the running Gateway \
                     once the Gateway closes it (no JVM restart)",
                    source,
                );
            }
            self.hitl_relogin_armed = true;
            self.hitl_relogin_armed_by = self.hitl_relogin_armed_by.max(Some(by));
            return State::WaitingForHitl2fa;
        }
        log::warn!(
            "{} — re-submitting the login in the running Gateway (no JVM restart; \
             2FA attempts used so far: {})",
            source,
            self.consecutive_2fa_timeouts,
        );
        self.handler_registry.reset();
        // The agent retires its form watcher once a login is submitted, so
        // the last `login_form_ready` the handler holds describes the form
        // as it was BEFORE that submit (it has "verified" a form with no
        // username field this way). Drop it; the handler then judges the
        // form from a fresh dump.
        let _ = self.handler_registry.login_form_tx.send(None);
        self.in_jvm_relogin_since = Some(Instant::now());
        self.in_jvm_relogin_by = Some(by);
        State::Authenticating
    }

    /// Record the latest Sunday re-authentication outcome for STATUS JSON.
    fn record_cold_restart_outcome(&mut self, outcome: ColdRestartOutcome, at_state: &State) {
        self.last_cold_restart_outcome = Some(ColdRestartOutcomeRecord {
            recorded_at: jiff::Zoned::now(),
            outcome,
            state: at_state.to_string(),
        });
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
        if let Some(next) = self.check_jvm_exit() {
            return Ok(next);
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
        // Don't touch the login window — just wait for the main Gateway window.
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
        if let Some(next) = self.check_jvm_exit() {
            return Ok(next);
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
                    // The cached flag was cleared when the last login was
                    // submitted and is never re-learned — the agent retires
                    // its form watcher after a submit. A form that came back
                    // in this JVM (revoke, refused push, RE-LOGIN dialog)
                    // would read as "authenticated" and be walked past.
                    // Look before concluding.
                    if self.gateway_shows_usable_login_form().await {
                        return Ok(self.begin_in_jvm_relogin(
                            "WaitingForLogin: login form back in the running Gateway",
                            RetryBy::NewLogin,
                        ));
                    }
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
        if let Some(since) = self.in_jvm_relogin_since {
            return self.do_authenticate_in_running_jvm(since).await;
        }
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
                // Credentials went in: a Connected in this JVM is now an
                // authentication (see `cold_restart_equivalent_pending`).
                self.cold_restart_equivalent_pending = true;
                self.last_login_action_at = Some(jiff::Timestamp::now());
                // The login window will morph into the connected window without
                // closing/reopening (IB Gateway mutates in place). Clear the cached
                // has_login_button flag so do_connected() doesn't see a stale "login form".
                self.observation.clear_login_buttons();
            }
            Some(Ok(crate::handlers::HandlerResult::Error(msg))) => {
                log::error!("Login handler reported error: {} — retrying", msg);
                self.handler_registry.reset();
                // Back off like the NotApplicable and None arms below. This arm
                // had no sleep, which did not matter while the login handler
                // could not actually report an error; now that it fails closed
                // on an unverified mode or a missing field, this is a real
                // retry path and it should not spin on the login form. The
                // loop stays bounded by login_dialog_timeout_secs because
                // returning the same state does not reset state_entered_at.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
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

    /// `do_authenticate` for a login retried inside the running JVM
    /// (`begin_in_jvm_relogin`). Differs from the fresh-JVM path in the two
    /// places where that path's assumptions do not hold for a JVM that has
    /// been through a login already:
    ///
    /// * It looks for the form in EVERY Gateway window. A Gateway mid-login
    ///   can show two windows titled "IBKR Gateway", and the first match need not be the one with the form.
    /// * "No text fields" is NOT read as "already authenticated" — here it
    ///   can be a form that has not redrawn yet. Only the status panel saying
    ///   "API Server: connected" means the login is done.
    ///
    /// Never returns `WaitingForLogin`: its cached fast path trusts a
    /// login-button flag that was cleared when the previous login was
    /// submitted, and would misroute this retry to DismissingPopups. The
    /// only way to a JVM restart is `IN_JVM_RELOGIN_FORM_GRACE` passing
    /// with no form and no connection, logged as an error naming why.
    async fn do_authenticate_in_running_jvm(
        &mut self,
        since: Instant,
    ) -> Result<State, StateMachineError> {
        if let Some(next) = self.check_jvm_exit() {
            log::error!(
                "In-JVM login retry: the JVM exited under the retry — relaunching \
                 (nothing left to re-submit into)"
            );
            return Ok(next);
        }

        // Everything below is read from the Gateway now — the window list and
        // each window's component dump — not from the event cache, which can
        // miss a dialog across a stream gap and never re-learns a returned
        // login form.
        let windows = self.agent_client.list_windows().await?;
        for w in &windows {
            match Self::classify_blocking_dialog(&w.title) {
                Some(State::WaitingFor2fa) => {
                    // A push from the previous login is still on screen: do
                    // not submit under it. Waiting on it doesn't use up the
                    // form grace — the Gateway closes it itself.
                    log::info!(
                        "In-JVM login retry: the Gateway still shows '{}' — waiting for it to close",
                        w.title
                    );
                    self.in_jvm_relogin_since = Some(Instant::now());
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    return Ok(State::Authenticating);
                }
                Some(next_state) => {
                    log::info!(
                        "In-JVM login retry: blocking dialog '{}' — transitioning to {}",
                        w.title,
                        next_state
                    );
                    return Ok(next_state);
                }
                None => {}
            }
        }

        let mut login_window = None;
        let mut connected = false;
        for w in windows.iter().filter(|w| {
            let t = w.title.to_lowercase();
            (t.contains("ib gateway") || t.contains("ibkr gateway")) && !t.contains("configuration")
        }) {
            match self.agent_client.dump_components(w.id).await {
                Ok(components) => {
                    if components_have_usable_login_form(&components) {
                        login_window = Some(w.clone());
                        break;
                    }
                    connected |= components_indicate_connected(&components);
                }
                Err(e) => log::debug!("In-JVM login retry: dump of '{}' failed: {}", w.title, e),
            }
        }

        // While the Gateway re-logs in by itself (its own "Login" window after
        // a backend drop) the login handler declines, and this retries until
        // that login ends: connected (above) or its window closes.
        if let Some(win) = login_window {
            // A form proves a retry is possible, not that one is wanted. The
            // policy's own retries don't push inside unattended hours, even
            // when they were decided in attended time and waited on a
            // prompt since. The operator's Retry, the Sunday
            // re-auth and a new login are not held.
            if self.in_jvm_relogin_by == Some(RetryBy::Policy) {
                if let Some(w) = self
                    .config
                    .twofa
                    .backoff
                    .unattended
                    .filter(|w| w.contains(jiff::Zoned::now().time()))
                {
                    log::warn!(
                        "In-JVM login retry held: it is the backoff policy's, and it is now \
                         inside unattended hours ({w}) — parking instead of sending an IB Key \
                         push nobody will answer"
                    );
                    self.hitl_park_reason = Some(HitlParkReason::UnattendedHours);
                    return Ok(State::WaitingForHitl2fa);
                }
            }
            match self.handler_registry.dispatch(&self.agent_client, &win).await {
                Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                    log::info!(
                        "Login re-submitted in the running Gateway after {}s (no JVM restart)",
                        since.elapsed().as_secs()
                    );
                    // Credentials went in: a Connected in this JVM is now an
                    // authentication (see `cold_restart_equivalent_pending`).
                    self.cold_restart_equivalent_pending = true;
                    self.last_login_action_at = Some(jiff::Timestamp::now());
                    self.observation.clear_login_buttons();
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    return Ok(State::WaitingFor2fa);
                }
                other => {
                    let why = match other {
                        Some(Ok(result)) => format!("{result:?}"),
                        Some(Err(e)) => e.to_string(),
                        None => "no handler matched".to_string(),
                    };
                    log::warn!(
                        "In-JVM login retry: login form found in '{}' but not submitted ({}) — retrying",
                        win.title,
                        why
                    );
                    self.handler_registry.reset();
                }
            }
        } else if connected {
            log::info!(
                "In-JVM login retry: the Gateway reports \"API Server: connected\" — the \
                 pending login completed; nothing to re-submit"
            );
            // Its push was answered in this JVM: an authentication, as for
            // the HITL positive probe (WaitingForHitl2fa -> WaitingForApiReady).
            self.cold_restart_equivalent_pending = true;
            return Ok(State::DismissingPopups);
        }

        if since.elapsed() >= IN_JVM_RELOGIN_FORM_GRACE {
            log::error!(
                "In-JVM login retry not possible in this Gateway: no usable login form \
                 appeared within {}s and it is not connected — relaunching the JVM, \
                 the only other way to get a login form",
                IN_JVM_RELOGIN_FORM_GRACE.as_secs()
            );
            return Ok(self.relaunch(RelaunchReason::NoUsableLoginForm));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::Authenticating)
    }

    /// Whether any Gateway window shows a login form a login can use, read
    /// from live component dumps — never the observation cache.
    async fn gateway_shows_usable_login_form(&self) -> bool {
        let Ok(windows) = self.agent_client.list_windows().await else {
            return false;
        };
        for w in windows.iter().filter(|w| {
            let t = w.title.to_lowercase();
            (t.contains("ib gateway") || t.contains("ibkr gateway")) && !t.contains("configuration")
        }) {
            if let Ok(components) = self.agent_client.dump_components(w.id).await {
                if components_have_usable_login_form(&components) {
                    return true;
                }
            }
        }
        false
    }

    /// The 2FA round ended without authenticating and the Gateway put its
    /// login form back in the running JVM (the push was refused, or IBKR
    /// rejected it). Counted against the 2FA attempt budget like a timeout;
    /// while budget remains the login is retried in this JVM, with the form
    /// judged afresh. It used to go to WaitingForLogin, whose cached
    /// "no login button" (cleared at submit, never re-learned) called the
    /// JVM authenticated — and then the popup sweep re-submitted behind it.
    ///
    /// The ONE place a 2FA round's end is turned into what happens next
    ///: no clock ends a round, only the Gateway — its prompt closed
    /// and the form back, a stuck prompt cancelled, or a challenge that never
    /// opened. Inside the configured unattended hours the first failed round
    /// parks: nobody is up to answer another push.
    fn after_failed_2fa_round(&mut self) -> State {
        self.consecutive_2fa_timeouts = self.consecutive_2fa_timeouts.saturating_add(1);
        if !self.config.twofa.relogin_after_timeout
            && self.config.twofa.timeout_action == crate::config::TwoFaTimeoutAction::Exit
        {
            log::error!("2FA round failed — shutting down (twofa.timeout_action = exit)");
            return State::Shutdown;
        }
        let backoff = &self.config.twofa.backoff;
        let unattended = backoff
            .unattended
            .filter(|w| w.contains(jiff::Zoned::now().time()));
        let park = if unattended.is_some() {
            Some(HitlParkReason::UnattendedHours)
        } else {
            match backoff.on_timeout {
                crate::config::TwoFaOnTimeout::RestartForever => None,
                crate::config::TwoFaOnTimeout::HitlImmediately => Some(HitlParkReason::HitlImmediately),
                crate::config::TwoFaOnTimeout::RestartThenHitl => (self.consecutive_2fa_timeouts
                    >= backoff.max_immediate_attempts)
                    .then_some(HitlParkReason::AttemptsExhausted),
            }
        };
        let why = match (park, unattended) {
            (Some(HitlParkReason::UnattendedHours), Some(w)) => format!(
                " — unattended hours ({w}): keeping the Gateway and waiting for you \
                 instead of sending another push"
            ),
            (Some(_), _) => " — waiting for the operator".to_string(),
            (None, _) => String::new(),
        };
        log::warn!(
            "2FA FAILED — the round ended without a login (2FA rounds without \
             success: {}/{}){}",
            self.consecutive_2fa_timeouts,
            backoff.max_immediate_attempts,
            why,
        );
        if let Some(reason) = park {
            self.hitl_park_reason = Some(reason);
            return State::WaitingForHitl2fa;
        }
        self.begin_in_jvm_relogin("2FA round failed", RetryBy::Policy)
    }

    /// The host maintenance hold file for this mode: next to the
    /// cold-restart-equivalent marker, where the scheduler reads it.
    fn maintenance_hold_path(&self) -> std::path::PathBuf {
        let dir = self
            .cold_restart_equivalent_marker_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        crate::maintenance_hold::path_in(dir)
    }

    /// `MAINT_HOLD`: the host is about to update the
    /// container runtime; the Sunday fire waits. One maintenance at a time —
    /// the same id may extend its own hold. Nothing about the gateway changes.
    fn maintenance_hold(&mut self, id: &str, ttl_secs: u64) {
        let path = self.maintenance_hold_path();
        let now = jiff::Timestamp::now();
        if let Some(active) = crate::maintenance_hold::read(&path).filter(|h| h.active_at(now)) {
            if active.id != id {
                log::error!(
                    "MAINT_HOLD '{}' refused: maintenance '{}' already holds the Sunday re-auth \
                     until {}",
                    id, active.id, active.expires_at
                );
                return;
            }
        }
        let hold = match crate::maintenance_hold::Hold::new(id, ttl_secs, now) {
            Ok(h) => h,
            Err(e) => {
                log::error!("MAINT_HOLD refused: {e}");
                return;
            }
        };
        match crate::maintenance_hold::write(&path, &hold) {
            Ok(()) => log::warn!(
                "Host maintenance '{}' holds the Sunday re-auth until {} ({}s) — the gateway is \
                 left alone; ibctl decides what it needs once the hold ends",
                id, hold.expires_at, ttl_secs
            ),
            Err(e) => log::error!(
                "MAINT_HOLD '{}': cannot write {} ({}) — NOT held; the Sunday re-auth may race \
                 the host update",
                id, path.display(), e
            ),
        }
        self.publish_snapshot();
    }

    /// `MAINT_RELEASE`: the maintenance is over. Only its own id releases
    /// it. The next scheduler tick decides on what it observes then.
    fn maintenance_release(&mut self, id: &str, result: &str) {
        let path = self.maintenance_hold_path();
        match crate::maintenance_hold::read(&path) {
            Some(h) if h.id == id => {
                if let Err(e) = crate::maintenance_hold::clear(&path) {
                    log::error!("MAINT_RELEASE '{}': cannot remove {} ({})", id, path.display(), e);
                    return;
                }
                log::warn!(
                    "Host maintenance '{}' released ({}) — the Sunday re-auth is decided on what \
                     the gateway shows now",
                    id, result
                );
                self.last_maintenance = Some(types::MaintenanceRecord {
                    id: id.to_string(),
                    result: result.to_string(),
                    released_at: jiff::Zoned::now(),
                });
            }
            Some(h) => log::warn!(
                "MAINT_RELEASE '{}' ignored: the hold on file is '{}'",
                id, h.id
            ),
            None => log::warn!("MAINT_RELEASE '{}' ignored: no hold on file", id),
        }
        self.publish_snapshot();
    }

    /// Relaunch the Gateway JVM for `reason`. The only ways off the login
    /// path to a new JVM; `apply_transition` records the reason.
    fn relaunch(&mut self, reason: RelaunchReason) -> State {
        self.relaunch_reason = Some(reason);
        State::Restarting
    }

    /// Record an entry into `Restarting` for STATUS `last_relaunch`. The
    /// tripwire: a relaunch from a login state while the running JVM shows
    /// an IB Key prompt, with no recorded reason, abandons an outstanding
    /// push — the abandoned-prompt failure.
    fn record_relaunch(&mut self, next: &State) {
        let reason = self.relaunch_reason.take();
        let from_login = matches!(
            self.state,
            State::WaitingFor2fa | State::WaitingForHitl2fa | State::Authenticating
        );
        let abandoned_prompt = reason.is_none()
            && from_login
            && self.supervisor.is_running()
            && self.observation.has_2fa_dialog();
        if abandoned_prompt {
            log::error!(
                "TRIPWIRE abandoned_prompt: relaunching the Gateway JVM from {} while it shows an IB \
                 Key prompt, with no recorded reason — an outstanding push is being abandoned",
                self.state
            );
        }
        let detail = match (reason, next) {
            (Some(r), _) => r.describe().to_string(),
            (None, State::Error(msg)) => format!("error: {msg}"),
            (None, _) => String::new(),
        };
        self.last_relaunch = Some(RelaunchRecord {
            at: jiff::Zoned::now(),
            from_state: self.state.to_string(),
            reason: reason.map_or("unspecified", RelaunchReason::as_str),
            detail,
            abandoned_prompt,
        });
    }

    /// Click Cancel on the IB Key prompt in `window` (the stuck
    /// ceiling, or the operator's Retry). What the Gateway does next is
    /// unverified; `PROMPT_CANCEL_GRACE` bounds it either way.
    async fn cancel_ib_key_prompt(&mut self, window: crate::types::WindowId) {
        match self.agent_client.click_button(window, "Cancel").await {
            Ok(true) => log::warn!("Clicked Cancel on the IB Key prompt"),
            Ok(false) => log::error!("The IB Key prompt has no Cancel button"),
            Err(e) => log::error!("Clicking Cancel on the IB Key prompt failed: {}", e),
        }
        self.prompt_cancel_sent_at = Some(Instant::now());
    }

    /// A Cancel ibctl clicked has had its grace and the prompt is still
    /// open: the in-JVM recovery failed, relaunch.
    fn prompt_ignored_cancel(&mut self) -> Option<State> {
        let sent = self.prompt_cancel_sent_at?;
        if sent.elapsed() < PROMPT_CANCEL_GRACE {
            return None;
        }
        log::error!(
            "The IB Key prompt is still open {}s after ibctl clicked its Cancel — \
             relaunching the JVM, the only other way out of it",
            sent.elapsed().as_secs()
        );
        Some(self.relaunch(RelaunchReason::PromptIgnoredCancel))
    }

    /// What the Gateway shows once an IB Key prompt has closed — expiry,
    /// refusal, approval and ibctl's own Cancel all close it — read from live
    /// dumps of its main windows. The ONE judgement both the 2FA wait and the
    /// HITL retry use: "connected" is a login, the form back
    /// is a failed round, and neither means keep looking, bounded by
    /// `CONFIRM_AFTER_CHALLENGE_CLOSE`.
    async fn gateway_after_prompt_closed(&self) -> AfterPrompt {
        let Ok(windows) = self.agent_client.list_windows().await else {
            return AfterPrompt::Nothing;
        };
        let (mut connected, mut form) = (false, false);
        for w in windows.iter().filter(|w| {
            let t = w.title.to_lowercase();
            t.contains("ib gateway") || t.contains("ibkr gateway")
        }) {
            if let Ok(components) = self.agent_client.dump_components(w.id).await {
                connected |= components_indicate_connected(&components);
                form |= components_have_login_form(&components);
            }
        }
        if connected {
            AfterPrompt::Connected
        } else if form {
            AfterPrompt::LoginForm
        } else {
            AfterPrompt::Nothing
        }
    }

    /// The challenge is on screen: the push is outstanding. Nothing here
    /// ends the round. Past `timeout_seconds` the operator is told
    /// it is waiting; past `STUCK_PROMPT_CEILING` the Gateway is taken to be
    /// stuck and the prompt is cancelled in the running JVM.
    async fn escalate_open_prompt(&mut self, window: crate::types::WindowId) -> Option<State> {
        let open_for = self
            .twofa_challenge_opened_at
            .get_or_insert_with(Instant::now)
            .elapsed();
        if self.prompt_cancel_sent_at.is_some() {
            return self.prompt_ignored_cancel();
        }
        if open_for >= STUCK_PROMPT_CEILING {
            log::error!(
                "IB Key prompt open for {}s, past the {}s stuck ceiling (the Gateway has \
                 closed them itself after about 17 minutes) — cancelling it in the running Gateway",
                open_for.as_secs(),
                STUCK_PROMPT_CEILING.as_secs(),
            );
            self.cancel_ib_key_prompt(window).await;
            return None;
        }
        if !self.twofa_overdue_logged
            && open_for >= std::time::Duration::from_secs(self.config.twofa.timeout_seconds)
        {
            self.twofa_overdue_logged = true;
            log::warn!(
                "IB Key push unanswered for {}s — keeping it: approve it in IBKR Mobile if \
                 your phone shows it. The Gateway ends the round by closing the prompt; \
                 ibctl retries then, in the running Gateway",
                open_for.as_secs()
            );
            self.publish_snapshot();
        }
        None
    }

    /// Single-step: check for 2FA dialog, handle TOTP/device selection, return.
    /// State tracked via twofa_seen, twofa_gone_at, twofa_device_selected fields.
    /// Deadline tracked via state_entered_at.
    async fn do_wait_for_2fa(&mut self) -> Result<State, StateMachineError> {
        if let Some(next) = self.check_jvm_exit() {
            return Ok(next);
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

                    // Once the device has been chosen, a 2FA dialog on screen is
                    // the challenge: the picker closed on our OK two seconds ago.
                    if self.twofa_device_selected {
                        self.twofa_challenge_seen = true;
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
                                    self.twofa_challenge_seen = true;
                                }
                            }
                        } else {
                            self.twofa_device_selected = true;
                            self.twofa_challenge_seen = true;
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

                    if self.twofa_challenge_seen {
                        if let Some(next) = self.escalate_open_prompt(win.id).await {
                            return Ok(next);
                        }
                    }
                } else if self.twofa_seen && !self.twofa_challenge_seen {
                    // Only the device picker has closed: the challenge is still
                    // to come. Nothing here is evidence of a login — the main
                    // window has had no text fields during a false
                    // "2FA SUCCEEDED" too. Keep waiting, `timeout_seconds` from
                    // the close at most.
                    if self.twofa_gone_at.is_none() {
                        self.twofa_gone_at = Some(Instant::now());
                        log::info!("2FA device picker closed — waiting for the IB Key challenge");
                    }
                    // A challenge approved between two polls would never be
                    // seen; the status panel saying connected still proves it.
                    for w in windows.iter().filter(|w| {
                        let t = w.title.to_lowercase();
                        t.contains("ib gateway") || t.contains("ibkr gateway")
                    }) {
                        if let Ok(components) = self.agent_client.dump_components(w.id).await {
                            if components_indicate_connected(&components) {
                                log::info!(
                                    "2FA SUCCEEDED — Gateway reports \"API Server: connected\" \
                                     (challenge answered between polls)"
                                );
                                return Ok(State::DismissingPopups);
                            }
                        }
                    }
                    let waited = self.twofa_gone_at.map(|t| t.elapsed()).unwrap_or_default();
                    if waited >= std::time::Duration::from_secs(self.config.twofa.timeout_seconds) {
                        log::warn!(
                            "The IB Key challenge never appeared {}s after the device picker \
                             closed, and the Gateway is not connected — treating the round as failed",
                            waited.as_secs()
                        );
                        return Ok(self.after_failed_2fa_round());
                    }
                } else if self.twofa_seen {
                    // FAIL-CLOSED 2FA verification.
                    //
                    // The CHALLENGE was seen and is now closed (the picker
                    // closing is handled above). Expiry, refusal and approval
                    // all close it, so the close only permits checking:
                    //   - "API Server: connected"  → approved (positive evidence)
                    //   - login form back          → failed round
                    //   - neither                  → keep confirming, bounded by
                    //     CONFIRM_AFTER_CHALLENGE_CLOSE; the 2FA timeout below
                    //     is suspended meanwhile — the round is over.
                    // "Gateway window with zero text fields" used to count as
                    // success; the main window of an unauthenticated Gateway
                    // has none either.

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
                        // Settling window passed. Inspect the live windows — not
                        // the observation cache, not timers.
                        match self.gateway_after_prompt_closed().await {
                            AfterPrompt::Connected => {
                                log::info!(
                                    "2FA SUCCEEDED — Gateway reports \"API Server: connected\" \
                                     (positive confirmation via object inspection)"
                                );
                                return Ok(State::DismissingPopups);
                            }
                            AfterPrompt::LoginForm => return Ok(self.after_failed_2fa_round()),
                            AfterPrompt::Nothing => {}
                        }

                        let closed_for = self.twofa_gone_at.map(|t| t.elapsed()).unwrap_or_default();
                        if closed_for >= CONFIRM_AFTER_CHALLENGE_CLOSE {
                            log::error!(
                                "2FA result unconfirmed: the challenge closed {}s ago and the \
                                 Gateway shows neither its login form nor \"API Server: \
                                 connected\" — treating the round as failed",
                                closed_for.as_secs()
                            );
                            return Ok(self.after_failed_2fa_round());
                        }
                        log::debug!("2FA challenge closed — waiting for the Gateway to report connected");
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

        // No clock ends the round. The Gateway does: it closes the
        // prompt (then the form back is a failed round, "connected" a login),
        // or it never shows one after the picker. An open prompt only
        // escalates — an alert, then the stuck ceiling. The 120 s timer that
        // used to stand here relaunched the JVM under prompts still open.

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(State::WaitingFor2fa)
    }

    async fn do_handle_session_conflict(&mut self) -> Result<State, StateMachineError> {
        let windows = self.agent_client.list_windows().await?;
        let Some(win) = windows
            .iter()
            .find(|w| w.title.to_lowercase().contains("existing session"))
        else {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            return Ok(State::DismissingPopups);
        };

        // Breaker open: the dialog stays on screen for a human.
        if self.session_conflict_breaker_open {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            return Ok(State::HandlingSessionConflict);
        }

        let now = Instant::now();
        self.session_conflicts
            .retain(|t| now.duration_since(*t) < session_conflict::BREAKER_WINDOW);
        self.session_conflicts.push_back(now);
        let recent = self.session_conflicts.len();
        let evidence = self
            .last_conflict_message
            .as_deref()
            .and_then(session_conflict::parse_evidence);
        let self_inflicted = evidence.as_ref().is_some_and(|e| {
            session_conflict::looks_self_inflicted(e.other_connected_at, self.last_login_action_at)
        });
        self.last_session_conflict = Some(crate::state_machine::types::SessionConflictRecord {
            at: jiff::Zoned::now(),
            other_ip: evidence.as_ref().map(|e| e.other_ip.clone()),
            other_connected_at: evidence.as_ref().map(|e| e.other_connected_at),
            self_inflicted,
            recent,
        });
        let who = match &evidence {
            Some(e) => format!("IP {} logged in at {}", e.other_ip, e.other_connected_at),
            None => "unidentified (dialog text not read)".to_string(),
        };
        let mirror = if self_inflicted {
            " — that is the session this Gateway's own last login created: it is displacing itself"
        } else {
            ""
        };
        log::warn!(
            "Session conflict {} of {} allowed in {} min: other session {}{}",
            recent,
            session_conflict::BREAKER_THRESHOLD,
            session_conflict::BREAKER_WINDOW.as_secs() / 60,
            who,
            mirror,
        );

        if recent >= session_conflict::BREAKER_THRESHOLD {
            self.session_conflict_breaker_open = true;
            log::error!(
                "Session-conflict loop: {} conflicts within {} min — no longer answering the \
                 dialog, which stays on screen for a human. Other session: {}{}. Answering \
                 it again only hands the session back and forth. \
                 Resolve the other session, then RESTART this mode.",
                recent,
                session_conflict::BREAKER_WINDOW.as_secs() / 60,
                who,
                mirror,
            );
            self.publish_snapshot();
            return Ok(State::HandlingSessionConflict);
        }

        match self.handler_registry.dispatch(&self.agent_client, win).await {
            Some(Ok(crate::handlers::HandlerResult::Handled)) => {
                log::info!("Session conflict resolved");
                // A takeover is a login action: the next dialog naming a
                // session from this moment names our own.
                self.last_login_action_at = Some(jiff::Timestamp::now());
            }
            Some(Ok(other)) => log::warn!("Session conflict dialog not answered: {:?}", other),
            Some(Err(e)) => log::error!("Session conflict handling failed: {}", e),
            None => log::warn!("No handler matched session conflict dialog"),
        }

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        Ok(State::DismissingPopups)
    }

    /// Single-step: dispatch popups once, check quiet period, return.
    /// Quiet period tracked via popup_last_dismissed. Deadline via state_entered_at.
    async fn do_dismiss_popups(&mut self) -> Result<State, StateMachineError> {
        if let Some(next) = self.check_jvm_exit() {
            return Ok(next);
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
                if let Some(Ok(_)) = self.handler_registry.dispatch_popup(&self.agent_client, win).await {
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
        if let Some(next) = self.check_jvm_exit() {
            return Ok(next);
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
        if let Some(next) = self.check_jvm_exit() {
            self.config_retries = 0;
            return Ok(next);
        }

        self.config_retries += 1;
        log::info!(
            "Applying post-login API configuration (attempt {}/{})",
            self.config_retries, MAX_CONFIG_RETRIES
        );

        let mut settings = crate::handlers::api_config::ApiConfigSettings::from_env();
        self.localize_restart_time(&mut settings);

        match crate::handlers::api_config::apply_api_config(&self.agent_client, &settings, self.config.timing.ui_tick_ms).await {
            Ok(report) => {
                log::info!("API configuration complete");
                if let Some(outcome) = report.auto_restart.clone() {
                    self.record_restart_time("login", outcome);
                }
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
        // An owed Sunday re-authentication arrived at Connected without
        // authenticating (apply_transition decided this). Run the cold
        // restart now — the one restart, after the in-progress login ended.
        if std::mem::take(&mut self.cold_restart_fire_on_connected) {
            self.cold_restart_owed_since = None;
            self.record_cold_restart_outcome(ColdRestartOutcome::Restarted, &State::Connected);
            log::info!("Sunday cold restart — full re-authentication required (owed since the scheduled fire)");
            self.publish_snapshot();
            self.abort_client_id_task();
            return Ok(State::Restarting);
        }

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
        // stop_socat / abort_client_id_task / connected_window_class /
        // handler_registry.reset are handled centrally in apply_transition
        // when we leave Connected — see the curr_is_connected branch.
        if let Some(next) = self.check_jvm_exit() {
            // Record & fire — zero debounce ⇒ matures immediately. This
            // bookkeeping is Connected-specific (a "proof" of connectedness
            // is being revoked), so it stays here rather than in
            // check_jvm_exit() — the other six call sites were never in
            // Connected and have no such proof to revoke.
            let src = revocation::RevocationSource::JvmDied;
            if self.revocation.observe(src).is_some() {
                log::warn!("proof revoked source=jvm_died next={}", next);
            }
            return Ok(next);
        }

        // --- Agent-reported disconnect (backstop for blind label inspection) ---
        // The agent told us the session dropped. Label inspection is the fast
        // path and usually beats this, but it cannot see a disconnect once the
        // Gateway has fallen back to a login prompt — there is no connection
        // label on that window. This source is driven by the agent's own report
        // so it cannot be blinded the same way. Long debounce (90s) keeps the
        // routine ~20-25s nightly IB blip from forcing a needless re-login.
        if self.agent_reported_disconnected {
            let src = revocation::RevocationSource::AgentReportedDisconnect;
            if let Some(fired) = self.revocation.observe(src) {
                let next = fired.next_state();
                log::warn!(
                    "proof revoked source=agent_reported_disconnect next={} \
                     (agent reported the session dropped and has not reported \
                     reconnection since; label inspection did not catch it, \
                     which is expected when the Gateway is on a login prompt)",
                    next
                );
                self.agent_reported_disconnected = false;
                self.revocation
                    .clear(revocation::RevocationTag::AgentReportedDisconnect);
                return Ok(next);
            }
        } else {
            self.revocation
                .clear(revocation::RevocationTag::AgentReportedDisconnect);
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

        // Track class changes (informational; not a revocation source)
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
                let _ = self.handler_registry.dispatch_popup(&self.agent_client, win).await;
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
                // FAIL-CLOSED re-login verification.
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

    /// Detect a JVM that has exited, and arm a warm restart if Gateway left
    /// an autorestart token behind before dying.
    ///
    /// # Why this exists
    ///
    /// Gateway's own scheduled `AUTO_RESTART_TIME` drops the API connection
    /// several seconds BEFORE the JVM process actually exits. On most days
    /// that gap is short: `do_connected()`'s own JVM-health check (zero
    /// debounce) observes the death first, while we are still in Connected,
    /// and correctly finds the token — a clean warm restart, no 2FA.
    ///
    /// When the gap is long enough, `DisconnectedLabelStable`'s
    /// 2s debounce matures FIRST, revoking Connected and landing the state
    /// machine in DismissingPopups moments before the JVM itself exits.
    /// `do_connected()` used to be the ONLY one of eight `!supervisor.is_running()`
    /// call sites that knew to look for the token; every other site fell
    /// straight to a bare `State::Error(...)`, which forces `do_restart()`
    /// into its cold path — no `-Drestart=`, plus the full
    /// `restart_delay_secs` backoff. That is correct for a genuine crash and
    /// wrong for a Gateway-initiated restart it had already handled cleanly:
    /// the result was a full re-login, repeated 2FA timeouts and a
    /// human-approved HITL push, for a restart that was designed to need no
    /// human at all.
    ///
    /// This is the single, state-independent home for that check. Which
    /// state we happened to be in when Gateway's restart raced against label
    /// inspection no longer decides whether the operator gets paged.
    ///
    /// Returns `Some(State::Restarting)` once the JVM is confirmed dead —
    /// with `warm_restart_pending` armed when a token was found, left `None`
    /// otherwise so a genuine crash still pays the cold-restart backoff
    /// (that delay exists to avoid hammering IBKR's backend right after an
    /// unplanned exit). Returns `None` if the JVM is still running, in which
    /// case the caller falls through to its own logic unchanged.
    fn check_jvm_exit(&mut self) -> Option<State> {
        if self.supervisor.is_running() {
            return None;
        }
        log::info!("JVM exited — checking for autorestart token");
        let autorestart_hash = self.supervisor.find_autorestart_path();
        if let Some(ref hash) = autorestart_hash {
            log::info!("Found autorestart token: {} — warm restart", hash);
        } else {
            log::info!("No autorestart token — crash or unexpected exit");
        }
        self.last_jvm_exit = Some(JvmExitRecord {
            at: jiff::Zoned::now().to_string(),
            from_state: self.state.to_string(),
            warm: autorestart_hash.is_some(),
        });
        self.warm_restart_pending = autorestart_hash;
        let _ = std::fs::remove_file(&self.config.agent.socket_path);
        Some(State::Restarting)
    }

    /// The zone the Gateway's session runs in, read from its `jts.ini` (what the
    /// Gateway saved at login), else the declared zone, else UTC.
    fn gateway_zone(&self) -> jiff::tz::TimeZone {
        let gateway = &self.config.gateway;
        let settings_dir = if gateway.settings_path.is_empty() { &gateway.tws_path } else { &gateway.settings_path };
        let ini = std::fs::read_to_string(std::path::Path::new(settings_dir).join("jts.ini")).ok();
        let name = crate::gateway_zone::effective_zone_name(Some(&gateway.time_zone), ini.as_deref());
        jiff::tz::TimeZone::get(&name).unwrap_or_else(|_| {
            log::warn!("Gateway zone {name:?} is not known here; using UTC");
            jiff::tz::TimeZone::UTC
        })
    }

    /// Type `time` (`h:mm AM|PM`, in the Gateway's own zone) into the Gateway's
    /// auto-restart field, read it back, and record whether it took.
    async fn set_gateway_restart(&mut self, time: String, source: &'static str) {
        log::info!("SETRESTART: setting the auto-restart time to {time} in the Gateway's zone");
        let settings = crate::handlers::api_config::ApiConfigSettings {
            master_client_id: None,
            read_only_api: None,
            bypass_order_precautions: None,
            allow_blind_trading: None,
            auto_restart_time: Some(time.clone()),
            auto_logoff_time: None,
        };
        let tick_ms = self.config.timing.ui_tick_ms;
        let outcome = match crate::handlers::api_config::apply_api_config(&self.agent_client, &settings, tick_ms).await {
            Ok(report) => report.auto_restart.unwrap_or(crate::handlers::api_config::AutoRestartOutcome {
                requested: time.clone(),
                applied: false,
                error: Some("the settings dialog reported no outcome".to_string()),
            }),
            Err(e) => crate::handlers::api_config::AutoRestartOutcome {
                requested: time.clone(),
                applied: false,
                error: Some(e.to_string()),
            },
        };
        self.record_restart_time(source, outcome);
    }

    fn record_restart_time(&mut self, source: &'static str, outcome: crate::handlers::api_config::AutoRestartOutcome) {
        match &outcome.error {
            None => log::info!("Auto-restart time set to {} ({source})", outcome.requested),
            Some(why) => log::error!("Auto-restart time {} not applied ({source}): {why}", outcome.requested),
        }
        self.last_setrestart = Some(RestartTimeRecord {
            at: jiff::Zoned::now().to_string(),
            source,
            requested: outcome.requested,
            applied: outcome.applied,
            error: outcome.error,
        });
    }

    /// Press a Gateway hotkey in its main window and record what happened.
    ///
    /// The key goes to the main window (never the first window listed, which can
    /// be a dialog), and the dialog handler is told to expect the confirmation
    /// prompt it causes. The agent's reply is checked: a key it could not send
    /// is a failure, logged and shown in STATUS, not a success.
    async fn press_hotkey(&mut self, command: &'static str, key: &'static str) {
        let windows = match self.agent_client.list_windows().await {
            Ok(windows) => windows,
            Err(e) => {
                self.record_hotkey(command, key, None, Err(format!("cannot list the Gateway's windows: {e}")));
                return;
            }
        };
        let Some(window) = crate::hotkey::main_gateway_window(&windows, self.config.auth.trading_mode) else {
            self.record_hotkey(command, key, None, Err("the Gateway's main window is not open".to_string()));
            return;
        };
        let (id, title) = (window.id, window.title.clone());
        log::info!("{command}: pressing {key} in {title:?}");
        self.handler_registry.hotkey_expectation.arm();
        // The Gateway holds the key press open until its confirmation prompt is
        // answered, and the dialog handler that answers it runs on this same
        // loop. Waiting for the reply would stall it, so only wait a moment.
        let outcome = match tokio::time::timeout(crate::hotkey::SEND_REPLY_WAIT, self.agent_client.send_key(id, key)).await {
            Ok(Ok(true)) => Ok(None),
            Ok(Ok(false)) => Err("the agent could not send the key".to_string()),
            Ok(Err(e)) => Err(format!("the agent failed to send the key: {e}")),
            Err(_) => Ok(Some("no reply yet: the Gateway holds the key press until its confirmation prompt is answered")),
        };
        self.record_hotkey(command, key, Some(title), outcome);
    }

    fn record_hotkey(
        &mut self,
        command: &'static str,
        key: &'static str,
        window: Option<String>,
        outcome: Result<Option<&'static str>, String>,
    ) {
        match &outcome {
            Ok(None) => log::info!("{command}: {key} sent"),
            Ok(Some(note)) => log::info!("{command}: {key} sent ({note})"),
            Err(why) => log::error!("{command} failed: {why}"),
        }
        self.last_hotkey = Some(crate::hotkey::HotkeyRecord {
            at: jiff::Zoned::now().to_string(),
            command,
            key,
            window,
            outcome: if outcome.is_ok() { "sent" } else { "failed" },
            note: outcome.as_ref().ok().copied().flatten(),
            error: outcome.err(),
        });
    }

    /// Read the Gateway's session zone back from its `jts.ini` (the Gateway
    /// rewrites it at login, so after a login it is the zone the session really
    /// runs in), record it for STATUS, and turn the configured daily restart time
    /// from the container's zone into that zone. This runs at every login: the
    /// Gateway stores a bare time of day, so a value converted once goes wrong at
    /// the next daylight-saving change.
    fn localize_restart_time(&mut self, settings: &mut crate::handlers::api_config::ApiConfigSettings) {
        let gateway = &self.config.gateway;
        let settings_dir = if gateway.settings_path.is_empty() { &gateway.tws_path } else { &gateway.settings_path };
        let ini = std::fs::read_to_string(std::path::Path::new(settings_dir).join("jts.ini")).ok();
        let report = crate::gateway_zone::zone_report(&gateway.time_zone, ini.as_deref());
        match (&report.declared, &report.in_jts_ini) {
            (Some(declared), seen) if seen.as_ref() != Some(declared) => log::warn!(
                "Gateway time zone: declared {declared} but its jts.ini says {}",
                seen.as_deref().unwrap_or("nothing")
            ),
            _ => log::info!("Gateway time zone in use: {}", report.effective),
        }
        if let Some(configured) = settings.auto_restart_time.clone() {
            match crate::gateway_zone::restart_time_to_type(
                &configured,
                &report.effective,
                &jiff::tz::TimeZone::system(),
                jiff::Timestamp::now(),
            ) {
                Ok(typed) => {
                    log::info!("Daily restart {configured} in the container's zone is {typed} in the Gateway's ({})", report.effective);
                    settings.auto_restart_time = Some(typed);
                }
                Err(why) => log::warn!("Daily restart time {configured:?} typed as it is: {why}"),
            }
        }
        self.gateway_time_zone = Some(report);
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
    ///   - the Sunday cold restart (decided in `handle_interrupt`; see
    ///     `cold_restart_decision` — resumes via `resume_login_from_hitl`)
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
            self.hitl_connected_observation_ticks = 0;
            // Schedule the first auto-retry deadline if strategy involves a timer.
            self.hitl_next_retry_at = self.compute_next_hitl_deadline(0);
            log::warn!(
                "HITL 2FA entered: strategy={:?} next_retry_at={:?} callback_valid_hours={} attempts_exhausted={}",
                backoff.strategy,
                self.hitl_next_retry_at.map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
                backoff.callback_valid_hours,
                self.consecutive_2fa_timeouts,
            );
        }

        // No cold-restart handling here. The Sunday fire is decided in ONE
        // place — `handle_interrupt` via `cold_restart_decision::decide`
        //. A `try_recv` used to live here, but this function runs
        // inside the main loop's `select!`, which has swapped
        // `self.cold_restart_rx` for a never-polled dummy: it could never
        // receive, and `cold_restart_preempts_hitl = true` never took effect.

        // No demote when the login form is back: after an IB Key push
        // expires the Gateway restores its form in the running JVM, so that
        // is the normal parked state, not a wedge (verified against a live
        // Gateway). The resume paths re-submit in this JVM: the operator's
        // Retry, the armed retry below, the HITL timer, the Sunday fire. The
        // old demote re-logged in unattended via WaitingForLogin —
        // another push nobody answers, through a cache that could call the
        // JVM authenticated — and could not fire anyway once the login-button
        // flag was cleared at submit.

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

        // A retry armed while the IB Key dialog was up (begin_in_jvm_relogin).
        // Once the Gateway has closed it — expired, refused, approved, or
        // cancelled by ibctl — and the settle IBC allows has passed, judge
        // what it shows (`gateway_after_prompt_closed`): a completed login is
        // taken as one, a form is re-submitted into, and nothing at all is
        // waited on up to CONFIRM_AFTER_CHALLENGE_CLOSE before the in-JVM
        // retry looks for a form (then its own grace, then a relaunch).
        if self.hitl_relogin_armed {
            if self.observation.has_2fa_dialog() {
                self.hitl_2fa_closed_at = None;
                // The operator's Retry closes the prompt; the
                // Sunday fire and the HITL timer wait for the Gateway.
                if self.hitl_cancel_requested {
                    if self.prompt_cancel_sent_at.is_some() {
                        if let Some(next) = self.prompt_ignored_cancel() {
                            return Ok(next);
                        }
                    } else if let Ok(windows) = self.agent_client.list_windows().await {
                        if let Some(win) = windows
                            .iter()
                            .find(|w| w.title.to_lowercase().contains("second factor"))
                        {
                            self.cancel_ib_key_prompt(win.id).await;
                        }
                    }
                }
            } else {
                let closed_at = *self.hitl_2fa_closed_at.get_or_insert_with(Instant::now);
                if closed_at.elapsed() >= RELOGIN_SETTLE_AFTER_2FA_CLOSE {
                    match self.gateway_after_prompt_closed().await {
                        AfterPrompt::Connected => {
                            log::info!(
                                "The IB Key prompt closed and the Gateway reports \"API Server: \
                                 connected\" — the login completed in this JVM; nothing to re-submit"
                            );
                            return Ok(State::WaitingForApiReady);
                        }
                        AfterPrompt::LoginForm => {}
                        AfterPrompt::Nothing
                            if closed_at.elapsed() < CONFIRM_AFTER_CHALLENGE_CLOSE =>
                        {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            self.process_queries().await;
                            return Ok(State::WaitingForHitl2fa);
                        }
                        AfterPrompt::Nothing => log::error!(
                            "{}s after the IB Key prompt closed the Gateway shows neither its \
                             login form nor \"API Server: connected\" — looking for a form in \
                             the running Gateway",
                            closed_at.elapsed().as_secs()
                        ),
                    }
                    if self.cold_restart_owed_since.is_some() {
                        // The week's re-auth is owed and its login starts now.
                        self.record_cold_restart_outcome(
                            ColdRestartOutcome::ResumedLogin,
                            &State::WaitingForHitl2fa,
                        );
                    }
                    let by = self.hitl_relogin_armed_by.unwrap_or(RetryBy::Policy);
                    return Ok(self.begin_in_jvm_relogin(
                        "IB Key prompt closed by the Gateway, login retry was waiting on it",
                        by,
                    ));
                }
            }
        }

        // Scheduled auto-retry deadline check.
        if let Some(deadline) = self.hitl_next_retry_at {
            if Instant::now() >= deadline {
                self.hitl_intervals_index = self
                    .hitl_intervals_index
                    .saturating_add(1);
                self.hitl_next_retry_at = self.compute_next_hitl_deadline(self.hitl_intervals_index);
                log::warn!(
                    "HITL auto-retry firing (interval index {}), next retry scheduled in {:?}s",
                    self.hitl_intervals_index,
                    self.hitl_next_retry_at
                        .map(|t| t.saturating_duration_since(Instant::now()).as_secs()),
                );
                return Ok(self.begin_in_jvm_relogin("HITL auto-retry", RetryBy::Policy));
            }
        }

        // HITL_RESUME and the Sunday fire arrive as interrupts and resume
        // through `resume_login_from_hitl`, the same path as the timer above.

        // Sleep briefly then come back — we want to remain responsive to
        // commands, cold restart, and the periodic deadline.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        self.process_queries().await;
        Ok(State::WaitingForHitl2fa)
    }

    /// When the next HITL auto-retry is due, on the wall clock. `None` when
    /// the strategy has no timer or the intervals list is empty. Traverses
    /// `intervals`, then holds at the last element.
    fn next_hitl_retry_at(
        strategy: &crate::config::HitlStrategy,
        intervals: &[u32],
        index: usize,
        unattended: Option<crate::unattended::UnattendedHours>,
        now: &jiff::Zoned,
    ) -> Option<jiff::Zoned> {
        if !matches!(
            strategy,
            crate::config::HitlStrategy::Periodic | crate::config::HitlStrategy::Both
        ) {
            return None;
        }
        let minutes = *intervals.get(index).or(intervals.last())?;
        let due = now.checked_add(jiff::SignedDuration::from_mins(i64::from(minutes))).ok()?;
        // Not while nobody is up to answer the push, and not deferred to the
        // window's end either: that would launch a push unattended.
        match unattended {
            Some(w) if w.contains(due.time()) => None,
            _ => Some(due),
        }
    }

    /// `next_hitl_retry_at` from now, as an `Instant`. A login parked for
    /// the unattended hours gets no timer at all: it stays parked until the
    /// operator's Retry or the Sunday re-auth, and the window ending never
    /// launches a push by itself.
    fn compute_next_hitl_deadline(&self, index: usize) -> Option<Instant> {
        if self.hitl_park_reason == Some(HitlParkReason::UnattendedHours) {
            return None;
        }
        let backoff = &self.config.twofa.backoff;
        let now = jiff::Zoned::now();
        let at = Self::next_hitl_retry_at(
            &backoff.strategy,
            &backoff.intervals_minutes,
            index,
            backoff.unattended,
            &now,
        );
        if at.is_none() && backoff.unattended.is_some() {
            if let Some(due) =
                Self::next_hitl_retry_at(&backoff.strategy, &backoff.intervals_minutes, index, None, &now)
            {
                log::warn!(
                    "HITL auto-retry due at {} falls inside unattended hours — no automatic \
                     retry; waiting for the operator's Retry or the Sunday re-auth",
                    due.strftime("%H:%M %Z")
                );
            }
        }
        let at = at?;
        let wait = now.duration_until(&at).unsigned_abs();
        Some(Instant::now() + wait)
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
        // Session conflict: answered only in HandlingSessionConflict, where
        // the loop breaker is — never by a popup sweep.
        if t.contains("existing session") {
            return Some(State::HandlingSessionConflict);
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
                self.press_hotkey("RECONNECTDATA", crate::hotkey::RECONNECT_DATA_KEY).await;
                Ok(())
            }
            Command::ReconnectAccount => {
                self.press_hotkey("RECONNECTACCOUNT", crate::hotkey::RECONNECT_ACCOUNT_KEY).await;
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
            Command::MaintHold { id, ttl_secs } => {
                self.maintenance_hold(&id, ttl_secs);
                Ok(())
            }
            Command::MaintRelease { id, result } => {
                self.maintenance_release(&id, &result);
                Ok(())
            }
            Command::HitlResume => {
                if matches!(self.state, State::WaitingForHitl2fa) {
                    // Only the operator sends HITL_RESUME. A prompt still on
                    // screen is closed for them.
                    self.hitl_cancel_requested = self.observation.has_2fa_dialog();
                    self.resume_login_from_hitl("HITL_RESUME received", RetryBy::Operator).await?;
                } else {
                    log::warn!(
                        "HITL_RESUME ignored — not in WaitingForHitl2fa (current={})",
                        self.state
                    );
                }
                Ok(())
            }
            Command::ResumeReconnect(ref token_str) => {
                // Park the resume token; the recovery tick
                // in the main loop will pass it through
                // `RecoveryCoordinator::compute` → `::apply` on the next
                // iteration. Any non-empty token string is accepted here
                // (parser rejects empty in `command_server::parse_command`);
                // the HMAC of the dashboard-signed URL is checked on the
                // dashboard side.
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
                self.set_gateway_restart(time_str.clone(), "time").await;
                Ok(())
            }
            Command::SetRestartNow => {
                let zone = self.gateway_zone();
                let time = crate::gateway_zone::next_restart_minute(jiff::Timestamp::now(), &zone);
                self.set_gateway_restart(time, "now").await;
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

/// A login form a retry can type into: the username and password fields — the
/// indices the login handler types at — visible, enabled and editable, and a
/// visible log-in button. `components_have_login_form` only asks whether any
/// field exists; a Gateway mid-login can hold fields that are disabled or
/// hidden. Keys absent from the dump count as "no" (fail closed).
///
/// The button's ENABLED state is deliberately not asked: after an IB Key push
/// expires the Gateway clears the password and disables "Log In" until one is
/// typed (a dummy character enables it). Requiring
/// it enabled before typing rejected a good form and relaunched the JVM. The
/// login handler checks the button once the credentials are in.
fn components_have_usable_login_form(components: &serde_json::Value) -> bool {
    use crate::handlers::login::{PASSWORD_FIELD, USERNAME_FIELD};
    let flag = |c: &serde_json::Value, key: &str| c.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
    let fields = components.get("textfields").and_then(|t| t.as_array());
    let usable_field = |index: usize| {
        fields
            .and_then(|f| f.get(index))
            .is_some_and(|f| flag(f, "visible") && flag(f, "enabled") && flag(f, "editable"))
    };
    let login_button = components
        .get("buttons")
        .and_then(|b| b.as_array())
        .is_some_and(|buttons| {
            buttons.iter().any(|b| {
                b.get("text")
                    .and_then(|t| t.as_str())
                    .is_some_and(|t| t.to_lowercase().contains("log in"))
                    && flag(b, "visible")
            })
        });
    usable_field(USERNAME_FIELD) && usable_field(PASSWORD_FIELD) && login_button
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_machine::types::ColdRestartOutcomeRecord;
    use crate::types::{ColdRestartOutcome, ColdRestartSignal, ColdRestartSkipReason, Command, Signal};

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

    // --- Liveness check label inspection tests ---
    //
    // Gateway renders the Connection Status info as JLabels, not JTable. A prior
    // version of the liveness check inspected `components["tables"]` for
    // "API Server: disconnected" — but the tables array was always empty on
    // the main Gateway window. This allowed the state machine to stay in
    // Connected for an hour while Gateway was actually at the login form.
    //
    // These tests use real JSON captured from the `/windows/<id>/dump` endpoint
    // of a production Gateway in that state. Regression guards:
    //
    //   1. MUST detect "API Server: disconnected" from labels alone
    //   2. MUST NOT false-positive when Gateway is in a benign no-connection-status state
    //   3. MUST detect login form via non-empty textfields
    //   4. MUST confirm "connected" when labels say so

    /// Real dump of the main Gateway window in the disconnected state
    /// (captured from a production Gateway).
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
            "must detect 'API Server: disconnected' from a real dump"
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
    // Regression guard. The state machine must NEVER
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
    /// Placeholder auth values for tests that need a syntactically valid
    /// (never real) username/password pair.
    fn test_auth_placeholder() -> (String, SecretString) {
        let u: String = ['x'; 3].iter().collect();
        let p: String = ['x'; 3].iter().collect();
        (u, SecretString::from(p))
    }

    fn make_test_state_machine(mock: MockAgent) -> StateMachine {
        make_test_state_machine_with(mock, |_| {})
    }

    /// `make_test_state_machine` with the config adjusted before validation.
    fn make_test_state_machine_with(mock: MockAgent, adjust: impl FnOnce(&mut Config)) -> StateMachine {
        // Build a minimally-valid config (values irrelevant to the tests).
        let mut cfg = Config::default();
        (cfg.auth.username, cfg.auth.password) = test_auth_placeholder();
        adjust(&mut cfg);
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
        // Arrange: Gateway shows "disconnected" label (the fail-open scenario).
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
        // (this case previously went undetected because the check was
        // looking at tables instead of labels).
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
    // Restarting) has been exercised in production and by manual
    // reproduction, not here. Wiring it up as an automated
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
    async fn test_agent_disconnect_revokes_when_label_inspection_is_blind() {
        // The blind-label bug, as a test.
        //
        // The Gateway fell back to a login prompt. A login prompt carries no
        // connection label, so the label dump below contains NO "disconnected"
        // string and DisconnectedLabelStable can never fire — the detector is
        // blind precisely when the failure is worst. Meanwhile the agent had
        // already told us the session dropped, and we were throwing that away.
        // Result: Connected retained for 20-25s — long enough for an operator
        // to open VNC and find the Gateway on a login prompt while ibctl
        // reported Connected.
        //
        // The backstop must revoke here on the agent's word alone.
        let dump = serde_json::json!({
            // Deliberately NO "disconnected" label — this is the blind spot.
            "labels": ["Purpose", "IBKR GATEWAY"],
            "textfields": [], "buttons": [], "tables": []
        });
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: dump,
            ..Default::default()
        };

        let mut sm = make_test_state_machine(mock);
        sm.state = State::Connected;
        sm.state_entered_at = Instant::now() - Duration::from_secs(300);
        sm.connected_window_class = Some("ibgateway.ay".to_string());
        sm.observation.synced = true;

        // The agent reported the drop, and the debounce has already elapsed.
        sm.agent_reported_disconnected = true;
        sm.revocation.seed_first_seen_for_test(
            revocation::RevocationSource::AgentReportedDisconnect,
            Duration::from_secs(600),
        );

        let next = sm.do_connected().await.unwrap();
        assert_eq!(
            next,
            State::WaitingForLogin,
            "agent-reported disconnect must revoke Connected even when the \
             label dump carries no connection label to inspect"
        );
    }

    #[tokio::test]
    async fn test_agent_stream_reconnect_clears_the_disconnect_verdict() {
        // Found by adversarial review, not by a failure — the gap this closes
        // had not bitten yet.
        //
        // If the agent process restarts, the stream drops and reconnects. Any
        // `-> connected` emitted during that gap is never delivered, so a
        // pre-gap "disconnected" verdict would survive into a healthy session
        // and revoke it ~90s later. That is the SAME false-positive class this
        // event was removed for in the first place ("stale events caused
        // restart loop"), arriving by a different door.
        //
        // A reconnect means our event history has a hole in it. Trust nothing
        // across it.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            ..Default::default()
        };
        let mut sm = make_test_state_machine(mock);
        sm.state = State::Connected;
        sm.agent_reported_disconnected = true;
        sm.revocation
            .observe(revocation::RevocationSource::AgentReportedDisconnect);
        assert!(sm
            .revocation
            .is_pending(revocation::RevocationTag::AgentReportedDisconnect));

        sm.handle_agent_event(crate::agent_events::AgentEvent::Hello {
            protocol_version: 2,
        })
        .await;

        assert!(
            !sm.agent_reported_disconnected,
            "a stream reconnect must void the pre-gap disconnect verdict"
        );
        assert!(
            !sm.revocation
                .is_pending(revocation::RevocationTag::AgentReportedDisconnect),
            "a stream reconnect must also cancel the pending debounce"
        );
    }

    #[tokio::test]
    async fn test_stale_agent_disconnect_cannot_revoke_a_fresh_connected_session() {
        // The guard that makes consuming this event safe at all.
        //
        // While in Launching/Login the Gateway IS genuinely disconnected, so
        // the agent legitimately reports it. If that verdict carried into the
        // session that follows, every fresh login would revoke itself ~90s
        // later. This is the false-positive class that caused the event to be
        // made informational-only in the first place; entry to Connected must
        // wipe the slate.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            ..Default::default()
        };
        let mut sm = make_test_state_machine(mock);

        // Pre-Connected: agent says disconnected, debounce already running.
        sm.state = State::ConfiguringApi;
        sm.agent_reported_disconnected = true;
        sm.revocation.observe(revocation::RevocationSource::AgentReportedDisconnect);
        assert!(sm
            .revocation
            .is_pending(revocation::RevocationTag::AgentReportedDisconnect));

        sm.apply_transition(State::Connected).await.unwrap();

        assert!(
            !sm.agent_reported_disconnected,
            "entering Connected must clear the stale disconnect verdict"
        );
        assert!(
            !sm.revocation
                .is_pending(revocation::RevocationTag::AgentReportedDisconnect),
            "entering Connected must cancel any debounce started before the session"
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
    // Property tests for the transition law
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
        // the exact scenario where the old code fabricated progress
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
    /// above — kept here as a parametrized law statement.
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
    // Sunday cold restart: one decision point. The pure table
    // lives in `cold_restart_decision`; these drive the REAL handler to
    // prove the state machine acts on it — and only once.
    // ----------------------------------------------------------------

    fn fire() -> Interrupt {
        Interrupt::ColdRestart(ColdRestartSignal::Fire)
    }

    fn outcome_of(sm: &StateMachine) -> &ColdRestartOutcome {
        &sm.last_cold_restart_outcome
            .as_ref()
            .expect("every Sunday fire must record an outcome")
            .outcome
    }

    #[tokio::test]
    async fn test_cold_restart_on_standby_records_standby_and_stays_put() {
        // Regression guard: a standby must never launch a
        // Gateway on the Sunday fire and race the primary for the account.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForLaunch;
        sm.handle_interrupt(fire()).await.expect("handler must not error");
        assert_eq!(sm.state, State::WaitingForLaunch);
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::Standby);
        assert!(sm.cold_restart_owed_since.is_none(), "a standby owes nothing");
    }

    #[tokio::test]
    async fn test_cold_restart_on_shutdown_records_stopping() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Shutdown;
        sm.handle_interrupt(fire()).await.expect("handler must not error");
        assert_eq!(sm.state, State::Shutdown);
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::Stopping);
    }

    #[tokio::test]
    async fn test_cold_restart_on_error_is_an_explicit_failure_not_idle() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Error("test-error".to_string());
        sm.handle_interrupt(fire()).await.expect("handler must not error");
        assert!(matches!(sm.state, State::Error(_)), "must not short-circuit recovery");
        assert_eq!(
            outcome_of(&sm),
            &ColdRestartOutcome::Failed { detail: "test-error".into() },
        );
        assert!(sm.cold_restart_owed_since.is_some(), "a failed mode still owes the re-auth");
    }

    // ----------------------------------------------------------------
    // Retrying a login in the RUNNING JVM. The Sunday
    // fire, the operator's "Retry login" and the HITL timer re-submit the
    // login into the Gateway that is already up. A JVM restart only
    // happens when there is no JVM, or the Gateway never offers a form.
    // ----------------------------------------------------------------

    /// Every transition that stops or starts the JVM: `do_restart` kills it
    /// (Restarting), `do_launch` starts one (Launching), STOP and recovery
    /// give-up kill it (WaitingForLaunch), `do_shutdown` kills it
    /// (Shutdown). An in-JVM retry must produce none of them.
    fn jvm_lifecycle_transitions(sm: &StateMachine) -> Vec<String> {
        let lifecycle = [State::Restarting, State::Launching, State::WaitingForLaunch, State::Shutdown]
            .map(|s| s.to_string());
        sm.transition_history
            .iter()
            .filter(|t| lifecycle.contains(&t.to))
            .map(|t| format!("{} -> {}", t.from, t.to))
            .collect()
    }

    const LIVE_GATEWAY: u64 = 7;
    const IB_KEY_DIALOG: u64 = 8;

    fn live_gateway_window() -> WindowInfo {
        WindowInfo {
            id: WindowId(LIVE_GATEWAY),
            title: "IBKR Gateway [LIVE]".into(),
            class: "ibgateway.aw".into(),
            bounds: None,
            visible: true,
        }
    }

    fn ib_key_dialog_window() -> WindowInfo {
        WindowInfo {
            id: WindowId(IB_KEY_DIALOG),
            title: "Second Factor Authentication".into(),
            class: "dialog".into(),
            bounds: None,
            visible: true,
        }
    }

    /// A dumped text field, as the agent reports it.
    fn field(index: u32, enabled: bool) -> serde_json::Value {
        serde_json::json!({"index": index, "visible": true, "enabled": enabled, "editable": true})
    }

    /// A dumped button, as the agent reports it.
    fn button(text: &str, enabled: bool) -> serde_json::Value {
        serde_json::json!({"text": text, "visible": true, "enabled": enabled})
    }

    /// `dump_components` of a Gateway window showing the LIVE login form.
    fn login_form_dump() -> serde_json::Value {
        serde_json::json!({
            "textfields": [field(0, true), field(1, true)],
            "buttons": [button("IB API", true), button("Live Trading", true), button("Log In", true)],
            "labels": [],
            "tables": []
        })
    }

    /// A Gateway window whose status panel says the API server is up.
    fn connected_dump() -> serde_json::Value {
        serde_json::json!({
            "textfields": [], "buttons": [], "tables": [],
            "labels": ["Purpose", "Status", "API Server", "connected"]
        })
    }

    /// A Gateway window with no form and no connection: mid-redraw, or a
    /// Gateway that will not offer a form again.
    fn no_form_no_connection_dump() -> serde_json::Value {
        serde_json::json!({
            "textfields": [], "buttons": [], "tables": [],
            "labels": ["Purpose", "Status", "API Server", "disconnected"]
        })
    }

    fn agent_showing(windows: Vec<WindowInfo>, dump: serde_json::Value) -> MockAgent {
        MockAgent { windows, dump_response: dump, ..Default::default() }
    }

    /// Observation cache of a LIVE mode parked overnight, at the 09:00 fire:
    /// the Gateway window (its login-button flag cleared when the overnight
    /// login was submitted) and, optionally, the IB Key dialog.
    fn stage_parked_hitl(sm: &mut StateMachine, ib_key_dialog_open: bool) {
        sm.observation = crate::agent_events::AgentObservation::new();
        sm.observation.window_opened(
            LIVE_GATEWAY,
            "IBKR Gateway [LIVE]".into(),
            "ibgateway.aw".into(),
            false,
            1,
        );
        if ib_key_dialog_open {
            sm.observation.window_opened(
                IB_KEY_DIALOG,
                "Second Factor Authentication".into(),
                "dialog".into(),
                false,
                2,
            );
        }
        sm.observation.synced = true;
    }

    /// LIVE parked in HITL at the 09:00 fire: the JVM relaunched
    /// overnight, three IB Key pushes timed out, HITL for hours since —
    /// with the real login handler, its submit guard still set by the
    /// overnight login.
    fn parked_live_hitl(agent: MockAgent, ib_key_dialog_open: bool) -> StateMachine {
        parked_live_hitl_with(agent, ib_key_dialog_open, |_| {})
    }

    /// `parked_live_hitl` with the config adjusted.
    fn parked_live_hitl_with(agent: MockAgent, ib_key_dialog_open: bool, adjust: impl FnOnce(&mut Config)) -> StateMachine {
        let mut sm = make_test_state_machine_with(agent, |c| {
            c.auth.trading_mode = crate::config::TradingMode::Live;
            adjust(c);
        });
        sm.handler_registry = DialogHandlerRegistry::with_defaults(&sm.config);
        // The same guard a submitted login leaves set.
        sm.handler_registry.mark_login_complete();
        // And the form report that login left behind: the agent retires its
        // form watcher after a submit, so in production this overnight value
        // is still what the login handler would read at 09:00.
        let _ = sm.handler_registry.login_form_tx.send(Some(crate::agent_events::LoginFormState {
            text_field_count: 5,
            password_field_count: 1,
            login_button: Some("Log In".into()),
            selected_mode: None,
        }));
        sm.state = State::WaitingForHitl2fa;
        sm.hitl_entered_at = Some(Instant::now() - Duration::from_secs(6 * 3600));
        sm.consecutive_2fa_timeouts = 3;
        stage_parked_hitl(&mut sm, ib_key_dialog_open);
        sm
    }

    #[tokio::test(start_paused = true)]
    async fn test_sunday_resume_after_overnight_restart_authenticates_in_the_same_jvm() {
        // The decisive scenario. Overnight the container restarted, the
        // new JVM's three IB Key pushes timed out, HITL followed, and the
        // Gateway closed the last dialog itself. At 09:00 the
        // week's re-authentication is FINISHED in that JVM — no JVM stop or
        // start — and the login that lands satisfies the Sunday requirement.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window()], login_form_dump()),
            false,
        );
        sm.cold_restart_equivalent_marker_path = marker.clone();

        // 09:00: the fire resumes the unfinished login.
        sm.handle_interrupt(fire()).await.unwrap();
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::ResumedLogin);
        assert_eq!(sm.state, State::Authenticating, "resumed in the running JVM");

        // The credentials go back into the running Gateway's login form.
        let next = sm.do_authenticate().await.unwrap();
        assert_eq!(next, State::WaitingFor2fa, "login re-submitted in the same JVM");
        sm.apply_transition(next).await.unwrap();

        // IBKR pushes a new IB Key challenge; the operator approves it.
        sm.agent_client = AgentClient::mock(agent_showing(
            vec![live_gateway_window(), ib_key_dialog_window()],
            login_form_dump(),
        ));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.agent_client =
            AgentClient::mock(agent_showing(vec![live_gateway_window()], connected_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::DismissingPopups, "2FA answered");
        for s in [next, State::WaitingForApiReady, State::ConfiguringApi, State::Connected] {
            sm.apply_transition(s).await.unwrap();
        }

        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new(), "JVM identity must not change");
        assert!(
            matches!(outcome_of(&sm), ColdRestartOutcome::Completed { .. }),
            "the in-JVM login settles the Sunday re-auth, got {:?}",
            outcome_of(&sm),
        );
        assert!(sm.cold_restart_owed_since.is_none());
        assert!(marker.exists(), "the in-JVM login is this week's re-authentication");
    }

    #[tokio::test]
    async fn test_retry_click_then_fire_is_one_login_and_no_jvm_restart() {
        // Operator taps "Retry login" at 08:59:50; the fire lands at 09:00.
        let mut sm = parked_live_hitl(MockAgent::default(), false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.state, State::Authenticating);
        let after_click = sm.transition_history.len();

        sm.handle_interrupt(fire()).await.unwrap();

        assert_eq!(sm.state, State::Authenticating);
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::Deferred, "the fire joins the click's login");
        assert_eq!(sm.transition_history.len(), after_click, "no second login");
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new());
        assert_eq!(sm.consecutive_2fa_timeouts, 3, "budget untouched");
    }

    #[tokio::test]
    async fn test_fire_then_retry_click_is_ignored_and_no_jvm_restart() {
        let mut sm = parked_live_hitl(MockAgent::default(), false);
        sm.handle_interrupt(fire()).await.unwrap();
        assert_eq!(sm.state, State::Authenticating);
        let after_fire = sm.transition_history.len();

        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();

        assert_eq!(sm.state, State::Authenticating);
        assert_eq!(sm.transition_history.len(), after_fire, "no second login");
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn test_open_ib_key_prompt_is_preserved_then_retried_once_the_gateway_closes_it() {
        // The Gateway still shows the IB Key dialog, so the push may still
        // be approvable: the Sunday fire neither re-submits under it nor
        // closes it. It arms ONE retry for when the Gateway closes it.
        let agent = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], login_form_dump());
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, true);
        sm.handle_interrupt(fire()).await.unwrap();
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::ChallengePending);
        assert!(sm.hitl_relogin_armed, "the fire arms the retry");
        assert_eq!(sm.state, State::WaitingForHitl2fa, "nothing re-submitted under a live challenge");
        assert!(sm.transition_history.is_empty());

        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa);
        assert!(
            clicked.lock().unwrap().is_empty(),
            "a scheduled retry never closes the prompt; only the operator's Retry does",
        );

        // IBKR expires the push; the Gateway closes its dialog.
        stage_parked_hitl(&mut sm, false);
        assert_eq!(
            sm.do_waiting_for_hitl_2fa().await.unwrap(),
            State::WaitingForHitl2fa,
            "settle after the close, as IBC does",
        );
        sm.hitl_2fa_closed_at = Some(Instant::now() - RELOGIN_SETTLE_AFTER_2FA_CLOSE);
        let next = sm.do_waiting_for_hitl_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating);
        sm.apply_transition(next).await.unwrap();

        assert_eq!(sm.transition_history.len(), 1, "exactly one retry");
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new());
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::ResumedLogin, "the owed re-auth's login started");
        assert!(!sm.hitl_relogin_armed, "leaving HITL disarms");
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_never_reads_a_missing_form_as_authenticated() {
        // The fresh-JVM path reads "Gateway window without text fields" as
        // already authenticated. In the running JVM that can be a form not
        // redrawn yet; only the status panel may say the login is done.
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window()], no_form_no_connection_dump()),
            false,
        );
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_authenticate().await.unwrap(), State::Authenticating, "keep looking for the form");
    }

    #[tokio::test]
    async fn test_in_jvm_retry_recognises_a_login_that_already_completed() {
        // The operator approved the old push just as the Gateway closed it.
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window()], connected_dump()),
            false,
        );
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_authenticate().await.unwrap(), State::DismissingPopups);
        assert!(
            sm.cold_restart_equivalent_pending,
            "the overnight login completed in this JVM when its push was approved",
        );
    }

    #[tokio::test]
    async fn test_in_jvm_retry_relaunches_only_when_the_gateway_never_offers_a_form() {
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window()], no_form_no_connection_dump()),
            false,
        );
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        sm.in_jvm_relogin_since = Some(Instant::now() - IN_JVM_RELOGIN_FORM_GRACE);
        let next = sm.do_authenticate().await.unwrap();
        assert_eq!(next, State::Restarting);
        sm.apply_transition(next).await.unwrap();
        assert!(sm.in_jvm_relogin_since.is_none(), "the relaunched JVM's login is a fresh-JVM login");
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_finds_the_form_in_whichever_gateway_window_has_it() {
        // A Gateway can open a second window titled "IBKR Gateway" during
        // login. Use the one carrying the form.
        let other = WindowInfo { id: WindowId(9), title: "IBKR Gateway".into(), ..live_gateway_window() };
        let mut agent = agent_showing(vec![other, live_gateway_window()], no_form_no_connection_dump());
        agent.dump_by_window.insert(LIVE_GATEWAY, login_form_dump());
        let mut sm = parked_live_hitl(agent, false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingFor2fa);
        assert!(
            sm.cold_restart_equivalent_pending,
            "credentials re-submitted: a Connected in this JVM is an authentication even if no push follows",
        );
    }

    #[tokio::test]
    async fn test_retry_with_the_jvm_gone_relaunches() {
        // The Gateway can exit on its own after failed 2FA (with exit
        // status 0). No JVM, no form to re-submit into.
        let mut sm = parked_live_hitl(MockAgent::default(), false);
        sm.supervisor.set_test_force_running(false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.state, State::Restarting);
    }

    #[tokio::test(start_paused = true)]
    async fn test_hitl_timer_retry_resubmits_in_the_running_jvm() {
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window()], login_form_dump()),
            false,
        );
        sm.hitl_next_retry_at = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::Authenticating);
    }

    #[tokio::test(start_paused = true)]
    async fn test_resumed_login_keeps_its_open_push_past_the_timer() {
        // The budget was spent overnight. The resumed login's push is still
        // on screen at the timer: it may still be approved, so it is kept
        // — the round ends when the Gateway closes it, and then
        // parks again (test_failed_2fa_after_the_retry_parks_again_...).
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], login_form_dump()),
            false,
        );
        sm.state = State::WaitingFor2fa;
        sm.state_entered_at =
            Instant::now() - Duration::from_secs(sm.config.twofa.timeout_seconds + 1);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        assert_eq!(sm.consecutive_2fa_timeouts, 3, "no round ended");
    }

    #[tokio::test]
    async fn test_hitl_resume_clears_hitl_bookkeeping() {
        let mut sm = parked_live_hitl(MockAgent::default(), false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.state, State::Authenticating);
        assert!(sm.hitl_entered_at.is_none(), "a later HITL entry must start fresh");
        assert_eq!(sm.consecutive_2fa_timeouts, 3, "a resume must not reset the 2FA budget");
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_ignores_the_previous_logins_form_report() {
        // Seen in production: the login handler "verified" a form
        // from the report the previous login left behind, then found no
        // username field. The retry must judge the form it sees now.
        let mut agent = agent_showing(
            vec![live_gateway_window()],
            serde_json::json!({
                "textfields": [field(0, true), field(1, true)],
                "buttons": [button("Paper Log In", true)],
                "labels": [], "tables": []
            }),
        );
        agent.click_not_found.insert("Log In".into());
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();

        assert_eq!(sm.do_authenticate().await.unwrap(), State::Authenticating);
        assert!(
            !clicked.lock().unwrap().contains(&"Log In".to_string()),
            "submitted on the strength of a stale form report: {:?}",
            clicked.lock().unwrap(),
        );
    }

    /// A LIVE login frame as the agent dumps it after an IB Key push
    /// expired (username redacted): username kept, password cleared, every
    /// field enabled — and "Log In" DISABLED until a password is typed (a
    /// dummy character in the password field enables it).
    fn form_after_ib_key_expiry(log_in_enabled: bool) -> serde_json::Value {
        serde_json::json!({
            "textfields": [
                {"index": 0, "text": "someuser", "visible": true, "enabled": true, "editable": true},
                {"index": 1, "text": "", "visible": true, "enabled": true, "editable": true},
                {"index": 2, "text": "/home/ibgateway/Jts_live", "visible": true, "enabled": true, "editable": false}
            ],
            "buttons": [
                {"text": "FIX CTCI", "visible": true, "enabled": true, "selected": false},
                {"text": "IB API", "visible": true, "enabled": true, "selected": true},
                {"text": "Live Trading", "visible": true, "enabled": true, "selected": true},
                {"text": "Paper Trading", "visible": true, "enabled": true, "selected": false},
                {"text": "Log In", "visible": true, "enabled": log_in_enabled, "selected": false}
            ],
            "labels": ["IBKR Gateway [LIVE]", "API Type", "Trading Mode"],
            "tables": []
        })
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_submits_into_the_form_the_gateway_shows_after_expiry() {
        // The earlier failure: the retry demanded an enabled "Log In"
        // BEFORE typing, so it rejected this form for 60 s and relaunched.
        let mut agent = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();

        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingFor2fa, "re-submitted in the same JVM");
        assert!(clicked.lock().unwrap().contains(&"Log In".to_string()));
    }

    #[tokio::test(start_paused = true)]
    async fn test_waiting_for_login_does_not_call_a_returned_form_authenticated() {
        // The form is back in the running JVM; the cache still says "no
        // login button" from the last submit. That used to read as
        // "already authenticated" and go to DismissingPopups.
        let mut agent = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let mut sm = parked_live_hitl(agent, false);
        sm.state = State::WaitingForLogin;
        assert_eq!(sm.do_wait_for_login().await.unwrap(), State::Authenticating);
        assert!(sm.in_jvm_relogin_since.is_some(), "handed to the in-JVM retry");
    }

    #[tokio::test]
    async fn test_waiting_for_login_with_no_form_still_moves_on() {
        // After a revoke: connected main window, no form.
        let mut sm = parked_live_hitl(agent_showing(vec![live_gateway_window()], connected_dump()), false);
        sm.state = State::WaitingForLogin;
        assert_eq!(sm.do_wait_for_login().await.unwrap(), State::DismissingPopups);
        assert!(sm.in_jvm_relogin_since.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_waits_for_usable_controls() {
        // Text fields present but disabled — a form mid-transition. Typing
        // into it and clicking a dead button would "submit" nothing.
        let agent = agent_showing(
            vec![live_gateway_window()],
            serde_json::json!({
                "textfields": [field(0, false), field(1, false)],
                "buttons": [button("Log In", false)],
                "labels": [], "tables": []
            }),
        );
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();

        assert_eq!(sm.do_authenticate().await.unwrap(), State::Authenticating);
        assert!(clicked.lock().unwrap().is_empty(), "nothing clicked on an unusable form");
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_asks_the_gateway_about_the_ib_key_prompt() {
        // The event cache missed the dialog (stream gap). The live window
        // list still shows it: keep waiting, and restart the form grace so
        // an open prompt can't run it out.
        let agent = agent_showing(
            vec![live_gateway_window(), ib_key_dialog_window()],
            login_form_dump(),
        );
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        sm.in_jvm_relogin_since = Some(Instant::now() - Duration::from_secs(59));

        assert_eq!(sm.do_authenticate().await.unwrap(), State::Authenticating);
        assert!(clicked.lock().unwrap().is_empty(), "nothing submitted under the prompt");
        assert!(sm.in_jvm_relogin_since.unwrap().elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(start_paused = true)]
    async fn test_failed_2fa_after_the_retry_parks_again_without_a_restart() {
        // The retried login's push is refused; the Gateway puts the form
        // back in the running JVM. The budget was spent overnight, so park
        // with a fresh page — not WaitingForLogin, whose cache still says
        // "no login button" and would call this JVM authenticated.
        let mut sm = parked_live_hitl(agent_showing(vec![live_gateway_window()], login_form_dump()), false);
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true; // the refused push's prompt
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingForHitl2fa);
        assert_eq!(sm.consecutive_2fa_timeouts, 4, "a failed round counts against the budget");
    }

    #[tokio::test(start_paused = true)]
    async fn test_failed_2fa_with_budget_left_retries_in_the_running_jvm() {
        let mut sm = parked_live_hitl(agent_showing(vec![live_gateway_window()], login_form_dump()), false);
        sm.consecutive_2fa_timeouts = 0;
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true; // the refused push's prompt
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::Authenticating);
        assert!(sm.in_jvm_relogin_since.is_some(), "the form is judged afresh, not from the cache");
    }

    #[tokio::test]
    async fn test_leaving_the_login_step_without_submitting_is_not_an_authentication() {
        // Authenticating found no form ("already authenticated") and moved
        // on. No credentials went in, so the Connected that follows is not
        // this week's re-authentication — the owed cold restart still runs.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let mut sm = make_test_state_machine(agent_showing(vec![gateway_window()], connected_dump()));
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.cold_restart_owed_since = Some(jiff::Zoned::now());
        sm.state = State::Authenticating;

        let next = sm.do_authenticate().await.unwrap();
        assert_eq!(next, State::DismissingPopups);
        for s in [next, State::WaitingForApiReady, State::ConfiguringApi, State::Connected] {
            sm.apply_transition(s).await.unwrap();
        }

        assert!(!marker.exists(), "no credentials were submitted");
        assert!(sm.cold_restart_owed_since.is_some() || sm.cold_restart_fire_on_connected);
        assert!(sm.cold_restart_fire_on_connected, "the owed restart must still run");
    }

    // The IB Key flow is two dialogs with the same title: the device picker
    // (ibctl chooses "IB Key", clicks OK, it closes) and, 9-18 s later, the
    // challenge ("IBKR sent you a notification"). The success check used to
    // run 5 s after ANY 2FA dialog closed, so the picker closing read as
    // "2FA SUCCEEDED". Leaving WaitingFor2fa reset the device flag, and
    // before an agent fix the device step then clicked OK on the live
    // challenge, cancelling it (the Gateway then showed "RE-LOGIN IS
    // REQUIRED").

    fn twofa_config(c: &mut Config) {
        c.auth.trading_mode = crate::config::TradingMode::Live;
        c.twofa.device = "IB Key".into();
    }

    #[tokio::test(start_paused = true)]
    async fn test_device_picker_closing_is_not_a_2fa_success() {
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], connected_dump()),
            twofa_config,
        );
        sm.state = State::WaitingFor2fa;
        // The picker: a device list is there — choose IB Key, click OK.
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        assert!(sm.twofa_device_selected);

        // Picker closed; the challenge hasn't opened yet. The main window
        // has no text fields — which proves nothing.
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], no_form_no_connection_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(20));
        assert_eq!(
            sm.do_wait_for_2fa().await.unwrap(),
            State::WaitingFor2fa,
            "the picker closing is not an answered challenge",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_picker_closed_then_gateway_connected_is_a_success() {
        // The challenge came and went between two polls: never seen, but
        // "API Server: connected" is positive evidence on its own.
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], connected_dump()),
            twofa_config,
        );
        sm.state = State::WaitingFor2fa;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "picker: IB Key chosen");
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], connected_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::DismissingPopups);
    }

    /// Picker, then challenge, then approval: the ordinary IB Key login.
    #[tokio::test(start_paused = true)]
    async fn test_approved_challenge_after_the_picker_is_a_success() {
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], connected_dump()),
            twofa_config,
        );
        sm.state = State::WaitingFor2fa;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "picker: IB Key chosen");

        // The challenge opens (the device was already chosen)...
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        // ...and closes, approved.
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], connected_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::DismissingPopups);
    }

    /// A challenge with no picker before it (an in-JVM re-submit can go
    /// straight to the push prompt).
    #[tokio::test(start_paused = true)]
    async fn test_challenge_closing_with_the_gateway_authenticated_is_a_success() {
        let mut challenge = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], connected_dump());
        challenge.list_item_found = false;
        let mut sm = make_test_state_machine_with(challenge, twofa_config);
        sm.state = State::WaitingFor2fa;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);

        // Approved: the challenge closes and the Gateway is logged in.
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], connected_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::DismissingPopups);
    }

    // A closed challenge permits checking for success; it does not
    // establish it. Expiry, refusal and approval all close it. Success
    // needs "API Server: connected"; the login form back is a failed round.
    // Observed approvals showed "connected" 10-132 s after the close.

    /// WaitingFor2fa just after the IB Key challenge closed, with the
    /// Gateway showing `dump`.
    async fn challenge_just_closed(dump: serde_json::Value) -> StateMachine {
        let mut challenge = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], dump.clone());
        challenge.list_item_found = false;
        let mut sm = make_test_state_machine_with(challenge, twofa_config);
        sm.state = State::WaitingFor2fa;
        sm.consecutive_2fa_timeouts = 3;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "challenge seen");
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], dump));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "challenge closed");
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        sm
    }

    #[tokio::test(start_paused = true)]
    async fn test_closed_challenge_without_evidence_is_not_a_success() {
        // No login form, but no "connected" either: the main window of an
        // unauthenticated Gateway looks exactly like this.
        let mut sm = challenge_just_closed(no_form_no_connection_dump()).await;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_2fa_timer_does_not_abandon_a_closed_challenge_being_confirmed() {
        // Approved at second 115; "connected" can take up to 132 s after the
        // close. The round is over — the timer must not restart under it.
        let mut sm = challenge_just_closed(no_form_no_connection_dump()).await;
        sm.state_entered_at = Instant::now() - Duration::from_secs(sm.config.twofa.timeout_seconds + 30);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        assert_eq!(sm.consecutive_2fa_timeouts, 3, "no attempt consumed while confirming");
    }

    #[tokio::test(start_paused = true)]
    async fn test_unconfirmed_closed_challenge_is_a_failed_round_after_the_bound() {
        let mut sm = challenge_just_closed(no_form_no_connection_dump()).await;
        sm.twofa_gone_at = Some(Instant::now() - CONFIRM_AFTER_CHALLENGE_CLOSE);
        assert_eq!(
            sm.do_wait_for_2fa().await.unwrap(),
            State::WaitingForHitl2fa,
            "budget spent: park, don't advance on no evidence",
        );
    }

    // A 2FA round ends when the Gateway ends it. A fixed 120 s timer used
    // to fire while the IB Key prompt was often still open, and each JVM
    // relaunch that followed sent another push. The Gateway has kept prompts
    // open for about 17 minutes, and pushes have been approved two to three minutes in.
    // IBC acts only when the
    // dialog closes (LoginManager.secondFactorAuthenticationDialogClosed).

    /// WaitingFor2fa with this round's IB Key challenge on screen.
    async fn challenge_open(adjust: impl FnOnce(&mut Config)) -> (StateMachine, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let mut challenge = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], no_form_no_connection_dump());
        challenge.list_item_found = false;
        let clicked = challenge.clicked.clone();
        let mut sm = make_test_state_machine_with(challenge, |c| {
            twofa_config(c);
            adjust(c);
        });
        sm.state = State::WaitingFor2fa;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "challenge seen");
        (sm, clicked)
    }

    /// Wind this round's clocks back: the prompt opened `open_for` ago.
    fn prompt_open_for(sm: &mut StateMachine, open_for: Duration) {
        sm.twofa_challenge_opened_at = Some(Instant::now() - open_for);
        sm.state_entered_at = Instant::now() - open_for - Duration::from_secs(3);
    }

    /// A wall-clock window around the current time, `ahead_h` hours on.
    fn unattended_around_now(c: &mut Config, ahead_h: i64) {
        let now = jiff::Zoned::now().time();
        let start = now.wrapping_add(jiff::SignedDuration::from_hours(ahead_h - 1));
        let end = now.wrapping_add(jiff::SignedDuration::from_hours(ahead_h + 1));
        let w = format!("{:02}:{:02}-{:02}:{:02}", start.hour(), start.minute(), end.hour(), end.minute());
        c.twofa.backoff.unattended_hours = w.clone();
        c.twofa.backoff.unattended = crate::unattended::UnattendedHours::parse(&w).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_2fa_timer_never_ends_a_round_with_the_prompt_open() {
        let (mut sm, clicked) = challenge_open(|_| {}).await;
        let past_timer = Duration::from_secs(sm.config.twofa.timeout_seconds + 1);
        prompt_open_for(&mut sm, past_timer);

        let next = sm.do_wait_for_2fa().await.unwrap();

        assert_eq!(next, State::WaitingFor2fa, "the push is outstanding: keep it");
        assert_eq!(sm.consecutive_2fa_timeouts, 0, "no round ended");
        assert!(sm.twofa_overdue_logged, "the operator is told the push is waiting");
        assert!(clicked.lock().unwrap().is_empty(), "nothing clicked on a live prompt");
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_open_prompt_outlives_the_longest_one_observed() {
        // About 17 minutes, closed by the Gateway itself.
        let (mut sm, clicked) = challenge_open(|_| {}).await;
        prompt_open_for(&mut sm, Duration::from_secs(1014));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        assert!(clicked.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_prompt_stuck_past_the_ceiling_is_cancelled_in_the_running_jvm() {
        let (mut sm, clicked) = challenge_open(|_| {}).await;
        prompt_open_for(&mut sm, STUCK_PROMPT_CEILING);

        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "wait for the Gateway to close it");
        assert_eq!(*clicked.lock().unwrap(), vec!["Cancel".to_string()]);
        assert!(sm.prompt_cancel_sent_at.is_some());
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        assert_eq!(clicked.lock().unwrap().len(), 1, "one Cancel, not one per tick");

        // The Gateway closes the prompt and puts its login form back: a
        // failed round, retried in this JVM.
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false)));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "settling");
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating);
        assert_eq!(sm.consecutive_2fa_timeouts, 1, "the stuck round counts against the budget");
        sm.apply_transition(next).await.unwrap();
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new());
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_prompt_that_ignores_cancel_relaunches_the_jvm_with_the_reason() {
        let (mut sm, _) = challenge_open(|_| {}).await;
        prompt_open_for(&mut sm, STUCK_PROMPT_CEILING);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);

        sm.prompt_cancel_sent_at = Some(Instant::now() - PROMPT_CANCEL_GRACE);
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::Restarting, "the in-JVM recovery failed");
        sm.apply_transition(next).await.unwrap();

        let r = sm.last_relaunch.as_ref().expect("relaunch recorded");
        assert_eq!(r.reason, "prompt_ignored_cancel");
        assert_eq!(r.from_state, "WaitingFor2fa");
        assert!(!r.abandoned_prompt, "a reasoned relaunch is not the tripwire");
    }

    #[tokio::test(start_paused = true)]
    async fn test_each_round_starts_its_own_prompt_clock() {
        // The last round's prompt hit the ceiling and was cancelled; the
        // retry's new push must not inherit that clock or that Cancel.
        let (mut sm, clicked) = challenge_open(|_| {}).await;
        prompt_open_for(&mut sm, STUCK_PROMPT_CEILING);
        sm.prompt_cancel_sent_at = Some(Instant::now() - PROMPT_CANCEL_GRACE);
        sm.state = State::Authenticating;
        sm.apply_transition(State::WaitingFor2fa).await.unwrap();

        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "a fresh push, kept");
        assert!(clicked.lock().unwrap().is_empty(), "nothing cancelled on the new prompt");
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_challenge_that_never_opens_after_the_picker_is_a_failed_round() {
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], no_form_no_connection_dump()),
            twofa_config,
        );
        sm.state = State::WaitingFor2fa;
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "picker: IB Key chosen");
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], no_form_no_connection_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "picker closed");

        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(sm.config.twofa.timeout_seconds + 1));
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating, "retried in this JVM, not relaunched");
        assert_eq!(sm.consecutive_2fa_timeouts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_failed_round_in_unattended_hours_parks_after_the_first_push() {
        // Without this, a night's failed rounds meant three pushes and two
        // relaunches nobody saw.
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false)),
            |c| {
                twofa_config(c);
                unattended_around_now(c, 0);
            },
        );
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true;
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));

        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::WaitingForHitl2fa, "no second push at night");
        assert_eq!(sm.consecutive_2fa_timeouts, 1, "with budget left (1/3)");
        assert_eq!(sm.hitl_park_reason, Some(HitlParkReason::UnattendedHours));
        sm.apply_transition(next).await.unwrap();
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new(), "the JVM is kept");

        // The operator's Retry in the morning: the park is over.
        sm.apply_transition(State::Authenticating).await.unwrap();
        assert_eq!(sm.hitl_park_reason, None, "a later park states its own reason");
    }

    #[tokio::test(start_paused = true)]
    async fn test_unattended_hours_outrank_restart_forever() {
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false)),
            |c| {
                twofa_config(c);
                c.twofa.backoff.on_timeout = crate::config::TwoFaOnTimeout::RestartForever;
                unattended_around_now(c, 0);
            },
        );
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true;
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingForHitl2fa);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_failed_round_outside_unattended_hours_retries_in_the_running_jvm() {
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false)),
            |c| {
                twofa_config(c);
                unattended_around_now(c, 6);
            },
        );
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true;
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::Authenticating);
        assert_eq!(sm.hitl_park_reason, None);
    }

    #[test]
    fn test_hitl_auto_retry_never_fires_inside_unattended_hours() {
        use crate::config::HitlStrategy;
        let night = crate::unattended::UnattendedHours::parse("22:00-08:00").unwrap();
        let tz = "[America/New_York]";
        let at = |s: &str| -> jiff::Zoned { format!("{s}{tz}").parse().unwrap() };

        let due = StateMachine::next_hitl_retry_at(&HitlStrategy::Periodic, &[60], 0, night, &at("2026-09-27T23:00:00-04:00"));
        assert_eq!(due, None, "not at midnight, and not at 08:00 either: wait for the operator");
        let due = StateMachine::next_hitl_retry_at(&HitlStrategy::Both, &[60], 0, night, &at("2026-09-28T07:30:00-04:00"));
        assert_eq!(due, Some(at("2026-09-28T08:30:00-04:00")), "already attended when due");
        let due = StateMachine::next_hitl_retry_at(&HitlStrategy::Periodic, &[60], 0, None, &at("2026-09-27T23:00:00-04:00"));
        assert_eq!(due, Some(at("2026-09-28T00:00:00-04:00")), "no window: unchanged");
        let due = StateMachine::next_hitl_retry_at(&HitlStrategy::NtfyCallback, &[60], 0, night, &at("2026-09-27T23:00:00-04:00"));
        assert_eq!(due, None, "no timer for the callback strategy");
    }

    #[tokio::test(start_paused = true)]
    async fn test_operator_retry_closes_an_open_prompt_then_retries_in_the_running_jvm() {
        // The decision: ibctl may close a prompt on the operator's
        // explicit Retry. The operator asked for a fresh push.
        let agent = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], login_form_dump());
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, true);

        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.state, State::WaitingForHitl2fa);
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa);
        assert_eq!(*clicked.lock().unwrap(), vec!["Cancel".to_string()]);

        // The Gateway closes it; the armed retry re-submits in this JVM.
        stage_parked_hitl(&mut sm, false);
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], login_form_dump()));
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa, "settle");
        sm.hitl_2fa_closed_at = Some(Instant::now() - RELOGIN_SETTLE_AFTER_2FA_CLOSE);
        let next = sm.do_waiting_for_hitl_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating);
        sm.apply_transition(next).await.unwrap();
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new());
        assert_eq!(sm.consecutive_2fa_timeouts, 3, "a resume does not touch the budget");
    }

    // What follows a Cancel is unverified in production, so every outcome is
    // judged from what the Gateway shows next: an
    // approval that raced the Cancel is a success, a form is retried, and
    // nothing at all is bounded. Nothing is typed over a completing login.

    /// Parked in HITL; the operator's Retry cancelled the open prompt and
    /// the Gateway closed it `closed_for` ago, now showing `dump`.
    async fn operator_cancelled(dump: serde_json::Value, closed_for: Duration) -> (StateMachine, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let agent = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], login_form_dump());
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, true);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa);
        assert_eq!(*clicked.lock().unwrap(), vec!["Cancel".to_string()]);
        stage_parked_hitl(&mut sm, false);
        let mut after = agent_showing(vec![live_gateway_window()], dump);
        after.clicked = clicked.clone();
        sm.agent_client = AgentClient::mock(after);
        sm.hitl_2fa_closed_at = Some(Instant::now() - closed_for);
        (sm, clicked)
    }

    #[tokio::test(start_paused = true)]
    async fn test_an_approval_that_raced_the_operators_cancel_is_recognised_not_resubmitted() {
        // Approved as Cancel was clicked: "connected" can take 132 s after
        // the close. Waiting 60 s and re-submitting (or relaunching) would
        // trample a login that is completing.
        let (mut sm, clicked) = operator_cancelled(no_form_no_connection_dump(), Duration::from_secs(60)).await;
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa, "nothing to judge yet");

        let mut connected = agent_showing(vec![live_gateway_window()], connected_dump());
        connected.clicked = clicked.clone();
        sm.agent_client = AgentClient::mock(connected);
        let next = sm.do_waiting_for_hitl_2fa().await.unwrap();
        assert_eq!(next, State::WaitingForApiReady, "the login completed in this JVM");
        assert_eq!(*clicked.lock().unwrap(), vec!["Cancel".to_string()], "nothing typed or clicked after");
        assert!(sm.last_relaunch.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_cancel_that_leaves_nothing_on_screen_is_bounded() {
        let (mut sm, _) = operator_cancelled(no_form_no_connection_dump(), CONFIRM_AFTER_CHALLENGE_CLOSE).await;
        let next = sm.do_waiting_for_hitl_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating, "after the bound: look for a form in this JVM");
        sm.apply_transition(next).await.unwrap();
        sm.in_jvm_relogin_since = Some(Instant::now() - IN_JVM_RELOGIN_FORM_GRACE);
        let next = sm.do_authenticate().await.unwrap();
        assert_eq!(next, State::Restarting, "no form ever: relaunch, the last resort");
        sm.apply_transition(next).await.unwrap();
        assert_eq!(sm.last_relaunch.as_ref().unwrap().reason, "no_usable_login_form");
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_stuck_prompt_approved_as_it_was_cancelled_is_a_success() {
        let (mut sm, clicked) = challenge_open(|_| {}).await;
        prompt_open_for(&mut sm, STUCK_PROMPT_CEILING);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);

        let mut approved = agent_showing(vec![live_gateway_window()], connected_dump());
        approved.clicked = clicked.clone();
        sm.agent_client = AgentClient::mock(approved);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "settling");
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::DismissingPopups);
        assert_eq!(sm.consecutive_2fa_timeouts, 0, "not a failed round");
        assert_eq!(*clicked.lock().unwrap(), vec!["Cancel".to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_cancelled_stuck_prompt_that_leaves_nothing_usable_is_bounded() {
        let (mut sm, _) = challenge_open(|_| {}).await;
        prompt_open_for(&mut sm, STUCK_PROMPT_CEILING);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], no_form_no_connection_dump()));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.twofa_gone_at = Some(Instant::now() - CONFIRM_AFTER_CHALLENGE_CLOSE);
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating, "a failed round, retried in this JVM");
        sm.apply_transition(next).await.unwrap();
        sm.in_jvm_relogin_since = Some(Instant::now() - IN_JVM_RELOGIN_FORM_GRACE);
        assert_eq!(sm.do_authenticate().await.unwrap(), State::Restarting);
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_login_parked_overnight_stays_parked_past_the_morning() {
        // Parking lasts until the operator's Retry or the Sunday re-auth:
        // the window ending must not launch a push by itself.
        let mut sm = make_test_state_machine_with(
            agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false)),
            |c| {
                twofa_config(c);
                c.twofa.backoff.strategy = crate::config::HitlStrategy::Periodic;
                c.twofa.backoff.intervals_minutes = vec![60];
                unattended_around_now(c, 0);
            },
        );
        sm.state = State::WaitingFor2fa;
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true;
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::WaitingForHitl2fa);
        sm.apply_transition(next).await.unwrap();
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_next_retry_at, None, "no automatic retry for an overnight park");
    }

    // "Login form back -> retry" stays subject to the
    // attempt budget and the unattended-hours policy. A form proves a retry
    // is possible, not that one is wanted. The budget is decided when the
    // round fails; the time of day is checked again when the push would
    // actually go, because an armed retry can wait on a prompt for minutes.

    #[tokio::test(start_paused = true)]
    async fn test_a_policy_retry_that_would_push_inside_unattended_hours_parks() {
        // The HITL timer fired at 21:59 with a prompt still up; the Gateway
        // closed it at 22:05 and put its form back.
        let mut agent = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl_with(agent, true, |c| unattended_around_now(c, 0));
        sm.hitl_next_retry_at = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa, "armed under the prompt");
        assert!(sm.hitl_relogin_armed);

        stage_parked_hitl(&mut sm, false);
        let mut back = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        back.dump_after_type = Some(form_after_ib_key_expiry(true));
        back.clicked = clicked.clone();
        sm.agent_client = AgentClient::mock(back);
        sm.hitl_2fa_closed_at = Some(Instant::now() - RELOGIN_SETTLE_AFTER_2FA_CLOSE);
        let next = sm.do_waiting_for_hitl_2fa().await.unwrap();
        assert_eq!(next, State::Authenticating, "the form is back: a retry is possible");
        sm.apply_transition(next).await.unwrap();

        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingForHitl2fa, "but not wanted at night");
        assert!(!clicked.lock().unwrap().contains(&"Log In".to_string()), "no push sent");
        assert_eq!(sm.hitl_park_reason, Some(HitlParkReason::UnattendedHours));
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_operators_retry_is_not_held_by_unattended_hours() {
        let mut agent = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl_with(agent, false, |c| unattended_around_now(c, 0));
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingFor2fa, "you asked for it");
        assert!(clicked.lock().unwrap().contains(&"Log In".to_string()));
    }

    #[test]
    fn test_an_armed_retry_keeps_its_strongest_asker() {
        // The operator's Retry armed it; the HITL timer firing later must
        // not demote it to a policy retry that unattended hours would hold.
        let mut sm = parked_live_hitl(MockAgent::default(), true);
        assert_eq!(sm.begin_in_jvm_relogin("HITL_RESUME received", RetryBy::Operator), State::WaitingForHitl2fa);
        assert_eq!(sm.begin_in_jvm_relogin("HITL auto-retry", RetryBy::Policy), State::WaitingForHitl2fa);
        assert_eq!(sm.hitl_relogin_armed_by, Some(RetryBy::Operator));
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_sunday_reauth_is_not_held_by_unattended_hours() {
        let mut agent = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let mut sm = parked_live_hitl_with(agent, false, |c| unattended_around_now(c, 0));
        sm.handle_interrupt(fire()).await.unwrap();
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::ResumedLogin);
        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingFor2fa, "the scheduled recovery");
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_form_returning_outside_a_2fa_round_is_a_new_login_at_any_hour() {
        // A revoke or RE-LOGIN at night is a new login's first push, like a
        // fresh JVM's; the policy parks after it fails, not before it.
        let mut agent = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let mut sm = parked_live_hitl_with(agent, false, |c| unattended_around_now(c, 0));
        sm.state = State::WaitingForLogin;
        let next = sm.do_wait_for_login().await.unwrap();
        assert_eq!(next, State::Authenticating);
        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingFor2fa);
    }

    #[tokio::test(start_paused = true)]
    async fn test_operator_retry_on_a_prompt_that_ignores_cancel_relaunches() {
        let agent = agent_showing(vec![live_gateway_window(), ib_key_dialog_window()], login_form_dump());
        let mut sm = parked_live_hitl(agent, true);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::WaitingForHitl2fa);

        sm.prompt_cancel_sent_at = Some(Instant::now() - PROMPT_CANCEL_GRACE);
        assert_eq!(sm.do_waiting_for_hitl_2fa().await.unwrap(), State::Restarting);
        assert_eq!(sm.relaunch_reason, Some(RelaunchReason::PromptIgnoredCancel));
    }

    #[tokio::test(start_paused = true)]
    async fn test_the_legacy_exit_action_fires_on_a_failed_round_not_on_the_timer() {
        let exit = |c: &mut Config| {
            c.twofa.timeout_action = crate::config::TwoFaTimeoutAction::Exit;
            c.twofa.relogin_after_timeout = false;
        };
        let (mut sm, _) = challenge_open(exit).await;
        let past_timer = Duration::from_secs(sm.config.twofa.timeout_seconds + 1);
        prompt_open_for(&mut sm, past_timer);
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa, "not while the push is open");

        sm.agent_client = AgentClient::mock(agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false)));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::WaitingFor2fa);
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        assert_eq!(sm.do_wait_for_2fa().await.unwrap(), State::Shutdown);
    }

    #[tokio::test]
    async fn test_relaunching_under_an_open_prompt_without_a_reason_trips_the_wire() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        stage_parked_hitl(&mut sm, true);
        sm.apply_transition(State::Restarting).await.unwrap();
        let r = sm.last_relaunch.as_ref().expect("relaunch recorded");
        assert!(r.abandoned_prompt, "an IB Key push was abandoned for no recorded reason");
        assert_eq!(r.reason, "unspecified");
    }

    #[tokio::test]
    async fn test_every_relaunch_from_the_login_path_records_why() {
        let mut sm = parked_live_hitl(
            agent_showing(vec![live_gateway_window()], no_form_no_connection_dump()),
            false,
        );
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        sm.in_jvm_relogin_since = Some(Instant::now() - IN_JVM_RELOGIN_FORM_GRACE);
        let next = sm.do_authenticate().await.unwrap();
        sm.apply_transition(next).await.unwrap();
        assert_eq!(sm.last_relaunch.as_ref().unwrap().reason, "no_usable_login_form");

        let mut sm = parked_live_hitl(MockAgent::default(), false);
        sm.supervisor.set_test_force_running(false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.last_relaunch.as_ref().unwrap().reason, "jvm_exited");
    }

    // A container restarted just after the target (09:02 for a 09:00
    // target) boots past it, and the scheduler does not
    // fire. That boot is the week's RESTART; the login stays owed — visibly,
    // with a current action if it parks — until it actually succeeds.

    fn booted_after_target(at: Option<jiff::Zoned>) -> Interrupt {
        Interrupt::ColdRestart(ColdRestartSignal::BootedAfterTarget { auth_satisfied_at: at })
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_boot_after_the_target_owes_the_login_until_it_succeeds_even_through_a_park() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let mut agent = agent_showing(vec![live_gateway_window()], form_after_ib_key_expiry(false));
        agent.dump_after_type = Some(form_after_ib_key_expiry(true));
        let mut sm = parked_live_hitl_with(agent, false, |_| {});
        sm.cold_restart_equivalent_marker_path = marker.clone();
        // The fresh gateway's own login is in progress, two rounds already failed.
        sm.hitl_entered_at = None;
        sm.state = State::WaitingFor2fa;
        sm.consecutive_2fa_timeouts = 2;

        sm.handle_interrupt(booted_after_target(None)).await.unwrap();
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::RestartedByBoot);
        assert!(sm.cold_restart_owed_since.is_some(), "the login is owed");
        assert_eq!(sm.state, State::WaitingFor2fa, "nothing restarted");

        // Its third round fails too: it parks for the operator.
        sm.twofa_seen = true;
        sm.twofa_challenge_seen = true;
        sm.twofa_gone_at = Some(Instant::now() - Duration::from_secs(6));
        let next = sm.do_wait_for_2fa().await.unwrap();
        assert_eq!(next, State::WaitingForHitl2fa);
        sm.apply_transition(next).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&sm.build_status_json()).unwrap();
        assert!(v["cold_restart_owed_since"].is_string(), "still visibly owed while parked");
        assert_eq!(v["last_cold_restart_outcome"]["outcome"], "restarted_by_boot");
        assert_eq!(v["hitl"]["active"], true, "the parked login offers Retry");

        // The operator's Retry logs in, in the running gateway; approved.
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.state, State::Authenticating);
        let next = sm.do_authenticate().await.unwrap();
        assert_eq!(next, State::WaitingFor2fa);
        for s in [next, State::DismissingPopups, State::WaitingForApiReady, State::ConfiguringApi, State::Connected] {
            sm.apply_transition(s).await.unwrap();
        }
        assert!(matches!(outcome_of(&sm), ColdRestartOutcome::Completed { .. }), "got {:?}", outcome_of(&sm));
        assert!(sm.cold_restart_owed_since.is_none());
        assert!(marker.exists(), "this week's re-authentication");
        assert_eq!(jvm_lifecycle_transitions(&sm), Vec::<String>::new(), "no restart at any point");
    }

    #[tokio::test]
    async fn test_a_restart_satisfied_by_boot_is_never_run_again_at_connected() {
        // A Connected without a fresh login (a warm reconnect) cannot finish
        // the owed login — but the restart was this boot: never a second one.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.handle_interrupt(booted_after_target(None)).await.unwrap();
        sm.state = State::WaitingForApiReady;
        sm.cold_restart_equivalent_pending = false;
        sm.apply_transition(State::Connected).await.unwrap();
        assert!(!sm.cold_restart_fire_on_connected, "no second restart");
        assert!(sm.cold_restart_owed_since.is_some(), "the login is still owed");
    }

    #[tokio::test]
    async fn test_a_boot_after_a_fresh_login_today_owes_nothing() {
        let mut sm = make_test_state_machine(MockAgent::default());
        let at = jiff::Zoned::now();
        sm.handle_interrupt(booted_after_target(Some(at.clone()))).await.unwrap();
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::AlreadySatisfied { at });
        assert!(sm.cold_restart_owed_since.is_none());
    }

    // The Sunday window can be one maintenance event with two
    // owners. A host doing its own maintenance holds ibctl's Sunday fire
    // while it updates the container runtime, then releases it. The hold is a file next to the
    // cold-restart-equivalent marker, so it survives the container restart it
    // covers and the scheduler reads it from the same directory.

    fn sm_with_settings_dir(dir: &std::path::Path) -> StateMachine {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = dir.join(".ibctl-cold-restart-equivalent-today");
        sm
    }

    fn hold_on_disk(dir: &std::path::Path) -> Option<crate::maintenance_hold::Hold> {
        crate::maintenance_hold::read(&crate::maintenance_hold::path_in(dir))
    }

    #[tokio::test]
    async fn test_a_maintenance_hold_is_written_where_the_scheduler_reads_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = sm_with_settings_dir(dir.path());
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-1".into(), ttl_secs: 1200 }))
            .await
            .unwrap();
        let hold = hold_on_disk(dir.path()).expect("hold persisted");
        assert_eq!(hold.id, "rt-1");
        assert!(hold.active_at(jiff::Timestamp::now()));
        assert_eq!(sm.state, State::Init, "a hold changes nothing about the gateway");
    }

    #[tokio::test]
    async fn test_releasing_the_hold_clears_it_and_records_the_result() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = sm_with_settings_dir(dir.path());
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-1".into(), ttl_secs: 600 })).await.unwrap();
        sm.handle_interrupt(Interrupt::Command(Command::MaintRelease { id: "rt-1".into(), result: "ok".into() }))
            .await
            .unwrap();
        assert!(hold_on_disk(dir.path()).is_none());
        let last = sm.last_maintenance.as_ref().expect("result recorded");
        assert_eq!((last.id.as_str(), last.result.as_str()), ("rt-1", "ok"));
    }

    #[tokio::test]
    async fn test_a_release_for_another_maintenance_leaves_the_hold() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = sm_with_settings_dir(dir.path());
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-1".into(), ttl_secs: 600 })).await.unwrap();
        sm.handle_interrupt(Interrupt::Command(Command::MaintRelease { id: "rt-0".into(), result: "ok".into() }))
            .await
            .unwrap();
        assert_eq!(hold_on_disk(dir.path()).map(|h| h.id), Some("rt-1".into()));
    }

    #[tokio::test]
    async fn test_one_maintenance_at_a_time() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = sm_with_settings_dir(dir.path());
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-1".into(), ttl_secs: 600 })).await.unwrap();
        let first = hold_on_disk(dir.path()).unwrap();
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-2".into(), ttl_secs: 600 })).await.unwrap();
        assert_eq!(hold_on_disk(dir.path()).unwrap().id, "rt-1", "a second maintenance is refused");
        // The same maintenance may extend its own hold.
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-1".into(), ttl_secs: 1800 })).await.unwrap();
        assert!(hold_on_disk(dir.path()).unwrap().expires_at > first.expires_at);
    }

    #[tokio::test]
    async fn test_an_over_long_hold_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = sm_with_settings_dir(dir.path());
        let ttl_secs = crate::maintenance_hold::MAX_TTL_SECS + 1;
        sm.handle_interrupt(Interrupt::Command(Command::MaintHold { id: "rt-1".into(), ttl_secs })).await.unwrap();
        assert!(hold_on_disk(dir.path()).is_none());
    }

    // One login in flight per JVM. A Gateway can start its own re-login
    // ('Login' window) after an IBKR drop; ibctl's popup sweep used to type
    // credentials into the reverted form as well, and the two logins then
    // displaced each other for hours.

    fn gateway_relogin_window() -> WindowInfo {
        WindowInfo { id: WindowId(12), title: "Login".into(), class: "dialog".into(), bounds: None, visible: true }
    }

    #[tokio::test(start_paused = true)]
    async fn test_popup_sweep_never_logs_in() {
        // The exact path: after the revoke, DismissingPopups with the
        // reverted form on screen and the login handler's guard reset.
        let agent = agent_showing(vec![live_gateway_window()], login_form_dump());
        let clicked = agent.clicked.clone();
        let mut sm = make_test_state_machine_with(agent, |c| c.auth.trading_mode = crate::config::TradingMode::Live);
        sm.handler_registry = DialogHandlerRegistry::with_defaults(&sm.config);
        sm.state = State::DismissingPopups;
        let _ = sm.do_dismiss_popups().await.unwrap();
        assert!(
            !clicked.lock().unwrap().contains(&"Log In".to_string()),
            "a popup sweep submitted credentials: {:?}",
            clicked.lock().unwrap(),
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_in_jvm_retry_does_not_race_the_gateways_own_relogin() {
        let mut agent = agent_showing(vec![live_gateway_window(), gateway_relogin_window()], login_form_dump());
        agent.dump_by_window.insert(12, no_form_no_connection_dump());
        let clicked = agent.clicked.clone();
        let mut sm = parked_live_hitl(agent, false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();

        assert_eq!(sm.do_authenticate().await.unwrap(), State::Authenticating, "wait for it");
        assert!(!clicked.lock().unwrap().contains(&"Log In".to_string()), "no second login");
    }

    // The session-conflict loop: "Reconnect This Session" clicked over and
    // over for hours, every dialog naming a session from the host's own IP
    // that ibctl's own previous click had created.

    fn conflict_dialog_window() -> WindowInfo {
        WindowInfo { id: WindowId(20), title: "Existing session detected".into(), class: "dialog".into(), bounds: None, visible: true }
    }

    fn paper_in_conflict(agent: MockAgent) -> StateMachine {
        let mut sm = make_test_state_machine(agent);
        sm.handler_registry = DialogHandlerRegistry::with_defaults(&sm.config);
        sm.state = State::HandlingSessionConflict;
        sm.last_conflict_message = Some("IP 203.0.113.7 connected at 16:09:26 09/26/2026 GMT.".into());
        sm
    }

    fn reconnect_clicks(clicked: &std::sync::Arc<std::sync::Mutex<Vec<String>>>) -> usize {
        clicked.lock().unwrap().iter().filter(|l| *l == "Reconnect This Session").count()
    }

    #[tokio::test(start_paused = true)]
    async fn test_session_conflict_loop_stops_clicking_at_the_threshold() {
        let agent = agent_showing(vec![gateway_window(), conflict_dialog_window()], serde_json::json!({}));
        let clicked = agent.clicked.clone();
        let mut sm = paper_in_conflict(agent);

        for n in 1..session_conflict::BREAKER_THRESHOLD {
            assert_eq!(sm.do_handle_session_conflict().await.unwrap(), State::DismissingPopups);
            assert_eq!(reconnect_clicks(&clicked), n);
        }
        assert_eq!(
            sm.do_handle_session_conflict().await.unwrap(),
            State::HandlingSessionConflict,
            "the dialog is left for a human",
        );
        assert!(sm.session_conflict_breaker_open);
        assert_eq!(sm.do_handle_session_conflict().await.unwrap(), State::HandlingSessionConflict);
        assert_eq!(
            reconnect_clicks(&clicked),
            session_conflict::BREAKER_THRESHOLD - 1,
            "no more clicks once the breaker is open",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_popup_sweep_never_answers_a_session_conflict() {
        // Observation not synced: the sweep sees the dialog first. It must
        // route to HandlingSessionConflict (where the breaker lives), not
        // click "Reconnect This Session" itself.
        let agent = agent_showing(vec![gateway_window(), conflict_dialog_window()], serde_json::json!({}));
        let clicked = agent.clicked.clone();
        let mut sm = make_test_state_machine(agent);
        sm.handler_registry = DialogHandlerRegistry::with_defaults(&sm.config);
        sm.observation.synced = false;
        sm.state = State::DismissingPopups;
        assert_eq!(sm.do_dismiss_popups().await.unwrap(), State::HandlingSessionConflict);
        assert_eq!(reconnect_clicks(&clicked), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_breaker_open_resumes_when_the_dialog_goes_away() {
        let mut sm = paper_in_conflict(agent_showing(vec![gateway_window()], serde_json::json!({})));
        sm.session_conflict_breaker_open = true;
        assert_eq!(sm.do_handle_session_conflict().await.unwrap(), State::DismissingPopups);
    }

    #[tokio::test(start_paused = true)]
    async fn test_conflict_evidence_is_recorded_and_our_own_session_is_recognised() {
        let agent = agent_showing(vec![gateway_window(), conflict_dialog_window()], serde_json::json!({}));
        let mut sm = paper_in_conflict(agent);
        // Our click at 16:09:26.641, next dialog "connected at 16:09:26".
        sm.last_login_action_at = Some("2026-09-26T16:09:26.641Z".parse().unwrap());
        sm.do_handle_session_conflict().await.unwrap();

        let rec = sm.last_session_conflict.clone().expect("recorded");
        assert_eq!(rec.other_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(rec.other_connected_at, Some("2026-09-26T16:09:26Z".parse().unwrap()));
        assert!(rec.self_inflicted, "the other session is the one our own click created");
        assert_eq!(rec.recent, 1);
        assert!(sm.last_login_action_at.unwrap() > "2026-09-26T16:09:26.641Z".parse().unwrap(),
            "this click is now our last login action");
    }

    #[tokio::test]
    async fn test_conflict_dialog_text_is_captured_from_the_agent_event() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.handle_agent_event(crate::agent_events::AgentEvent::ErrorDialog {
            window_title: "Existing session detected".into(),
            message: Some("IP 203.0.113.7 connected at 16:09:17 09/26/2026 GMT.".into()),
            buttons: vec!["Reconnect This Session".into(), "Cancel".into()],
        })
        .await;
        assert_eq!(sm.last_conflict_message.as_deref(), Some("IP 203.0.113.7 connected at 16:09:17 09/26/2026 GMT."));
    }

    #[tokio::test]
    async fn test_connected_closes_the_breaker() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.session_conflict_breaker_open = true;
        sm.session_conflicts.push_back(Instant::now());
        sm.state = State::ConfiguringApi;
        sm.apply_transition(State::Connected).await.unwrap();
        assert!(!sm.session_conflict_breaker_open);
        assert!(sm.session_conflicts.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn test_submitting_credentials_is_a_login_action() {
        let mut sm = parked_live_hitl(agent_showing(vec![live_gateway_window()], login_form_dump()), false);
        sm.handle_interrupt(Interrupt::Command(Command::HitlResume)).await.unwrap();
        assert_eq!(sm.do_authenticate().await.unwrap(), State::WaitingFor2fa);
        assert!(sm.last_login_action_at.is_some());
    }

    #[tokio::test]
    async fn test_cold_restart_preserves_an_outstanding_push() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingFor2fa;
        sm.handle_interrupt(fire()).await.expect("handler must not error");
        assert_eq!(sm.state, State::WaitingFor2fa, "an outstanding push is preserved");
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::ChallengePending);
        assert!(sm.cold_restart_owed_since.is_some());
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
    // HITL with the login form back
    //
    // A HITL wait of several hours while the JVM showed its login form
    // again was once answered with a demote to WaitingForLogin after 3
    // ticks of "login form, no 2FA dialog" — an unattended re-login.
    // The form coming back in the running JVM is simply what the Gateway
    // does when a push expires, so every resume path re-submits into it
    // instead. The wait is ended by
    // the operator's Retry, the armed retry, the HITL timer or the Sunday
    // fire; a parked mode with its form back stays parked.
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
    async fn test_hitl_with_the_login_form_back_stays_parked_for_the_operator() {
        // A parked mode whose IB Key prompt expired shows its login form
        // again: that is the normal parked state (verified against a live
        // Gateway). It used to be demoted to WaitingForLogin after 3
        // ticks to log in again unattended, which is another push at 03:00
        // that nobody answers, through a path whose cache calls the JVM
        // authenticated. Parked stays parked; the operator's Retry, the armed
        // retry and the Sunday fire resume it in the running JVM.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_only(&mut sm, 1);
        for tick in 1..=5 {
            assert_eq!(
                sm.do_waiting_for_hitl_2fa().await.expect("tick"),
                State::WaitingForHitl2fa,
                "tick {tick}",
            );
        }
    }

    #[tokio::test]
    async fn test_hitl_holds_when_2fa_dialog_still_visible() {
        // The legitimate HITL state: login window behind, 2FA dialog in front.
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_and_2fa(&mut sm, 1);
        for tick in 1..=5 {
            assert_eq!(
                sm.do_waiting_for_hitl_2fa().await.expect("tick"),
                State::WaitingForHitl2fa,
                "tick {tick}",
            );
        }
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
    async fn test_hitl_positive_check_needs_the_login_form_gone() {
        // The positive probe only runs with no login form and no 2FA dialog
        // on screen; with the form showing, even a "connected" dump is not
        // acted on, and the mode stays parked.
        let mock = MockAgent {
            windows: vec![gateway_window()],
            dump_response: parse(FIXTURE_API_SERVER_UP_API_CLIENT_DOWN),
            ..Default::default()
        };
        let mut sm = make_test_state_machine(mock);
        sm.state = State::WaitingForHitl2fa;
        stage_login_form_only(&mut sm, 1);
        for tick in 1..=3 {
            assert_eq!(
                sm.do_waiting_for_hitl_2fa().await.expect("tick"),
                State::WaitingForHitl2fa,
                "tick {tick}",
            );
            assert_eq!(sm.hitl_connected_observation_ticks, 0);
        }
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
    // The filter is the load-bearing piece here: we
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
    // Scheduler skip, and the settlement of an owed re-auth.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn test_skipped_fresh_auth_records_already_satisfied_and_does_not_restart() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::Connected;
        let last_login = jiff::Zoned::now();

        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Skipped(
            ColdRestartSkipReason::FreshAuthToday { at: last_login.clone() },
        )))
        .await
        .expect("Skipped handler must not error");

        assert_eq!(sm.state, State::Connected, "Skipped must NOT restart");
        assert_eq!(
            outcome_of(&sm),
            &ColdRestartOutcome::AlreadySatisfied { at: last_login },
        );
        assert!(sm.cold_restart_owed_since.is_none());
    }

    #[tokio::test]
    async fn test_skipped_on_standby_stays_standby() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.state = State::WaitingForLaunch;
        sm.handle_interrupt(Interrupt::ColdRestart(ColdRestartSignal::Skipped(
            ColdRestartSkipReason::FreshAuthToday { at: jiff::Zoned::now() },
        )))
        .await
        .unwrap();
        assert_eq!(sm.state, State::WaitingForLaunch);
    }

    #[tokio::test]
    async fn test_fire_on_connected_records_restarted_over_a_prior_outcome() {
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.last_cold_restart_outcome = Some(ColdRestartOutcomeRecord {
            recorded_at: jiff::Zoned::now(),
            outcome: ColdRestartOutcome::Standby,
            state: "WaitingForLaunch".into(),
        });
        sm.state = State::Connected;
        sm.handle_interrupt(fire()).await.unwrap();
        assert_eq!(sm.state, State::Restarting);
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::Restarted);
        assert!(sm.cold_restart_owed_since.is_none(), "a restart owes nothing further");
    }

    #[tokio::test]
    async fn test_owed_reauth_is_completed_by_an_authenticating_login() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = dir.path().join(".equiv");
        sm.cold_restart_owed_since = Some(jiff::Zoned::now());
        sm.state = State::ConfiguringApi;
        sm.cold_restart_equivalent_pending = true;

        sm.apply_transition(State::Connected).await.unwrap();

        assert!(matches!(outcome_of(&sm), ColdRestartOutcome::Completed { .. }));
        assert!(sm.cold_restart_owed_since.is_none());
        assert!(!sm.cold_restart_fire_on_connected, "an authenticated login needs no restart");
    }

    #[tokio::test]
    async fn test_owed_reauth_reaching_connected_without_authenticating_restarts_once() {
        // e.g. the fire was Deferred behind a warm restart, which reconnects
        // without credentials: the week's re-auth is still owed.
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = dir.path().join(".equiv");
        sm.cold_restart_owed_since = Some(jiff::Zoned::now());
        sm.state = State::DismissingPopups;
        assert!(!sm.cold_restart_equivalent_pending);

        sm.apply_transition(State::Connected).await.unwrap();
        assert!(sm.cold_restart_fire_on_connected);

        let next = sm.do_connected().await.unwrap();

        assert_eq!(next, State::Restarting, "the owed cold restart runs now");
        assert_eq!(outcome_of(&sm), &ColdRestartOutcome::Restarted);
        assert!(sm.cold_restart_owed_since.is_none());
        assert!(!sm.cold_restart_fire_on_connected, "one-shot");
    }

    #[tokio::test(start_paused = true)]
    async fn test_credentials_login_without_a_2fa_dialog_counts_as_authentication() {
        // PAPER: credentials submitted, no 2FA dialog
        // (grace-period escape), Connected. That IS this week's re-auth.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let mut sm = make_test_state_machine(agent_showing(
            vec![gateway_window()],
            serde_json::json!({
                "textfields": [field(0, true), field(1, true)],
                "buttons": [button("IB API", true), button("Paper Trading", true), button("Paper Log In", true)],
                "labels": [], "tables": []
            }),
        ));
        sm.handler_registry = DialogHandlerRegistry::with_defaults(&sm.config);
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::Authenticating;

        let submitted = sm.do_authenticate().await.unwrap();
        assert_eq!(submitted, State::WaitingFor2fa, "credentials submitted");
        for next in [
            submitted,
            State::DismissingPopups,
            State::WaitingForApiReady,
            State::ConfiguringApi,
            State::Connected,
        ] {
            sm.apply_transition(next).await.unwrap();
        }

        assert!(marker.exists(), "a credentials login must be recorded as an authentication");
    }

    #[tokio::test]
    async fn test_warm_restart_path_is_not_an_authentication() {
        // IBC -Drestart= relaunch, as a live Gateway logs it:
        // WaitingForLogin -> DismissingPopups -> ... -> Connected.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let mut sm = make_test_state_machine(MockAgent::default());
        sm.cold_restart_equivalent_marker_path = marker.clone();
        sm.state = State::Launching;

        for next in [
            State::WaitingForAgent,
            State::WaitingForLogin,
            State::DismissingPopups,
            State::WaitingForApiReady,
            State::ConfiguringApi,
            State::Connected,
        ] {
            sm.apply_transition(next).await.unwrap();
        }

        assert!(!marker.exists(), "a warm restart must not satisfy the weekly re-auth");
    }

    // ----------------------------------------------------------------
    // cold_restart_equivalent_pending lifecycle.
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

    // Parameterization: the flag-set arm in apply_transition matches
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
        // The positive-direction HITL probe: the JVM reached
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
        // The negative-direction stale-form demote: the 2FA
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
    // Marker gate — marker is written ONLY when the flag is true.
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
        // A scenario the existing tests don't cover end-to-end:
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
    // Recovery coordinator wrapper wiring tests
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
    /// Regression guard for dwell_guard leaks via seven direct-assign
    /// sites, and for GivenUp entry not aborting the guard either.
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
    /// Regression guard for the dormant-state tick gate.
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
    // ------------------------------------------------------------------
    // JVM-death token detection outside Connected
    //
    // Gateway's own scheduled AUTO_RESTART_TIME drops the API connection
    // several seconds BEFORE the JVM process actually exits. On most days
    // that gap is short enough that `do_connected()`'s own JvmDied check
    // (zero debounce) observes the death first, while we are still in
    // Connected, and correctly finds the autorestart token Gateway leaves
    // behind — a clean warm restart, no 2FA.
    //
    // When the gap is long enough, DisconnectedLabelStable's
    // 2s debounce matures FIRST, revoking Connected and landing the state
    // machine in DismissingPopups — moments before the JVM actually exits.
    // `do_connected()` used to be the ONLY one of eight `!supervisor.is_running()`
    // call sites that knew to call `find_autorestart_path()`; every other
    // site fell straight to a bare `State::Error(...)`, forcing a full cold
    // reauth (2FA, possibly timing out into a human-approved HITL push) even
    // though Gateway had already written a perfectly good token to disk.
    //
    // `check_jvm_exit()` is the fix: a single, state-independent check that
    // every "JVM might have died here" site now shares, so which state we
    // happened to be in when Gateway's own restart raced against label
    // inspection no longer decides whether the operator gets paged.

    /// Build a state machine with a fake autorestart token on disk and the
    /// JVM already reported dead — the exact shape `check_jvm_exit()` must
    /// recognize regardless of which state calls it.
    fn make_test_state_machine_with_dead_jvm_and_token(
        mock: MockAgent,
        token_hash: &str,
    ) -> (StateMachine, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let session_dir = dir.path().join(token_hash);
        std::fs::create_dir(&session_dir).unwrap();
        std::fs::write(session_dir.join("autorestart"), b"").unwrap();

        let mut sm = make_test_state_machine(mock);
        sm.supervisor.set_test_settings_path(dir.path().display().to_string());
        sm.supervisor.set_test_force_running(false);
        (sm, dir)
    }

    /// Same, but no token file — the genuine-crash case. `check_jvm_exit()`
    /// must still detect the death (so we don't hang) but must NOT arm a
    /// warm restart, preserving the cold-restart backoff a real crash needs
    /// so we don't hammer IBKR's backend.
    fn make_test_state_machine_with_dead_jvm_no_token(mock: MockAgent) -> (StateMachine, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut sm = make_test_state_machine(mock);
        sm.supervisor.set_test_settings_path(dir.path().display().to_string());
        sm.supervisor.set_test_force_running(false);
        (sm, dir)
    }

    #[tokio::test]
    async fn test_dismiss_popups_jvm_death_arms_warm_restart_when_token_present() {
        // The race itself. Reproduces DismissingPopups exactly as it is
        // entered when the label wins: Connected revoked by disconnected_label,
        // JVM still finishing its own scheduled exit a beat later.
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "abcdefghijklmnopabcdefghijklmnopabcdefgh");
        sm.state = State::DismissingPopups;

        let result = sm.do_dismiss_popups().await.expect("handler should not error");

        assert_eq!(
            result,
            State::Restarting,
            "a dead JVM with a token on disk must go straight to Restarting, not Error"
        );
        assert_eq!(
            sm.warm_restart_pending.as_deref(),
            Some("abcdefghijklmnopabcdefghijklmnopabcdefgh"),
            "the token found on disk must be armed so do_restart() skips cold reauth"
        );
    }

    #[tokio::test]
    async fn test_dismiss_popups_jvm_death_without_token_stays_cold() {
        let (mut sm, _dir) = make_test_state_machine_with_dead_jvm_no_token(MockAgent::default());
        sm.state = State::DismissingPopups;

        let result = sm.do_dismiss_popups().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(
            sm.warm_restart_pending, None,
            "no token on disk ⇒ genuine crash ⇒ must NOT claim a warm restart              (do_restart's cold-restart backoff exists precisely to avoid              hammering IBKR's backend after an unplanned exit)"
        );
    }

    #[tokio::test]
    async fn test_wait_for_2fa_jvm_death_arms_warm_restart_when_token_present() {
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "tok2fa");
        sm.state = State::WaitingFor2fa;

        let result = sm.do_wait_for_2fa().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(sm.warm_restart_pending.as_deref(), Some("tok2fa"));
    }

    #[tokio::test]
    async fn test_wait_for_agent_jvm_death_arms_warm_restart_when_token_present() {
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "tokagent");
        sm.state = State::WaitingForAgent;

        let result = sm.do_wait_for_agent().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(sm.warm_restart_pending.as_deref(), Some("tokagent"));
    }

    #[tokio::test]
    async fn test_wait_for_login_cold_auth_jvm_death_arms_warm_restart_when_token_present() {
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "toklogin");
        sm.state = State::WaitingForLogin;
        // Cold-auth path only — not the already-warm_restart_pending fast path.
        sm.warm_restart_pending = None;

        let result = sm.do_wait_for_login().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(sm.warm_restart_pending.as_deref(), Some("toklogin"));
    }

    #[tokio::test]
    async fn test_wait_for_api_ready_jvm_death_arms_warm_restart_when_token_present() {
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "tokapi");
        sm.state = State::WaitingForApiReady;

        let result = sm.do_wait_for_api_ready().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(sm.warm_restart_pending.as_deref(), Some("tokapi"));
    }

    #[tokio::test]
    async fn test_configure_api_jvm_death_arms_warm_restart_when_token_present() {
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "tokconfig");
        sm.state = State::ConfiguringApi;

        let result = sm.do_configure_api().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(sm.warm_restart_pending.as_deref(), Some("tokconfig"));
    }

    #[tokio::test]
    async fn test_connected_jvm_death_still_arms_warm_restart_and_still_revokes() {
        // Regression guard for the refactor: do_connected's own JvmDied
        // revocation-bus bookkeeping (the "proof revoked source=jvm_died"
        // logging/debounce-clear semantics) must survive extracting the
        // shared token-check into check_jvm_exit().
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "tokconnected");
        sm.state = State::Connected;
        sm.connected_window_class = Some("ibgateway.ay".to_string());

        let result = sm.do_connected().await.expect("handler should not error");

        assert_eq!(result, State::Restarting);
        assert_eq!(sm.warm_restart_pending.as_deref(), Some("tokconnected"));
    }
    #[tokio::test]
    async fn test_entering_connected_stops_login_handler_matching_main_window() {
        // End-to-end wiring check for the login-sweep fix: does
        // apply_transition's entry-to-Connected arm actually reach
        // LoginHandler through the real registry, not just the unit-level
        // mark_login_complete()/can_handle() pairing tested in
        // handlers::login and handlers::tests?
        //
        // Uses with_defaults() rather than the empty registry
        // make_test_state_machine() normally wires up, specifically to
        // exercise the real LoginHandler this bug lives in.
        let mut cfg = Config::default();
        (cfg.auth.username, cfg.auth.password) = test_auth_placeholder();
        cfg.auth.trading_mode = crate::config::TradingMode::Paper;
        let config = ValidConfig::new_unchecked(cfg);

        let mock = MockAgent::default();
        let agent_client = AgentClient::mock(mock);
        let supervisor = Supervisor::new(
            config.gateway.clone(),
            std::path::PathBuf::from("/dev/null/not-used-in-tests.jar"),
            "/dev/null/not-used.sock".to_string(),
            5,
        );
        let handler_registry = DialogHandlerRegistry::with_defaults(&config);

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
                let (_tx, rx) = mpsc::channel(1);
                rx
            },
        };
        let (snapshot_tx, _snapshot_rx) = watch::channel(Arc::new(QuerySnapshot::initializing()));
        let cold_restart_equivalent_marker_path = std::env::temp_dir()
            .join("ibctl-test-cold-restart-equivalent-do-not-use-2");
        let mut sm = StateMachine::new(
            config,
            agent_client,
            supervisor,
            handler_registry,
            channels,
            snapshot_tx,
            cold_restart_equivalent_marker_path,
        );
        sm.supervisor.set_test_force_running(true);

        let main_window = WindowInfo {
            id: WindowId(1),
            title: "IBKR Gateway [PAPER]".to_string(),
            class: "ibgateway.aw".to_string(),
            bounds: None,
            visible: true,
        };

        sm.apply_transition(State::Connected)
            .await
            .expect("apply_transition must not error");

        let result = sm
            .handler_registry
            .dispatch(&sm.agent_client, &main_window)
            .await;
        assert!(
            result.is_none(),
            "after entering Connected, no handler — least of all LoginHandler —              should match the main Gateway window; got {:?}",
            result
        );
    }

    // ----------------------------------------------------------------
    // Gateway hotkeys (RECONNECTDATA / RECONNECTACCOUNT)
    // ----------------------------------------------------------------

    fn hotkey_window(id: u64, title: &str, width: i32, height: i32) -> WindowInfo {
        WindowInfo {
            id: WindowId(id),
            title: title.into(),
            class: "ibgateway.aw".into(),
            bounds: Some(crate::agent_client::Bounds { x: 0, y: 0, width, height }),
            // As the real agent lists them: no `visible` field, so it parses as false.
            visible: false,
        }
    }

    #[tokio::test]
    async fn test_reconnect_data_presses_ctrl_alt_f_in_the_main_window_not_a_dialog() {
        let mock = MockAgent {
            windows: vec![hotkey_window(1, "IBKR Gateway", 450, 170), hotkey_window(2, "IBKR Gateway [PAPER]", 700, 558)],
            ..MockAgent::default()
        };
        let keys = mock.keys_sent.clone();
        let mut sm = make_test_state_machine(mock);

        sm.handle_command(Command::ReconnectData).await.unwrap();

        assert_eq!(*keys.lock().unwrap(), vec![(2u64, "ctrl alt F".to_string())]);
        let record = sm.last_hotkey.clone().unwrap();
        assert_eq!((record.command, record.outcome), ("RECONNECTDATA", "sent"));
        assert_eq!(record.window.as_deref(), Some("IBKR Gateway [PAPER]"));
        assert!(
            sm.handler_registry.hotkey_expectation.consume(Duration::from_secs(30)),
            "the prompt the key causes must be expected"
        );
    }

    #[tokio::test]
    async fn test_reconnect_account_presses_ctrl_alt_r() {
        let mock = MockAgent { windows: vec![hotkey_window(2, "IBKR Gateway [PAPER]", 700, 558)], ..MockAgent::default() };
        let keys = mock.keys_sent.clone();
        let mut sm = make_test_state_machine(mock);

        sm.handle_command(Command::ReconnectAccount).await.unwrap();

        assert_eq!(*keys.lock().unwrap(), vec![(2u64, "ctrl alt R".to_string())]);
        assert_eq!(sm.last_hotkey.as_ref().unwrap().command, "RECONNECTACCOUNT");
    }

    #[tokio::test]
    async fn test_a_key_the_agent_could_not_send_is_a_reported_failure() {
        let mock = MockAgent {
            windows: vec![hotkey_window(2, "IBKR Gateway [PAPER]", 700, 558)],
            send_key_result: false,
            ..MockAgent::default()
        };
        let mut sm = make_test_state_machine(mock);

        sm.handle_command(Command::ReconnectData).await.unwrap();

        let record = sm.last_hotkey.clone().unwrap();
        assert_eq!(record.outcome, "failed");
        assert!(record.error.unwrap().contains("could not send the key"));
    }

    #[tokio::test]
    async fn test_no_main_window_means_no_key_and_a_reported_failure() {
        let mock = MockAgent { windows: vec![hotkey_window(1, "IBKR Gateway", 450, 170)], ..MockAgent::default() };
        let keys = mock.keys_sent.clone();
        let mut sm = make_test_state_machine(mock);

        sm.handle_command(Command::ReconnectData).await.unwrap();

        assert!(keys.lock().unwrap().is_empty(), "nothing is sent to a dialog");
        let record = sm.last_hotkey.clone().unwrap();
        assert_eq!(record.outcome, "failed");
        assert!(record.error.unwrap().contains("main window"));
        assert!(!sm.handler_registry.hotkey_expectation.consume(Duration::from_secs(30)), "nothing was pressed, so nothing is expected");
    }

    // ----------------------------------------------------------------
    // SETRESTART: next minute or a given time, read back, recorded
    // ----------------------------------------------------------------

    fn restart_dialog_mock(field_text: &str) -> MockAgent {
        MockAgent {
            windows: vec![
                hotkey_window(1, "IBKR Gateway [PAPER]", 700, 558),
                hotkey_window(2, "Configuration", 800, 600),
            ],
            dump_after_type: Some(serde_json::json!({"textfields": [{"index": 0, "text": field_text}]})),
            ..MockAgent::default()
        }
    }

    fn sm_with_fast_ui(mock: MockAgent) -> StateMachine {
        make_test_state_machine_with(mock, |cfg| cfg.timing.ui_tick_ms = 1)
    }

    #[tokio::test]
    async fn test_setrestart_with_a_time_records_that_it_was_applied() {
        let mut sm = sm_with_fast_ui(restart_dialog_mock("5:05"));

        sm.handle_command(Command::SetRestartTime("5:05 PM".to_string())).await.unwrap();

        let record = sm.last_setrestart.clone().unwrap();
        assert_eq!((record.source, record.requested.as_str(), record.applied), ("time", "5:05 PM", true));
        assert_eq!(record.error, None);
    }

    #[tokio::test]
    async fn test_a_restart_time_the_field_did_not_keep_is_recorded_as_not_applied() {
        let mut sm = sm_with_fast_ui(restart_dialog_mock("9:00"));

        sm.handle_command(Command::SetRestartTime("5:05 PM".to_string())).await.unwrap();

        let record = sm.last_setrestart.clone().unwrap();
        assert!(!record.applied);
        assert!(record.error.unwrap().contains("instead of"));
    }

    #[tokio::test]
    async fn test_a_bare_setrestart_types_the_next_whole_minute() {
        let zone = jiff::tz::TimeZone::UTC;
        let before = crate::gateway_zone::next_restart_minute(jiff::Timestamp::now(), &zone);
        let field = before.split(' ').next().unwrap().to_string();
        let mut sm = sm_with_fast_ui(restart_dialog_mock(&field));

        sm.handle_command(Command::SetRestartNow).await.unwrap();

        let after = crate::gateway_zone::next_restart_minute(jiff::Timestamp::now(), &zone);
        let record = sm.last_setrestart.clone().unwrap();
        assert_eq!(record.source, "now");
        assert!(record.requested == before || record.requested == after, "{} not in {{{before}, {after}}}", record.requested);
    }

    #[tokio::test]
    async fn test_setrestart_with_no_configuration_dialog_is_recorded_as_failed() {
        let mock = MockAgent { windows: vec![hotkey_window(1, "IBKR Gateway [PAPER]", 700, 558)], ..MockAgent::default() };
        let mut sm = make_test_state_machine_with(mock, |cfg| cfg.timing.ui_tick_ms = 0);

        sm.handle_command(Command::SetRestartTime("5:05 PM".to_string())).await.unwrap();

        let record = sm.last_setrestart.clone().unwrap();
        assert!(!record.applied);
        assert!(record.error.is_some());
    }

    #[tokio::test]
    async fn test_status_says_a_gateway_exit_with_a_saved_session_was_warm() {
        let (mut sm, _dir) =
            make_test_state_machine_with_dead_jvm_and_token(MockAgent::default(), "abcdefghijklmnopabcdefghijklmnopabcdefgh");
        sm.state = State::Connected;

        assert!(sm.check_jvm_exit().is_some());

        let record = sm.last_jvm_exit.clone().unwrap();
        assert!(record.warm, "a token on disk means the restart reuses the session");
        assert_eq!(record.from_state, "Connected");
    }

    #[tokio::test]
    async fn test_status_says_a_gateway_exit_without_a_saved_session_was_cold() {
        let (mut sm, _dir) = make_test_state_machine_with_dead_jvm_no_token(MockAgent::default());
        sm.state = State::Connected;

        assert!(sm.check_jvm_exit().is_some());

        assert!(!sm.last_jvm_exit.clone().unwrap().warm);
    }

    #[tokio::test]
    async fn test_nothing_is_recorded_while_the_gateway_is_still_running() {
        let mut sm = make_test_state_machine(MockAgent::default());

        assert!(sm.check_jvm_exit().is_none());

        assert!(sm.last_jvm_exit.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_key_press_the_gateway_holds_open_behind_its_prompt_is_not_a_failure_and_does_not_stall() {
        let mock = MockAgent {
            windows: vec![hotkey_window(2, "IBKR Gateway [PAPER]", 700, 558)],
            send_key_delay: Some(Duration::from_secs(600)),
            ..MockAgent::default()
        };
        let mut sm = make_test_state_machine(mock);
        let started = tokio::time::Instant::now();

        sm.handle_command(Command::ReconnectData).await.unwrap();

        assert!(started.elapsed() < Duration::from_secs(5), "must not wait out the agent's reply: {:?}", started.elapsed());
        let record = sm.last_hotkey.clone().unwrap();
        assert_eq!(record.outcome, "sent");
        assert!(record.note.unwrap().contains("confirmation prompt"));
        assert_eq!(record.error, None);
        assert!(sm.handler_registry.hotkey_expectation.consume(Duration::from_secs(30)));
    }
}
