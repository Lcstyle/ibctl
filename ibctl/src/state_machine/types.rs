//! Core types for the state machine: State enum, Stats, Transition, Channels, errors.

use std::collections::VecDeque;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{mpsc, watch};

use crate::agent_client::AgentClient;
use crate::types::{ColdRestartSignal, Command, Query, QuerySnapshot};
use crate::config::ValidConfig;
use crate::handlers::DialogHandlerRegistry;
use crate::types::Signal;
use crate::supervisor::Supervisor;

use super::revocation::RevocationTracker;

#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("supervisor error: {0}")]
    Supervisor(#[from] crate::supervisor::SupervisorError),
    #[error("agent error: {0}")]
    Agent(#[from] crate::agent_client::AgentError),
    #[error("handler error: {0}")]
    Handler(#[from] crate::handlers::HandlerError),
}

/// All possible states in the ibctl lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Standby mode: process running, JVM not launched. Awaiting START command.
    WaitingForLaunch,
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
    /// Waiting for Gateway's API port to accept connections before configuring.
    /// Prevents ConfiguringApi from running while Gateway is still authenticating
    /// or shows "API Server: disconnected" in the Connection Status dialog.
    WaitingForApiReady,
    /// Applying post-login API configuration (master client ID, read-only, etc.)
    ConfiguringApi,
    /// Fully connected and monitoring for new dialogs.
    ///
    /// Normal path to this state: positive label confirmation at one of
    /// three sites in mod.rs (the only code that returns `Ok(State::Connected)`
    /// via the state-transition flow):
    ///   * WaitingForApiReady — `components_indicate_connected()` returned true
    ///   * ConfiguringApi — `apply_api_config()` succeeded (UI was responsive)
    ///   * ReconnectingSession — positive authentication confirmation
    ///
    /// Debug path: SETSTATE Connected (localhost-only, privileged command)
    /// forces the state for the dashboard's state-machine dialog so
    /// operators can observe Connected-state behavior without a full login.
    Connected,
    /// Recovering from connection loss — graduated re-login flow.
    /// Waits 30s, clicks Re-login, tracks attempts. If failed, restarts JVM.
    ReconnectingSession,
    /// Restarting the Gateway JVM
    Restarting,
    /// Waiting for IB system to become available (maintenance/outage/no internet)
    WaitingForIB,
    /// Human-in-the-loop 2FA: repeated 2FA timeouts exhausted the immediate
    /// retry budget. Exits via timer (intervals_minutes), via HITL_RESUME
    /// command (typically from a dashboard ntfy callback), or preempted by
    /// cold restart.
    WaitingForHitl2fa,
    /// Shutting down cleanly
    Shutdown,
    /// Unrecoverable error state
    Error(String),
}

impl State {
    /// Parse a state name from a string (for SETSTATE command).
    pub fn from_name(name: &str) -> Option<State> {
        match name {
            "WaitingForLaunch" => Some(State::WaitingForLaunch),
            "Init" => Some(State::Init),
            "Launching" => Some(State::Launching),
            "WaitingForAgent" => Some(State::WaitingForAgent),
            "WaitingForLogin" => Some(State::WaitingForLogin),
            "Authenticating" => Some(State::Authenticating),
            "WaitingFor2fa" => Some(State::WaitingFor2fa),
            "HandlingSessionConflict" => Some(State::HandlingSessionConflict),
            "DismissingPopups" => Some(State::DismissingPopups),
            "WaitingForApiReady" => Some(State::WaitingForApiReady),
            "ConfiguringApi" => Some(State::ConfiguringApi),
            // SETSTATE Connected is accepted as a localhost-only debug tool
            // (the command server's is_privileged_command list gates SETSTATE
            // to 127.0.0.1 peers, which in practice means the dashboard's
            // state-machine dialog). Forcing Connected kicks off the normal
            // `do_connected` work — socat, client-ID refresh task, revocation
            // bus, active probe — so operators can observe Connected-state
            // behavior without driving a full login flow.
            //
            // This is NOT a fake or "forced" state. State::Connected is a
            // unit variant; nothing distinguishes it from a real promotion
            // at the type level. Downstream consumers will see `ready: true`
            // and may act on it — use with operator discretion, same as
            // other privileged commands (RESTART, STOP, etc.).
            "Connected" => Some(State::Connected),
            "ReconnectingSession" => Some(State::ReconnectingSession),
            "Restarting" => Some(State::Restarting),
            "WaitingForIB" => Some(State::WaitingForIB),
            "WaitingForHitl2fa" => Some(State::WaitingForHitl2fa),
            "Shutdown" => Some(State::Shutdown),
            _ => None,
        }
    }
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
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Stats {
    pub restarts_today: u32,
    pub relogins_today: u32,
    pub dialogs_dismissed: u32,
    pub last_2fa_duration_secs: Option<f64>,
    pub config_apply_duration_secs: Option<f64>,
}

/// A recorded state transition.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Transition {
    pub timestamp: String,
    pub from: String,
    pub to: String,
}

/// Bundled mpsc receivers for the state machine's inbound channels.
/// Tests that don't need an event stream construct a dummy channel and
/// drop the sender immediately; they don't need to express "no events"
/// via Option at this layer.
pub struct Channels {
    pub signals: mpsc::Receiver<Signal>,
    pub commands: mpsc::Receiver<Command>,
    pub queries: mpsc::Receiver<Query>,
    pub cold_restart: mpsc::Receiver<ColdRestartSignal>,
    pub agent_events: mpsc::Receiver<crate::agent_events::AgentEvent>,
}

/// Internal enum for interrupt sources.
pub(super) enum Interrupt {
    Signal(Signal),
    Command(Command),
    ColdRestart,
    AgentEvent(crate::agent_events::AgentEvent),
}

/// IB system status — pushed by dashboard or external clients via IBSTATUS command.
pub struct IbSystemStatus {
    pub(super) available: bool,
    pub(super) status: String,
    pub(super) reason: String,
    pub(super) last_updated: Option<Instant>,
    pub(super) return_state: Option<Box<State>>,
}

impl IbSystemStatus {
    fn new() -> Self {
        Self {
            available: true,
            status: "available".to_string(),
            reason: String::new(),
            last_updated: None,
            return_state: None,
        }
    }
}

/// Pause/ceiling controls for the state machine.
pub struct PauseControl {
    pub(super) paused: bool,
    pub(super) ceiling_state: Option<State>,
}

impl PauseControl {
    fn new() -> Self {
        Self {
            paused: false,
            ceiling_state: None,
        }
    }
}

/// The main state machine that orchestrates the IB Gateway lifecycle.
pub struct StateMachine {
    pub(super) state: State,
    pub(super) config: ValidConfig,
    pub(super) agent_client: AgentClient,
    pub(super) supervisor: Supervisor,
    pub(super) handler_registry: DialogHandlerRegistry,
    pub(super) signal_rx: mpsc::Receiver<Signal>,
    pub(super) command_rx: mpsc::Receiver<Command>,
    pub(super) query_rx: mpsc::Receiver<Query>,
    pub(super) cold_restart_rx: mpsc::Receiver<ColdRestartSignal>,
    pub(super) socat_process: Option<std::process::Child>,
    pub(super) config_retries: u32,
    pub(super) pause: PauseControl,
    pub(super) ib_status: IbSystemStatus,
    pub(super) start_time: Instant,
    pub(super) connected_since: Option<Instant>,
    pub(super) transition_history: VecDeque<Transition>,
    pub(super) cached_client_ids: Vec<String>,
    /// Set by do_connected when JVM exits during warm restart — carries the
    /// autorestart session hash to pass as -Drestart on relaunch (skips 2FA).
    pub(super) warm_restart_pending: Option<String>,
    /// Background task that periodically refreshes client IDs from the agent.
    /// Stored here so it survives cancellation of `do_connected()` by the
    /// `tokio::select!` loop and gets properly cleaned up on state transitions.
    pub(super) client_id_task: Option<tokio::task::JoinHandle<()>>,
    /// Watch receiver for client IDs from the background refresh task.
    pub(super) client_id_rx: Option<tokio::sync::watch::Receiver<Vec<String>>>,
    /// Tracks consecutive re-login dialog appearances. Reset on Connected.
    pub(super) relogin_attempts: u32,
    /// Window class recorded when entering Connected state. Used to detect silent
    /// session loss: if the main window's class changes (e.g. ibgateway.ay → ibgateway.az),
    /// Gateway reverted to the login form without showing a RE-LOGIN dialog.
    pub(super) connected_window_class: Option<String>,
    /// 2FA device selection state — survives tokio::select! cancellation.
    /// Set true after device is selected and OK clicked. Reset on state transitions
    /// that start a new login cycle.
    pub(super) twofa_device_selected: bool,
    /// Whether the 2FA dialog has been observed during the current WaitingFor2fa state.
    /// Reset on state entry. Used to distinguish "no 2FA needed" from "2FA completed".
    pub(super) twofa_seen: bool,
    /// When the 2FA dialog first disappeared after being seen. Used for 3s confirmation
    /// delay to avoid reacting to transient redraws. Reset when dialog reappears.
    pub(super) twofa_gone_at: Option<Instant>,
    /// Timestamp when the current state was entered. Used for deadline-based timeouts
    /// instead of internal loops. Reset on every state transition in apply_transition().
    pub(super) state_entered_at: Instant,
    /// Last popup dismissed in DismissingPopups state. Tracks quiet period to detect
    /// when all popups are gone. Reset on state entry.
    pub(super) popup_last_dismissed: Option<Instant>,
    /// Consecutive agent communication failures within the current state.
    /// Reset on state entry. Used for error escalation (10 failures = give up).
    pub(super) consecutive_agent_failures: u32,
    /// Agent event stream receiver — window open/close events from the Java agent.
    pub(super) event_rx: Option<mpsc::Receiver<crate::agent_events::AgentEvent>>,
    /// Centralized UI observation cache — updated by events and targeted queries.
    /// State handlers read this instead of polling the agent directly.
    pub(super) observation: crate::agent_events::AgentObservation,
    pub(super) stats: Stats,
    /// Watch channel sender for publishing query snapshots.
    /// Command server reads the latest snapshot directly — no mpsc round-trip.
    /// Placed after JoinHandle fields for correct drop order (Sender before Handle).
    pub(super) snapshot_tx: watch::Sender<Arc<QuerySnapshot>>,
    /// Monotonic version counter for snapshots.
    pub(super) snapshot_version: u64,
    /// Source-tagged revocation bus for `Connected` state. Tracks per-source
    /// debounce timers for contradictions (login form reappears, "disconnected"
    /// label stabilizes, window class morph, etc.). See `verifier::RevocationSource`.
    /// Used by `do_connected` to decide when a contradiction has persisted
    /// long enough to revoke the proof and transition out.
    pub(super) revocation: RevocationTracker,

    // --- HITL 2FA state ---
    /// Consecutive 2FA timeouts. Incremented on each `do_wait_for_2fa` timeout,
    /// reset on successful Connected entry (per `twofa.backoff.counter_reset`).
    pub(super) consecutive_2fa_timeouts: u32,
    /// When we entered `WaitingForHitl2fa` most recently. Used for the
    /// periodic-retry timer and for `hitl.entered_at` in STATUS JSON.
    pub(super) hitl_entered_at: Option<Instant>,
    /// Next periodic auto-retry deadline. None = strategy does not include
    /// timer, or we're not in HITL.
    pub(super) hitl_next_retry_at: Option<Instant>,
    /// Which entry in `intervals_minutes` we're currently at. Increments after
    /// each scheduled retry fires; held at `intervals.len() - 1` on overflow.
    pub(super) hitl_intervals_index: usize,
    /// Ntfy push attempts for the current HITL entry. Counted against
    /// `ntfy_send_retries` on subsequent wakeups.
    pub(super) hitl_ntfy_attempts: u32,
    /// Whether the initial ntfy push succeeded for the current HITL entry.
    pub(super) hitl_ntfy_sent: bool,
    /// When Connected was first entered continuously. Reset on any exit from
    /// Connected. Used by `counter_reset = "stable"` to decide when the counter
    /// may reset.
    pub(super) connected_continuously_since: Option<Instant>,
    /// Flag set by the TCP probe task when consecutive failures exceed the
    /// threshold. Consumed in `do_connected` to fire ApiPortListenerLost.
    /// AtomicBool so the probe task can set it without needing a lock.
    pub(super) api_port_probe_failed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Handle for the TCP probe task, for cancellation on Connected exit.
    pub(super) api_port_probe_task: Option<tokio::task::JoinHandle<()>>,
}

impl StateMachine {
    pub fn new(
        config: ValidConfig,
        agent_client: AgentClient,
        supervisor: Supervisor,
        handler_registry: DialogHandlerRegistry,
        channels: Channels,
        snapshot_tx: watch::Sender<Arc<QuerySnapshot>>,
    ) -> Self {
        Self {
            state: State::Init,
            config,
            agent_client,
            supervisor,
            handler_registry,
            signal_rx: channels.signals,
            command_rx: channels.commands,
            query_rx: channels.queries,
            cold_restart_rx: channels.cold_restart,
            // event_rx stays wrapped in Option because the main select! loop
            // takes it out and puts it back across await boundaries. The
            // Option on the struct field is lifecycle, not optionality.
            event_rx: Some(channels.agent_events),
            observation: crate::agent_events::AgentObservation::new(),
            socat_process: None,
            config_retries: 0,
            pause: PauseControl::new(),
            ib_status: IbSystemStatus::new(),
            start_time: Instant::now(),
            connected_since: None,
            transition_history: VecDeque::with_capacity(100),
            cached_client_ids: Vec::new(),
            warm_restart_pending: None,
            client_id_task: None,
            client_id_rx: None,
            relogin_attempts: 0,
            connected_window_class: None,
            twofa_device_selected: false,
            twofa_seen: false,
            twofa_gone_at: None,
            state_entered_at: Instant::now(),
            popup_last_dismissed: None,
            consecutive_agent_failures: 0,
            stats: Stats::default(),
            snapshot_tx,
            snapshot_version: 0,
            revocation: RevocationTracker::new(),
            consecutive_2fa_timeouts: 0,
            hitl_entered_at: None,
            hitl_next_retry_at: None,
            hitl_intervals_index: 0,
            hitl_ntfy_attempts: 0,
            hitl_ntfy_sent: false,
            connected_continuously_since: None,
            api_port_probe_failed: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
            api_port_probe_task: None,
        }
    }

    /// Record a state transition in the history ring buffer.
    pub(super) fn record_transition(&mut self, from: &State, to: &State) {
        if from == to {
            return;
        }
        if self.transition_history.len() >= 100 {
            self.transition_history.pop_front();
        }
        self.transition_history.push_back(Transition {
            timestamp: chrono_timestamp(),
            from: from.to_string(),
            to: to.to_string(),
        });
    }
}

/// Compute client advisory fields from the current state.
/// Returns (should_connect, should_wait, wait_reason, client_id_likely_stale).
pub(crate) fn client_advisory(state: &State) -> (bool, bool, Option<&'static str>, bool) {
    let (should_connect, should_wait, wait_reason) = match state {
        State::WaitingForLaunch => (false, false, Some("standby")),
        State::Init | State::Launching | State::WaitingForAgent => (false, true, Some("launching")),
        State::WaitingForLogin | State::Authenticating => (false, true, Some("logging_in")),
        State::WaitingFor2fa => (false, true, Some("2fa_pending")),
        State::HandlingSessionConflict => (false, true, Some("session_conflict")),
        State::DismissingPopups | State::WaitingForApiReady | State::ConfiguringApi => (false, true, Some("configuring")),
        State::Connected => (true, false, None),
        State::ReconnectingSession => (false, true, Some("reconnecting")),
        State::Restarting => (false, true, Some("restarting")),
        State::WaitingForIB => (false, true, Some("ib_maintenance")),
        State::WaitingForHitl2fa => (false, true, Some("awaiting_operator")),
        State::Shutdown => (false, false, None),
        State::Error(_) => (false, false, None),
    };
    let client_id_likely_stale = matches!(state, State::Restarting);
    (should_connect, should_wait, wait_reason, client_id_likely_stale)
}

/// Epoch seconds timestamp — browser converts to local time.
pub(super) fn chrono_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connected_should_connect() {
        let (should_connect, should_wait, reason, stale) =
            client_advisory(&State::Connected);
        assert!(should_connect);
        assert!(!should_wait);
        assert!(reason.is_none());
        assert!(!stale);
    }

    #[test]
    fn test_init_should_wait() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::Init);
        assert!(!should_connect);
        assert!(should_wait);
        assert_eq!(reason, Some("launching"));
    }

    #[test]
    fn test_2fa_pending() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::WaitingFor2fa);
        assert!(!should_connect);
        assert!(should_wait);
        assert_eq!(reason, Some("2fa_pending"));
    }

    #[test]
    fn test_restarting_stale_ids() {
        let (_, should_wait, reason, stale) = client_advisory(&State::Restarting);
        assert!(should_wait);
        assert_eq!(reason, Some("restarting"));
        assert!(stale);
    }

    #[test]
    fn test_shutdown_no_connect_no_wait() {
        let (should_connect, should_wait, _, _) = client_advisory(&State::Shutdown);
        assert!(!should_connect);
        assert!(!should_wait);
    }

    #[test]
    fn test_error_no_connect_no_wait() {
        let (should_connect, should_wait, _, _) = client_advisory(&State::Error("test".into()));
        assert!(!should_connect);
        assert!(!should_wait);
    }

    #[test]
    fn test_configuring_api_should_wait() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::ConfiguringApi);
        assert!(!should_connect);
        assert!(should_wait);
        assert_eq!(reason, Some("configuring"));
    }

    #[test]
    fn test_waiting_for_launch_standby() {
        let (should_connect, should_wait, reason, _) = client_advisory(&State::WaitingForLaunch);
        assert!(!should_connect);
        assert!(!should_wait);
        assert_eq!(reason, Some("standby"));
    }

    #[test]
    fn test_all_states_covered() {
        let states = vec![
            State::WaitingForLaunch,
            State::Init, State::Launching, State::WaitingForAgent,
            State::WaitingForLogin, State::Authenticating,
            State::WaitingFor2fa, State::HandlingSessionConflict,
            State::DismissingPopups, State::ConfiguringApi,
            State::Connected,
            State::Restarting, State::Shutdown,
            State::Error("test".into()),
        ];
        for state in &states {
            let (sc, sw, _, _) = client_advisory(state);
            if matches!(state, State::Connected) {
                assert!(sc, "Connected should allow connect");
                assert!(!sw, "Connected should not wait");
            }
        }
    }

    #[test]
    fn test_state_display() {
        assert_eq!(State::Init.to_string(), "Init");
        assert_eq!(State::Connected.to_string(), "Connected");
        assert_eq!(State::WaitingFor2fa.to_string(), "WaitingFor2fa");
        assert_eq!(State::Error("boom".into()).to_string(), "Error(boom)");
    }

    #[test]
    fn test_from_name_accepts_all_states_including_connected() {
        // SETSTATE Connected is a localhost-only debug affordance used by
        // the dashboard's state-machine dialog; accept it the same as any
        // other state.
        assert!(matches!(State::from_name("Connected"), Some(State::Connected)));
        assert!(matches!(State::from_name("Init"), Some(State::Init)));
        assert!(matches!(State::from_name("WaitingForLogin"), Some(State::WaitingForLogin)));
        assert!(State::from_name("NotARealState").is_none());
    }
}
