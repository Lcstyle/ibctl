//! Core types for the state machine: State enum, Stats, Transition, Channels, errors.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{mpsc, watch};

use crate::agent_client::AgentClient;
use crate::types::{ColdRestartOutcome, ColdRestartSignal, Command, Query, QuerySnapshot};
use crate::config::ValidConfig;
use crate::handlers::DialogHandlerRegistry;
use crate::types::Signal;
use crate::supervisor::Supervisor;

use super::recovery::{AbortOnDrop, DwellSuccess, RecoveryCoordinator, ResumeToken};
use super::revocation::RevocationTracker;

/// The latest Sunday re-authentication outcome for this mode, with when it
/// was recorded and the state the mode was in at that moment. Replaced on
/// every new outcome (a fire, a scheduler skip, or the settlement of an
/// owed re-auth), never cleared — STATUS always carries the latest truth.
#[derive(Debug, Clone)]
pub struct ColdRestartOutcomeRecord {
    pub recorded_at: jiff::Zoned,
    pub outcome: ColdRestartOutcome,
    pub state: String,
}

/// The latest "Existing session detected" dialog ibctl handled, and what it
/// said about the other session. Surfaced in STATUS.
#[derive(Debug, Clone)]
pub struct SessionConflictRecord {
    pub at: jiff::Zoned,
    pub other_ip: Option<String>,
    pub other_connected_at: Option<jiff::Timestamp>,
    /// The other session's login time matches one of our own login actions:
    /// this Gateway is displacing itself.
    pub self_inflicted: bool,
    /// Conflicts within the breaker window, this one included.
    pub recent: usize,
}

/// Why a login is parked in `WaitingForHitl2fa`. STATUS
/// `hitl.parked_reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitlParkReason {
    /// `max_immediate_attempts` 2FA rounds failed in a row.
    AttemptsExhausted,
    /// `on_timeout = hitl_immediately`: the first failed round parks.
    HitlImmediately,
    /// A round failed inside the configured unattended hours: nobody is up
    /// to answer another push.
    UnattendedHours,
}

impl HitlParkReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AttemptsExhausted => "attempts_exhausted",
            Self::HitlImmediately => "hitl_immediately",
            Self::UnattendedHours => "unattended_hours",
        }
    }
}

/// Who asked for a login retry in the running JVM. A
/// returned login form shows a retry is possible, not that one is wanted:
/// only the backoff policy's own retries are held back by unattended hours.
/// Ordered weakest to strongest — an armed retry keeps its strongest asker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RetryBy {
    /// After a failed round with budget left, or the HITL timer.
    Policy,
    /// A login form back outside a 2FA round (revoke, RE-LOGIN): a new
    /// login's first push, like a fresh JVM's.
    NewLogin,
    /// The Sunday re-authentication: scheduled recovery.
    SundayReauth,
    /// The operator's Retry (`HITL_RESUME`).
    Operator,
}

/// The last host maintenance released to this mode.
/// STATUS `maintenance.last`.
#[derive(Debug, Clone)]
pub struct MaintenanceRecord {
    pub id: String,
    pub result: String,
    pub released_at: jiff::Zoned,
}

/// Why ibctl relaunched the Gateway JVM from the login path.
/// Everything else on that path happens in the running JVM, so each of
/// these is logged as an ERROR and published in STATUS `last_relaunch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaunchReason {
    /// The JVM exited: there is no login form left to re-submit into.
    JvmExited,
    /// The in-JVM login retry found no usable login form within its grace.
    NoUsableLoginForm,
    /// An IB Key prompt stayed open past the stuck ceiling and did not close
    /// when its Cancel was clicked.
    PromptIgnoredCancel,
}

impl RelaunchReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JvmExited => "jvm_exited",
            Self::NoUsableLoginForm => "no_usable_login_form",
            Self::PromptIgnoredCancel => "prompt_ignored_cancel",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::JvmExited => "the Gateway JVM exited",
            Self::NoUsableLoginForm => {
                "the in-JVM login retry found no usable login form in the running Gateway"
            }
            Self::PromptIgnoredCancel => {
                "an IB Key prompt stayed open past the stuck ceiling and did not close on Cancel"
            }
        }
    }
}

/// The latest JVM relaunch (entry into `Restarting`) and why. STATUS
/// `last_relaunch`.
#[derive(Debug, Clone)]
pub struct RelaunchRecord {
    pub at: jiff::Zoned,
    pub from_state: String,
    /// `RelaunchReason::as_str`, or `"unspecified"`.
    pub reason: &'static str,
    pub detail: String,
    /// Relaunched from a login state while the running JVM showed an IB Key
    /// prompt, with no recorded reason — the abandoned-prompt tripwire.
    pub abandoned_prompt: bool,
}

/// The last time the Gateway process was found to have exited, for STATUS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct JvmExitRecord {
    pub at: String,
    /// The state ibctl was in when it noticed.
    pub from_state: String,
    /// A saved session was found, so the relaunch reuses it and needs no 2FA.
    /// `false` is a crash or a cold exit: the relaunch logs in from scratch.
    pub warm: bool,
}

/// The last attempt to set the Gateway's auto-restart time, for STATUS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RestartTimeRecord {
    pub at: String,
    /// `now` (a bare SETRESTART), `time` (SETRESTART with a time) or `login`
    /// (the configured daily time, applied after a login).
    pub source: &'static str,
    /// The time typed, `h:mm AM|PM` in the Gateway's own zone.
    pub requested: String,
    /// Every control was found and the field read back as typed.
    pub applied: bool,
    pub error: Option<String>,
}

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
    /// Returns true when the JVM is performing or about to perform a fresh
    /// authentication: credentials submission, 2FA (immediate or HITL),
    /// post-auth API configuration, JVM relaunch with pending re-auth, or
    /// the initial launch leading into the login form.
    ///
    /// This is the single source of truth for "did a real human-or-credential
    /// event drive the transition into Connected?" Used by `apply_transition`
    /// to gate writing the fresh-auth marker — adding a new credential-gathering
    /// state requires only updating this list, not chasing the predicate
    /// across distant files.
    ///
    /// `ReconnectingSession` is intentionally excluded: that path can
    /// self-resolve without any credential entry (the Connected->revoke->
    /// Connected flap we explicitly filter out).
    pub fn is_credential_gathering(&self) -> bool {
        matches!(
            self,
            State::WaitingForLogin
                | State::Authenticating
                | State::WaitingFor2fa
                | State::WaitingForHitl2fa
                | State::DismissingPopups
                | State::WaitingForApiReady
                | State::ConfiguringApi
                | State::Restarting
                | State::Launching
        )
    }

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
    /// Cumulative count of PRECAUTION_LABELS entries the Gateway UI didn't
    /// match. Non-zero here means the Java-side tolerant matcher failed
    /// too — either Gateway renamed a checkbox or added Unicode punctuation
    /// the normalizer doesn't handle. TRIPWIRE for label-drift-class
    /// drift; surfaces on /api/status via inline serialize in queries.rs.
    pub precaution_labels_not_found: u32,
    /// Same tripwire, one field for the Read-Only API label specifically.
    /// Kept separate so oncall can see at a glance whether the drift hit
    /// the API-settings page or the API-precautions page.
    pub read_only_api_label_not_found: u32,
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
    ColdRestart(ColdRestartSignal),
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
    /// Whether the 2FA dialog seen in this WaitingFor2fa is the CHALLENGE
    /// (the push prompt), not the IB Key device picker that precedes it.
    /// Both carry the same title. Only a closed challenge is evidence a push
    /// was answered; the picker closing means the challenge is on its way
    /// (typically several seconds later). Reset on state entry.
    pub(super) twofa_challenge_seen: bool,
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
    /// Latest `ConnectionStatusChanged` verdict from the agent: true once it
    /// reports `-> disconnected`, false again on `-> connected`.
    ///
    /// Consumed ONLY by `do_connected`, and reset on entry to Connected, so a
    /// stale disconnect observed during Launching/Login cannot fire against
    /// the session that follows it. That staleness is the exact reason the
    /// event was made informational-only in the first place; scoping it this
    /// way keeps the guarantee while restoring the signal.
    pub(super) agent_reported_disconnected: bool,

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
    /// Consecutive ticks where the world-state suggests the JVM has
    /// reached the connected steady state (main Gateway window present,
    /// "API Server: connected" label visible, no 2FA dialog). Once this
    /// reaches `HITL_DEMOTE_TICK_THRESHOLD`, the handler demotes to
    /// WaitingForApiReady so the standard post-auth setup runs (including
    /// socat start). Cleared on entry to / exit from WaitingForHitl2fa.
    pub(super) hitl_connected_observation_ticks: u8,
    /// A login retry was asked for (operator's Retry, the Sunday fire, the
    /// HITL timer) while the Gateway still showed its IB Key dialog. The
    /// challenge may still be approvable, so nothing is re-submitted under
    /// it; the HITL tick re-submits once the Gateway closes the dialog —
    /// IBC's `ReloginAfterSecondFactorAuthenticationTimeout` behaviour.
    /// Cleared on leaving WaitingForHitl2fa.
    pub(super) hitl_relogin_armed: bool,
    /// While armed: when the IB Key dialog was first seen gone. The retry
    /// waits `RELOGIN_SETTLE_AFTER_2FA_CLOSE` from here, as IBC does.
    pub(super) hitl_2fa_closed_at: Option<Instant>,
    /// The operator's Retry (`HITL_RESUME`) arrived while the Gateway showed
    /// an IB Key prompt: close it with Cancel rather than wait for the
    /// Gateway. The Sunday fire and the HITL timer never set this.
    /// Cleared on leaving WaitingForHitl2fa.
    pub(super) hitl_cancel_requested: bool,
    /// Why the login is parked. Cleared on leaving WaitingForHitl2fa.
    pub(super) hitl_park_reason: Option<HitlParkReason>,
    /// When this round's IB Key challenge was first seen open. The alert
    /// and the stuck ceiling count from here, never from state entry.
    /// Reset on entry to WaitingFor2fa.
    pub(super) twofa_challenge_opened_at: Option<Instant>,
    /// The "push unanswered" WARN has been logged for this round.
    pub(super) twofa_overdue_logged: bool,
    /// When ibctl clicked Cancel on an IB Key prompt (stuck ceiling, or the
    /// operator's Retry). If the prompt is still open `PROMPT_CANCEL_GRACE`
    /// later, the JVM is relaunched. Reset on entry to WaitingFor2fa and on
    /// leaving WaitingForHitl2fa.
    pub(super) prompt_cancel_sent_at: Option<Instant>,
    /// Why the next entry into `Restarting` happens; consumed there.
    pub(super) relaunch_reason: Option<RelaunchReason>,
    /// The latest JVM relaunch. STATUS `last_relaunch`.
    pub(super) last_relaunch: Option<RelaunchRecord>,
    /// The last host maintenance released to this mode.
    pub(super) last_maintenance: Option<MaintenanceRecord>,
    /// This process booted after the Sunday target: the week's restart is
    /// satisfied, so an owed re-auth is settled by a login only — never by
    /// another restart. Cleared when it settles.
    pub(super) restart_satisfied_by_boot: bool,
    /// Set while a login is being re-submitted INSIDE the running JVM
    /// (`begin_in_jvm_relogin`); the instant the retry began.
    /// Switches `do_authenticate` to `do_authenticate_in_running_jvm`, which
    /// looks for the form in every Gateway window and never reads "no form"
    /// as "authenticated" without the status panel saying so. Cleared on
    /// leaving Authenticating.
    pub(super) in_jvm_relogin_since: Option<Instant>,
    /// Who asked for the in-JVM retry under way. Cleared with
    /// `in_jvm_relogin_since`.
    pub(super) in_jvm_relogin_by: Option<RetryBy>,
    /// Who armed the retry waiting on an open prompt (strongest wins).
    /// Cleared on leaving WaitingForHitl2fa.
    pub(super) hitl_relogin_armed_by: Option<RetryBy>,
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
    /// Absolute path to the per-mode cold-restart-equivalent marker. Updated
    /// when a real cold-restart-equivalent completes (arrival into Connected
    /// from a credential-gathering state AND a 2FA challenge was answered
    /// successfully during this JVM lifecycle). The cold-restart scheduler
    /// reads this to decide whether to skip an upcoming scheduled fire.
    ///
    /// Renamed from `fresh_auth_marker_path` when the semantics narrowed:
    /// the marker now specifically records a "JVM-kill + answered 2FA"
    /// event, not just any arrival at Connected. Warm restarts (IBC's
    /// daily -Drestart= pattern) that bypass 2FA do NOT write this marker.
    pub(super) cold_restart_equivalent_marker_path: PathBuf,
    /// Set to true when a 2FA challenge was answered successfully since the
    /// last Launching state entry. Consulted in apply_transition's Connected-
    /// entry branch to decide whether to write the cold-restart-equivalent
    /// marker — only real cold-restart-equivalents (full kill + relaunch +
    /// 2FA response) should count for the Sunday cold-restart skip policy.
    /// Warm restarts (IBC's daily -Drestart= pattern) do NOT pass through
    /// WaitingFor2fa or WaitingForHitl2fa, so this stays false through them.
    ///
    /// Lifecycle (in apply_transition):
    /// - Reset to false on every entry into State::Launching (covers every
    ///   JVM (re)start: warm/cold/error recovery/HITL auto-retry).
    /// - Set to true on WaitingFor2fa -> {DismissingPopups, WaitingForApiReady,
    ///   ConfiguringApi, Connected} when self.twofa_seen == true (the
    ///   twofa_seen gate excludes the grace-period escape at line 1188
    ///   where no 2FA dialog was ever presented).
    /// - Set to true on WaitingForHitl2fa -> WaitingForApiReady (the
    ///   positive-direction probe), and when an
    ///   in-JVM retry finds the Gateway connected (the same late approval).
    /// - Set to true where the login handler reports credentials SUBMITTED
    ///   (`do_authenticate`, `do_authenticate_in_running_jvm`) — a paper
    ///   login has no 2FA to answer. Not on merely leaving
    ///   Authenticating: it also leaves when it finds no form.
    /// - Reset to false immediately after writing the marker on Connected
    ///   entry — so a subsequent Connected->revoke->ReconnectingSession->
    ///   Connected loop doesn't carry stale truth.
    ///
    /// Intentionally NOT exposed via STATUS JSON: internal bookkeeping.
    pub(super) cold_restart_equivalent_pending: bool,
    /// Latest Sunday re-authentication outcome. Surfaced in STATUS
    /// JSON as `last_cold_restart_outcome` so the dashboard can tell the
    /// operator, per mode, what happened or what to do.
    pub(super) last_cold_restart_outcome: Option<ColdRestartOutcomeRecord>,
    /// Set when a Sunday fire left the week's re-authentication owed
    /// (`cold_restart_decision::owes_reauth`); the instant it became owed.
    /// Settled at the next `Connected`: `Completed` if that login
    /// authenticated, otherwise the cold restart runs then. RAM only — a
    /// process restart re-enters through a full login anyway.
    pub(super) cold_restart_owed_since: Option<jiff::Zoned>,
    /// One-shot handoff from `apply_transition` (which observes whether the
    /// arriving login authenticated) to `do_connected` (which may return
    /// `Restarting`): an owed re-auth reached Connected WITHOUT
    /// authenticating (warm restart / reconnect), so run the cold restart now.
    pub(super) cold_restart_fire_on_connected: bool,

    // --- session-conflict evidence and loop breaker ---
    /// When each "Existing session detected" dialog was handled, pruned to
    /// `session_conflict::BREAKER_WINDOW`. Cleared on Connected.
    pub(super) session_conflicts: std::collections::VecDeque<Instant>,
    /// Too many conflicts in the window: stop clicking, leave the dialog for
    /// a human. Cleared on Connected.
    pub(super) session_conflict_breaker_open: bool,
    pub(super) last_session_conflict: Option<SessionConflictRecord>,
    /// Text of the latest "Existing session detected" dialog, from the
    /// agent's error_dialog event — it names the other session's IP and time.
    pub(super) last_conflict_message: Option<String>,
    /// Wall-clock time of our last login action: credentials submitted, or
    /// "Reconnect This Session" clicked.
    pub(super) last_login_action_at: Option<jiff::Timestamp>,

    // --- three-phase reconnection recovery coordinator ---
    /// Recovery coordinator — owns phase + marker I/O. Ticked once per
    /// main-loop iteration; every mutation goes through
    /// `RecoveryCoordinator::apply`.
    pub(super) recovery: RecoveryCoordinator,
    /// Dwell timer for Connected → record_success. Populated on entering
    /// Connected via `apply_transition`, dropped (auto-aborts the task)
    /// on leaving Connected. When the task fires uncancelled, it sends
    /// a `DwellSuccess` down `dwell_success_tx`; the main loop drains
    /// the receiver and applies via `recovery.record_success`.
    pub(super) dwell_guard: Option<AbortOnDrop>,
    /// Sender half held by the spawned dwell task (via `clone()`).
    pub(super) dwell_success_tx: tokio::sync::mpsc::UnboundedSender<DwellSuccess>,
    /// Receiver half drained by the main loop each tick. Unbounded is
    /// fine because a Connected dwell only fires once per Connected
    /// entry — the queue never grows.
    pub(super) dwell_success_rx: tokio::sync::mpsc::UnboundedReceiver<DwellSuccess>,
    /// Pending resume token from a `Command::ResumeReconnect`. Taken by
    /// `take_pending_resume_token` on the next recovery tick and passed
    /// into `RecoveryCoordinator::compute` / `::apply`.
    pub(super) pending_resume_token: Option<ResumeToken>,
    /// Trading-mode tag ("live" | "paper") used for the resume token's
    /// mode field. Determined from `config.auth.trading_mode` at
    /// construction; recovery marker paths are scoped by this same tag.
    pub(super) recovery_mode_tag: String,
    /// The Gateway's session time zone as last read after a login: what was
    /// declared, what its `jts.ini` held, and the zone times are converted
    /// into. `None` until the first login completes.
    pub(super) gateway_time_zone: Option<crate::gateway_zone::ZoneReport>,
    /// The Gateway hotkey ibctl pressed last (RECONNECTDATA / RECONNECTACCOUNT)
    /// and whether the agent sent it.
    pub(super) last_hotkey: Option<crate::hotkey::HotkeyRecord>,
    /// The last attempt to set the auto-restart time and whether it took.
    pub(super) last_setrestart: Option<RestartTimeRecord>,
    /// The last Gateway exit ibctl noticed, and whether it was a warm restart.
    pub(super) last_jvm_exit: Option<JvmExitRecord>,
}

impl StateMachine {
    pub fn new(
        config: ValidConfig,
        agent_client: AgentClient,
        supervisor: Supervisor,
        handler_registry: DialogHandlerRegistry,
        channels: Channels,
        snapshot_tx: watch::Sender<Arc<QuerySnapshot>>,
        cold_restart_equivalent_marker_path: PathBuf,
    ) -> Self {
        // Recovery coordinator — settings_dir derived from the cold-restart
        // marker's parent (already resolved from TWS_SETTINGS_PATH in
        // main.rs). Mode tag maps TradingMode → "live" | "paper"; "both"
        // maps to "paper" pending a per-mode split (paper is the dominant
        // use case and matches the existing marker convention).
        let settings_dir = cold_restart_equivalent_marker_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/home/ibgateway/Jts"));
        let recovery_mode_tag = match config.auth.trading_mode {
            crate::config::TradingMode::Live => "live".to_string(),
            crate::config::TradingMode::Paper | crate::config::TradingMode::Both => {
                "paper".to_string()
            }
        };
        let recovery_config = config.timing.recovery.to_runtime();
        let (recovery, recovery_outcome) = RecoveryCoordinator::boot(
            settings_dir,
            recovery_mode_tag.clone(),
            recovery_config,
        );
        match &recovery_outcome {
            super::recovery::RecoveryLoadOutcome::Loaded(state) => {
                log::info!(
                    "recovery.loaded phase={} phase_entered_at={}",
                    state.phase.as_str(),
                    state.phase_entered_at,
                );
            }
            super::recovery::RecoveryLoadOutcome::Defaulted { reason } => {
                log::warn!("recovery.defaulted reason={reason}");
            }
            super::recovery::RecoveryLoadOutcome::RefusedGivenUpAutoReset { reason } => {
                log::warn!("recovery.blocked_by_refuse_givenup reason={reason}");
            }
        }
        let (dwell_success_tx, dwell_success_rx) = tokio::sync::mpsc::unbounded_channel();

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
            twofa_challenge_seen: false,
            twofa_gone_at: None,
            state_entered_at: Instant::now(),
            popup_last_dismissed: None,
            consecutive_agent_failures: 0,
            stats: Stats::default(),
            snapshot_tx,
            snapshot_version: 0,
            revocation: RevocationTracker::new(),
            agent_reported_disconnected: false,
            consecutive_2fa_timeouts: 0,
            hitl_entered_at: None,
            hitl_next_retry_at: None,
            hitl_intervals_index: 0,
            hitl_ntfy_attempts: 0,
            hitl_ntfy_sent: false,
            hitl_connected_observation_ticks: 0,
            hitl_relogin_armed: false,
            hitl_2fa_closed_at: None,
            hitl_cancel_requested: false,
            hitl_park_reason: None,
            twofa_challenge_opened_at: None,
            twofa_overdue_logged: false,
            prompt_cancel_sent_at: None,
            relaunch_reason: None,
            last_relaunch: None,
            last_maintenance: None,
            restart_satisfied_by_boot: false,
            in_jvm_relogin_since: None,
            in_jvm_relogin_by: None,
            hitl_relogin_armed_by: None,
            connected_continuously_since: None,
            api_port_probe_failed: std::sync::Arc::new(
                std::sync::atomic::AtomicBool::new(false),
            ),
            api_port_probe_task: None,
            cold_restart_equivalent_marker_path,
            cold_restart_equivalent_pending: false,
            last_cold_restart_outcome: None,
            cold_restart_owed_since: None,
            cold_restart_fire_on_connected: false,
            session_conflicts: std::collections::VecDeque::new(),
            session_conflict_breaker_open: false,
            last_session_conflict: None,
            last_conflict_message: None,
            last_login_action_at: None,
            recovery,
            dwell_guard: None,
            dwell_success_tx,
            dwell_success_rx,
            pending_resume_token: None,
            recovery_mode_tag,
            gateway_time_zone: None,
            last_hotkey: None,
            last_setrestart: None,
            last_jvm_exit: None,
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
        State::WaitingForLaunch => (false, true, Some("standby")),
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
        assert!(should_wait);
        assert_eq!(reason, Some("standby"));
    }

    #[test]
    fn test_waiting_for_launch_should_wait_standby() {
        let (should_connect, should_wait, reason, stale) = client_advisory(&State::WaitingForLaunch);
        assert!(!should_connect, "standby must not invite clients to connect");
        assert!(should_wait, "standby is a waiting state — should_wait must be paired with wait_reason to satisfy the invariant every other waiting state (Init, WaitingFor2fa, Restarting, ...) already satisfies");
        assert_eq!(reason, Some("standby"));
        assert!(!stale, "standby does not stale client_ids — only Restarting does");
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

    #[test]
    fn test_is_credential_gathering_covers_expected_states() {
        // The nine states currently classified as "real credential or
        // login-pipeline work in progress". A successful arrival into
        // Connected from any of these counts as a fresh authentication
        // for the cold-restart skip ratchet.
        let gathering = [
            State::WaitingForLogin,
            State::Authenticating,
            State::WaitingFor2fa,
            State::WaitingForHitl2fa,
            State::DismissingPopups,
            State::WaitingForApiReady,
            State::ConfiguringApi,
            State::Restarting,
            State::Launching,
        ];
        for s in &gathering {
            assert!(
                s.is_credential_gathering(),
                "{} must be classified as credential-gathering",
                s,
            );
        }

        // States that must NOT count — either no credential entry happens
        // (ReconnectingSession self-resolves), the JVM hasn't started yet
        // (Init, WaitingForLaunch, WaitingForAgent), the gateway is paused
        // on an external condition (WaitingForIB, HandlingSessionConflict),
        // or we're already done (Connected, Shutdown, Error).
        let non_gathering = [
            State::ReconnectingSession,
            State::Connected,
            State::Init,
            State::Shutdown,
            State::WaitingForLaunch,
            State::WaitingForAgent,
            State::WaitingForIB,
            State::HandlingSessionConflict,
            State::Error("boom".into()),
        ];
        for s in &non_gathering {
            assert!(
                !s.is_credential_gathering(),
                "{} must NOT be classified as credential-gathering",
                s,
            );
        }
    }
}
