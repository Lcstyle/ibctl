//! Source-tagged revocation bus for the Connected state.
//!
//! # Entry into Connected
//!
//! `State::Connected` can only be returned from the three promotion sites in
//! `mod.rs` that have positively confirmed Gateway is ready:
//!
//! * `do_wait_for_api_ready` — confirms the `connected` label via
//!   `components_indicate_connected()`
//! * `do_configure_api` — runs after the login flow and apply_api_config has
//!   actually driven the Configure → Settings dialog (UI is responsive)
//! * `do_reconnecting_session` — confirms authentication via active label
//!   inspection
//!
//! Timeouts, retry exhaustion, or "absence of errors" never promote.
//! There is no debug override — `State::from_name("Connected")` returns
//! `None`, so SETSTATE Connected is rejected by the command server.
//!
//! # Exit from Connected (this module)
//!
//! `RevocationTracker` debounces contradiction observations per source and
//! returns `Some(source)` when a source's contradiction has persisted past
//! its own debounce window. `do_connected` calls it on every tick:
//!
//!   JvmDied                 → immediate
//!   ReloginDialog           → immediate
//!   SessionConflict         → immediate
//!   ErrorDialog             → 500 ms
//!   WindowClassMorphed      → 500 ms  (not wired yet; see TODO on the variant)
//!   LoginFormVisible        → 1 s
//!   DisconnectedLabelStable → 2 s
//!
//! Every matured revocation emits a structured log line
//! (`proof revoked source=<tag> next=<state>`) so operators grepping
//! post-incident can find every Connected exit and why it fired.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::State;

/// A compile-time-enumerated tag identifying the *kind* of contradiction,
/// independent of its payload. Used as the dedup key in `RevocationTracker`
/// so that e.g. two different error-dialog titles share one debounce timer.
///
/// Taking a `RevocationTag` (rather than `&str`) in `clear()` / `is_pending()`
/// makes typos a compile error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationTag {
    JvmDied,
    ErrorDialog,
    ReloginDialog,
    SessionConflict,
    LoginFormVisible,
    DisconnectedLabelStable,
    WindowClassMorphed,
    ApiPortListenerLost,
    AgentReportedDisconnect,
}

impl RevocationTag {
    /// Short snake_case name used in structured logs
    /// (`proof revoked source=<tag>`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JvmDied => "jvm_died",
            Self::ErrorDialog => "error_dialog",
            Self::ReloginDialog => "relogin_dialog",
            Self::SessionConflict => "session_conflict",
            Self::LoginFormVisible => "login_form_visible",
            Self::DisconnectedLabelStable => "disconnected_label",
            Self::WindowClassMorphed => "window_class_morphed",
            Self::ApiPortListenerLost => "api_port_listener_lost",
            Self::AgentReportedDisconnect => "agent_reported_disconnect",
        }
    }
}

impl std::fmt::Display for RevocationTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single source of negative evidence capable of revoking the Connected state.
///
/// Variants carry enough context for structured logging; the dedup key used
/// by `RevocationTracker` is derived via `.tag()` which returns a typed
/// `RevocationTag` that can be passed to `clear()` / `is_pending()` without
/// constructing a fresh `RevocationSource` with a dummy payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevocationSource {
    /// JVM process exited or crashed. Fires immediately.
    JvmDied,
    /// A window matching known disconnect error-dialog titles appeared.
    /// Fires after a short debounce in case the dialog is auto-dismissed by
    /// the agent handlers before the verifier has a chance to observe it.
    ///
    /// The title is `Arc<str>` so repeated observations across ticks don't
    /// re-allocate the string — a refcount bump is free.
    ///
    /// NOT CURRENTLY CONSTRUCTED — the title-scan predicate that used to
    /// trigger this produced false positives on benign Gateway notifications
    /// ("Restart in progress", BBO-warning note, GatewayNotificationHandler
    /// dialogs). Canonical session-loss signals are `DisconnectedLabelStable`
    /// and `LoginFormVisible`. Kept in the enum so future typed-event wiring
    /// (off `AgentEvent::ErrorDialog` with strict keyword filter) can be
    /// added without re-designing the source type.
    #[allow(dead_code)]
    ErrorDialog(Arc<str>),
    /// The "Re-login is required" dialog appeared. Fires immediately.
    ReloginDialog,
    /// Session conflict dialog ("Existing session detected"). Immediate.
    SessionConflict,
    /// Login form textfields appeared on the main Gateway window. Debounced
    /// because window morphs can briefly expose transient textfield state.
    LoginFormVisible,
    /// Disconnected label observed (label-based detection). Longest
    /// debounce — label refresh lag is a known transient source.
    DisconnectedLabelStable,
    /// Main window class changed unexpectedly (e.g. `ibgateway.ay` → `ibgateway.az`)
    /// without the benign-update path that `do_connected` recognizes.
    // TODO: `do_connected` currently only logs benign class changes and does
    // not observe this revocation source. Either wire it up or remove the variant.
    #[allow(dead_code)]
    WindowClassMorphed { from: String, to: String },
    /// The agent reported `ConnectionStatusChanged{connected -> disconnected}`
    /// and has not reported reconnection since.
    ///
    /// This is the BACKSTOP for the blind spot in label inspection. The agent's
    /// report is authoritative — it is the Gateway telling us its own session
    /// dropped — but it was historically discarded (see the handler in mod.rs)
    /// because stale events during Launching/Login caused false-positive
    /// restarts. That is handled here by only observing this source from
    /// `do_connected`, and by clearing it on entry to Connected so nothing
    /// seen before the session began can fire against it.
    ///
    /// HONEST STATUS: DEFENSE IN DEPTH, not a fix for a demonstrated failure.
    ///
    /// It was introduced citing short disconnects (20s and 25s) that produced
    /// no revocation while Connected was retained. That citation does not
    /// hold up, and it is recorded here so nobody re-derives a false lineage:
    ///
    ///   * Those sessions SELF-HEALED in well under a minute. Retaining
    ///     Connected across a transient blip is arguably correct — revoking
    ///     would have forced a pointless re-login.
    ///   * This source debounces 90s, so it would NOT have fired on either
    ///     disconnect anyway. It changes nothing about what was observed.
    ///
    /// What it actually guards is a case with NO observed instance: an
    /// agent-reported disconnect persisting past 90s that label inspection
    /// does not catch. A false Connected held ~1h at a login form is that
    /// shape, but its causes — fail-open transitions into Connected, and
    /// liveness reading `tables` instead of `labels` — are both fixed.
    /// Whether any path remains is unknown; this exists so that if one does,
    /// it is bounded at 90s.
    ///
    /// It is not free: a genuine >90s disconnect that would have self-healed
    /// at, say, 120s now costs a re-login. Judged worth it for a live trading
    /// gateway, where a false Connected is the more expensive error.
    ///
    /// Label inspection remains the fast path (measured at 7ms); this is
    /// deliberately an INDEPENDENT signal rather than a second reading of the
    /// same UI, so it holds when that path does not.
    AgentReportedDisconnect,
    /// Gateway's API port stopped accepting TCP connections. The probe task
    /// already counted consecutive failures past the configured threshold,
    /// so this revocation fires immediately (zero debounce).
    ApiPortListenerLost,
}

impl RevocationSource {
    /// How long a contradiction must persist before this source fires.
    pub fn debounce(&self) -> Duration {
        match self {
            Self::JvmDied => Duration::from_millis(0),
            Self::ErrorDialog(_) => Duration::from_millis(500),
            Self::ReloginDialog => Duration::from_millis(0),
            Self::SessionConflict => Duration::from_millis(0),
            Self::LoginFormVisible => Duration::from_millis(1000),
            Self::DisconnectedLabelStable => Duration::from_millis(2000),
            Self::WindowClassMorphed { .. } => Duration::from_millis(500),
            // The probe task already debounced via consecutive failure count.
            Self::ApiPortListenerLost => Duration::ZERO,
            // Must sit ABOVE the routine ~20-25s nightly IB reconnect blip
            // (self-healing) or every night forces a pointless re-login.
            // Well below the hours-long outage this exists to catch.
            Self::AgentReportedDisconnect => Duration::from_secs(90),
        }
    }

    /// State to transition to when this source revokes Connected.
    pub fn next_state(&self) -> State {
        match self {
            Self::JvmDied => State::Restarting,
            Self::ErrorDialog(_) => State::Restarting,
            Self::ReloginDialog => State::ReconnectingSession,
            Self::SessionConflict => State::HandlingSessionConflict,
            Self::LoginFormVisible => State::WaitingForLogin,
            Self::DisconnectedLabelStable => State::WaitingForLogin,
            Self::WindowClassMorphed { .. } => State::WaitingForLogin,
            // Restart kills the JVM cleanly; the port is gone anyway.
            Self::ApiPortListenerLost => State::Restarting,
            // The Gateway is sitting on the login prompt — go re-login rather
            // than bounce the JVM, which is slower and loses more.
            Self::AgentReportedDisconnect => State::WaitingForLogin,
        }
    }

    /// Typed dedup key.
    pub fn tag(&self) -> RevocationTag {
        match self {
            Self::JvmDied => RevocationTag::JvmDied,
            Self::ErrorDialog(_) => RevocationTag::ErrorDialog,
            Self::ReloginDialog => RevocationTag::ReloginDialog,
            Self::SessionConflict => RevocationTag::SessionConflict,
            Self::LoginFormVisible => RevocationTag::LoginFormVisible,
            Self::DisconnectedLabelStable => RevocationTag::DisconnectedLabelStable,
            Self::WindowClassMorphed { .. } => RevocationTag::WindowClassMorphed,
            Self::ApiPortListenerLost => RevocationTag::ApiPortListenerLost,
            Self::AgentReportedDisconnect => RevocationTag::AgentReportedDisconnect,
        }
    }
}

/// Tracks per-source debounce state for `RevocationSource` observations.
///
/// Call `observe()` every time a contradiction is detected; it returns
/// `Some(source)` once the source's debounce has elapsed, at which point the
/// caller should transition state. Call `clear()` when the contradiction
/// stops so the debounce resets cleanly. `clear_all()` is called on state
/// transitions that start a new Connected session.
///
/// The tracker does NOT perform the transition itself — it only tells the
/// caller when a revocation source has matured past its debounce.
#[derive(Debug, Default)]
pub struct RevocationTracker {
    first_seen: HashMap<RevocationTag, (Instant, RevocationSource)>,
}

impl RevocationTracker {
    pub fn new() -> Self { Self::default() }

    /// Record a contradiction observation.
    ///
    /// Returns `Some(source)` on the first tick where the source's debounce
    /// has elapsed since first observation. Returns `None` while still within
    /// the debounce window.
    pub fn observe(&mut self, source: RevocationSource) -> Option<RevocationSource> {
        let tag = source.tag();
        let debounce = source.debounce();
        let now = Instant::now();

        match self.first_seen.get(&tag) {
            Some((first, _)) => {
                if now.duration_since(*first) >= debounce {
                    Some(source)
                } else {
                    None
                }
            }
            None => {
                self.first_seen.insert(tag, (now, source.clone()));
                if debounce.is_zero() {
                    Some(source)
                } else {
                    None
                }
            }
        }
    }

    /// Test-only: pretend a source was first observed `ago` in the past, so a
    /// debounce can be exercised without sleeping through it. Kept behind
    /// `cfg(test)` so the production surface stays observe/clear/is_pending.
    #[cfg(test)]
    pub(super) fn seed_first_seen_for_test(&mut self, source: RevocationSource, ago: Duration) {
        self.first_seen
            .insert(source.tag(), (Instant::now() - ago, source));
    }

    /// Cancel a pending debounce (the contradiction stopped).
    /// Takes the typed `RevocationTag` so a typo becomes a compile error.
    pub fn clear(&mut self, tag: RevocationTag) {
        self.first_seen.remove(&tag);
    }

    /// Reset every pending debounce. Called on every transition that starts
    /// a fresh Connected session.
    pub fn clear_all(&mut self) {
        self.first_seen.clear();
    }

    /// Whether any source is currently being debounced.
    pub fn any_pending(&self) -> bool {
        !self.first_seen.is_empty()
    }

    /// Whether a specific source is currently debouncing.
    #[allow(dead_code)]
    pub fn is_pending(&self, tag: RevocationTag) -> bool {
        self.first_seen.contains_key(&tag)
    }

    /// Test helper: seed the first-seen timestamp for a source to an
    /// artificially earlier time so the next `observe()` call matures
    /// without requiring real wall-clock elapsed time.
    #[cfg(test)]
    pub(in crate::state_machine) fn seed_first_seen_for_tests(
        &mut self,
        source: RevocationSource,
        elapsed: Duration,
    ) {
        let tag = source.tag();
        self.first_seen
            .insert(tag, (Instant::now() - elapsed, source));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_sources_fire_on_first_observe() {
        let mut t = RevocationTracker::new();
        assert_eq!(
            t.observe(RevocationSource::JvmDied),
            Some(RevocationSource::JvmDied),
            "JVM death must fire on first observation (zero debounce)"
        );
    }

    #[test]
    fn debounced_sources_reject_single_observation() {
        let mut t = RevocationTracker::new();
        assert_eq!(
            t.observe(RevocationSource::LoginFormVisible),
            None,
            "login form has 1s debounce — first observation must not fire"
        );
        assert!(t.is_pending(RevocationTag::LoginFormVisible));
    }

    #[test]
    fn debounced_sources_fire_after_debounce_elapses() {
        let mut t = RevocationTracker::new();
        // Seed the first_seen map with a timestamp far in the past so the
        // debounce has "elapsed" without actually sleeping.
        t.first_seen.insert(
            RevocationTag::DisconnectedLabelStable,
            (
                Instant::now() - Duration::from_secs(5),
                RevocationSource::DisconnectedLabelStable,
            ),
        );
        assert_eq!(
            t.observe(RevocationSource::DisconnectedLabelStable),
            Some(RevocationSource::DisconnectedLabelStable),
            "disconnected label must fire once its 2s debounce has elapsed"
        );
    }

    #[test]
    fn clear_cancels_pending_debounce() {
        let mut t = RevocationTracker::new();
        t.observe(RevocationSource::LoginFormVisible);
        assert!(t.is_pending(RevocationTag::LoginFormVisible));
        t.clear(RevocationTag::LoginFormVisible);
        assert!(!t.is_pending(RevocationTag::LoginFormVisible));
    }

    #[test]
    fn clear_all_resets_every_timer() {
        let mut t = RevocationTracker::new();
        t.observe(RevocationSource::LoginFormVisible);
        t.observe(RevocationSource::ErrorDialog("x".into()));
        assert!(t.any_pending());
        t.clear_all();
        assert!(!t.any_pending());
    }

    #[test]
    fn error_dialog_payload_shares_debounce_with_other_error_dialogs() {
        let mut t = RevocationTracker::new();
        // Different titles, same tag.
        assert!(t.observe(RevocationSource::ErrorDialog("A".into())).is_none());
        assert!(t.observe(RevocationSource::ErrorDialog("B".into())).is_none());
        assert_eq!(t.first_seen.len(), 1);
    }

    #[test]
    fn each_source_has_expected_next_state() {
        assert_eq!(RevocationSource::JvmDied.next_state(), State::Restarting);
        assert_eq!(
            RevocationSource::ErrorDialog("x".into()).next_state(),
            State::Restarting
        );
        assert_eq!(
            RevocationSource::ReloginDialog.next_state(),
            State::ReconnectingSession
        );
        assert_eq!(
            RevocationSource::SessionConflict.next_state(),
            State::HandlingSessionConflict
        );
        assert_eq!(
            RevocationSource::LoginFormVisible.next_state(),
            State::WaitingForLogin
        );
        assert_eq!(
            RevocationSource::DisconnectedLabelStable.next_state(),
            State::WaitingForLogin
        );
        assert_eq!(
            RevocationSource::WindowClassMorphed {
                from: "a".into(),
                to: "b".into()
            }
            .next_state(),
            State::WaitingForLogin
        );
        assert_eq!(
            RevocationSource::ApiPortListenerLost.next_state(),
            State::Restarting
        );
    }

    // ── AgentReportedDisconnect ─────────────────────────────────────────
    //
    // Regression tests for a Connected state that outlived the session.
    //
    // The Gateway agent emits ConnectionStatusChanged{connected->disconnected},
    // which is the AUTHORITATIVE statement that the session dropped. It was
    // deliberately made informational-only (see the handler in mod.rs) because
    // stale "disconnected" events arriving during Launching/Login caused
    // false-positive restarts on first Connected entry.
    //
    // The replacement — active label inspection — only works while a window
    // carrying a connection label is on screen. When the Gateway falls back to
    // a LOGIN PROMPT there is no such label, so the detector goes blind exactly
    // when the failure is most severe, and Connected persists indefinitely.
    //
    // Observed in production: one disconnect revoked via disconnected_label in
    // 7ms, but others lasting 20s and 25s produced NO revocation at all and
    // Connected was retained — over VNC the live Gateway was sitting on the
    // login prompt while ibctl reported Connected.
    //
    // This source is the BACKSTOP for that blind spot: slower than label
    // inspection (which stays the fast path), but it cannot be blinded by the
    // window contents because it is driven by the agent's own report.

    #[test]
    fn agent_disconnect_debounce_outlasts_the_routine_nightly_blip() {
        // IB drops and restores the connection most nights; measured at
        // 20s and 25s, self-healing both times.
        // Revoking on those would force a pointless nightly re-login, so the
        // debounce MUST sit above them. If someone lowers this, that churn is
        // what they are buying.
        let d = RevocationSource::AgentReportedDisconnect.debounce();
        assert!(
            d >= Duration::from_secs(60),
            "debounce {:?} must exceed the observed ~25s benign nightly              disconnect or every night forces a re-login",
            d
        );
    }

    #[test]
    fn agent_disconnect_does_not_fire_immediately() {
        let mut t = RevocationTracker::new();
        assert_eq!(
            t.observe(RevocationSource::AgentReportedDisconnect),
            None,
            "must debounce — a transient blip must not tear down a live session"
        );
        assert!(t.is_pending(RevocationTag::AgentReportedDisconnect));
    }

    #[test]
    fn agent_disconnect_fires_once_debounce_elapses() {
        let mut t = RevocationTracker::new();
        t.first_seen.insert(
            RevocationTag::AgentReportedDisconnect,
            (
                Instant::now() - Duration::from_secs(600),
                RevocationSource::AgentReportedDisconnect,
            ),
        );
        assert_eq!(
            t.observe(RevocationSource::AgentReportedDisconnect),
            Some(RevocationSource::AgentReportedDisconnect),
            "a disconnect the agent still reports after the debounce is a real              session loss and must revoke Connected"
        );
    }

    #[test]
    fn agent_disconnect_clears_when_connection_returns() {
        // The 20-25s nightly blip path: observed, then the agent reports
        // reconnected, so the pending debounce must be cancelled and a later
        // observation must start a fresh window rather than fire instantly.
        let mut t = RevocationTracker::new();
        t.observe(RevocationSource::AgentReportedDisconnect);
        assert!(t.is_pending(RevocationTag::AgentReportedDisconnect));
        t.clear(RevocationTag::AgentReportedDisconnect);
        assert!(!t.is_pending(RevocationTag::AgentReportedDisconnect));
        assert_eq!(
            t.observe(RevocationSource::AgentReportedDisconnect),
            None,
            "after clearing, the debounce window must restart from zero"
        );
    }

    #[test]
    fn agent_disconnect_routes_to_waiting_for_login() {
        // The Gateway is sitting on the login prompt — that is precisely the
        // state we failed to detect, so that is where we must go.
        assert_eq!(
            RevocationSource::AgentReportedDisconnect.next_state(),
            State::WaitingForLogin
        );
    }
}
