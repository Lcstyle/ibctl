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
}
