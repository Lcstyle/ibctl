//! Proof-carrying Connected state + source-tagged revocation bus.
//!
//! # Design
//!
//! Entering `State::Connected` requires a `ConnectedProof`. The proof's
//! constructor is crate-private; code outside `state_machine::verifier` cannot
//! mint one. This moves the safety invariant "we only claim Connected when
//! the Gateway is actually ready" from convention into the type system — no
//! handler can accidentally return `Ok(State::Connected(...))` without going
//! through `try_enter_connected()`.
//!
//! Exiting `State::Connected` is governed by a revocation bus (`RevocationTracker`)
//! with per-source debounce. Each `RevocationSource` has its own timer:
//! immediate sources (JVM dead, session conflict, re-login dialog) fire on
//! first observation; debounced sources (login-form reappearance,
//! "disconnected" label stabilization, window-class morph) only fire after
//! sustained contradiction. This matches real Gateway physics — there are
//! several legitimate transient UI phases where a single-frame observation
//! would be a false positive.
//!
//! # Transition Law
//!
//! - **Promotion:** positive evidence must come from the verifier;
//!   no timeout, retry exhaustion, or absence-of-errors may mint a proof.
//! - **Retention:** a valid proof is kept across ticks without re-verification.
//! - **Revocation:** any observed contradiction may demote, subject to its
//!   source-specific debounce.
//! - **Silence:** timeouts may only delay, restart, or demote — never promote.
//!
//! This law is enforced by property tests in the `state_machine::tests` module.

// Phase 0 scaffold — most methods are used in Phase 1 (revocation bus wire-up)
// and Phase 2 (centralized minting). Silence dead-code lint until then.
#![allow(dead_code)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use bitflags::bitflags;

use super::State;

bitflags! {
    /// Families of evidence that can contribute to minting a `ConnectedProof`.
    ///
    /// Note: we group signals by *family* rather than track each raw signal
    /// independently. Labels + textfields + has-login-button all come from a
    /// single `dump_components` call against one window — treating them as
    /// three independent votes would be fake rigor. Each family represents
    /// a distinct observation mechanism:
    ///
    /// * `UI_SNAPSHOT`       — JLabels / textfields / buttons from `dump_components`
    /// * `WINDOW_INVENTORY`  — `list_windows` (separate HTTP endpoint)
    /// * `EVENT_STREAM`      — NDJSON push events from the Java agent
    /// * `TCP_PROBE`         — out-of-band TCP connect check (dashboard-side)
    /// * `SUPERVISOR_ALIVE`  — OS-level child-process liveness
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct EvidenceKinds: u8 {
        const UI_SNAPSHOT       = 0b0000_0001;
        const WINDOW_INVENTORY  = 0b0000_0010;
        const EVENT_STREAM      = 0b0000_0100;
        const TCP_PROBE         = 0b0000_1000;
        const SUPERVISOR_ALIVE  = 0b0001_0000;
        /// Forced transition via SETSTATE debug command — not a real proof.
        /// Always logged with a loud warning so operators can tell apart
        /// synthetic from verified states.
        const FORCED            = 0b1000_0000;
    }
}

impl EvidenceKinds {
    /// Human-readable list of contributing evidence families, for logging
    /// and STATUS JSON output.
    pub fn tags(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.contains(Self::UI_SNAPSHOT) { out.push("ui_snapshot"); }
        if self.contains(Self::WINDOW_INVENTORY) { out.push("window_inventory"); }
        if self.contains(Self::EVENT_STREAM) { out.push("event_stream"); }
        if self.contains(Self::TCP_PROBE) { out.push("tcp_probe"); }
        if self.contains(Self::SUPERVISOR_ALIVE) { out.push("supervisor_alive"); }
        if self.contains(Self::FORCED) { out.push("forced"); }
        out
    }
}

/// Verifier version — bump when the semantic criteria for minting a proof
/// change. Stored inside every `ConnectedProof` so logs and STATUS JSON can
/// distinguish proofs issued under different rule sets.
pub const VERIFIER_VERSION: u32 = 1;

/// Proof that Gateway has reached a verified Connected state.
///
/// # Invariants
///
/// - Constructors are crate-private (`pub(super)` functions in this module).
///   No code outside `state_machine::verifier` can produce a `ConnectedProof`.
/// - `issued_at` is the wall-clock instant the proof was minted — NOT the
///   time Gateway first reached the connected UI state. Age is informational.
/// - `snapshot_version` / `event_seq` record the StateMachine's internal
///   version counters at the instant the proof was issued. These give every
///   proof a cheap provenance trail visible in logs.
///
/// # Equality
///
/// `ConnectedProof` implements `PartialEq` by field, which includes
/// `issued_at`. Two proofs minted in different ticks will never compare equal,
/// so prefer `matches!(state, State::Connected(_))` over `== State::Connected(proof)`
/// for "is this the Connected state?" checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectedProof {
    issued_at: Instant,
    snapshot_version: u64,
    event_seq: u64,
    evidence: EvidenceKinds,
    verifier_version: u32,
}

impl ConnectedProof {
    /// Mint a proof from verified evidence. Only callable from within the
    /// `state_machine` module.
    #[allow(dead_code)] // used in later phases
    pub(super) fn mint(
        snapshot_version: u64,
        event_seq: u64,
        evidence: EvidenceKinds,
    ) -> Self {
        Self {
            issued_at: Instant::now(),
            snapshot_version,
            event_seq,
            evidence,
            verifier_version: VERIFIER_VERSION,
        }
    }

    /// Synthetic proof for `SETSTATE Connected` debug command and tests.
    /// Marked `EvidenceKinds::FORCED` so it is visually distinct in logs
    /// from genuine verifier output.
    pub(super) fn forced() -> Self {
        Self {
            issued_at: Instant::now(),
            snapshot_version: 0,
            event_seq: 0,
            evidence: EvidenceKinds::FORCED,
            verifier_version: VERIFIER_VERSION,
        }
    }

    pub fn age(&self) -> Duration { self.issued_at.elapsed() }
    pub fn snapshot_version(&self) -> u64 { self.snapshot_version }
    pub fn event_seq(&self) -> u64 { self.event_seq }
    pub fn evidence(&self) -> EvidenceKinds { self.evidence }
    pub fn verifier_version(&self) -> u32 { self.verifier_version }

    /// True when this proof was produced by a SETSTATE override rather than
    /// a real verifier run. Consumers (STATUS JSON, logs) should surface
    /// this so operators are not misled.
    pub fn is_forced(&self) -> bool {
        self.evidence.contains(EvidenceKinds::FORCED)
    }
}

/// Reasons the verifier may refuse to mint a proof. Used in later phases
/// when `try_enter_connected()` wraps the 3 current construction sites.
#[allow(dead_code)] // constructed in Phase 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationFailure {
    JvmDead,
    NoPositiveLabel,
    LoginFormVisible,
    DisconnectedLabelPresent,
    SessionConflictVisible,
    ReloginDialogVisible,
    AgentUnreachable,
}

/// A single source of negative evidence capable of revoking a `ConnectedProof`.
///
/// Variants carry enough context for structured logging; the dedup key used
/// by `RevocationTracker` is derived via `.tag()` so that e.g. two different
/// error-dialog titles share one debounce timer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RevocationSource {
    /// JVM process exited or crashed. Fires immediately.
    JvmDied,
    /// A window matching known disconnect error-dialog titles appeared.
    /// Fires after a short debounce in case the dialog is auto-dismissed by
    /// the agent handlers before the verifier has a chance to observe it.
    ErrorDialog(String),
    /// The "Re-login is required" dialog appeared. Fires immediately —
    /// this dialog is a definitive signal from Gateway itself.
    ReloginDialog,
    /// Session conflict dialog ("Existing session detected"). Immediate.
    SessionConflict,
    /// Login form textfields appeared on the main Gateway window. Debounced
    /// because window morphs can briefly expose transient textfield state.
    LoginFormVisible,
    /// `components_indicate_disconnected()` returned true consistently.
    /// Longest debounce — label refresh lag is a known transient source.
    DisconnectedLabelStable,
    /// Main window class changed unexpectedly (e.g. `ibgateway.ay` → `ibgateway.az`)
    /// without the benign-update path that `do_connected` recognizes.
    WindowClassMorphed { from: String, to: String },
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
        }
    }

    /// State to transition to when this source revokes the proof.
    pub fn next_state(&self) -> State {
        match self {
            Self::JvmDied => State::Restarting,
            Self::ErrorDialog(_) => State::Restarting,
            Self::ReloginDialog => State::ReconnectingSession,
            Self::SessionConflict => State::HandlingSessionConflict,
            Self::LoginFormVisible => State::WaitingForLogin,
            Self::DisconnectedLabelStable => State::WaitingForLogin,
            Self::WindowClassMorphed { .. } => State::WaitingForLogin,
        }
    }

    /// Short tag used as the dedup key in `RevocationTracker` and in
    /// structured log lines (`proof revoked source=login_form_visible`).
    pub fn tag(&self) -> &'static str {
        match self {
            Self::JvmDied => "jvm_died",
            Self::ErrorDialog(_) => "error_dialog",
            Self::ReloginDialog => "relogin_dialog",
            Self::SessionConflict => "session_conflict",
            Self::LoginFormVisible => "login_form_visible",
            Self::DisconnectedLabelStable => "disconnected_label",
            Self::WindowClassMorphed { .. } => "window_class_morphed",
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
/// caller when a revocation source has matured past its debounce. This keeps
/// verification (truth) separate from transition policy (control flow).
#[derive(Debug, Default)]
pub struct RevocationTracker {
    /// Per-tag `(first_seen_at, latest_observed_source)` pairs.
    /// The source is stored so logs can include its full payload when fired.
    first_seen: HashMap<&'static str, (Instant, RevocationSource)>,
}

impl RevocationTracker {
    pub fn new() -> Self { Self::default() }

    /// Record a contradiction observation.
    ///
    /// Returns `Some(source)` on the first tick where the source's debounce
    /// has elapsed since first observation. Returns `None` while still within
    /// the debounce window, or on repeated observations after the source has
    /// already fired (caller should act once and then `clear()`).
    pub fn observe(&mut self, source: RevocationSource) -> Option<RevocationSource> {
        let tag = source.tag();
        let debounce = source.debounce();
        let now = Instant::now();

        match self.first_seen.get(tag) {
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

    /// Cancel a pending debounce (e.g. the login form disappeared before
    /// the 1s threshold). Idempotent.
    pub fn clear(&mut self, tag: &str) {
        self.first_seen.remove(tag);
    }

    /// Reset every pending debounce. Called on every transition that starts
    /// a fresh Connected session (so stale timers from a prior session don't
    /// leak across).
    pub fn clear_all(&mut self) {
        self.first_seen.clear();
    }

    /// Whether any source is currently being debounced.
    #[allow(dead_code)]
    pub fn any_pending(&self) -> bool {
        !self.first_seen.is_empty()
    }

    /// Whether a specific source is currently debouncing.
    #[allow(dead_code)]
    pub fn is_pending(&self, tag: &str) -> bool {
        self.first_seen.contains_key(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_tags_enumerate_all_set_flags() {
        let e = EvidenceKinds::UI_SNAPSHOT | EvidenceKinds::SUPERVISOR_ALIVE;
        assert_eq!(e.tags(), vec!["ui_snapshot", "supervisor_alive"]);
    }

    #[test]
    fn forced_proof_is_distinct_in_evidence() {
        let p = ConnectedProof::forced();
        assert!(p.is_forced());
        assert_eq!(p.verifier_version(), VERIFIER_VERSION);
    }

    #[test]
    fn mint_records_provenance() {
        let p = ConnectedProof::mint(42, 1234, EvidenceKinds::UI_SNAPSHOT);
        assert_eq!(p.snapshot_version(), 42);
        assert_eq!(p.event_seq(), 1234);
        assert_eq!(p.evidence(), EvidenceKinds::UI_SNAPSHOT);
        assert!(!p.is_forced());
    }

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
        assert!(t.is_pending("login_form_visible"));
    }

    #[test]
    fn debounced_sources_fire_after_debounce_elapses() {
        let mut t = RevocationTracker::new();
        // Seed the first_seen map with a timestamp far in the past so the
        // debounce has "elapsed" without actually sleeping.
        t.first_seen.insert(
            "disconnected_label",
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
        assert!(t.is_pending("login_form_visible"));
        t.clear("login_form_visible");
        assert!(!t.is_pending("login_form_visible"));
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
        // First observation with title "A" — pending.
        assert!(t.observe(RevocationSource::ErrorDialog("A".into())).is_none());
        // Second observation with title "B" reuses the same debounce timer
        // (both have tag "error_dialog").
        assert!(t.observe(RevocationSource::ErrorDialog("B".into())).is_none());
        // But the backing HashMap only has one entry.
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
    }
}
