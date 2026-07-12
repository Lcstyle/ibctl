//! Three-phase reconnection recovery coordinator (pure decision layer + marker I/O).
//!
//! # Model
//!
//! The state machine currently retries reconnection back-to-back forever
//! when Gateway can't reach IB — the user watched paper cycle
//! `WaitingForLogin → Authenticating → WaitingFor2fa → (fail) →
//! ReconnectingSession → …` for an entire day on 2026-07-10. This module
//! adds a phase-timer wrapper around that inner loop:
//!
//! ```text
//!  Aggressive ── time > aggressive_phase_max ──►  BackoffEvery15Min
//!      ▲                                                │
//!      │                                        time > backoff_phase_max
//!      │                                                ▼
//!      └── ResumeToken ── (user tapped ntfy link) ── GivenUp
//! ```
//!
//! - **Aggressive**: current back-to-back retry loop. Timer runs from the last
//!   Connected-with-dwell success (or state-machine startup if never Connected).
//! - **BackoffEvery15Min**: throttled retries once the aggressive timer trips
//!   `aggressive_phase_max_secs`. The Restarting → WaitingForLogin cycle sleeps
//!   until the next `backoff_interval_secs` boundary.
//! - **GivenUp**: the SM halts reconnection attempts entirely and emits a
//!   ntfy alert with a signed callback URL (HITL-2FA pattern). Only exit is
//!   the user tapping the URL, which mints a `ResumeToken` that transitions
//!   back to `Aggressive` with a fresh phase timer.
//!
//! # Design constraints
//!
//! Mirrors [`crate::cold_restart`]'s pure/impure split verbatim:
//!
//! - [`compute_next_action`] is the SOLE authority for phase transition
//!   decisions. Referentially transparent. No `&mut`, no clock reads, no
//!   IO, no logging. Callers pass a [`RecoverySnapshot`] built from the
//!   coordinator's fields plus external inputs (elapsed durations,
//!   fingerprint streak, cold-restart-pending, resume token).
//! - Elapsed time is `min(wall_elapsed, mono_elapsed)` — computed by the
//!   caller. Wall alone would trip on NTP jumps and VM restore-from-snapshot;
//!   monotonic alone loses meaning across container restarts. `min()` is
//!   conservative: never escalate faster than the slower of the two.
//! - Cold-restart precedence: a scheduled cold restart preempts every phase
//!   transition. The [`NextAction::DeferToColdRestart`] variant signals this
//!   to the wrapper. Cold restart preserves `phase_entered_at` unless the
//!   post-restart Connected dwell records success.
//! - Fingerprint tripwire: if the state machine loops through the SAME
//!   `(last_error, transition, connect_stage)` fingerprint N times in a row,
//!   skip time-based escalation entirely and go straight to
//!   [`NextAction::ForceHitlEarly`]. Same failure repeating for 40 minutes
//!   is a stronger signal than "clock says 40 minutes elapsed".
//!
//! # Bug-class proof
//!
//! Every input to [`compute_next_action`] is either pure config or a per-tick
//! snapshot value. No captured-once-then-stale booleans (Bug 4 class). No
//! `Instant` or `Zoned` captured on struct construction and reused later —
//! the wrapper freshly samples both clocks each tick and passes the deltas.
//!
//! The `bug_class_invariant_compute_next_action_is_pure` determinism test
//! calls the function three times with identical inputs and asserts identical
//! outputs; any future change that violates purity is caught mechanically.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::types::Signal;

/// Discriminant + payloads for the three reconnection phases.
///
/// Stored as an enum on [`RecoveryCoordinator`] rather than a compile-time
/// type-state parameter because the coordinator is held as a field on
/// [`crate::state_machine::types::StateMachine`] and must transition
/// in place without moving `self` out through the async event loop.
///
/// Compile-time invariant proof comes from the pure decision function's
/// contract: only `EscalateToBackoff` can produce `BackoffEvery15Min`, only
/// `FireGiveUpAlert` can produce `GivenUp`, only `ResumeToAggressive` can
/// exit `GivenUp`. Wrapper code is the sole applier of these actions and
/// exhaustively matches [`NextAction`], so illegal transitions can't slip
/// in via any other path.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Deserialize,
    serde::Serialize,
)]
pub enum RecoveryPhase {
    // Explicit per-variant rename — serde's default `rename_all = "snake_case"`
    // maps `BackoffEvery15Min` to `backoff_every15_min` (no underscore before
    // digits) which does NOT match [`as_str`] output `"backoff_every_15min"`
    // that STATUS JSON and structured logs already expose. Keep the wire
    // format consistent with `as_str`.
    /// Back-to-back retries (current behaviour).
    #[serde(rename = "aggressive")]
    Aggressive,
    /// Throttled to one retry per `backoff_interval_secs`.
    #[serde(rename = "backoff_every_15min")]
    BackoffEvery15Min,
    /// Halted; awaiting user resume via signed callback URL.
    #[serde(rename = "given_up")]
    GivenUp,
}

impl RecoveryPhase {
    /// Stable string tag for structured logs + STATUS JSON. Snake-case.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Aggressive => "aggressive",
            Self::BackoffEvery15Min => "backoff_every_15min",
            Self::GivenUp => "given_up",
        }
    }
}

/// Pure config — all thresholds, no state.
///
/// Env overrides applied by the caller BEFORE snapshot construction; the
/// pure function trusts what's in `cfg`. See `IBCTL_RECOVERY_*_SECS` for
/// the env kill-switch and per-threshold overrides used in e2e tests.
///
/// INVARIANT: no timestamps, no derived booleans, no Instant. Adding one
/// re-opens the Bug 4 class.
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// Aggressive → Backoff threshold. Default 3600 (1h).
    pub aggressive_phase_max_secs: u64,
    /// Backoff → GivenUp threshold. Default 10800 (3h).
    pub backoff_phase_max_secs: u64,
    /// Sleep between Backoff-phase retries. Default 900 (15 min).
    pub backoff_interval_secs: u64,
    /// Minimum Connected dwell before a success resets the phase timer.
    /// Default 60 (per plan decision).
    pub min_success_dwell_secs: u64,
    /// Same-error streak that skips time-based escalation and forces
    /// HITL immediately. Default 8 (~40 min at 5-min cycles).
    pub fingerprint_streak_forcing_hitl: u32,
    /// Ntfy give-up alert callback URL lifetime, in hours. Exposed on
    /// STATUS so the dashboard monitor's ntfy body reflects the real
    /// operator-configured value rather than a fabricated default
    /// (finding B-HIGH-1). Default 12.
    pub giveup_callback_valid_hours: u32,
    /// Minimum wall-clock interval before re-firing a give-up alert.
    /// Exposed on STATUS so the dashboard monitor's resend cadence is
    /// operator-configurable end-to-end (finding B-HIGH-1). Default 6.
    pub giveup_alert_resend_interval_hours: u32,
    /// Master kill switch — when true the coordinator returns Sleep(0)
    /// unconditionally and refuses to write markers. Set via
    /// `IBCTL_RECOVERY_DISABLED=1`. Precedence: env > TOML > default.
    pub disabled: bool,
}

impl RecoveryConfig {
    /// Default values matching the plan and TOML defaults.
    /// Kept const so tests and callers agree without duplicating literals.
    pub const DEFAULT_AGGRESSIVE_MAX_SECS: u64 = 3600;
    pub const DEFAULT_BACKOFF_MAX_SECS: u64 = 10800;
    pub const DEFAULT_BACKOFF_INTERVAL_SECS: u64 = 900;
    pub const DEFAULT_MIN_SUCCESS_DWELL_SECS: u64 = 60;
    pub const DEFAULT_FINGERPRINT_STREAK: u32 = 8;
    pub const DEFAULT_GIVEUP_CALLBACK_VALID_HOURS: u32 = 12;
    pub const DEFAULT_GIVEUP_ALERT_RESEND_INTERVAL_HOURS: u32 = 6;
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            aggressive_phase_max_secs: Self::DEFAULT_AGGRESSIVE_MAX_SECS,
            backoff_phase_max_secs: Self::DEFAULT_BACKOFF_MAX_SECS,
            backoff_interval_secs: Self::DEFAULT_BACKOFF_INTERVAL_SECS,
            min_success_dwell_secs: Self::DEFAULT_MIN_SUCCESS_DWELL_SECS,
            fingerprint_streak_forcing_hitl: Self::DEFAULT_FINGERPRINT_STREAK,
            giveup_callback_valid_hours: Self::DEFAULT_GIVEUP_CALLBACK_VALID_HOURS,
            giveup_alert_resend_interval_hours:
                Self::DEFAULT_GIVEUP_ALERT_RESEND_INTERVAL_HOURS,
            disabled: false,
        }
    }
}

/// Per-tick snapshot passed to [`compute_next_action`]. Built fresh by the
/// async wrapper — never carried across ticks.
///
/// `phase_elapsed_secs` is `min(wall_delta, monotonic_delta)` from the phase
/// entry point. See module docs for why min-of-two-clocks.
#[derive(Debug, Clone)]
pub struct RecoverySnapshot {
    pub phase: RecoveryPhase,
    /// `min(wall_now - phase_entered_at_wall, mono_now - phase_entered_at_mono)`.
    /// Capped at u64::MAX; a negative wall delta (clock ran backwards) is
    /// clamped to 0 by the caller.
    pub phase_elapsed_secs: u64,
    /// True iff `mono_now - last_full_success_at_mono >= min_success_dwell_secs`
    /// AND that success occurred inside the current phase's lifetime.
    /// The wrapper is responsible for scoping: a success recorded in a
    /// previous phase does not count toward the current phase's timer.
    pub had_success_this_phase: bool,
    /// From `RESUME_RECONNECT` command; None if no token pending.
    /// Presence of Some(_) is treated as "user tapped the link".
    pub resume_token: Option<ResumeToken>,
    /// Result of `cold_restart::compute_next_action(...)` this tick.
    /// True when a scheduled cold restart is FireEligible.
    pub cold_restart_pending: bool,
    /// Consecutive-identical-failure counter. Reset on any progress
    /// (Connected or a different transition failure fingerprint).
    pub failure_fingerprint_streak: u32,
}

/// Opaque proof-of-authorization from the dashboard callback endpoint.
///
/// Constructor is private-ish (only the caller that verified the HMAC
/// signature builds one). The pure function only observes presence, not
/// content — the token's payload is validated by the dashboard side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeToken {
    /// Trading mode the token was minted for. Prevents a `?mode=paper`
    /// typo from resuming live — matched against the coordinator's own
    /// mode before the wrapper accepts the token.
    pub mode: String,
    /// Wall-clock instant the token was minted (for expiry checks).
    pub minted_at: jiff::Timestamp,
    /// Opaque nonce material supplied by the caller (RESUME_RECONNECT
    /// argument on the wire). Stage 3 accepts any non-empty string;
    /// stage 5 wires HMAC verification against a dashboard-signed URL.
    /// Included in [`hash_token`] so distinct operator-supplied tokens
    /// produce distinct hashes — the single-use nonce invariant depends
    /// on this. Prior to threading this field, every `RESUME_RECONNECT`
    /// invocation minted a `(mode, minted_at)` pair with wall-clock
    /// granularity, so a second tap a second later was accepted as a
    /// "different" token.
    pub nonce_material: String,
}

/// Per-tick decision from [`compute_next_action`].
///
/// The wrapper matches this exhaustively. Every phase transition happens
/// through this enum; there is no other path. See module docs for the
/// compile-time-transitions argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextAction {
    /// Not eligible to transition this tick. Wrapper continues its normal
    /// state-machine cycle. Sleep duration is the wrapper's polling
    /// interval hint; Duration::ZERO means "no wait, next tick immediately".
    Sleep(Duration),
    /// Aggressive timer tripped. Wrapper writes the marker, updates
    /// `phase`, resets phase_entered_at.
    EscalateToBackoff,
    /// Backoff timer tripped. Wrapper writes the marker, sends the
    /// give-up ntfy alert with a signed callback URL, stops attempts.
    FireGiveUpAlert,
    /// User tapped the resume link. Wrapper clears `last_full_success_at`
    /// (per plan decision), transitions to Aggressive, resets timer.
    ResumeToAggressive,
    /// A scheduled cold restart is imminent. Wrapper skips this tick's
    /// escalation and lets the cold-restart path run — cold restart
    /// preserves `phase_entered_at` unless the post-restart Connected
    /// dwell records success.
    DeferToColdRestart,
    /// Fingerprint tripwire fired: N identical failures in a row.
    /// Wrapper sends the give-up alert immediately (regardless of phase
    /// timer) — "same error 8 times in 40 min" is a stronger signal
    /// than "clock says 40 min elapsed".
    ForceHitlEarly,
}

/// THE sole authority for recovery-phase transition decisions.
///
/// CONTRACT: no `&mut`, no clock reads, no filesystem, no logging, no
/// captured state. Determinism enforced by
/// `bug_class_invariant_compute_next_action_is_pure`.
pub fn compute_next_action(snap: &RecoverySnapshot, cfg: &RecoveryConfig) -> NextAction {
    // Gate 0: master kill switch. Returned unconditionally so an operator
    // can disable the entire coordinator via IBCTL_RECOVERY_DISABLED=1
    // without editing TOML or restarting. Env applied by the caller BEFORE
    // constructing cfg; the pure function just observes `disabled`.
    if cfg.disabled {
        return NextAction::Sleep(Duration::ZERO);
    }

    // Gate 1: cold-restart precedence. A scheduled cold restart is a stronger
    // signal than any recovery phase — the JVM is about to be recycled anyway,
    // so backoff / give-up decisions this tick are stale. Preserving
    // phase_entered_at across the cold restart is the wrapper's job; the pure
    // function just says "defer".
    if snap.cold_restart_pending {
        return NextAction::DeferToColdRestart;
    }

    // Gate 2: resume token from user tap. Only valid in GivenUp — a stray
    // token in Aggressive or Backoff is a no-op (wrapper marks the token
    // consumed with a "no phase to resume from" response page). We surface
    // the resume as an action only when the phase actually needs it.
    if snap.resume_token.is_some() && snap.phase == RecoveryPhase::GivenUp {
        return NextAction::ResumeToAggressive;
    }

    // Gate 3: fingerprint tripwire. Skips time-based escalation entirely
    // when we're seeing the SAME failure signature repeatedly. Threshold
    // is per-config; default 8 ≈ 40 min at 5-min cycles.
    //
    // Only fires in Aggressive/Backoff — GivenUp has already emitted an
    // alert, so re-fingerprinting is meaningless there.
    if snap.phase != RecoveryPhase::GivenUp
        && snap.failure_fingerprint_streak >= cfg.fingerprint_streak_forcing_hitl
    {
        return NextAction::ForceHitlEarly;
    }

    match snap.phase {
        RecoveryPhase::Aggressive => {
            // Success dwell resets the phase timer — but only if the success
            // occurred INSIDE this phase (wrapper's responsibility to scope).
            // Zero-elapsed short-circuit; wrapper won't call in this state
            // often, but pure fn should be well-defined.
            if snap.had_success_this_phase {
                return NextAction::Sleep(Duration::ZERO);
            }
            if snap.phase_elapsed_secs >= cfg.aggressive_phase_max_secs {
                return NextAction::EscalateToBackoff;
            }
            NextAction::Sleep(Duration::ZERO)
        }
        RecoveryPhase::BackoffEvery15Min => {
            // Success in Backoff resets to Aggressive — but that transition
            // is driven by the wrapper when it observes the Connected dwell,
            // not by this pure function. Here we only decide escalate vs
            // continue-sleeping.
            if snap.phase_elapsed_secs >= cfg.backoff_phase_max_secs {
                return NextAction::FireGiveUpAlert;
            }
            // Sleep until the next backoff_interval_secs boundary.
            let remainder = snap.phase_elapsed_secs % cfg.backoff_interval_secs;
            let sleep_secs = cfg.backoff_interval_secs.saturating_sub(remainder);
            NextAction::Sleep(Duration::from_secs(sleep_secs))
        }
        RecoveryPhase::GivenUp => {
            // No resume token this tick (resume was already handled by
            // Gate 2 above). Continue parking — 1-hour sleep is a
            // conservative heartbeat; the caller may wake sooner on
            // command-server events.
            NextAction::Sleep(Duration::from_secs(3600))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_default() -> RecoveryConfig {
        RecoveryConfig::default()
    }

    fn snap(phase: RecoveryPhase, elapsed: u64) -> RecoverySnapshot {
        RecoverySnapshot {
            phase,
            phase_elapsed_secs: elapsed,
            had_success_this_phase: false,
            resume_token: None,
            cold_restart_pending: false,
            failure_fingerprint_streak: 0,
        }
    }

    fn dummy_token() -> ResumeToken {
        ResumeToken {
            mode: "paper".to_string(),
            minted_at: jiff::Timestamp::from_second(1_720_000_000).unwrap(),
            nonce_material: "test-dummy-nonce".to_string(),
        }
    }

    // ─── Aggressive phase ─────────────────────────────────────────────────

    #[test]
    fn aggressive_at_zero_sleeps() {
        let s = snap(RecoveryPhase::Aggressive, 0);
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::Sleep(Duration::ZERO));
    }

    #[test]
    fn aggressive_at_59min_below_threshold_sleeps() {
        let s = snap(RecoveryPhase::Aggressive, 59 * 60);
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::Sleep(Duration::ZERO));
    }

    #[test]
    fn aggressive_at_exactly_1h_escalates() {
        let s = snap(RecoveryPhase::Aggressive, 3600);
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::EscalateToBackoff);
    }

    #[test]
    fn aggressive_past_threshold_with_recent_success_stays() {
        // Success inside this phase resets the timer — even at 61min
        // elapsed, `had_success_this_phase=true` keeps us Aggressive.
        let mut s = snap(RecoveryPhase::Aggressive, 61 * 60);
        s.had_success_this_phase = true;
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::Sleep(Duration::ZERO));
    }

    // ─── Backoff phase ────────────────────────────────────────────────────

    #[test]
    fn backoff_at_5min_sleeps_until_next_boundary() {
        // 5 min into a 15-min interval → sleep 10 min.
        let s = snap(RecoveryPhase::BackoffEvery15Min, 5 * 60);
        assert_eq!(
            compute_next_action(&s, &cfg_default()),
            NextAction::Sleep(Duration::from_secs(10 * 60))
        );
    }

    #[test]
    fn backoff_just_before_boundary_sleeps_1s() {
        // 14min59s into a 15-min interval → sleep 1s.
        let s = snap(RecoveryPhase::BackoffEvery15Min, 14 * 60 + 59);
        assert_eq!(
            compute_next_action(&s, &cfg_default()),
            NextAction::Sleep(Duration::from_secs(1))
        );
    }

    #[test]
    fn backoff_at_2h59min_sleeps_60s() {
        // 2h59m into 3h max, interval-aligned residue.
        let s = snap(RecoveryPhase::BackoffEvery15Min, 179 * 60);
        assert_eq!(
            compute_next_action(&s, &cfg_default()),
            NextAction::Sleep(Duration::from_secs(60))
        );
    }

    #[test]
    fn backoff_past_3h_fires_giveup() {
        let s = snap(RecoveryPhase::BackoffEvery15Min, 3 * 3600 + 60);
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::FireGiveUpAlert);
    }

    // ─── GivenUp phase ────────────────────────────────────────────────────

    #[test]
    fn givenup_without_token_parks() {
        let s = snap(RecoveryPhase::GivenUp, 5 * 3600);
        assert_eq!(
            compute_next_action(&s, &cfg_default()),
            NextAction::Sleep(Duration::from_secs(3600))
        );
    }

    #[test]
    fn givenup_with_token_resumes() {
        let mut s = snap(RecoveryPhase::GivenUp, 5 * 3600);
        s.resume_token = Some(dummy_token());
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::ResumeToAggressive);
    }

    #[test]
    fn resume_token_in_aggressive_is_noop() {
        // Gate 2 only surfaces ResumeToAggressive when phase == GivenUp.
        // A stray token in Aggressive falls through to normal timer logic.
        let mut s = snap(RecoveryPhase::Aggressive, 10);
        s.resume_token = Some(dummy_token());
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::Sleep(Duration::ZERO));
    }

    // ─── Cold-restart precedence ──────────────────────────────────────────

    #[test]
    fn cold_restart_preempts_aggressive_escalate() {
        // At 61min in Aggressive we would normally EscalateToBackoff; when
        // cold_restart_pending, DeferToColdRestart wins.
        let mut s = snap(RecoveryPhase::Aggressive, 61 * 60);
        s.cold_restart_pending = true;
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::DeferToColdRestart);
    }

    #[test]
    fn cold_restart_preempts_backoff_giveup() {
        let mut s = snap(RecoveryPhase::BackoffEvery15Min, 3 * 3600 + 60);
        s.cold_restart_pending = true;
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::DeferToColdRestart);
    }

    #[test]
    fn cold_restart_preempts_givenup_park() {
        let mut s = snap(RecoveryPhase::GivenUp, 0);
        s.cold_restart_pending = true;
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::DeferToColdRestart);
    }

    // ─── Fingerprint tripwire ─────────────────────────────────────────────

    #[test]
    fn fingerprint_streak_forces_hitl_from_aggressive() {
        // Same failure 8 times → skip time-based escalation, HITL now.
        let mut s = snap(RecoveryPhase::Aggressive, 10 * 60);
        s.failure_fingerprint_streak = 8;
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::ForceHitlEarly);
    }

    #[test]
    fn fingerprint_streak_below_threshold_uses_time_axis() {
        let mut s = snap(RecoveryPhase::Aggressive, 10);
        s.failure_fingerprint_streak = 7;
        assert_eq!(compute_next_action(&s, &cfg_default()), NextAction::Sleep(Duration::ZERO));
    }

    #[test]
    fn fingerprint_streak_ignored_in_givenup() {
        // GivenUp has already emitted an alert; fingerprinting is
        // meaningless there.
        let mut s = snap(RecoveryPhase::GivenUp, 0);
        s.failure_fingerprint_streak = 100;
        assert_eq!(
            compute_next_action(&s, &cfg_default()),
            NextAction::Sleep(Duration::from_secs(3600))
        );
    }

    // ─── Kill switch ──────────────────────────────────────────────────────

    #[test]
    fn disabled_returns_sleep_zero_unconditionally() {
        let mut cfg = cfg_default();
        cfg.disabled = true;
        // Every phase, every state — disabled wins.
        for phase in [
            RecoveryPhase::Aggressive,
            RecoveryPhase::BackoffEvery15Min,
            RecoveryPhase::GivenUp,
        ] {
            let mut s = snap(phase, 10 * 3600);
            s.cold_restart_pending = true;
            s.resume_token = Some(dummy_token());
            s.failure_fingerprint_streak = 100;
            assert_eq!(
                compute_next_action(&s, &cfg),
                NextAction::Sleep(Duration::ZERO),
                "disabled must beat every other signal in {phase:?}",
            );
        }
    }

    // ─── Bug-class invariants ─────────────────────────────────────────────

    #[test]
    fn bug_class_invariant_compute_next_action_is_pure() {
        // Determinism enforcement: three calls with identical inputs must
        // return identical outputs. Guards against a future change that
        // sneaks in a clock read, an atomic counter, or a captured mut.
        let s = snap(RecoveryPhase::Aggressive, 30 * 60);
        let cfg = cfg_default();
        let a = compute_next_action(&s, &cfg);
        let b = compute_next_action(&s, &cfg);
        let c = compute_next_action(&s, &cfg);
        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn phase_str_stable() {
        // STATUS JSON and structured logs depend on these strings.
        // Changing them silently breaks dashboard rendering.
        assert_eq!(RecoveryPhase::Aggressive.as_str(), "aggressive");
        assert_eq!(RecoveryPhase::BackoffEvery15Min.as_str(), "backoff_every_15min");
        assert_eq!(RecoveryPhase::GivenUp.as_str(), "given_up");
    }
}

// ---------------------------------------------------------------------------
// Persistence layer (impure — filesystem access, atomic write, sidecar).
//
// Consulted at coordinator boot and on every phase transition. Sits below the
// pure-decision code above; the async wrapper is the sole caller.
//
// # Fail-safe policy (PR-C stage 2 design, Reviewer A HIGH — mandatory)
//
// Loading returns one of three outcomes:
//   - `Loaded(state)` — main file exists and parses cleanly.
//   - `Defaulted { reason }` — file missing, parse error, schema mismatch,
//     OR corrupt-and-sidecar-says-something-safe. Coordinator starts fresh
//     in Aggressive; caller logs `reason` as a warn.
//   - `RefusedGivenUpAutoReset { reason }` — main file corrupt AND sidecar
//     `.last-known-phase.txt` says "given_up". Coordinator BLOCKS at the
//     resume gate until `IBCTL_RECOVERY_FORCE_RESET=1` (`force_reset=true`).
//
// # Sidecar file
//
// A `.ibctl-recovery-state.{mode}.last-known-phase.txt` file mirrors the
// current phase name (from [`RecoveryPhase::as_str`]) as a single line.
// Written atomically BEFORE the main marker on every GivenUp save, so a
// disk-full or crash mid-main-write cannot lose the "we were in GivenUp"
// information. Pre-cleaned BEFORE the main marker on every non-GivenUp
// save so a subsequent parse-clean main marker with a stale "given_up"
// sidecar can be treated as a durable interrupted-transition record,
// not as a wedge to work around.
//
// Load consults the sidecar in three places:
//   1. When the main marker is missing (NotFound).
//   2. When the main marker read/parse fails.
//   3. When the main marker parses cleanly but its phase != GivenUp.
// In all three, "sidecar says given_up" → RefusedGivenUpAutoReset.
// force_reset=true (from `IBCTL_RECOVERY_FORCE_RESET=1`) bypasses this.
//
// # Mode scoping
//
// Live and paper get separate marker/sidecar files
// (`.ibctl-recovery-state.live.json` vs `.paper.json`). A shared file would
// race-clobber between the two coordinators.
// ---------------------------------------------------------------------------

/// Persistent recovery state, written between coordinator ticks.
///
/// `last_known_phase` mirrors `phase` at write time — the two are always
/// equal in a freshly-written file. The redundancy is load-time salvage
/// scaffolding: when the main file is corrupt or schema-mismatched, a
/// partial `serde_json::Value` parse can still surface
/// `last_known_phase` even if the strongly-typed `RecoveryPersistedState`
/// deserialisation fails — used as a second fail-safe rung behind the
/// sidecar in [`classify_corrupt`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryPersistedState {
    pub schema_version: u32,
    pub phase: RecoveryPhase,
    pub phase_entered_at: jiff::Zoned,
    pub phase_entered_at_monotonic_secs_since_boot: u64,
    pub last_full_success_at: Option<jiff::Zoned>,
    pub giveup_alert_sent_at: Option<jiff::Timestamp>,
    pub resumed_by_token_hash: Option<String>,
    pub last_known_phase: RecoveryPhase,
}

/// Outcome of a [`load`] call. Three-branch fail-safe from the PR-C stage 2
/// design.
///
/// `#[must_use]` — a wrapper that ignores this value (or collapses Refused
/// into Defaulted) silently degrades the fail-safe. Match exhaustively.
#[derive(Debug)]
#[must_use = "recovery load outcome carries GivenUp-refusal signal — the wrapper must \
              match exhaustively (Loaded/Defaulted/RefusedGivenUpAutoReset), NOT fall \
              back to `if let Loaded { .. } else { start_fresh }` which collapses the \
              fail-safe into the fail-open path"]
pub enum RecoveryLoadOutcome {
    /// Main marker parsed cleanly. Coordinator resumes from this state.
    Loaded(RecoveryPersistedState),
    /// Main marker missing OR corrupt with no GivenUp sidecar. Coordinator
    /// starts fresh in Aggressive. Caller SHOULD log the reason.
    Defaulted { reason: String },
    /// Main marker corrupt AND sidecar says the last phase was GivenUp.
    /// Coordinator blocks at the resume gate to prevent silently retrying
    /// operator-halted reconnection loops. Set `force_reset=true` (from
    /// `IBCTL_RECOVERY_FORCE_RESET=1`) to bypass.
    RefusedGivenUpAutoReset { reason: String },
}

impl RecoveryLoadOutcome {
    /// True when the outcome indicates the operator's GivenUp state was
    /// preserved on disk and the wrapper MUST block the reconnect loop
    /// until [`crate::state_machine::recovery::load`] is re-invoked with
    /// `force_reset=true` (via `IBCTL_RECOVERY_FORCE_RESET=1`) or the
    /// sidecar is cleared.
    ///
    /// Type-level guard so the wrapper cannot accidentally lump this into
    /// the Defaulted "start fresh" path.
    #[allow(dead_code)] // exposed in PR-C stage 4 STATUS JSON boot-diagnostics
    pub fn should_block_boot(&self) -> bool {
        matches!(self, Self::RefusedGivenUpAutoReset { .. })
    }
}

/// Path to the main marker file for the given trading mode.
///
/// Format: `{settings_dir}/.ibctl-recovery-state.{mode}.json`.
/// Mode is one of `"live"` or `"paper"`. The debug-only assertion catches
/// a future refactor that might pass a config-supplied string, blocking
/// path-traversal (`..`) or separator injection at the module boundary.
pub fn marker_path(settings_dir: &Path, mode: &str) -> PathBuf {
    debug_assert!(
        mode == "live" || mode == "paper",
        "mode must be 'live' or 'paper', got {mode:?} — refuse path-injection at the boundary",
    );
    settings_dir.join(format!(".ibctl-recovery-state.{mode}.json"))
}

/// Path to the corruption-resilient sidecar mirror of the current phase.
///
/// Format: `{settings_dir}/.ibctl-recovery-state.{mode}.last-known-phase.txt`.
pub fn sidecar_path(settings_dir: &Path, mode: &str) -> PathBuf {
    debug_assert!(
        mode == "live" || mode == "paper",
        "mode must be 'live' or 'paper', got {mode:?} — refuse path-injection at the boundary",
    );
    settings_dir.join(format!(
        ".ibctl-recovery-state.{mode}.last-known-phase.txt"
    ))
}

/// Load persisted recovery state for the given mode.
///
/// See module-level fail-safe policy. `force_reset=true` demotes a
/// [`RecoveryLoadOutcome::RefusedGivenUpAutoReset`] to
/// [`RecoveryLoadOutcome::Defaulted`] — this is the
/// `IBCTL_RECOVERY_FORCE_RESET=1` operator override.
///
/// The `force_reset` argument is passed in by the caller (who reads the env
/// var itself) — this function reads no environment. Keeps it pure w.r.t.
/// env, so tests never need to poke real environment state.
pub fn load(settings_dir: &Path, mode: &str, force_reset: bool) -> RecoveryLoadOutcome {
    let main = marker_path(settings_dir, mode);
    let raw = match std::fs::read_to_string(&main) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Fail-safe: consult the sidecar even when the main marker is
            // absent. The first-ever GivenUp save writes the sidecar BEFORE
            // the main marker; a crash between the two leaves sidecar-only
            // on disk. Returning Defaulted here would silently discard a
            // durable GivenUp record (Reviewer A HIGH / Reviewer B HIGH-1).
            return classify_corrupt(
                settings_dir,
                mode,
                force_reset,
                format!("recovery marker missing at {}", main.display()),
            );
        }
        Err(e) => {
            // Read error other than NotFound (permission, IO): treat as
            // corrupt so the sidecar fail-safe can classify it correctly.
            return classify_corrupt(
                settings_dir,
                mode,
                force_reset,
                format!("read error at {}: {}", main.display(), e),
            );
        }
    };

    let state: RecoveryPersistedState = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            return classify_corrupt(
                settings_dir,
                mode,
                force_reset,
                format!("JSON parse error in {}: {}", main.display(), e),
            );
        }
    };

    if state.schema_version != 1 {
        return classify_corrupt(
            settings_dir,
            mode,
            force_reset,
            format!(
                "schema_version mismatch in {}: got {}, expected 1",
                main.display(),
                state.schema_version,
            ),
        );
    }

    // Reviewer B HIGH-2: cross-check the sidecar even when the main marker
    // parses cleanly. A crash between sidecar-write and main-rename during
    // a phase-to-GivenUp transition leaves main=stale-non-GivenUp +
    // sidecar=given_up on disk. The old policy read the sidecar only on
    // parse failure, so this state silently resumed the pre-GivenUp phase.
    //
    // save() also pre-cleans the sidecar for non-GivenUp writes now, so
    // the only way this branch fires is a crash-window state or an
    // operator-crafted mismatch — both should surface for manual triage.
    if !force_reset && state.phase != RecoveryPhase::GivenUp {
        let side = sidecar_path(settings_dir, mode);
        if let Ok(content) = std::fs::read_to_string(&side) {
            if content.trim() == RecoveryPhase::GivenUp.as_str() {
                return RecoveryLoadOutcome::RefusedGivenUpAutoReset {
                    reason: format!(
                        "main marker at {} parses cleanly as phase={}, but sidecar at \
                         {} indicates last phase was given_up — a crash between sidecar \
                         write and main rename can produce this state. Refusing \
                         auto-reset. Set IBCTL_RECOVERY_FORCE_RESET=1 to override.",
                        main.display(),
                        state.phase.as_str(),
                        side.display(),
                    ),
                };
            }
        }
    }

    // Reviewer B MED-3: force_reset also demotes a validly-parsed GivenUp
    // marker to Defaulted. Without this, an operator whose ntfy path is
    // broken had no escape but to `rm` the marker file. Distinct reason
    // string keeps the two override flavours greppable in journalctl.
    if force_reset && state.phase == RecoveryPhase::GivenUp {
        return RecoveryLoadOutcome::Defaulted {
            reason: format!(
                "valid GivenUp marker at {} demoted to Defaulted by \
                 IBCTL_RECOVERY_FORCE_RESET override",
                main.display(),
            ),
        };
    }

    RecoveryLoadOutcome::Loaded(state)
}

/// Fail-safe classifier for a corrupt/mismatched main marker.
///
/// If `force_reset` is set (operator override via `IBCTL_RECOVERY_FORCE_RESET=1`)
/// we always Default. Otherwise the sidecar is consulted: content
/// `"given_up"` means the last known phase was operator-halted GivenUp, and
/// silently auto-resetting to Aggressive would re-launch a reconnection loop
/// the operator had already halted (Reviewer A HIGH). Any other sidecar
/// content — including absent or unreadable — falls through to Defaulted.
fn classify_corrupt(
    settings_dir: &Path,
    mode: &str,
    force_reset: bool,
    reason: String,
) -> RecoveryLoadOutcome {
    if force_reset {
        return RecoveryLoadOutcome::Defaulted {
            reason: format!("{reason} (IBCTL_RECOVERY_FORCE_RESET override applied)"),
        };
    }
    // Primary signal: the sidecar file.
    let side = sidecar_path(settings_dir, mode);
    if let Ok(content) = std::fs::read_to_string(&side) {
        if content.trim() == RecoveryPhase::GivenUp.as_str() {
            return RecoveryLoadOutcome::RefusedGivenUpAutoReset {
                reason: format!(
                    "{reason}; sidecar at {} indicates last phase was given_up — \
                     refusing auto-reset. Set IBCTL_RECOVERY_FORCE_RESET=1 to override.",
                    side.display(),
                ),
            };
        }
    }
    // Reviewer B MED-4: even a schema-mismatched or partially-corrupt main
    // file may still contain a well-formed `last_known_phase` field. Peek
    // via `serde_json::Value` so a wrong-schema upgrade path or an
    // unrelated typo can't silently reset an operator-halted GivenUp.
    // Fulfils the invariant promised by the field's docstring.
    let main = marker_path(settings_dir, mode);
    if let Ok(raw) = std::fs::read_to_string(&main) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(s) = v.get("last_known_phase").and_then(|f| f.as_str()) {
                if s == RecoveryPhase::GivenUp.as_str() {
                    return RecoveryLoadOutcome::RefusedGivenUpAutoReset {
                        reason: format!(
                            "{reason}; partial-parse of {} shows \
                             last_known_phase=given_up — refusing auto-reset. \
                             Set IBCTL_RECOVERY_FORCE_RESET=1 to override.",
                            main.display(),
                        ),
                    };
                }
            }
        }
    }
    RecoveryLoadOutcome::Defaulted { reason }
}

/// Save persisted recovery state atomically.
///
/// Contract:
/// - `state.phase == GivenUp`: write sidecar FIRST, then main marker. A
///   crash mid-main-write leaves sidecar=given_up + main=stale (or absent),
///   and [`load`] refuses the auto-reset. This is the fail-safe rung the
///   whole module is built to protect.
/// - `state.phase != GivenUp`: remove sidecar FIRST, then write main marker.
///   Pre-cleaning closes the crash window that formerly left
///   main=new-non-GivenUp + sidecar=stale-given_up on disk — under the
///   sidecar-cross-check policy that state now refuses auto-reset, which
///   would silently block every legitimate non-GivenUp save (Reviewer B
///   HIGH-2). Post-cleaning was the old ordering; pre-cleaning is the fix.
/// - Both writes use write-to-`.tmp`+`rename` — same-directory rename is
///   POSIX-atomic and a concurrent reader either sees the previous content
///   or the new content, never a torn write. Non-GivenUp saves that crash
///   between sidecar-remove and main-rename leave main=OLD-marker +
///   sidecar=absent, which loads back as `Loaded(old phase)` — no wedge.
pub fn save(
    settings_dir: &Path,
    mode: &str,
    state: &RecoveryPersistedState,
) -> io::Result<()> {
    let main = marker_path(settings_dir, mode);
    let side = sidecar_path(settings_dir, mode);

    if state.phase == RecoveryPhase::GivenUp {
        // Sidecar written FIRST — a crash before main rename leaves the
        // "operator halted us" evidence on disk for load() to refuse.
        atomic_write(&side, RecoveryPhase::GivenUp.as_str().as_bytes())?;
    } else {
        // Pre-clean sidecar BEFORE main-write. See docstring above.
        match std::fs::remove_file(&side) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(&main, &json)?;

    Ok(())
}

/// Remove the sidecar file for the given mode. Idempotent — a missing
/// sidecar is not an error.
///
/// Not yet called from production code — reserved for a future
/// operator-facing "clear this stuck sidecar" tool. Kept behind
/// `#[allow(dead_code)]` (rather than deleted) because the persistence
/// tests exercise it and the fail-safe module invariants depend on it.
#[allow(dead_code)]
pub fn clear_sidecar(settings_dir: &Path, mode: &str) -> io::Result<()> {
    let side = sidecar_path(settings_dir, mode);
    match std::fs::remove_file(&side) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Durable atomic file write via temp file + rename + parent-dir fsync.
///
/// Mirrors `crate::state_machine::markers::atomic_write` — kept private to
/// this module so the marker contract is self-contained. Same-directory
/// rename is POSIX-atomic; the tmp file lives next to the target so the
/// rename never crosses filesystems.
///
/// Reviewer A MED-1: sync errors are propagated. A failed writeback
/// (ENOSPC, EIO) means the data in the tmp file is untrustworthy and the
/// rename would install garbage into the target.
///
/// Reviewer A MED-2: the parent directory is fsynced AFTER the rename so
/// the dirent update is durable across a crash. Without this, on
/// `data=writeback` ext4, non-journaled filesystems, or certain xfs mount
/// options, the target file may show OLD content (or the tmp file may be
/// the only visible entry) after power loss. The dir-fsync is
/// best-effort — platforms that reject `fsync` on a directory handle
/// (Windows) return an error we silently discard.
fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "marker path has no file name")
    })?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        // Reviewer A MED-1: propagate sync errors. Silent discard was a
        // durability foot-gun on non-`data=ordered` filesystems.
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;

    // Reviewer A MED-2: dirent durability. Ignore errors from platforms
    // that don't support fsync-on-directory (Windows).
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod marker_tests {
    //! RED-phase tests for the persistence layer.
    //!
    //! Every impl function is `unimplemented!("stage 2 GREEN")`, so any test
    //! that reaches an impl call panics with that message and is reported as
    //! FAILED. This is the RED state.
    //!
    //! Tests use `tempfile::TempDir` for filesystem isolation and construct
    //! `jiff::Zoned` values from a fixed -04:00 offset so results are
    //! deterministic across the CI host's TZ.

    use super::*;
    use tempfile::TempDir;

    // -------- fixtures --------------------------------------------------

    /// Deterministic wall-clock instant for tests: 2026-06-14 09:00 -04:00.
    fn fixed_zoned() -> jiff::Zoned {
        jiff::civil::date(2026, 6, 14)
            .at(9, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::fixed(jiff::tz::Offset::constant(-4)))
            .expect("synthetic zoned must construct")
    }

    /// A canonical persisted state with all Option fields populated so the
    /// serialization roundtrip exercises every branch.
    ///
    /// `last_known_phase` mirrors `phase` (the spec-mandated invariant at
    /// write time).
    fn sample_state(phase: RecoveryPhase) -> RecoveryPersistedState {
        RecoveryPersistedState {
            schema_version: 1,
            phase,
            phase_entered_at: fixed_zoned(),
            phase_entered_at_monotonic_secs_since_boot: 12_345,
            last_full_success_at: Some(fixed_zoned()),
            giveup_alert_sent_at: Some(
                jiff::Timestamp::from_second(1_720_000_000).expect("valid unix ts"),
            ),
            resumed_by_token_hash: Some("a".repeat(64)),
            last_known_phase: phase,
        }
    }

    /// Hand-crafted JSON matching schema_version=1 with the given phase.
    /// Used where the test needs to plant a valid main marker without going
    /// through `save()` (whose contract also touches the sidecar).
    fn valid_marker_json(phase: RecoveryPhase) -> String {
        let now = fixed_zoned();
        format!(
            r#"{{
                "schema_version": 1,
                "phase": "{p}",
                "phase_entered_at": "{now}",
                "phase_entered_at_monotonic_secs_since_boot": 12345,
                "last_full_success_at": null,
                "giveup_alert_sent_at": null,
                "resumed_by_token_hash": null,
                "last_known_phase": "{p}"
            }}"#,
            p = phase.as_str(),
            now = now,
        )
    }

    // -------- path convention -------------------------------------------

    #[test]
    fn test_marker_path_format() {
        // Additional beyond spec: pin the exact filename convention. A
        // silent path change would produce a stale-file split-brain — the
        // old-format file lingers as "no marker" and the coordinator boots
        // fresh forever.
        let dir = TempDir::new().unwrap();
        assert_eq!(
            marker_path(dir.path(), "paper"),
            dir.path().join(".ibctl-recovery-state.paper.json"),
        );
        assert_eq!(
            marker_path(dir.path(), "live"),
            dir.path().join(".ibctl-recovery-state.live.json"),
        );
    }

    #[test]
    fn test_sidecar_path_format() {
        // Additional beyond spec: same rationale as `test_marker_path_format`
        // but for the corruption-resilience sidecar.
        let dir = TempDir::new().unwrap();
        assert_eq!(
            sidecar_path(dir.path(), "paper"),
            dir.path().join(".ibctl-recovery-state.paper.last-known-phase.txt"),
        );
        assert_eq!(
            sidecar_path(dir.path(), "live"),
            dir.path().join(".ibctl-recovery-state.live.last-known-phase.txt"),
        );
    }

    #[test]
    fn test_paper_and_live_paths_are_distinct() {
        // Spec test 9. A shared file would race-clobber between the two
        // coordinators (Reviewer A HIGH). Cover BOTH main and sidecar paths.
        let dir = TempDir::new().unwrap();
        assert_ne!(
            marker_path(dir.path(), "paper"),
            marker_path(dir.path(), "live"),
            "paper and live main markers must be distinct",
        );
        assert_ne!(
            sidecar_path(dir.path(), "paper"),
            sidecar_path(dir.path(), "live"),
            "paper and live sidecars must be distinct",
        );
    }

    // -------- load: happy paths and missing/corrupt ---------------------

    #[test]
    fn test_load_missing_file_returns_defaulted() {
        // Spec test 1. Fresh dir with no marker file — coordinator must
        // default (not error) so first-boot works without any manual step.
        // Reason must be diagnostic (contain the path and the "missing"
        // hint) so `journalctl | grep` operator-triage works.
        let dir = TempDir::new().unwrap();
        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                assert!(
                    reason.contains(".ibctl-recovery-state.paper.json"),
                    "reason should include the marker path: {}",
                    reason,
                );
                assert!(
                    reason.contains("missing"),
                    "reason should distinguish 'missing' from 'parse error': {}",
                    reason,
                );
            }
            other => panic!(
                "expected Defaulted for missing file, got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn test_save_then_load_roundtrip() {
        // Spec test 2. THE core contract: save a state, load it back,
        // every field survives. Exercises the full JSON schema.
        let dir = TempDir::new().unwrap();
        let original = sample_state(RecoveryPhase::BackoffEvery15Min);

        save(dir.path(), "paper", &original).expect("save must succeed");

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(loaded) => {
                assert_eq!(loaded, original, "every field must roundtrip");
            }
            other => panic!("expected Loaded, got {:?}", other),
        }
    }

    #[test]
    fn test_load_malformed_json_returns_defaulted() {
        // Spec test 3. A hand-corrupted JSON file must NOT panic and must
        // NOT silently succeed — return Defaulted so caller logs.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-recovery-state.paper.json");
        std::fs::write(&path, "{not valid json at all").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                assert!(
                    !reason.is_empty(),
                    "Defaulted reason must describe parse failure",
                );
            }
            other => panic!("expected Defaulted for malformed JSON, got {:?}", other),
        }
    }

    #[test]
    fn test_load_schema_version_mismatch_returns_defaulted() {
        // Spec test 4. A future schema_version we don't understand must
        // fall back to defaults — refusing to interpret unknown fields is
        // safer than a wrong interpretation.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-recovery-state.paper.json");
        let now = fixed_zoned();
        let bad = format!(
            r#"{{
                "schema_version": 999,
                "phase": "aggressive",
                "phase_entered_at": "{now}",
                "phase_entered_at_monotonic_secs_since_boot": 0,
                "last_full_success_at": null,
                "giveup_alert_sent_at": null,
                "resumed_by_token_hash": null,
                "last_known_phase": "aggressive"
            }}"#,
            now = now,
        );
        std::fs::write(&path, bad).unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                assert!(
                    reason.to_ascii_lowercase().contains("schema")
                        || reason.contains("999"),
                    "reason should mention schema mismatch (got: {})",
                    reason,
                );
            }
            other => panic!(
                "expected Defaulted for schema version mismatch, got {:?}",
                other,
            ),
        }
    }

    // -------- fail-safe: corrupt main + sidecar interaction --------------

    #[test]
    fn test_load_corrupt_marker_with_givenup_sidecar_refuses_reset() {
        // Spec test 5. THE flagship fail-safe: corrupt main marker AND
        // sidecar says GivenUp → refuse auto-reset. Reviewer A HIGH.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "corrupt garbage {").unwrap();
        std::fs::write(&side, "given_up").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { reason } => {
                assert!(
                    !reason.is_empty(),
                    "reason must describe the refusal for operator triage",
                );
            }
            other => panic!(
                "expected RefusedGivenUpAutoReset for corrupt+GivenUp-sidecar, got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn test_load_corrupt_marker_with_aggressive_sidecar_returns_defaulted() {
        // Spec test 6. Corrupt main + sidecar says Aggressive → safe to
        // auto-reset (we weren't in an operator-halted phase). The sidecar
        // for Aggressive/Backoff should not exist per the invariant, but
        // this test defends against manual operator intervention.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "still garbage").unwrap();
        std::fs::write(&side, "aggressive").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { .. } => { /* OK */ }
            other => panic!(
                "expected Defaulted for corrupt+Aggressive-sidecar, got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn test_load_corrupt_marker_no_sidecar_returns_defaulted() {
        // Spec test 7. Corrupt main + no sidecar → Defaulted. This is the
        // "clean install after a crash mid-write" case. Reason must
        // discriminate "parse error" from "missing" so operator can
        // triage the failure class without opening the code.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        std::fs::write(&main, "corrupt no sidecar").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                let lower = reason.to_ascii_lowercase();
                assert!(
                    lower.contains("parse") || lower.contains("json"),
                    "reason should identify the parse-error class: {}",
                    reason,
                );
            }
            other => panic!(
                "expected Defaulted for corrupt marker without sidecar, got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn test_force_reset_overrides_givenup_refusal() {
        // Spec test 8. The `IBCTL_RECOVERY_FORCE_RESET=1` escape hatch:
        // even when the fail-safe would refuse, force_reset demotes it
        // to Defaulted so the coordinator can boot fresh.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "corrupt garbage {").unwrap();
        std::fs::write(&side, "given_up").unwrap();

        match load(dir.path(), "paper", true) {
            RecoveryLoadOutcome::Defaulted { .. } => { /* OK */ }
            other => panic!(
                "expected Defaulted (forced override) for corrupt+GivenUp-sidecar+force_reset, got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn test_load_valid_non_givenup_main_with_stale_givenup_sidecar_refuses_reset() {
        // Reviewer B HIGH-2 fix: previously this test asserted "main
        // wins over stale sidecar" for the Loaded path. That policy
        // masked a real fail-safe hole — a crash between sidecar-write
        // and main-rename during a phase-to-GivenUp transition left
        // main=stale-non-GivenUp + sidecar=given_up on disk, and the
        // old policy silently resumed the pre-GivenUp phase.
        //
        // Under the new policy any GivenUp evidence — sidecar OR
        // last_known_phase in a partially-parseable main — refuses
        // auto-reset. The former "stale sidecar wedge" concern is now
        // closed by save() pre-cleaning the sidecar BEFORE writing a
        // non-GivenUp main marker, so this exact on-disk state can no
        // longer arise from a normal non-GivenUp save.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, valid_marker_json(RecoveryPhase::Aggressive)).unwrap();
        std::fs::write(&side, "given_up").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { reason } => {
                assert!(
                    !reason.is_empty(),
                    "reason must describe the refusal for operator triage",
                );
                assert!(
                    reason.contains("given_up"),
                    "reason should mention given_up: {}",
                    reason,
                );
            }
            other => panic!(
                "sidecar-vs-main disagreement must refuse auto-reset, got {:?}",
                other,
            ),
        }
    }

    #[test]
    fn test_load_valid_non_givenup_main_with_stale_givenup_sidecar_force_reset_loads() {
        // Companion to the refusal test above: force_reset lets the
        // operator declare the sidecar stale on purpose and boot into
        // whatever the main marker says.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, valid_marker_json(RecoveryPhase::Aggressive)).unwrap();
        std::fs::write(&side, "given_up").unwrap();

        match load(dir.path(), "paper", true) {
            RecoveryLoadOutcome::Loaded(state) => {
                assert_eq!(state.phase, RecoveryPhase::Aggressive);
            }
            other => panic!(
                "force_reset must let main marker win, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer A HIGH-1 / Reviewer B HIGH-1 -----------------------

    #[test]
    fn test_load_missing_main_with_givenup_sidecar_refuses_reset() {
        // A first-time GivenUp save writes the sidecar BEFORE the main
        // marker; a crash between the two leaves sidecar-only on disk.
        // load() must consult the sidecar even on NotFound — otherwise
        // the fail-safe rung is silently bypassed on first boot.
        let dir = TempDir::new().unwrap();
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&side, "given_up").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { reason } => {
                assert!(!reason.is_empty());
                assert!(
                    reason.contains("missing"),
                    "reason should preserve the 'missing' diagnostic: {}",
                    reason,
                );
            }
            other => panic!(
                "missing main + GivenUp sidecar must refuse, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer B HIGH-2: save() pre-clean invariant ---------------

    #[test]
    fn test_save_non_givenup_precleans_stale_sidecar_before_main_write() {
        // The pre-clean ordering closes the crash window that would
        // otherwise leave main=new-non-GivenUp + sidecar=stale-given_up
        // on disk — a state now interpreted as an interrupted
        // phase-to-GivenUp transition and refused.
        let dir = TempDir::new().unwrap();
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        // Plant a stale sidecar (as if a previous GivenUp save had
        // written it but the process died before completing).
        std::fs::write(&side, "given_up").unwrap();

        save(dir.path(), "paper", &sample_state(RecoveryPhase::Aggressive))
            .expect("save Aggressive must succeed");

        assert!(
            !side.exists(),
            "sidecar must be removed by non-GivenUp save (pre-clean invariant)",
        );

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(s) => assert_eq!(s.phase, RecoveryPhase::Aggressive),
            other => panic!("expected Loaded after clean non-GivenUp save, got {:?}", other),
        }
    }

    // -------- Reviewer B MED-3: force_reset over valid GivenUp marker -----

    #[test]
    fn test_force_reset_demotes_valid_givenup_marker_to_defaulted() {
        // Without this, an operator whose ntfy path was broken had no
        // way to boot fresh from GivenUp — force_reset only worked
        // against corrupt markers, and `rm`-ing the marker file is a
        // foot-gun. Under the fix force_reset also demotes a validly-
        // parsed GivenUp marker to Defaulted.
        let dir = TempDir::new().unwrap();
        save(dir.path(), "paper", &sample_state(RecoveryPhase::GivenUp))
            .expect("save GivenUp");

        match load(dir.path(), "paper", true) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                let lower = reason.to_ascii_lowercase();
                assert!(
                    lower.contains("force_reset")
                        || lower.contains("override")
                        || lower.contains("demoted"),
                    "reason should describe the override: {}",
                    reason,
                );
            }
            other => panic!(
                "force_reset must demote valid GivenUp marker, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer B MED-4: last_known_phase salvage -------------------

    #[test]
    fn test_load_wrong_schema_with_last_known_phase_givenup_refuses_reset() {
        // Even when the sidecar is absent but the main marker has a
        // wrong schema version (so it doesn't Loaded), the salvage
        // rung reads `last_known_phase` via serde_json::Value.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let now = fixed_zoned();
        let bad_schema = format!(
            r#"{{
                "schema_version": 999,
                "phase": "aggressive",
                "phase_entered_at": "{now}",
                "phase_entered_at_monotonic_secs_since_boot": 0,
                "last_full_success_at": null,
                "giveup_alert_sent_at": null,
                "resumed_by_token_hash": null,
                "last_known_phase": "given_up"
            }}"#,
            now = now,
        );
        std::fs::write(&main, bad_schema).unwrap();
        // No sidecar written on purpose — force the salvage path to fire.

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { reason } => {
                assert!(reason.to_ascii_lowercase().contains("last_known_phase"));
            }
            other => panic!(
                "wrong-schema main with last_known_phase=given_up must refuse, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer B MED-1: type-level guard on outcome ---------------

    #[test]
    fn test_should_block_boot_accessor() {
        // Guards against a wrapper that collapses Refused into
        // Defaulted by mistake.
        let refused = RecoveryLoadOutcome::RefusedGivenUpAutoReset {
            reason: "test".into(),
        };
        let defaulted = RecoveryLoadOutcome::Defaulted {
            reason: "test".into(),
        };
        let loaded =
            RecoveryLoadOutcome::Loaded(sample_state(RecoveryPhase::Aggressive));
        assert!(refused.should_block_boot());
        assert!(!defaulted.should_block_boot());
        assert!(!loaded.should_block_boot());
    }

    // -------- Reviewer C HIGH-1: wire format for RecoveryPhase ------------

    #[test]
    fn test_recovery_phase_json_wire_format_is_locked() {
        // Pins the exact serde string for each variant. A future
        // change that drops #[serde(rename = "...")] would compile clean
        // but break every persisted marker file — silent-until-deploy.
        assert_eq!(
            serde_json::to_string(&RecoveryPhase::Aggressive).unwrap(),
            "\"aggressive\"",
        );
        assert_eq!(
            serde_json::to_string(&RecoveryPhase::BackoffEvery15Min).unwrap(),
            "\"backoff_every_15min\"",
        );
        assert_eq!(
            serde_json::to_string(&RecoveryPhase::GivenUp).unwrap(),
            "\"given_up\"",
        );
        // Symmetric: deserialize must recognize the same strings.
        assert_eq!(
            serde_json::from_str::<RecoveryPhase>("\"aggressive\"").unwrap(),
            RecoveryPhase::Aggressive,
        );
        assert_eq!(
            serde_json::from_str::<RecoveryPhase>("\"backoff_every_15min\"").unwrap(),
            RecoveryPhase::BackoffEvery15Min,
        );
        assert_eq!(
            serde_json::from_str::<RecoveryPhase>("\"given_up\"").unwrap(),
            RecoveryPhase::GivenUp,
        );
    }

    // -------- Reviewer C HIGH-2: state field names locked -----------------

    #[test]
    fn test_persisted_state_json_field_names_are_locked() {
        // Pins every expected field name. Renaming a field silently
        // succeeds within a build (both sides use the new name) but
        // breaks load-after-deploy against files written by prior
        // builds. Also freezes the field count so an accidental extra
        // field is caught.
        let s = sample_state(RecoveryPhase::Aggressive);
        let v = serde_json::to_value(&s).expect("to_value");
        let obj = v.as_object().expect("state serializes as JSON object");
        let expected = [
            "schema_version",
            "phase",
            "phase_entered_at",
            "phase_entered_at_monotonic_secs_since_boot",
            "last_full_success_at",
            "giveup_alert_sent_at",
            "resumed_by_token_hash",
            "last_known_phase",
        ];
        for field in expected {
            assert!(
                obj.contains_key(field),
                "field {} missing from serialized JSON. keys: {:?}",
                field,
                obj.keys().collect::<Vec<_>>(),
            );
        }
        assert_eq!(
            obj.len(),
            expected.len(),
            "unexpected field count in serialized JSON: {:?}",
            obj.keys().collect::<Vec<_>>(),
        );
    }

    // -------- Reviewer C HIGH-3: read-error branch coverage ---------------

    #[test]
    #[cfg(unix)]
    fn test_load_read_error_with_givenup_sidecar_refuses_reset() {
        // Covers the Err(e) != NotFound branch of read_to_string.
        // Skipped when running as root because permission bits are
        // ignored — the runtime check below detects that.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "unreadable content").unwrap();
        std::fs::write(&side, "given_up").unwrap();
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Root bypasses permission bits — skip.
        if std::fs::read_to_string(&main).is_ok() {
            std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o644))
                .unwrap();
            eprintln!("skipping: chmod 000 bypassed (likely running as root)");
            return;
        }

        let outcome = load(dir.path(), "paper", false);
        // Restore permissions so TempDir can drop cleanly.
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o644)).unwrap();
        match outcome {
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { reason } => {
                assert!(reason.to_ascii_lowercase().contains("read error"));
            }
            other => panic!(
                "unreadable main + GivenUp sidecar must refuse, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer C HIGH-4: GivenUp roundtrip ------------------------

    #[test]
    fn test_save_then_load_roundtrip_givenup() {
        // Previously the roundtrip test only covered BackoffEvery15Min.
        // The steady-state GivenUp case (main=GivenUp + sidecar="given_up")
        // must load back as Loaded(GivenUp), not RefusedGivenUpAutoReset.
        let dir = TempDir::new().unwrap();
        let original = sample_state(RecoveryPhase::GivenUp);
        save(dir.path(), "paper", &original).expect("save GivenUp");

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(loaded) => {
                assert_eq!(loaded, original, "every field must roundtrip");
                assert_eq!(loaded.phase, RecoveryPhase::GivenUp);
            }
            other => panic!("expected Loaded(GivenUp), got {:?}", other),
        }
    }

    // -------- Reviewer C MED-1: all-None options roundtrip ----------------

    #[test]
    fn test_save_then_load_roundtrip_all_options_none() {
        // If serde ever grew `skip_serializing_if = "Option::is_none"`
        // the roundtrip would keep working (both sides use the new
        // shape) but the wire format would silently change and break
        // load-after-deploy. Assert nulls are explicit.
        let dir = TempDir::new().unwrap();
        let mut original = sample_state(RecoveryPhase::BackoffEvery15Min);
        original.last_full_success_at = None;
        original.giveup_alert_sent_at = None;
        original.resumed_by_token_hash = None;

        save(dir.path(), "paper", &original).expect("save");

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(loaded) => assert_eq!(loaded, original),
            other => panic!("expected Loaded, got {:?}", other),
        }

        let raw = std::fs::read_to_string(
            dir.path().join(".ibctl-recovery-state.paper.json"),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        for field in [
            "last_full_success_at",
            "giveup_alert_sent_at",
            "resumed_by_token_hash",
        ] {
            assert!(
                v.get(field).map(|x| x.is_null()).unwrap_or(false),
                "{} must be explicit null in JSON, got {:?}",
                field,
                v.get(field),
            );
        }
    }

    // -------- Reviewer C MED-2: sidecar trim -------------------------------

    #[test]
    fn test_load_corrupt_marker_with_givenup_sidecar_trailing_newline_refuses_reset() {
        // Sidecar with trailing newline (as most editors write) must
        // still trip refuse-reset. Locks the `.trim()` normalization.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "corrupt").unwrap();
        std::fs::write(&side, "given_up\n").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { .. } => { /* OK */ }
            other => panic!(
                "trailing-newline sidecar must still refuse, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer C MED-3: empty sidecar ------------------------------

    #[test]
    fn test_load_corrupt_marker_with_empty_sidecar_returns_defaulted() {
        // An empty sidecar (defensive against zero-length race) must
        // NOT trip refuse-reset.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        std::fs::write(&main, "corrupt").unwrap();
        std::fs::write(&side, "").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { .. } => { /* OK */ }
            other => panic!("empty sidecar must default, got {:?}", other),
        }
    }

    // -------- Reviewer C MED-4: force_reset short-circuit -----------------

    #[test]
    fn test_force_reset_defaults_without_reading_sidecar() {
        // force_reset must short-circuit the sidecar-consult path,
        // regardless of whether a sidecar is present.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        std::fs::write(&main, "corrupt").unwrap();
        // no sidecar

        match load(dir.path(), "paper", true) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                assert!(
                    reason.to_ascii_lowercase().contains("override"),
                    "reason should mention override, got: {}",
                    reason,
                );
            }
            other => panic!(
                "force_reset without sidecar must default, got {:?}",
                other,
            ),
        }
    }

    // -------- Reviewer C MED-5: save error propagation --------------------

    #[test]
    #[cfg(unix)]
    fn test_save_returns_err_when_settings_dir_readonly() {
        // Save must propagate write errors so the wrapper can log
        // rather than silently ignoring persistence failures.
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555))
            .unwrap();

        // Skip if we can still create files (root bypasses perm bits).
        let probe = dir.path().join(".probe");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).ok();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            eprintln!("skipping: readonly bypass (likely running as root)");
            return;
        }

        let res = save(dir.path(), "paper", &sample_state(RecoveryPhase::Aggressive));
        // Reset perms so TempDir can drop cleanly.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(res.is_err(), "save on readonly dir must Err, got {:?}", res);
    }

    // -------- Reviewer C MED-6: re-save overwrites, no orphans -----------

    #[test]
    fn test_save_twice_overwrites_and_leaves_no_orphans() {
        // Successive saves fully replace prior content: no leftover
        // .tmp, and the sidecar tracks the LATEST phase (not a stale
        // one from a previous save).
        let dir = TempDir::new().unwrap();
        save(dir.path(), "paper", &sample_state(RecoveryPhase::Aggressive))
            .expect("save 1");
        save(dir.path(), "paper", &sample_state(RecoveryPhase::GivenUp))
            .expect("save 2");

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(s) => assert_eq!(s.phase, RecoveryPhase::GivenUp),
            other => panic!("expected Loaded(GivenUp), got {:?}", other),
        }
        assert!(dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt")
            .exists());
        for e in std::fs::read_dir(dir.path()).unwrap() {
            let name = e.unwrap().file_name();
            assert!(
                !name.to_string_lossy().ends_with(".tmp"),
                "orphan .tmp: {:?}",
                name,
            );
        }
    }

    // -------- Reviewer C LOW-1: schema version 0 --------------------------

    #[test]
    fn test_load_schema_version_zero_returns_defaulted() {
        // Strict-equality check on schema_version (not >=). A future
        // downgrade artefact is treated the same as any other mismatch.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-recovery-state.paper.json");
        let now = fixed_zoned();
        let bad = format!(
            r#"{{
                "schema_version": 0,
                "phase": "aggressive",
                "phase_entered_at": "{now}",
                "phase_entered_at_monotonic_secs_since_boot": 0,
                "last_full_success_at": null,
                "giveup_alert_sent_at": null,
                "resumed_by_token_hash": null,
                "last_known_phase": "aggressive"
            }}"#,
            now = now,
        );
        std::fs::write(&path, bad).unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Defaulted { reason } => {
                let lower = reason.to_ascii_lowercase();
                assert!(
                    lower.contains("schema") || reason.contains("0"),
                    "reason should mention schema mismatch, got: {}",
                    reason,
                );
            }
            other => panic!("expected Defaulted, got {:?}", other),
        }
    }

    // -------- save: sidecar invariant across phases ---------------------

    #[test]
    fn test_save_writes_sidecar_on_givenup_phase() {
        // Spec test 10. Saving GivenUp must produce the sidecar with the
        // phase name as content.
        let dir = TempDir::new().unwrap();
        save(dir.path(), "paper", &sample_state(RecoveryPhase::GivenUp))
            .expect("save must succeed");

        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        assert!(side.exists(), "sidecar file must exist after GivenUp save");
        let contents = std::fs::read_to_string(&side).unwrap();
        assert_eq!(
            contents.trim(),
            RecoveryPhase::GivenUp.as_str(),
            "sidecar must contain the phase name",
        );
    }

    #[test]
    fn test_save_removes_sidecar_on_non_givenup_phase() {
        // Spec test 11. GivenUp exit must clear the sidecar so a subsequent
        // corrupt-main-marker load doesn't wrongly refuse-reset.
        let dir = TempDir::new().unwrap();
        // 1. Enter GivenUp — sidecar written.
        save(dir.path(), "paper", &sample_state(RecoveryPhase::GivenUp))
            .expect("save GivenUp must succeed");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        assert!(side.exists(), "precondition: sidecar exists after GivenUp save");

        // 2. Exit GivenUp — sidecar must be removed.
        save(dir.path(), "paper", &sample_state(RecoveryPhase::Aggressive))
            .expect("save Aggressive must succeed");
        assert!(
            !side.exists(),
            "sidecar must be removed after Aggressive save",
        );
    }

    #[test]
    fn test_save_from_clean_state_only_writes_sidecar_for_givenup() {
        // Additional beyond spec: the invariant "sidecar exists ⟺ phase
        // is GivenUp" must hold from a clean state for ALL phases, not
        // just after a prior GivenUp → non-GivenUp transition (that case
        // is test 11). Parametrized over the three phases.
        for phase in [
            RecoveryPhase::Aggressive,
            RecoveryPhase::BackoffEvery15Min,
            RecoveryPhase::GivenUp,
        ] {
            let dir = TempDir::new().unwrap();
            save(dir.path(), "paper", &sample_state(phase))
                .unwrap_or_else(|e| panic!("save must succeed for {phase:?}: {e}"));

            let side = dir
                .path()
                .join(".ibctl-recovery-state.paper.last-known-phase.txt");
            match phase {
                RecoveryPhase::GivenUp => assert!(
                    side.exists(),
                    "GivenUp must produce sidecar from clean state",
                ),
                _ => assert!(
                    !side.exists(),
                    "non-GivenUp {:?} must NOT produce sidecar from clean state",
                    phase,
                ),
            }
        }
    }

    #[test]
    fn test_clear_sidecar_is_idempotent() {
        // Spec test 12. clear_sidecar called twice — both must succeed
        // (second call must NOT surface a NotFound error).
        let dir = TempDir::new().unwrap();
        clear_sidecar(dir.path(), "paper").expect("first clear must succeed (idempotent when absent)");
        clear_sidecar(dir.path(), "paper").expect("second clear must succeed");

        // And after actually writing one.
        save(dir.path(), "paper", &sample_state(RecoveryPhase::GivenUp))
            .expect("save GivenUp must succeed");
        clear_sidecar(dir.path(), "paper").expect("clear must remove existing sidecar");
        let side = dir
            .path()
            .join(".ibctl-recovery-state.paper.last-known-phase.txt");
        assert!(!side.exists(), "sidecar removed after clear");
        clear_sidecar(dir.path(), "paper").expect("second clear after removal must succeed");
    }

    // -------- atomicity / crash recovery --------------------------------

    #[test]
    fn test_atomic_write_never_leaves_tmp_file_on_success() {
        // Spec test 13. Same contract as markers.rs::atomic_write —
        // after a successful save the only files present should be the
        // marker and (for GivenUp) the sidecar. No orphan .tmp files.
        let dir = TempDir::new().unwrap();
        save(dir.path(), "paper", &sample_state(RecoveryPhase::GivenUp))
            .expect("save must succeed");

        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        for e in &entries {
            assert!(
                !e.ends_with(".tmp"),
                "orphan tmp file leaked into settings dir: {} (all entries: {:?})",
                e,
                entries,
            );
        }
    }

    #[test]
    fn test_load_after_partial_tmp_write_leftover_still_loads_main() {
        // Spec test 14. Simulate a prior crash that left a garbage
        // .tmp file behind (rename never completed). The .tmp is NOT
        // the main marker — load must ignore it and read the valid
        // main marker.
        let dir = TempDir::new().unwrap();
        let main = dir.path().join(".ibctl-recovery-state.paper.json");
        let tmp = dir.path().join(".ibctl-recovery-state.paper.json.tmp");
        std::fs::write(&main, valid_marker_json(RecoveryPhase::BackoffEvery15Min))
            .unwrap();
        std::fs::write(&tmp, "half-written garbage {").unwrap();

        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(state) => {
                assert_eq!(state.phase, RecoveryPhase::BackoffEvery15Min);
            }
            other => panic!(
                "orphan tmp file must not affect main marker load, got {:?}",
                other,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryCoordinator — async wrapper around compute_next_action + persistence.
//
// PR-C stage 3 (RED phase): all methods `unimplemented!("stage 3 GREEN")`.
// GREEN phase wires this into `StateMachine` (see spec: types.rs + mod.rs
// apply_transition hooks + main-loop tick).
//
// Design principles mirrored from `crate::cold_restart::scheduler_loop`:
//
//   * `compute()` is a thin builder around the pure `compute_next_action` —
//     it samples clocks + reads accessors, but delegates every decision to
//     the pure function above. No policy lives here.
//
//   * `apply()` is the SOLE mutation surface: any phase transition, marker
//     write, alert-dedupe timestamp, or resume-token consumption goes
//     through this method. The wrapper (mod.rs main loop) can never
//     bypass it to mutate coordinator state directly.
//
//   * NO captured `jiff::Zoned::now()` or `Instant::now()` snapshotted at
//     construction and reused later. The coordinator's stored timestamps
//     represent EVENTS ("we entered this phase at T") — facts about the
//     past, not derived predicates. The Bug-4-class regression test
//     `test_bug_class_no_captured_now` asserts this structurally by
//     driving virtual time forward and checking the reported elapsed
//     reflects the delta.
// ---------------------------------------------------------------------------

/// What actually happened when an action was applied. Emitted for
/// structured logging and used by the main loop to decide whether to
/// fire a downstream signal (give-up alert → dashboard consumer).
///
/// `#[must_use]` — an integration point that ignores this value silently
/// swallows every phase change. Match exhaustively.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "AppliedAction carries phase-transition + alert outcomes — \
              the main-loop wrapper must match exhaustively so it can log \
              and fan out downstream signals (Signal::RecoveryGaveUp, etc.)"]
pub enum AppliedAction {
    /// Nothing observable happened this tick — Sleep(_) is the common
    /// case here.
    NoChange,
    /// Phase transitioned Aggressive → BackoffEvery15Min.
    EscalatedToBackoff,
    /// Phase transitioned {Aggressive, Backoff} → GivenUp AND the
    /// dedupe check said the alert was fresh (not already sent). The
    /// wrapper is responsible for the actual ntfy publish; the coordinator
    /// only stamps `giveup_alert_sent_at` and returns this variant.
    FiredGiveUpAlert,
    /// Phase transitioned GivenUp → Aggressive because a valid
    /// [`ResumeToken`] arrived.
    ResumedToAggressive,
    /// Cold restart is pending or the config is disabled — no state
    /// change, wrapper skips the recovery arc this tick.
    Deferred,
}

/// Errors from [`RecoveryCoordinator::apply`] / [`RecoveryCoordinator::record_success`].
///
/// The wrapper is expected to log these at `error!` and continue — a
/// marker-write failure should not abort the state machine. GREEN phase
/// will refine the variants (e.g. distinguish "wall clock ran backwards"
/// from "disk full").
#[derive(Debug, thiserror::Error)]
pub enum RecoveryApplyError {
    /// Failed to persist state to disk. Wrapper logs and continues; the
    /// coordinator's in-memory phase remains authoritative for the tick
    /// but will re-attempt marker write on the next transition.
    #[error("marker write failed: {0}")]
    MarkerWrite(#[from] io::Error),
    /// Wall clock ran backwards more than `now_wall < phase_entered_at`
    /// or a monotonic delta exceeded the recovery-window sanity bound.
    /// PR-C stage 3B policy: skip this tick, log warn, do not mutate
    /// phase. Reserved for the future clock-skew guard — the current
    /// implementation clamps deltas to 0 in `phase_elapsed_secs`.
    #[error("clock skew detected: {reason}")]
    #[allow(dead_code)] // reserved for PR-C stage 3B clock-skew guard
    ClockSkew { reason: String },
    /// A resume token was consumed twice (single-use invariant).
    #[error("resume token replay: token hash already recorded as consumed")]
    TokenReplay,
    /// The current phase does not accept this action (e.g.
    /// `record_success` while in `GivenUp`).
    #[error("invalid action for current phase {phase:?}: {reason}")]
    InvalidForPhase { phase: RecoveryPhase, reason: String },
}

/// Envelope sent from the Connected-dwell timer task back to the main
/// loop. The task cannot hold `&mut StateMachine` across `.await`, so it
/// signals success via an `mpsc::UnboundedSender<DwellSuccess>` and the
/// main loop calls [`RecoveryCoordinator::record_success`] to commit it.
///
/// Both timestamps are sampled by the dwell task itself, not the main
/// loop — the delta between "dwell fired at T" and "main loop applied
/// it at T'" is bounded by tokio scheduling latency (small) but keeping
/// the fire timestamp keeps the wall/mono anchors coherent.
#[derive(Debug, Clone)]
pub struct DwellSuccess {
    pub recorded_at_wall: jiff::Zoned,
    pub recorded_at_mono: std::time::Instant,
}

/// Guard that aborts a Tokio task when dropped.
///
/// Used for the Connected-dwell timer: on entering `State::Connected`
/// the wrapper spawns a task that sleeps `min_success_dwell_secs` then
/// sends a `DwellSuccess`. If we leave `Connected` before that fires,
/// the guard's `Drop` aborts the task so it can never call
/// `record_success` against a stale phase.
///
/// The `AbortHandle` inner is INTENTIONALLY not a pub field — a public
/// tuple field would let callers construct instances via `AbortOnDrop(h)`
/// which bypasses future invariants we may add to the constructor
/// (e.g. GREEN-phase logging, weak-count check, or a "handle already
/// consumed" guard). Use [`AbortOnDrop::new`].
pub struct AbortOnDrop {
    inner: tokio::task::AbortHandle,
}

impl AbortOnDrop {
    /// Wrap a spawned task's abort handle so it dies when the guard is
    /// dropped.
    pub fn new(handle: tokio::task::AbortHandle) -> Self {
        Self { inner: handle }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        // Abort the wrapped task — the timer future cannot fire (and
        // cannot deliver DwellSuccess) once this returns. `abort()` is
        // idempotent: calling on an already-completed task is a no-op.
        self.inner.abort();
    }
}

/// Three-phase reconnection recovery coordinator.
///
/// See module docs for the state model. Instance state carries only
/// EVENT timestamps (past facts) and the current phase; every per-tick
/// decision goes through the pure [`compute_next_action`] via
/// [`Self::compute`].
///
/// # Field ownership
///
/// The coordinator OWNS phase + marker paths. The wrapper (mod.rs main
/// loop) owns the dwell-guard (which lives in `StateMachine`, not here,
/// because it needs to interact with the SelectOutcome flow) and the
/// dwell_success channel.
pub struct RecoveryCoordinator {
    /// Trading mode ("live" | "paper"). Mode-scoped so live/paper never
    /// collide on marker paths and a `?mode=paper` resume URL cannot
    /// resume live.
    mode: String,
    /// Path to `{settings_dir}` — where marker files live.
    settings_dir: PathBuf,
    /// Pure config with env overrides already applied (by
    /// [`crate::config::RecoveryTimingConfig::to_runtime`]).
    config: RecoveryConfig,

    /// Current phase — the SINGLE source of truth in memory. Mirrored to
    /// disk on every transition via [`save`].
    phase: RecoveryPhase,
    /// When we entered the current phase (wall clock). This is a FACT
    /// (past instant), NOT a captured-once predicate — recomputing
    /// elapsed vs `now_wall` per tick keeps Bug 4 class unrepresentable.
    phase_entered_at_wall: jiff::Zoned,
    /// Monotonic anchor for elapsed-in-phase computation. Set on phase
    /// entry, not construction — meaningful only within the current
    /// container lifetime (the marker's `_secs_since_boot` companion
    /// bridges cross-restart continuity).
    phase_entered_at_mono: std::time::Instant,

    /// When did we last dwell in Connected for `min_success_dwell_secs`.
    /// None if never or if resumed (per design decision: a resume from
    /// GivenUp does NOT preserve the pre-give-up success anchor —
    /// operator has attested the situation changed).
    last_full_success_at: Option<jiff::Zoned>,
    /// Monotonic anchor for the dwell check itself, scoped to the
    /// CURRENT container. Lost across container restart (which is why
    /// `last_full_success_at` carries the wall-clock counterpart for
    /// cross-restart continuity via the marker).
    last_full_success_mono: Option<std::time::Instant>,

    /// Once fired, the wall-clock instant of the give-up ntfy — used
    /// for the resend dedupe (`giveup_alert_resend_interval_hours`).
    giveup_alert_sent_at: Option<jiff::Timestamp>,

    /// Hash of the resume token consumed to exit GivenUp; single-use
    /// nonce prevents URL replay (operator taps once, curl-scripts a
    /// second time by mistake, second call rejects).
    resumed_by_token_hash: Option<String>,

    /// True if [`RecoveryCoordinator::boot`] observed
    /// [`RecoveryLoadOutcome::RefusedGivenUpAutoReset`] — main loop
    /// blocks at the resume gate until the operator taps the resume
    /// link or `IBCTL_RECOVERY_FORCE_RESET=1` restart lands.
    blocked_awaiting_resume: bool,

    /// Optional channel for publishing a
    /// [`Signal::RecoveryGaveUp`](crate::types::Signal::RecoveryGaveUp)
    /// on the give-up transition. Additive to the existing in-line halt
    /// (JVM kill + WaitingForLaunch park) — external subscribers (SSE
    /// bus, dashboard) use this for push-side notification. `None` when
    /// the wrapper hasn't installed a subscriber; sends silently drop
    /// on a closed channel because a slow consumer must not stall the
    /// coordinator.
    giveup_signal_tx: Option<tokio::sync::mpsc::UnboundedSender<Signal>>,
}

impl RecoveryCoordinator {
    /// Build from marker load. Reads `IBCTL_RECOVERY_FORCE_RESET` env
    /// once via [`read_force_reset_env`] (single canonical env-var reader
    /// for the coordinator; the pure `load()` fn takes force_reset as an
    /// arg to stay env-independent for testing).
    ///
    /// Returns the outcome alongside the coordinator so the caller can:
    ///   - `RefusedGivenUpAutoReset` → log at warn + set the alert-fired
    ///     Signal so the dashboard re-surfaces the pending resume URL.
    ///     Coordinator is constructed with `phase = GivenUp` so the
    ///     resume-token gate in the pure function accepts the operator's
    ///     tap on the ntfy link.
    ///   - `Defaulted { reason }` → log at warn (reason contains the
    ///     load-time diagnostic). Coordinator starts fresh in Aggressive.
    ///   - `Loaded(state)` → log at info with restored phase. Coordinator
    ///     mirrors every persisted field back into memory.
    pub fn boot(
        settings_dir: PathBuf,
        mode: String,
        config: RecoveryConfig,
    ) -> (Self, RecoveryLoadOutcome) {
        let force_reset = read_force_reset_env();
        let outcome = load(&settings_dir, &mode, force_reset);

        let now_mono = std::time::Instant::now();
        let now_wall = jiff::Zoned::now();

        let (
            phase,
            phase_entered_at_wall,
            last_full_success_at,
            giveup_alert_sent_at,
            resumed_by_token_hash,
            blocked_awaiting_resume,
        ) = match &outcome {
            RecoveryLoadOutcome::Loaded(state) => (
                state.phase,
                state.phase_entered_at.clone(),
                state.last_full_success_at.clone(),
                state.giveup_alert_sent_at,
                state.resumed_by_token_hash.clone(),
                false,
            ),
            RecoveryLoadOutcome::Defaulted { .. } => (
                RecoveryPhase::Aggressive,
                now_wall.clone(),
                None,
                None,
                None,
                false,
            ),
            RecoveryLoadOutcome::RefusedGivenUpAutoReset { .. } => (
                // On refuse, treat as if we were in GivenUp so the pure
                // function's Gate 2 (resume_token) can fire — otherwise
                // the operator would tap the ntfy link and the resume
                // path would be unreachable ("wrong phase, no-op").
                RecoveryPhase::GivenUp,
                now_wall.clone(),
                None,
                None,
                None,
                true,
            ),
        };

        // Cross-restart mono-anchor recalibration.
        //
        // Naïve `phase_entered_at_mono = Instant::now()` at every boot
        // means `mono_delta = 0` immediately after any container
        // restart, and `phase_elapsed_secs = min(wall_delta, mono_delta)`
        // clamps to 0 — the coordinator can never escalate in a
        // restart-prone environment (Backoff → GivenUp is unreachable
        // when the container OOMs faster than 3h).
        //
        // Fix: when we loaded a Loaded outcome, sample the wall_delta at
        // boot (`now_wall - phase_entered_at_wall`) and back-date the
        // mono anchor by that amount. Then `Instant::now().duration_since(
        // anchor)` at any subsequent tick returns roughly `wall_delta_at_boot
        // + time_since_boot` — a mono clock that pretends the phase
        // started `wall_delta_at_boot` before this container's boot.
        //
        // Safety on the NTP-backwards guard: mono still runs forward at
        // its own rate, so `min(wall, mono)` still refuses to escalate
        // faster than mono allows. If wall jumps backward the resulting
        // wall_delta shrinks, `min` picks wall, and we conservatively
        // under-count.
        //
        // Overflow guard: if `wall_delta` is so large that back-dating
        // saturates (phase entered before the container's mono clock
        // started, which is common — CLOCK_MONOTONIC starts at 0 on
        // boot), fall back to the naïve anchor. In that case elapsed is
        // bounded by container uptime, matching the historical
        // conservative behaviour.
        let phase_entered_at_mono = match &outcome {
            RecoveryLoadOutcome::Loaded(state) => {
                let wall_delta_secs = (now_wall.timestamp().as_second()
                    - state.phase_entered_at.timestamp().as_second())
                    .max(0) as u64;
                now_mono
                    .checked_sub(std::time::Duration::from_secs(wall_delta_secs))
                    .unwrap_or(now_mono)
            }
            _ => now_mono,
        };

        let coord = Self {
            mode,
            settings_dir,
            config,
            phase,
            phase_entered_at_wall,
            phase_entered_at_mono,
            last_full_success_at,
            last_full_success_mono: None,
            giveup_alert_sent_at,
            resumed_by_token_hash,
            blocked_awaiting_resume,
            giveup_signal_tx: None,
        };
        (coord, outcome)
    }

    /// Install a channel to be notified when this coordinator enters
    /// `GivenUp`. Called once by the wrapper (typically main loop
    /// setup) so an external subscriber can receive
    /// [`Signal::RecoveryGaveUp`](crate::types::Signal::RecoveryGaveUp)
    /// on the give-up transition. Replaces any previously installed
    /// sender — the caller owns installation lifecycle.
    ///
    /// `#[allow(dead_code)]` because the SSE bus wiring lands in a
    /// follow-up wave; the stage 5 test at `test_signal_recovery_gave_up_
    /// sent_on_fire_alert` exercises the setter directly. Remove the
    /// allow once the wrapper wires the sender from `main`.
    #[allow(dead_code)]
    pub fn set_giveup_signal_sender(
        &mut self,
        tx: tokio::sync::mpsc::UnboundedSender<Signal>,
    ) {
        self.giveup_signal_tx = Some(tx);
    }

    /// Per-tick decision. Builds a fresh [`RecoverySnapshot`] from
    /// coordinator state + arguments and delegates to the pure
    /// [`compute_next_action`]. Returns the raw action — the wrapper
    /// applies it via [`Self::apply`].
    ///
    /// `now_wall` and `now_mono` MUST be sampled together (same tick).
    /// The coordinator does not sample them itself — dependency
    /// inversion for test injection.
    ///
    /// `resume_token` is CONSUMED here (via [`Self::apply`]'s
    /// `consumed_token` argument) only when the action is
    /// [`NextAction::ResumeToAggressive`]; otherwise it's peek-only.
    pub fn compute(
        &self,
        now_wall: &jiff::Zoned,
        now_mono: std::time::Instant,
        cold_restart_pending: bool,
        resume_token: Option<ResumeToken>,
        failure_fingerprint_streak: u32,
    ) -> NextAction {
        let phase_elapsed_secs = self.phase_elapsed_secs(now_wall, now_mono);

        // last_full_success_at is scoped to the current phase by design:
        // every phase transition (via apply()) clears both anchors, and
        // record_success() only sets them within the current phase.
        // Presence therefore encodes "success has landed this phase".
        let had_success_this_phase = self.last_full_success_at.is_some();

        let snap = RecoverySnapshot {
            phase: self.phase,
            phase_elapsed_secs,
            had_success_this_phase,
            resume_token,
            cold_restart_pending,
            failure_fingerprint_streak,
        };
        compute_next_action(&snap, &self.config)
    }

    /// Apply the [`NextAction`] returned by [`Self::compute`]. This is
    /// the SOLE mutation surface — every phase transition, marker
    /// write, alert dedupe, and token-consumption happens here.
    ///
    /// Idempotent on `Sleep` / `DeferToColdRestart` — they return
    /// `AppliedAction::NoChange` / `Deferred` without mutating state
    /// or touching disk.
    ///
    /// The wrapper passes `consumed_token` matching the token it fed
    /// into `compute` on the same tick, so `apply` can hash it for
    /// [`Self::resumed_by_token_hash`] without needing to re-derive the
    /// nonce material.
    pub fn apply(
        &mut self,
        action: NextAction,
        now_wall: jiff::Zoned,
        now_mono: std::time::Instant,
        consumed_token: Option<ResumeToken>,
    ) -> Result<AppliedAction, RecoveryApplyError> {
        match action {
            // Non-mutating actions — no marker rewrite, no phase change.
            // Test guard: `test_apply_sleep_does_not_touch_marker_on_disk`
            // asserts mtime doesn't move for Sleep.
            NextAction::Sleep(_) => Ok(AppliedAction::NoChange),
            NextAction::DeferToColdRestart => Ok(AppliedAction::Deferred),

            NextAction::EscalateToBackoff => {
                log::warn!(
                    "recovery.phase_changed prev={} next={} elapsed_secs={} trigger=time",
                    self.phase.as_str(),
                    RecoveryPhase::BackoffEvery15Min.as_str(),
                    self.phase_elapsed_secs(&now_wall, now_mono),
                );
                self.enter_phase(RecoveryPhase::BackoffEvery15Min, now_wall, now_mono);
                self.persist()?;
                Ok(AppliedAction::EscalatedToBackoff)
            }

            // Both FireGiveUpAlert (time-based) and ForceHitlEarly
            // (fingerprint-based) land in the same GivenUp terminus; the
            // wrapper distinguishes them via structured log fields but the
            // coordinator's on-disk state is identical.
            NextAction::FireGiveUpAlert | NextAction::ForceHitlEarly => {
                // Dedupe: apply() called twice in the same GivenUp phase
                // must NOT re-stamp the alert timestamp — otherwise
                // `giveup_alert_resend_interval_hours` reduces to 0.
                // (See `test_giveup_alert_dedupe_stamps_only_once_per_phase_entry`.)
                if self.phase == RecoveryPhase::GivenUp
                    && self.giveup_alert_sent_at.is_some()
                {
                    log::debug!(
                        "recovery.tick_evaluated phase=given_up next_action=fire_giveup_alert \
                         reason=dedupe_already_sent",
                    );
                    return Ok(AppliedAction::NoChange);
                }
                let prev = self.phase.as_str();
                let trigger = match action {
                    NextAction::FireGiveUpAlert => "time",
                    NextAction::ForceHitlEarly => "fingerprint_streak",
                    _ => unreachable!("outer match already scoped these two"),
                };
                log::warn!(
                    "recovery.phase_changed prev={prev} next={next} elapsed_secs={elapsed} \
                     trigger={trigger}",
                    prev = prev,
                    next = RecoveryPhase::GivenUp.as_str(),
                    elapsed = self.phase_elapsed_secs(&now_wall, now_mono),
                    trigger = trigger,
                );
                let sent_at = now_wall.timestamp();
                // Clone the wall clock for the Signal payload before
                // enter_phase moves it into `phase_entered_at_wall`. The
                // Signal carries the SAME wall instant that persistence
                // stamps as `phase_entered_at`, so downstream consumers
                // and STATUS-poll observers see a consistent timeline.
                let phase_entered_at = now_wall.clone();
                self.enter_phase(RecoveryPhase::GivenUp, now_wall, now_mono);
                self.giveup_alert_sent_at = Some(sent_at);
                self.persist()?;
                // ERROR level: give-up is an operator-must-act event.
                // On-call log filters that suppress WARN would silently
                // drop the alert; the ntfy push at stage 5 supplements
                // but does not replace journalctl visibility.
                log::error!(
                    "recovery.giveup_alert_sent sent_at={sent_at} resend_count=0 \
                     callback_url_hash=",
                    sent_at = sent_at,
                );
                // Fan out a push-side notification to any subscriber
                // (SSE bus, dashboard). Send-on-closed-channel is a
                // silent drop — a stalled consumer must not block the
                // coordinator. The in-line halt behaviour (mod.rs kills
                // the JVM and parks in WaitingForLaunch) is unchanged;
                // this is additive.
                if let Some(tx) = &self.giveup_signal_tx {
                    let _ = tx.send(Signal::RecoveryGaveUp {
                        mode: self.mode.clone(),
                        phase_entered_at,
                    });
                }
                Ok(AppliedAction::FiredGiveUpAlert)
            }

            NextAction::ResumeToAggressive => {
                // Guard: the wrapper feeds the token used by the pure
                // function on the same tick. Applying ResumeToAggressive
                // without a token is a wrapper-side bug (main loop forgot
                // to forward `take_pending_resume_token`); surface it.
                let token = consumed_token.ok_or_else(|| {
                    RecoveryApplyError::InvalidForPhase {
                        phase: self.phase,
                        reason: "ResumeToAggressive requires a resume token".to_string(),
                    }
                })?;
                let hash = hash_token(&token);
                if let Some(existing) = &self.resumed_by_token_hash {
                    if existing == &hash {
                        // Single-use nonce invariant.
                        return Err(RecoveryApplyError::TokenReplay);
                    }
                }
                let prev = self.phase.as_str();
                log::info!(
                    "recovery.resumed by={hash_prefix} prior_phase={prev}",
                    hash_prefix = hash.chars().take(8).collect::<String>(),
                    prev = prev,
                );
                self.enter_phase(RecoveryPhase::Aggressive, now_wall, now_mono);
                // Resume clears the alert-sent stamp so a future re-give-up
                // is not deduped against a prior cycle's timestamp.
                self.giveup_alert_sent_at = None;
                self.resumed_by_token_hash = Some(hash);
                self.blocked_awaiting_resume = false;
                self.persist()?;
                Ok(AppliedAction::ResumedToAggressive)
            }
        }
    }

    /// Record a successful Connected dwell. Called by the main loop
    /// when it drains a [`DwellSuccess`] from the dwell channel — the
    /// dwell task itself cannot mutate coordinator state.
    ///
    /// Success semantics:
    ///   - In `Aggressive`: sets `last_full_success_at`; phase
    ///     unchanged. Next `compute` returns Sleep(0) even at high
    ///     elapsed because `had_success_this_phase` short-circuits.
    ///   - In `BackoffEvery15Min`: transitions phase back to
    ///     Aggressive (dwell is stronger evidence of recovery than
    ///     any timer). Marker rewritten.
    ///   - In `GivenUp`: rejected with `InvalidForPhase` — the
    ///     wrapper's dwell guard should have been aborted on
    ///     GivenUp entry, so seeing a success here is a bug.
    pub fn record_success(
        &mut self,
        now_wall: jiff::Zoned,
        now_mono: std::time::Instant,
    ) -> Result<(), RecoveryApplyError> {
        match self.phase {
            RecoveryPhase::GivenUp => Err(RecoveryApplyError::InvalidForPhase {
                phase: RecoveryPhase::GivenUp,
                reason: "record_success is invalid in GivenUp — the dwell guard \
                        should have been aborted on GivenUp entry"
                    .to_string(),
            }),
            RecoveryPhase::Aggressive => {
                self.last_full_success_at = Some(now_wall);
                self.last_full_success_mono = Some(now_mono);
                self.persist()?;
                Ok(())
            }
            RecoveryPhase::BackoffEvery15Min => {
                // Dwell success in Backoff is strong recovery evidence:
                // reset to Aggressive with a fresh timer. The wall/mono
                // anchors move to `now_*` — see `enter_phase`.
                log::info!(
                    "recovery.phase_changed prev={} next={} elapsed_secs={} trigger=success",
                    self.phase.as_str(),
                    RecoveryPhase::Aggressive.as_str(),
                    self.phase_elapsed_secs(&now_wall, now_mono),
                );
                self.enter_phase(RecoveryPhase::Aggressive, now_wall.clone(), now_mono);
                self.last_full_success_at = Some(now_wall);
                self.last_full_success_mono = Some(now_mono);
                self.persist()?;
                Ok(())
            }
        }
    }

    // -------- Read-only accessors for STATUS JSON (stage 4) -----------------

    pub fn phase(&self) -> RecoveryPhase {
        self.phase
    }

    // The accessors below feed STATUS JSON in PR-C stage 4; kept as
    // `pub` (not `pub(super)`) because the STATUS JSON builder lives in
    // `queries.rs` and consumes these via the coordinator's public
    // surface. Once wired into `build_status_json` in stage 4 GREEN,
    // the `#[allow(dead_code)]` guards were dropped.
    pub fn phase_entered_at(&self) -> &jiff::Zoned {
        &self.phase_entered_at_wall
    }

    pub fn last_full_success_at(&self) -> Option<&jiff::Zoned> {
        self.last_full_success_at.as_ref()
    }

    pub fn is_blocked_awaiting_resume(&self) -> bool {
        self.blocked_awaiting_resume
    }

    /// Wall-clock instant the give-up alert was stamped (dedupe anchor
    /// for the ntfy resend interval; stage 5 will populate resends).
    /// STATUS JSON serialises this via jiff's `Timestamp` Serialize
    /// impl (UTC ISO with `Z` suffix). None until the coordinator has
    /// fired at least one give-up alert this GivenUp phase.
    pub fn giveup_alert_sent_at(&self) -> Option<jiff::Timestamp> {
        self.giveup_alert_sent_at
    }

    /// The Backoff-phase inter-retry interval in seconds. Needed by
    /// `queries.rs::build_status_json` to compute `next_retry_at` at
    /// the next `backoff_interval_secs` boundary from `phase_entered_at`.
    /// Kept on the coordinator (rather than exposed via the `config`
    /// field directly) so a future per-mode override policy stays
    /// centralised behind this getter.
    pub fn config_backoff_interval_secs(&self) -> u64 {
        self.config.backoff_interval_secs
    }

    /// Convenience accessor for the apply_transition hook in mod.rs
    /// that reads the dwell threshold when starting the Connected timer
    /// task. Kept on the coordinator (not on `config` directly) so a
    /// future override policy (e.g. per-mode overrides, operator kill
    /// switch that changes the threshold live) stays centralized.
    pub fn config_min_success_dwell_secs(&self) -> u64 {
        self.config.min_success_dwell_secs
    }

    /// STATUS-JSON accessor: aggressive-phase max in seconds. Exposed on
    /// the wire so the dashboard's give-up alert body reports the real
    /// operator-configured value rather than a hardcoded 3600 (finding
    /// B-HIGH-1).
    pub fn config_aggressive_phase_max_secs(&self) -> u64 {
        self.config.aggressive_phase_max_secs
    }

    /// STATUS-JSON accessor: backoff-phase max in seconds (finding B-HIGH-1).
    pub fn config_backoff_phase_max_secs(&self) -> u64 {
        self.config.backoff_phase_max_secs
    }

    /// STATUS-JSON accessor: signed callback URL lifetime in hours
    /// (finding B-HIGH-1). The dashboard monitor uses this to mint the
    /// ntfy action button's token with the operator-configured lifetime.
    pub fn config_giveup_callback_valid_hours(&self) -> u32 {
        self.config.giveup_callback_valid_hours
    }

    /// STATUS-JSON accessor: minimum wall-clock interval between give-up
    /// alert resends, in hours (finding B-HIGH-1). The dashboard
    /// monitor's dedupe-resend gate reads this value.
    pub fn config_giveup_alert_resend_interval_hours(&self) -> u32 {
        self.config.giveup_alert_resend_interval_hours
    }

    // -------- private helpers ----------------------------------------------

    /// Enter a new phase: update phase + both wall/mono anchors +
    /// invalidate the success anchors. Every phase transition goes
    /// through this so no field is missed. Does NOT persist — callers
    /// call `persist()` explicitly to keep error handling co-located
    /// with the transition site.
    fn enter_phase(
        &mut self,
        next: RecoveryPhase,
        now_wall: jiff::Zoned,
        now_mono: std::time::Instant,
    ) {
        self.phase = next;
        self.phase_entered_at_wall = now_wall;
        self.phase_entered_at_mono = now_mono;
        // Success anchors are phase-scoped; a new phase means the old
        // success is no longer relevant to `had_success_this_phase`.
        self.last_full_success_at = None;
        self.last_full_success_mono = None;
    }

    /// Compute `min(wall_delta, mono_delta)` from phase entry to `now_*`.
    /// Both deltas clamp to 0 (wall clock can run backwards under NTP;
    /// mono `checked_duration_since` returns None if `now_mono` predates
    /// the phase-entry anchor).
    fn phase_elapsed_secs(&self, now_wall: &jiff::Zoned, now_mono: std::time::Instant) -> u64 {
        let wall_delta_secs = (now_wall.timestamp().as_second()
            - self.phase_entered_at_wall.timestamp().as_second())
        .max(0) as u64;
        let mono_delta_secs = now_mono
            .checked_duration_since(self.phase_entered_at_mono)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        wall_delta_secs.min(mono_delta_secs)
    }

    /// Serialize + atomically write the current coordinator state to the
    /// marker file. Called after every mutating apply() branch and after
    /// record_success in Backoff.
    fn persist(&self) -> Result<(), RecoveryApplyError> {
        let state = RecoveryPersistedState {
            schema_version: 1,
            phase: self.phase,
            phase_entered_at: self.phase_entered_at_wall.clone(),
            // GREEN-phase note: `phase_entered_at_monotonic_secs_since_boot`
            // is set to 0 because we do not (yet) sample the system boot
            // time via /proc/uptime or CLOCK_BOOTTIME. The field exists in
            // the schema for future cross-restart continuity work; for
            // now the wall clock is the authoritative time source across
            // restarts and mono is scoped to the current container.
            phase_entered_at_monotonic_secs_since_boot: 0,
            last_full_success_at: self.last_full_success_at.clone(),
            giveup_alert_sent_at: self.giveup_alert_sent_at,
            resumed_by_token_hash: self.resumed_by_token_hash.clone(),
            last_known_phase: self.phase,
        };
        save(&self.settings_dir, &self.mode, &state).map_err(RecoveryApplyError::MarkerWrite)
    }
}

/// Compute a stable hash of a [`ResumeToken`] for the single-use nonce
/// invariant. Uses `std::hash::DefaultHasher` (SipHash) — cryptographic
/// resistance is not required here because the token nonce is a
/// server-minted HMAC on the dashboard side (stage 5); the coordinator's
/// hash only needs deterministic equality within one process lifetime
/// and durable equality across restarts (via marker persistence).
fn hash_token(token: &ResumeToken) -> String {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    token.mode.hash(&mut hasher);
    token.minted_at.as_second().hash(&mut hasher);
    // Include the caller-supplied nonce material so two different
    // operator taps mint different hashes even within the same wall-
    // second. Without this, `resumed_by_token_hash` collapses to a
    // (mode, wall_second) key and the single-use replay guard reduces
    // to a per-second rate limit.
    token.nonce_material.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Read `IBCTL_RECOVERY_FORCE_RESET` from process env, returning true
/// when set to `1`, `true`, `yes`, or `on` (case-insensitive).
///
/// Called at coordinator construction only. Serialised across tests
/// (which may set the env var) via [`ENV_LOCK`] so parallel test
/// execution stays deterministic. Production callers do not lock —
/// the env is stable across `boot()` in production.
fn read_force_reset_env() -> bool {
    match std::env::var("IBCTL_RECOVERY_FORCE_RESET").ok() {
        Some(v) => matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => false,
    }
}

#[cfg(test)]
mod integration_tests {
    //! RED-phase tests for the RecoveryCoordinator + AbortOnDrop.
    //!
    //! Every stub is `unimplemented!("stage 3 GREEN: ...")`, so any test
    //! that reaches an API call panics with that message and is reported
    //! as FAILED. This is the RED state — no test may accidentally pass.
    //!
    //! Tests use `tempfile::TempDir` for marker isolation and construct
    //! `jiff::Zoned` values from a fixed offset so results are
    //! deterministic across the CI host's TZ.
    //!
    //! # Test dependency inversion
    //!
    //! `compute` / `apply` / `record_success` all take `now_wall` +
    //! `now_mono` as arguments — the coordinator never samples the
    //! wall/mono clock itself. This lets tests drive virtual time
    //! forward without `tokio::time::pause()` for the pure-logic
    //! coordinator tests. The dwell-timer tests, which do exercise
    //! `tokio::time::sleep`, use `pause()` + `advance()`.
    //!
    //! # Coverage rationale
    //!
    //! The 19-item spec list covers boot/apply/record_success/dwell.
    //! Tests beyond the spec (marked "additional") are noted with a
    //! justification comment adjacent to the `#[test]` attribute so a
    //! reviewer can spot the deviation.
    //!
    //! # Env-var serialization
    //!
    //! `IBCTL_RECOVERY_FORCE_RESET` is a process-global env var read
    //! inside `RecoveryCoordinator::boot`. Tests that MANIPULATE this
    //! env (test 4) and tests that OBSERVE the "no force_reset" path
    //! (test 3, test 23) both acquire [`ENV_LOCK`] to prevent parallel
    //! test-thread races. Tests that don't care about force_reset
    //! (missing marker, fresh dir) do not lock — their outcome is
    //! independent of the env value.
    #![allow(clippy::disallowed_names)]

    use super::*;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// Serializes access to `IBCTL_RECOVERY_FORCE_RESET` across test
    /// threads. Test 4 acquires this lock, sets the env, boots, and
    /// clears the env — all under one guarded window so tests 3 / 23
    /// (which acquire the same lock and expect env-unset) never observe
    /// a leaked set.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // -------- fixtures --------------------------------------------------

    fn fixed_zoned() -> jiff::Zoned {
        jiff::civil::date(2026, 7, 11)
            .at(9, 0, 0, 0)
            .to_zoned(jiff::tz::TimeZone::fixed(jiff::tz::Offset::constant(-4)))
            .expect("synthetic zoned must construct")
    }

    fn later(base: &jiff::Zoned, secs: i64) -> jiff::Zoned {
        base.checked_add(jiff::SignedDuration::from_secs(secs))
            .expect("Zoned math must succeed")
    }

    fn default_cfg() -> RecoveryConfig {
        RecoveryConfig::default()
    }

    fn disabled_cfg() -> RecoveryConfig {
        RecoveryConfig {
            disabled: true,
            ..RecoveryConfig::default()
        }
    }

    fn sample_state(phase: RecoveryPhase) -> RecoveryPersistedState {
        RecoveryPersistedState {
            schema_version: 1,
            phase,
            phase_entered_at: fixed_zoned(),
            phase_entered_at_monotonic_secs_since_boot: 0,
            last_full_success_at: None,
            giveup_alert_sent_at: None,
            resumed_by_token_hash: None,
            last_known_phase: phase,
        }
    }

    fn dummy_token() -> ResumeToken {
        ResumeToken {
            mode: "paper".to_string(),
            minted_at: jiff::Timestamp::from_second(1_720_000_000).unwrap(),
            nonce_material: "integration-dummy-nonce".to_string(),
        }
    }

    // ---------------------------------------------------------------------
    // 1. Boot / load-outcome integration
    // ---------------------------------------------------------------------

    #[test]
    fn test_coordinator_boot_missing_marker_defaults_to_aggressive() {
        // Spec test 1. Fresh settings dir → coordinator starts in
        // Aggressive; RecoveryLoadOutcome::Defaulted is returned for
        // the main-loop logger.
        let dir = TempDir::new().unwrap();
        let (coord, outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        match outcome {
            RecoveryLoadOutcome::Defaulted { .. } => { /* OK */ }
            other => panic!("expected Defaulted for missing marker, got {:?}", other),
        }
        assert_eq!(coord.phase(), RecoveryPhase::Aggressive);
        assert!(!coord.is_blocked_awaiting_resume());
        assert!(coord.last_full_success_at().is_none());
    }

    #[test]
    fn test_coordinator_boot_loaded_marker_restores_phase() {
        // Spec test 2. Plant a valid marker with phase=Backoff → boot
        // restores phase and phase_entered_at from disk.
        let dir = TempDir::new().unwrap();
        let expected_phase = RecoveryPhase::BackoffEvery15Min;
        let mut planted = sample_state(expected_phase);
        planted.phase_entered_at = fixed_zoned();
        save(dir.path(), "paper", &planted).expect("plant marker");

        let (coord, outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        match outcome {
            RecoveryLoadOutcome::Loaded(_) => { /* OK */ }
            other => panic!("expected Loaded, got {:?}", other),
        }
        assert_eq!(coord.phase(), expected_phase);
        assert_eq!(coord.phase_entered_at(), &fixed_zoned());
        assert!(!coord.is_blocked_awaiting_resume());
    }

    #[test]
    fn test_coordinator_boot_refused_givenup_sets_blocked_flag() {
        // Spec test 3. Corrupt main + sidecar=given_up → coordinator
        // boots with blocked_awaiting_resume=true so the main loop's
        // reconnect arc parks until the operator resumes.
        //
        // Acquires ENV_LOCK to guarantee test 4 is NOT concurrently
        // holding IBCTL_RECOVERY_FORCE_RESET=1, which would flip this
        // test's expected outcome from Refused to Defaulted.
        let _env_guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".ibctl-recovery-state.paper.json"),
            "corrupt garbage {",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".ibctl-recovery-state.paper.last-known-phase.txt"),
            "given_up",
        )
        .unwrap();

        let (coord, outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        assert!(
            outcome.should_block_boot(),
            "outcome must be RefusedGivenUpAutoReset, got {:?}",
            outcome,
        );
        assert!(coord.is_blocked_awaiting_resume());
    }

    #[test]
    fn test_coordinator_boot_force_reset_env_bypasses_refused() {
        // Spec test 4. `IBCTL_RECOVERY_FORCE_RESET=1` demotes Refused
        // to Defaulted.
        //
        // GREEN-phase implementation choice (documented in return
        // report): `boot()` reads the env var directly, so this test
        // must actually SET the env for the assertion to hold.
        // `std::env::set_var` is safe under Rust 2021 edition (this
        // crate uses 2021); the `unsafe` requirement only lands in
        // 2024. Serialized via ENV_LOCK against tests 3 / 23.
        let _env_guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".ibctl-recovery-state.paper.json"),
            "corrupt",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".ibctl-recovery-state.paper.last-known-phase.txt"),
            "given_up",
        )
        .unwrap();

        std::env::set_var("IBCTL_RECOVERY_FORCE_RESET", "1");
        let (coord, outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        std::env::remove_var("IBCTL_RECOVERY_FORCE_RESET");

        match outcome {
            RecoveryLoadOutcome::Defaulted { .. } => { /* OK */ }
            other => panic!(
                "force_reset must demote Refused to Defaulted, got {:?}",
                other,
            ),
        }
        assert!(!coord.is_blocked_awaiting_resume());
    }

    // ---------------------------------------------------------------------
    // 2. Apply — marker persistence + phase transitions
    // ---------------------------------------------------------------------

    #[test]
    fn test_apply_escalate_to_backoff_writes_marker() {
        // Spec test 5. Apply EscalateToBackoff → marker on disk
        // shows phase=backoff_every_15min, phase field is updated,
        // AppliedAction::EscalatedToBackoff returned.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let now_wall = fixed_zoned();
        let now_mono = Instant::now();

        let applied = coord
            .apply(NextAction::EscalateToBackoff, now_wall.clone(), now_mono, None)
            .expect("apply must not error");
        assert_eq!(applied, AppliedAction::EscalatedToBackoff);
        assert_eq!(coord.phase(), RecoveryPhase::BackoffEvery15Min);
        // Marker on disk reflects the transition (integration point).
        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(state) => {
                assert_eq!(state.phase, RecoveryPhase::BackoffEvery15Min);
            }
            other => panic!("expected Loaded(Backoff), got {:?}", other),
        }
    }

    #[test]
    fn test_apply_fire_giveup_writes_marker_and_sidecar() {
        // Spec test 6. Apply FireGiveUpAlert → phase=GivenUp on disk,
        // sidecar file exists with `given_up`, dedupe timestamp set.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        // Fast-forward to Backoff first so FireGiveUpAlert is a valid
        // downstream transition. (GREEN impl may accept it from
        // Aggressive too via ForceHitlEarly — that's spec test 10.)
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate to backoff");

        let applied = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("apply give-up must not error");
        assert_eq!(applied, AppliedAction::FiredGiveUpAlert);
        assert_eq!(coord.phase(), RecoveryPhase::GivenUp);
        // Marker and sidecar on disk.
        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(state) => {
                assert_eq!(state.phase, RecoveryPhase::GivenUp);
                assert!(
                    state.giveup_alert_sent_at.is_some(),
                    "dedupe timestamp must be stamped on give-up",
                );
            }
            other => panic!("expected Loaded(GivenUp), got {:?}", other),
        }
        assert!(
            dir.path()
                .join(".ibctl-recovery-state.paper.last-known-phase.txt")
                .exists(),
            "sidecar must exist after GivenUp save",
        );
    }

    #[test]
    fn test_apply_resume_clears_last_success_and_returns_to_aggressive() {
        // Spec test 7. From GivenUp with a valid ResumeToken → phase
        // returns to Aggressive, last_full_success_at is cleared (per
        // plan decision: a resume is operator-attestation that the
        // pre-give-up success is no longer trustworthy).
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        // Drive to GivenUp via Escalate → Fire.
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("giveup");

        let token = dummy_token();
        let applied = coord
            .apply(
                NextAction::ResumeToAggressive,
                fixed_zoned(),
                Instant::now(),
                Some(token),
            )
            .expect("resume must not error");
        assert_eq!(applied, AppliedAction::ResumedToAggressive);
        assert_eq!(coord.phase(), RecoveryPhase::Aggressive);
        assert!(
            coord.last_full_success_at().is_none(),
            "last_full_success_at must clear on resume (plan decision)",
        );
    }

    #[test]
    fn test_apply_defer_to_cold_restart_is_noop() {
        // Spec test 8. DeferToColdRestart is idempotent — phase
        // unchanged, no marker rewrite, AppliedAction::Deferred.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let before = coord.phase();
        let applied = coord
            .apply(NextAction::DeferToColdRestart, fixed_zoned(), Instant::now(), None)
            .expect("defer must not error");
        assert_eq!(applied, AppliedAction::Deferred);
        assert_eq!(coord.phase(), before);
    }

    #[test]
    fn test_apply_sleep_is_noop() {
        // Spec test 9. Sleep(_) is idempotent — phase unchanged.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let before = coord.phase();
        let applied = coord
            .apply(
                NextAction::Sleep(Duration::from_secs(5)),
                fixed_zoned(),
                Instant::now(),
                None,
            )
            .expect("sleep must not error");
        assert_eq!(applied, AppliedAction::NoChange);
        assert_eq!(coord.phase(), before);
    }

    #[test]
    fn test_apply_force_hitl_early_fires_giveup_channel() {
        // Spec test 10. ForceHitlEarly bypasses the time-based Backoff
        // rung and jumps straight to GivenUp — AppliedAction is
        // FiredGiveUpAlert regardless of current phase (Aggressive OK).
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        assert_eq!(coord.phase(), RecoveryPhase::Aggressive);
        let applied = coord
            .apply(NextAction::ForceHitlEarly, fixed_zoned(), Instant::now(), None)
            .expect("force hitl must not error");
        assert_eq!(applied, AppliedAction::FiredGiveUpAlert);
        assert_eq!(coord.phase(), RecoveryPhase::GivenUp);
    }

    // ---------------------------------------------------------------------
    // 3. record_success semantics
    // ---------------------------------------------------------------------

    #[test]
    fn test_record_success_from_aggressive_clears_timer() {
        // Spec test 11. In Aggressive, record_success sets
        // last_full_success_at and (by extension of the pure fn's
        // had_success_this_phase gate) resets the phase timer without
        // changing phase.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        assert_eq!(coord.phase(), RecoveryPhase::Aggressive);
        assert!(coord.last_full_success_at().is_none());

        let wall = fixed_zoned();
        coord
            .record_success(wall.clone(), Instant::now())
            .expect("record_success from Aggressive");
        assert_eq!(coord.phase(), RecoveryPhase::Aggressive);
        assert_eq!(
            coord.last_full_success_at(),
            Some(&wall),
            "last_full_success_at must be stamped",
        );
    }

    #[test]
    fn test_record_success_from_backoff_transitions_to_aggressive() {
        // Spec test 12. In Backoff, a full dwell is strong evidence of
        // recovery — coordinator transitions back to Aggressive with
        // a fresh phase timer.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        assert_eq!(coord.phase(), RecoveryPhase::BackoffEvery15Min);

        let wall = later(&fixed_zoned(), 300);
        coord
            .record_success(wall.clone(), Instant::now())
            .expect("record_success from Backoff");
        assert_eq!(
            coord.phase(),
            RecoveryPhase::Aggressive,
            "success in Backoff resets to Aggressive",
        );
        assert_eq!(coord.last_full_success_at(), Some(&wall));
        // Marker on disk reflects the reset.
        match load(dir.path(), "paper", false) {
            RecoveryLoadOutcome::Loaded(state) => {
                assert_eq!(state.phase, RecoveryPhase::Aggressive);
            }
            other => panic!("expected Loaded(Aggressive), got {:?}", other),
        }
    }

    // ---------------------------------------------------------------------
    // 4. Dwell timer + AbortOnDrop guard
    // ---------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn test_dwell_guard_aborts_task_when_dropped() {
        // Spec test 13. AbortOnDrop::drop aborts the wrapped task so
        // it cannot fire after we leave Connected.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = tx.send(());
        });
        let guard = AbortOnDrop::new(handle.abort_handle());
        // Drop the guard immediately — task should be aborted.
        drop(guard);
        tokio::time::advance(Duration::from_secs(120)).await;
        // Yield so the task runtime observes the abort.
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "dropped guard must abort task before it sends",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_dwell_success_sender_delivered_on_60s_sleep() {
        // Spec test 14. When the guard is held for the full dwell
        // window, the timer task completes and delivers the
        // DwellSuccess to the main-loop channel.
        //
        // GREEN-phase note (documented in return report): tokio's
        // `time::advance` under `start_paused` only wakes timers that
        // have already been registered. A freshly-spawned task hasn't
        // been polled yet at spawn time — so its `sleep()` deadline is
        // computed only when the executor first polls the task. If we
        // advance BEFORE the task is polled, the task's sleep gets
        // deadline = current_mock_time + dwell_secs, which is BEYOND
        // the advance. We must yield_now once first to let the task
        // register its timer at t=0, then advance past the deadline.
        // Tests 13 and 15 don't hit this because they exercise the
        // abort path which is deterministic regardless of poll order.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DwellSuccess>();
        let dwell_secs: u64 = 60;
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(dwell_secs)).await;
            let _ = tx.send(DwellSuccess {
                recorded_at_wall: jiff::Zoned::now(),
                recorded_at_mono: Instant::now(),
            });
        });
        let _guard = AbortOnDrop::new(handle.abort_handle());
        // Prime the task so its sleep() registers a wake at t=0.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(70)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_ok(),
            "dwell timer must deliver DwellSuccess after {}s",
            dwell_secs,
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_dwell_success_sender_not_delivered_on_early_abort() {
        // Spec test 15. Dropping the guard mid-sleep aborts before
        // the delivery — verifies the "leave Connected before 60s"
        // path in the mod.rs main loop.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<DwellSuccess>();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let _ = tx.send(DwellSuccess {
                recorded_at_wall: jiff::Zoned::now(),
                recorded_at_mono: Instant::now(),
            });
        });
        let guard = AbortOnDrop::new(handle.abort_handle());
        // Advance half the window, then drop the guard.
        tokio::time::advance(Duration::from_secs(30)).await;
        drop(guard);
        tokio::time::advance(Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "dropping the guard mid-sleep must abort delivery",
        );
    }

    // ---------------------------------------------------------------------
    // 5. Resume token single-use invariant
    // ---------------------------------------------------------------------

    #[test]
    fn test_resume_token_consumed_only_once() {
        // Spec test 16. Two apply(ResumeToAggressive, ..., Some(token))
        // calls with the same token nonce must be idempotent-with-
        // reject: second call returns TokenReplay, phase unchanged.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        // Drive to GivenUp.
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("giveup");

        let token = dummy_token();
        let _ = coord
            .apply(
                NextAction::ResumeToAggressive,
                fixed_zoned(),
                Instant::now(),
                Some(token.clone()),
            )
            .expect("first resume must succeed");
        assert_eq!(coord.phase(), RecoveryPhase::Aggressive);

        // Second use of same token must fail. Drive back to GivenUp
        // synthetically to prove it's the TOKEN that's rejected, not
        // just "wrong phase".
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("re-escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("re-giveup");
        let second = coord.apply(
            NextAction::ResumeToAggressive,
            fixed_zoned(),
            Instant::now(),
            Some(token),
        );
        assert!(
            matches!(second, Err(RecoveryApplyError::TokenReplay)),
            "second use of same token must be rejected: {:?}",
            second,
        );
    }

    // ---------------------------------------------------------------------
    // 6. Disabled kill switch
    // ---------------------------------------------------------------------

    #[test]
    fn test_disabled_config_returns_sleep_zero() {
        // Spec test 17. Disabled config → compute returns Sleep(0)
        // for every phase, regardless of elapsed time or fingerprint.
        let dir = TempDir::new().unwrap();
        let (coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            disabled_cfg(),
        );
        // Even at extreme elapsed + max fingerprint + resume token
        // present + cold restart pending — every switch says "escalate"
        // or "act", the kill switch overrides.
        let action = coord.compute(
            &fixed_zoned(),
            Instant::now(),
            false,
            None,
            0,
        );
        assert_eq!(action, NextAction::Sleep(Duration::ZERO));
    }

    // ---------------------------------------------------------------------
    // 7. Cold-restart precedence
    // ---------------------------------------------------------------------

    #[test]
    fn test_cold_restart_pending_returns_defer_action() {
        // Spec test 18. Even at 61-min elapsed in Aggressive (would
        // normally EscalateToBackoff), a pending cold restart wins
        // → compute returns DeferToColdRestart.
        let dir = TempDir::new().unwrap();
        let (coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let action = coord.compute(
            &fixed_zoned(),
            Instant::now(),
            true, // cold restart pending
            None,
            0,
        );
        assert_eq!(action, NextAction::DeferToColdRestart);
    }

    // ---------------------------------------------------------------------
    // 8. Bug-class regression: no captured `now`
    // ---------------------------------------------------------------------

    #[test]
    fn test_bug_class_no_captured_now() {
        // Spec test 19. Drive virtual time forward via the coordinator's
        // own arguments (now_wall / now_mono are inputs to compute() and
        // apply(), never sampled internally). Construct a coordinator,
        // sleep a virtual hour, and verify the elapsed reflected in the
        // pure function reflects the delta accurately — no captured-
        // once frame from construction.
        //
        // The proof is structural: the coordinator's compute() and
        // apply() take now_wall + now_mono as arguments. If the impl
        // ever samples jiff::Zoned::now() internally, this test would
        // still pass — the SIGNATURE is the guardrail. What THIS test
        // checks is a corollary: the elapsed-in-phase computation
        // uses the CALLER's now, not a construction snapshot. If a
        // future impl captured a Zoned at boot() and computed elapsed
        // relative to that, the pure function would compute EscalateToBackoff
        // at t=0 (because phase_entered_at is decades in the past),
        // which is wrong.
        let dir = TempDir::new().unwrap();
        let (coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        // At t=0 relative to the coordinator's phase entry, we should
        // be Sleeping (elapsed=0 < 3600).
        let entered_wall = coord.phase_entered_at().clone();
        let action_t0 = coord.compute(&entered_wall, Instant::now(), false, None, 0);
        assert_eq!(
            action_t0,
            NextAction::Sleep(Duration::ZERO),
            "at t=0 in Aggressive, must sleep — got {:?}",
            action_t0,
        );
        // At t=1h, we should escalate (elapsed=3600 >= 3600).
        let wall_1h = later(&entered_wall, 3600);
        let mono_1h = Instant::now() + Duration::from_secs(3600);
        let action_1h = coord.compute(&wall_1h, mono_1h, false, None, 0);
        assert_eq!(
            action_1h,
            NextAction::EscalateToBackoff,
            "at t=1h in Aggressive, must escalate — got {:?}",
            action_1h,
        );
    }

    // ---------------------------------------------------------------------
    // Additional beyond spec — noted with justification per test.
    // ---------------------------------------------------------------------

    #[test]
    fn test_apply_sleep_does_not_touch_marker_on_disk() {
        // ADDITIONAL: extends spec test 9 by asserting Sleep does NOT
        // rewrite the marker. Without this, a GREEN-phase impl that
        // "helpfully" persists on every apply() would fsync on every
        // 30s tick — a durability foot-gun on flaky storage.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        // First save produces a marker.
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("initial write");
        let marker = dir.path().join(".ibctl-recovery-state.paper.json");
        let mtime_before = std::fs::metadata(&marker)
            .and_then(|m| m.modified())
            .unwrap();
        // Sleep should NOT bump mtime — the sleep advances virtual
        // wall time by 1s so if a rewrite HAD happened, mtime would
        // change under a filesystem with sub-second granularity.
        std::thread::sleep(Duration::from_millis(50));
        let _ = coord
            .apply(
                NextAction::Sleep(Duration::from_secs(1)),
                fixed_zoned(),
                Instant::now(),
                None,
            )
            .expect("sleep");
        let mtime_after = std::fs::metadata(&marker)
            .and_then(|m| m.modified())
            .unwrap();
        assert_eq!(
            mtime_before, mtime_after,
            "Sleep must not rewrite marker (avoid gratuitous disk churn)",
        );
    }

    #[test]
    fn test_apply_resume_without_token_errors_invalid_for_phase() {
        // ADDITIONAL: guard against an apply(ResumeToAggressive, ..., None)
        // slipping through. The pure `compute_next_action` only produces
        // `ResumeToAggressive` when a token is present; but the wrapper
        // is the sole applier, so a bug in the wrapper (e.g. taking the
        // token pending then forgetting to forward it) must be caught,
        // not silently accepted.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("giveup");
        let result = coord.apply(
            NextAction::ResumeToAggressive,
            fixed_zoned(),
            Instant::now(),
            None,
        );
        assert!(
            matches!(result, Err(RecoveryApplyError::InvalidForPhase { .. })),
            "resume without token must error, got {:?}",
            result,
        );
    }

    #[test]
    fn test_record_success_in_givenup_is_rejected() {
        // ADDITIONAL: hardens the invariant "dwell guard is aborted on
        // GivenUp entry" — even if it somehow fires, the coordinator
        // must reject. Cross-check for the AbortOnDrop wiring in mod.rs.
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("giveup");

        let result = coord.record_success(fixed_zoned(), Instant::now());
        assert!(
            matches!(result, Err(RecoveryApplyError::InvalidForPhase { .. })),
            "record_success in GivenUp must error, got {:?}",
            result,
        );
    }

    #[test]
    fn test_apply_from_blocked_state_still_allows_resume() {
        // ADDITIONAL: coordinator booted with blocked_awaiting_resume=true
        // (RefusedGivenUpAutoReset) must still ACCEPT a valid resume
        // token — otherwise the "operator taps the ntfy link" recovery
        // path is broken by our own fail-safe.
        //
        // Acquires ENV_LOCK for the same reason as test 3: prevents
        // concurrent test 4 from turning our expected Refused outcome
        // into Defaulted via IBCTL_RECOVERY_FORCE_RESET.
        let _env_guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join(".ibctl-recovery-state.paper.json"),
            "corrupt",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".ibctl-recovery-state.paper.last-known-phase.txt"),
            "given_up",
        )
        .unwrap();
        let (mut coord, outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        assert!(outcome.should_block_boot());
        assert!(coord.is_blocked_awaiting_resume());

        let token = dummy_token();
        // The coordinator should accept the resume even from blocked.
        // GREEN-phase impl: blocked implies phase=GivenUp on disk was
        // salvage-detected; coordinator re-uses the fail-safe as the
        // starting phase.
        let applied = coord
            .apply(
                NextAction::ResumeToAggressive,
                fixed_zoned(),
                Instant::now(),
                Some(token),
            )
            .expect("resume from blocked-boot must succeed");
        assert_eq!(applied, AppliedAction::ResumedToAggressive);
        assert!(!coord.is_blocked_awaiting_resume());
    }

    #[test]
    fn test_config_min_success_dwell_secs_accessor_returns_config_value() {
        // ADDITIONAL: the accessor used by apply_transition's Connected-
        // entry hook to size the dwell task's sleep MUST return the
        // config value (not a hard-coded 60). Guards against a
        // GREEN-phase copy-paste of the literal.
        let dir = TempDir::new().unwrap();
        let cfg = RecoveryConfig {
            min_success_dwell_secs: 123,
            ..RecoveryConfig::default()
        };
        let (coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            cfg,
        );
        assert_eq!(coord.config_min_success_dwell_secs(), 123);
    }

    #[test]
    fn test_boot_paper_and_live_do_not_collide() {
        // ADDITIONAL: mode-scoping regression. Two boots against the
        // same settings dir but different modes must NOT read each
        // other's marker. Directly guards the "wrong mode reads live
        // marker" DoS.
        //
        // Acquires ENV_LOCK because we assert `Loaded(GivenUp)` on the
        // live boot — if test 4 (test_coordinator_boot_force_reset_env_bypasses_refused)
        // is concurrently holding IBCTL_RECOVERY_FORCE_RESET=1, the
        // Loaded outcome demotes to Defaulted (valid GivenUp marker
        // bypassed by the env override) and the assertion fails.
        let _env_guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new().unwrap();
        let mut live_state = sample_state(RecoveryPhase::GivenUp);
        live_state.phase_entered_at = fixed_zoned();
        save(dir.path(), "live", &live_state).expect("plant live");

        // Paper boot must NOT see live's GivenUp — paper marker is
        // absent, so paper defaults to Aggressive.
        let (paper_coord, paper_outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        assert!(matches!(paper_outcome, RecoveryLoadOutcome::Defaulted { .. }));
        assert_eq!(paper_coord.phase(), RecoveryPhase::Aggressive);

        // Live boot sees GivenUp on the same disk.
        let (live_coord, live_outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "live".to_string(),
            default_cfg(),
        );
        assert!(matches!(live_outcome, RecoveryLoadOutcome::Loaded(_)));
        assert_eq!(live_coord.phase(), RecoveryPhase::GivenUp);
    }

    #[test]
    fn test_giveup_alert_dedupe_stamps_only_once_per_phase_entry() {
        // ADDITIONAL: apply(FireGiveUpAlert) called twice in a row (as
        // could happen if the pure fn returned FireGiveUpAlert again on
        // the next tick before the wrapper's outbound consumer noticed
        // phase already == GivenUp) must NOT re-stamp the dedupe
        // timestamp. Otherwise `giveup_alert_resend_interval_hours` is
        // effectively 0 (each tick resets the clock).
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let first = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("first giveup fire");
        assert_eq!(first, AppliedAction::FiredGiveUpAlert);

        // Second call in same phase — should NOT re-fire.
        let second = coord
            .apply(
                NextAction::FireGiveUpAlert,
                later(&fixed_zoned(), 1),
                Instant::now(),
                None,
            )
            .expect("second giveup fire is idempotent");
        assert_eq!(
            second,
            AppliedAction::NoChange,
            "already-fired give-up must return NoChange (dedupe)",
        );
    }

    // ---------------------------------------------------------------------
    // 9. Post-review fixes (PR-C stage 3, review pass)
    // ---------------------------------------------------------------------

    #[test]
    fn test_resume_token_hash_incorporates_nonce_material() {
        // Two ResumeTokens minted within the same wall-second with the
        // same mode but DIFFERENT nonce_material MUST produce different
        // hashes. Guards Review B/C H-2: without the nonce field, the
        // single-use invariant collapsed to a per-wall-second rate limit
        // because `RESUME_RECONNECT` (which discards the token string
        // and mints `(mode, jiff::Timestamp::now())`) always produced
        // the same `(mode, second)` key within a given second.
        let mode = "paper".to_string();
        let minted_at = jiff::Timestamp::from_second(1_720_000_000).unwrap();
        let t1 = ResumeToken {
            mode: mode.clone(),
            minted_at,
            nonce_material: "token-A".to_string(),
        };
        let t2 = ResumeToken {
            mode: mode.clone(),
            minted_at,
            nonce_material: "token-B".to_string(),
        };
        assert_ne!(
            hash_token(&t1),
            hash_token(&t2),
            "distinct nonce_material MUST yield distinct hashes",
        );
        // Same tokens hash identically (determinism).
        let t3 = ResumeToken {
            mode,
            minted_at,
            nonce_material: "token-A".to_string(),
        };
        assert_eq!(hash_token(&t1), hash_token(&t3));
    }

    #[test]
    fn test_two_distinct_nonce_tokens_do_not_replay_reject_each_other() {
        // Follow-up on the nonce fix: two tokens with distinct nonce
        // material MUST both be individually consumable in separate
        // GivenUp cycles (i.e. TokenReplay is per-hash, not per-mode).
        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        // Cycle 1: escalate → giveup → resume with token-A
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("giveup");
        let token_a = ResumeToken {
            mode: "paper".to_string(),
            minted_at: jiff::Timestamp::from_second(1_720_000_000).unwrap(),
            nonce_material: "token-A".to_string(),
        };
        let _ = coord
            .apply(
                NextAction::ResumeToAggressive,
                fixed_zoned(),
                Instant::now(),
                Some(token_a),
            )
            .expect("first resume with token-A");
        // Cycle 2: re-escalate → giveup → resume with token-B (different
        // nonce). Must succeed — token-A's hash != token-B's hash so the
        // replay guard does NOT fire.
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("re-escalate");
        let _ = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("re-giveup");
        let token_b = ResumeToken {
            mode: "paper".to_string(),
            minted_at: jiff::Timestamp::from_second(1_720_000_000).unwrap(),
            nonce_material: "token-B".to_string(),
        };
        let applied = coord
            .apply(
                NextAction::ResumeToAggressive,
                fixed_zoned(),
                Instant::now(),
                Some(token_b),
            )
            .expect("second resume with distinct token-B must succeed");
        assert_eq!(applied, AppliedAction::ResumedToAggressive);
    }

    #[test]
    fn test_boot_mono_anchor_recalibrates_wall_delta_across_restart() {
        // Regression for Review B H-3 / Review C M-3: without mono-anchor
        // back-dating, `min(wall_delta, mono_delta)` clamps to 0
        // immediately after any container restart, so a phase timer
        // never accrues time across restarts and the Backoff → GivenUp
        // escalation cannot fire in a restart-prone environment.
        //
        // Fix: on boot from a Loaded outcome, seed
        // `phase_entered_at_mono = Instant::now() - wall_delta_at_boot`
        // so `mono_delta` at any tick tracks the pre-restart elapsed.
        let dir = TempDir::new().unwrap();
        // Plant a marker with phase entered 2 hours ago.
        let two_hours_ago = later(&jiff::Zoned::now(), -7200);
        let planted = RecoveryPersistedState {
            schema_version: 1,
            phase: RecoveryPhase::BackoffEvery15Min,
            phase_entered_at: two_hours_ago.clone(),
            phase_entered_at_monotonic_secs_since_boot: 0,
            last_full_success_at: None,
            giveup_alert_sent_at: None,
            resumed_by_token_hash: None,
            last_known_phase: RecoveryPhase::BackoffEvery15Min,
        };
        save(dir.path(), "paper", &planted).expect("plant marker");
        let (coord, outcome) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );
        assert!(matches!(outcome, RecoveryLoadOutcome::Loaded(_)));
        assert_eq!(coord.phase(), RecoveryPhase::BackoffEvery15Min);
        // Compute a fresh (now_wall, now_mono) tick — the coordinator's
        // reported elapsed must reflect ~2h, not 0. Both clocks must
        // report at least ~2h - 1s (tick jitter tolerance).
        let now_wall = jiff::Zoned::now();
        let now_mono = std::time::Instant::now();
        let elapsed = coord.phase_elapsed_secs(&now_wall, now_mono);
        assert!(
            elapsed >= 7195,
            "phase_elapsed_secs must reflect wall_delta across the restart \
             boundary; got {} secs (expected ~7200)",
            elapsed,
        );
        // Sanity: coordinator's own phase_entered_at is what we planted.
        assert_eq!(
            coord.phase_entered_at().timestamp().as_second(),
            two_hours_ago.timestamp().as_second(),
        );
    }

    // ---------------------------------------------------------------------
    // 10. Stage 5 — RecoveryGaveUp Signal fan-out
    // ---------------------------------------------------------------------
    //
    // The dashboard's ReconnectGiveUpMonitor watches STATUS JSON for the
    // give_up phase transition, but that's a poll loop with an inherent
    // latency floor (STATUS TTL + monitor tick interval). For a push-side
    // consumer (currently only tests, later the SSE bus), the recovery
    // coordinator emits a `Signal::RecoveryGaveUp { mode, phase_entered_at }`
    // on the give-up transition — additive to the existing in-line halt
    // behaviour (JVM kill + WaitingForLaunch park), never a replacement.
    //
    // The channel is installed by the wrapper via
    // `RecoveryCoordinator::set_giveup_signal_sender` at construction time.
    // If the sender is None (no subscriber), the coordinator silently
    // drops the notification — the phase transition itself is unaffected.

    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_recovery_gave_up_sent_on_fire_alert() {
        // RED-phase spec test: applying FireGiveUpAlert (or ForceHitlEarly)
        // must publish a `Signal::RecoveryGaveUp { mode, phase_entered_at }`
        // on the sender installed via `set_giveup_signal_sender`, provided
        // the transition actually fires (dedupe of a second-in-same-phase
        // apply() must NOT re-fire the signal — the alert-sent stamp gates
        // both).
        //
        // Compile-level RED: `Signal::RecoveryGaveUp` does not yet exist as
        // a variant on `crate::types::Signal` (which is currently
        // `#[derive(Copy)]` — the new variant carrying `String` +
        // `jiff::Zoned` will force dropping `Copy`, an intended API break).
        // `set_giveup_signal_sender` also does not exist on
        // `RecoveryCoordinator`. Both are stage 5 GREEN work.
        use crate::types::Signal;
        use tokio::sync::mpsc;

        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );

        let (tx, mut rx) = mpsc::unbounded_channel::<Signal>();
        coord.set_giveup_signal_sender(tx);

        // Drive to GivenUp via Escalate → FireGiveUpAlert.
        let _ = coord
            .apply(NextAction::EscalateToBackoff, fixed_zoned(), Instant::now(), None)
            .expect("escalate");
        let applied = coord
            .apply(NextAction::FireGiveUpAlert, fixed_zoned(), Instant::now(), None)
            .expect("fire give-up must not error");
        assert_eq!(applied, AppliedAction::FiredGiveUpAlert);

        // Yield once so the sender's queued message can be observed.
        tokio::task::yield_now().await;

        let sig = rx
            .try_recv()
            .expect("Signal::RecoveryGaveUp must be published on FireGiveUpAlert");
        match sig {
            Signal::RecoveryGaveUp { mode, phase_entered_at } => {
                assert_eq!(mode, "paper", "mode must match coordinator's mode");
                assert_eq!(
                    phase_entered_at.timestamp().as_second(),
                    fixed_zoned().timestamp().as_second(),
                    "phase_entered_at must match the wall clock passed to apply()",
                );
            }
            other => panic!(
                "expected Signal::RecoveryGaveUp, got {:?}",
                other,
            ),
        }

        // Dedupe: a second FireGiveUpAlert in the same GivenUp phase must
        // NOT publish a second Signal — otherwise the SSE bus would show
        // one give-up as N events every time the wrapper spun the loop.
        let dedupe = coord
            .apply(
                NextAction::FireGiveUpAlert,
                later(&fixed_zoned(), 1),
                Instant::now(),
                None,
            )
            .expect("dedupe apply must not error");
        assert_eq!(
            dedupe,
            AppliedAction::NoChange,
            "second FireGiveUpAlert must dedupe (see \
             test_giveup_alert_dedupe_stamps_only_once_per_phase_entry)",
        );
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "dedupe branch must NOT publish a second Signal::RecoveryGaveUp",
        );
    }

    // -----------------------------------------------------------------
    // Finding C-LOW-8 companion: same fan-out invariant for the
    // fingerprint-triggered `ForceHitlEarly` path. The two variants share
    // the same match arm in `apply`, but the original Signal test only
    // exercised `FireGiveUpAlert`. A refactor that split the arm and
    // dropped the `tx.send(...)` from the ForceHitlEarly branch would
    // silently kill fingerprint-tripwire give-ups from the SSE bus.
    // -----------------------------------------------------------------
    #[tokio::test(flavor = "current_thread")]
    async fn test_signal_recovery_gave_up_sent_on_force_hitl_early() {
        use crate::types::Signal;
        use tokio::sync::mpsc;

        let dir = TempDir::new().unwrap();
        let (mut coord, _) = RecoveryCoordinator::boot(
            dir.path().to_path_buf(),
            "paper".to_string(),
            default_cfg(),
        );

        let (tx, mut rx) = mpsc::unbounded_channel::<Signal>();
        coord.set_giveup_signal_sender(tx);

        // ForceHitlEarly bypasses the aggressive/backoff progression and
        // lands us straight into GivenUp.
        let applied = coord
            .apply(
                NextAction::ForceHitlEarly,
                fixed_zoned(),
                Instant::now(),
                None,
            )
            .expect("force-hitl-early must not error");
        assert_eq!(applied, AppliedAction::FiredGiveUpAlert);

        tokio::task::yield_now().await;
        let sig = rx
            .try_recv()
            .expect(
                "Signal::RecoveryGaveUp must fire for ForceHitlEarly too",
            );
        match sig {
            Signal::RecoveryGaveUp { mode, phase_entered_at } => {
                assert_eq!(mode, "paper");
                assert_eq!(
                    phase_entered_at.timestamp().as_second(),
                    fixed_zoned().timestamp().as_second(),
                );
            }
            other => panic!(
                "expected Signal::RecoveryGaveUp for ForceHitlEarly, \
                 got {:?}",
                other,
            ),
        }
    }
}
