//! What the Sunday cold restart does to one mode — decided in ONE place.
//!
//! IBKR requires a full re-authentication once a week; the scheduler in
//! `cold_restart.rs` sends `ColdRestartSignal::Fire` at the configured
//! Sunday time. What that fire should *do* depends entirely on where the
//! mode already is, because "restart completed" and "authentication
//! completed" are separate events:
//!
//! * A mode that already restarted and is **waiting for the operator's
//!   2FA** does not need another restart — it needs its unfinished login
//!   finished, in the JVM that is running. It gets the same in-JVM retry
//!   `HITL_RESUME` performs (`StateMachine::begin_in_jvm_relogin`).
//! * A mode whose Gateway **still shows the IB Key dialog** keeps that
//!   push — it may still be approvable — and retries once the Gateway
//!   closes it.
//! * A mode with a login **already in progress** is not restarted under
//!   that login (no competing recovery); the re-auth is owed and settled
//!   when that login ends.
//! * A standby or an exiting process is intentionally idle; a failed
//!   mode is not — it gets an explicit, loud outcome.
//!
//! Before this module, the decision lived in two places: the main loop's
//! `select!` arm (which filed `WaitingForHitl2fa` under "dormant") and a
//! preemption block in `do_waiting_for_hitl_2fa` that polled a dummy
//! receiver and could never fire. Between them, a mode waiting in HITL
//! when the fire arrived was left waiting there for hours.
//!
//! Pure: no clock reads, no I/O, exhaustive `match` with no wildcard arm —
//! adding a `State` variant is a compile error here until someone decides
//! what the Sunday fire means for it.

use super::types::State;
use crate::types::ColdRestartOutcome;

/// Decide the Sunday cold restart's outcome for a mode in `state`.
///
/// * `challenge_open` — the Gateway is showing its IB Key dialog
///   (`AgentObservation::has_2fa_dialog`). The Gateway closes that dialog
///   itself when IBKR expires the push, so while it is up the push may
///   still be approvable. Observed rather than timed: IBKR does not publish
///   the push lifetime (in practice the dialog closes a few minutes after
///   opening), and an open dialog is no proof the phone still shows the
///   prompt — hence "pending", with the operator told as much.
/// * `preempts_hitl` — `twofa.backoff.cold_restart_preempts_hitl`.
pub(super) fn decide(state: &State, challenge_open: bool, preempts_hitl: bool) -> ColdRestartOutcome {
    match state {
        State::Connected => ColdRestartOutcome::Restarted,

        State::WaitingFor2fa => ColdRestartOutcome::ChallengePending,
        State::WaitingForHitl2fa if challenge_open => ColdRestartOutcome::ChallengePending,
        State::WaitingForHitl2fa if preempts_hitl => ColdRestartOutcome::ResumedLogin,
        State::WaitingForHitl2fa => ColdRestartOutcome::AwaitingOperator,

        State::Init
        | State::Launching
        | State::WaitingForAgent
        | State::WaitingForLogin
        | State::Authenticating
        | State::HandlingSessionConflict
        | State::DismissingPopups
        | State::WaitingForApiReady
        | State::ConfiguringApi
        | State::Restarting
        | State::ReconnectingSession
        | State::WaitingForIB => ColdRestartOutcome::Deferred,

        State::WaitingForLaunch => ColdRestartOutcome::Standby,
        State::Shutdown => ColdRestartOutcome::Stopping,
        State::Error(detail) => ColdRestartOutcome::Failed { detail: detail.clone() },
    }
}

/// Does this outcome leave the week's re-authentication still owed?
/// An owed re-auth is settled at the mode's next `Connected`: recorded
/// `Completed` if that login authenticated, otherwise the cold restart
/// runs then.
pub(super) fn owes_reauth(outcome: &ColdRestartOutcome) -> bool {
    matches!(
        outcome,
        ColdRestartOutcome::ResumedLogin
            | ColdRestartOutcome::ChallengePending
            | ColdRestartOutcome::AwaitingOperator
            | ColdRestartOutcome::Deferred
            | ColdRestartOutcome::Failed { .. }
            | ColdRestartOutcome::RestartedByBoot
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_is_restarted() {
        assert_eq!(decide(&State::Connected, false, true), ColdRestartOutcome::Restarted);
    }

    #[test]
    fn hitl_with_the_prompt_gone_is_resumed_not_dormant() {
        // In HITL for hours; the Gateway closed the push dialog minutes in.
        assert_eq!(decide(&State::WaitingForHitl2fa, false, true), ColdRestartOutcome::ResumedLogin);
    }

    #[test]
    fn hitl_with_preemption_disabled_is_awaiting_operator_not_dormant() {
        assert_eq!(
            decide(&State::WaitingForHitl2fa, false, false),
            ColdRestartOutcome::AwaitingOperator,
        );
    }

    #[test]
    fn hitl_with_the_prompt_on_screen_preserves_it() {
        for preempts in [true, false] {
            assert_eq!(
                decide(&State::WaitingForHitl2fa, true, preempts),
                ColdRestartOutcome::ChallengePending,
            );
        }
    }

    #[test]
    fn outstanding_push_is_preserved() {
        for open in [true, false] {
            assert_eq!(decide(&State::WaitingFor2fa, open, true), ColdRestartOutcome::ChallengePending);
        }
    }

    #[test]
    fn every_login_in_progress_state_defers_instead_of_restarting_under_it() {
        for s in [
            State::Init,
            State::Launching,
            State::WaitingForAgent,
            State::WaitingForLogin,
            State::Authenticating,
            State::HandlingSessionConflict,
            State::DismissingPopups,
            State::WaitingForApiReady,
            State::ConfiguringApi,
            State::Restarting,
            State::ReconnectingSession,
            State::WaitingForIB,
        ] {
            assert_eq!(decide(&s, false, true), ColdRestartOutcome::Deferred, "state {s}");
        }
    }

    #[test]
    fn intentional_idle_is_distinct_from_failure() {
        assert_eq!(decide(&State::WaitingForLaunch, false, true), ColdRestartOutcome::Standby);
        assert_eq!(decide(&State::Shutdown, false, true), ColdRestartOutcome::Stopping);
        assert_eq!(
            decide(&State::Error("jvm died".into()), false, true),
            ColdRestartOutcome::Failed { detail: "jvm died".into() },
        );
    }

    #[test]
    fn owed_outcomes() {
        use ColdRestartOutcome as O;
        for o in [O::ResumedLogin, O::ChallengePending, O::AwaitingOperator, O::Deferred, O::Failed { detail: "x".into() }] {
            assert!(owes_reauth(&o), "{o:?} must owe the re-auth");
        }
        for o in [O::Restarted, O::Standby, O::Stopping] {
            assert!(!owes_reauth(&o), "{o:?} must not owe the re-auth");
        }
    }
}
