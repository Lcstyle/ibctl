//! Sunday cold restart timer.
//!
//! IBKR requires a full shutdown and re-login once a week (Sundays).
//! Gateway does NOT have a built-in cold restart — this is an IBC feature
//! that ibctl must replicate.
//!
//! How IBC handles it:
//! 1. IBC's Java code runs a timer checking for Sunday + ColdRestartTime
//! 2. When timer fires, creates COLDRESTART marker file
//! 3. Shuts down the Gateway JVM
//! 4. ibcstart.sh's while loop detects exit, finds marker, clears autorestart
//! 5. Relaunches JVM without autorestart flag → forces full re-auth + 2FA
//!
//! How ibctl handles it:
//! 1. Rust background task ticks every 30s.
//! 2. Each tick calls the PURE [`compute_next_action`] function with a fresh
//!    wall-clock sample and a fresh on-disk [`MarkerState`] snapshot. The
//!    decision is one of [`NextAction::Sleep`], [`NextAction::Skip`], or
//!    [`NextAction::FireEligible`].
//! 3. The fire window is "at-or-past target time on target day, with
//!    marker dedup" — NOT a strict minute equality. This deliberate
//!    widening defends against NTP forward jumps that would otherwise
//!    skip the exact minute landing (e.g., 08:45 → 10:00 step → never
//!    sampled 09:00). The on-disk fired marker provides the single-fire
//!    invariant.
//! 4. When FireEligible, the wrapper logs PENDING, sleeps 30s, then RE-EVALUATES
//!    by calling `compute_next_action` again with a fresh sample. This closes
//!    the race where a real cold-restart-equivalent (2FA re-auth) landed
//!    inside the warning window.
//! 5. Writes marker file to settings dir (survives container restart if
//!    volume-mounted) BEFORE sending the channel signal. If the marker
//!    write FAILS, the Fire signal is NOT sent — the wider window would
//!    otherwise re-fire on the next tick. This trades availability (we
//!    log an error and retry) for safety (no 2FA spam loop on broken
//!    permissions).
//! 6. Sends signal to state machine which kills JVM and does full re-auth.
//!
//! ## Bug-class proof: captured-once-then-stale state is unrepresentable
//!
//! The historical Bug 1 + Bug 4 were both instances of the same class — a RAM
//! boolean derived from `jiff::Zoned::now()` AT CONSTRUCTION that gated a
//! per-tick decision and went stale when a calendar boundary advanced past
//! the captured frame. The bug class is now eliminated by structure:
//!
//! - The PURE function [`compute_next_action`] has no `&mut self`, no closure
//!   environment, no statics — its type signature forbids hidden state.
//! - The SOLE captured-state container [`SchedulerConfig`] documents that no
//!   field may be a DERIVED PREDICATE (bool or scalar interpreting `now()`).
//!   The only time-derived field is [`SchedulerConfig::boot_at`], which is an
//!   immutable FACT (a specific wall-clock instant) — facts about the past do
//!   not go stale. Their INTERPRETATION ("was it past target?") is recomputed
//!   per-tick via [`started_past_target_on_startup_day`].
//! - The CI-enforced regression test
//!   `bug1_bug4_two_consecutive_sundays_same_cfg_both_fire` holds ONE
//!   `SchedulerConfig` across two synthetic Sundays and proves both
//!   return `FireEligible` from the pure function.
//! - The async-loop-body regression test
//!   `bug1_bug4_async_two_virtual_sundays_both_fire_via_scheduler_loop`
//!   drives the ACTUAL [`scheduler_loop`] async closure body across two
//!   virtual Sundays with `tokio::time::advance` and an injected clock,
//!   asserting two `ColdRestartSignal::Fire` arrive on the channel using
//!   ONE process lifetime / ONE `SchedulerConfig`. This catches the
//!   Bug 1 / Bug 4 class even if it lives in the async closure body
//!   (e.g., a future `let mut fired_this_lifetime = false;` captured by
//!   the per-tick match arm).
//! - The property test `bug_class_invariant_compute_next_action_is_pure`
//!   calls compute_next_action thrice with identical inputs and asserts
//!   identical outputs — catching any cached/hidden state.
//!
//! Timezone: respects the TZ env var (jiff uses system timezone).

use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::sync::mpsc;

use crate::types::{ColdRestartSignal, ColdRestartSkipReason};

// ---------------------------------------------------------------------------
// Public types (module-public so tests can construct them; SchedulerConfig
// fields are pub so test fixtures can build synthetic configs without
// reflection or test-only constructors).
// ---------------------------------------------------------------------------

/// Immutable facts captured ONCE at scheduler construction.
///
/// INVARIANT: every field is either pure config or an immutable wall-clock
/// FACT. No field is a DERIVED predicate (no booleans, no "did we already
/// do X?" scalars). The only time-derived field is [`boot_at`], which is
/// the raw wall-clock instant — its INTERPRETATION is recomputed per-tick
/// by [`compute_next_action`], never cached.
///
/// CODE REVIEW RULE: rejecting a PR that adds a bool/derived-scalar field
/// here is mandatory. See the `bug_class_invariant_compute_next_action_is_pure`
/// and `bug1_bug4_two_consecutive_sundays_same_cfg_both_fire` tests.
///
/// [`boot_at`]: SchedulerConfig::boot_at
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Target day-of-week, Sunday=0..Saturday=6 (matches
    /// [`jiff::Weekday::to_sunday_zero_offset`]).
    pub target_dow: u32,
    /// Target hour, 0..=23 (24h clock).
    pub target_hour: u32,
    /// Target minute, 0..=59.
    pub target_minute: u32,
    /// IMMUTABLE FACT — wall-clock at scheduler construction. NOT a predicate.
    /// `compute_next_action` recomputes interpretation per-tick from
    /// `(boot_at, now)`. To "refresh" this field, reconstruct the future.
    pub boot_at: jiff::Zoned,
}

/// Per-tick snapshot of on-disk marker state. Built fresh from IO by the
/// async wrapper at the top of each tick (and again after the warning
/// sleep). NEVER carried across tick boundaries — falls out of scope at
/// `continue`.
#[derive(Debug, Clone)]
pub struct MarkerState {
    /// `already_fired(marker_path, now.year, now.day_of_year)` — true iff the
    /// on-disk fired marker matches today's (year, day_of_year).
    pub fired_today: bool,
    /// `read_cold_restart_equivalent_marker(equiv_path)`; None = absent or
    /// unparseable (fail-safe toward firing).
    pub equivalent_marker: Option<jiff::Zoned>,
}

/// Per-tick decision from [`compute_next_action`].
#[derive(Debug, Clone)]
pub enum NextAction {
    /// Not eligible at this instant. Wrapper continues to next tick.
    Sleep,
    /// Skip predicate matured. Wrapper writes the fired marker (with
    /// pre-wait timestamp) and emits
    /// [`ColdRestartSignal::Skipped`](crate::types::ColdRestartSignal::Skipped).
    Skip { reason: ColdRestartSkipReason },
    /// Fire-eligible AND the skip predicate did not mature. Wrapper:
    ///
    /// - First call (initial tick): logs PENDING, sleeps 30s, re-evaluates.
    /// - Second call (after warning): writes marker, sends Fire.
    ///
    /// The pure function does NOT distinguish the two calls — only inputs
    /// differ. This is what makes the warning-window race close testable
    /// with a single pure-function table.
    FireEligible,
}

/// Equality for [`NextAction`] compares discriminants and (for `Skip`)
/// reason discriminants — NOT inner `jiff::Zoned` payloads. This is the
/// useful equality for assertions: two Skip decisions count as equal when
/// they agree on the REASON the scheduler chose Skip, regardless of the
/// exact wall-clock instant the marker recorded. Tests that need the
/// payload destructure with `match` and inspect fields directly.
impl PartialEq for NextAction {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (NextAction::Sleep, NextAction::Sleep) => true,
            (NextAction::FireEligible, NextAction::FireEligible) => true,
            (NextAction::Skip { reason: a }, NextAction::Skip { reason: b }) => {
                matches!(
                    (a, b),
                    (
                        ColdRestartSkipReason::FreshAuthToday { .. },
                        ColdRestartSkipReason::FreshAuthToday { .. },
                    ) | (
                        ColdRestartSkipReason::DormantSite,
                        ColdRestartSkipReason::DormantSite,
                    )
                )
            }
            _ => false,
        }
    }
}

const DAY_NAMES: [&str; 7] = [
    "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
];

// ---------------------------------------------------------------------------
// Pure decision layer (zero IO, zero time-sampling, zero logging).
// ---------------------------------------------------------------------------

/// THE sole authority for fire/skip/sleep decisions. Referentially
/// transparent.
///
/// CONTRACT: this function has NO captured state. It does not call
/// [`jiff::Zoned::now`], does not touch the filesystem, does not log, does
/// not take `&mut self`. Any future change that violates this contract
/// must be reverted. The `bug_class_invariant_compute_next_action_is_pure`
/// determinism test catches violations mechanically.
///
/// See the module-level "Bug-class proof" section for the structural
/// argument that captured-once-then-stale state is unrepresentable here.
pub fn compute_next_action(
    now: &jiff::Zoned,
    cfg: &SchedulerConfig,
    markers: &MarkerState,
) -> NextAction {
    // Gate 1: target weekday.
    let now_dow = now.weekday().to_sunday_zero_offset() as u32;
    if now_dow != cfg.target_dow {
        return NextAction::Sleep;
    }

    // Gate 2: per-day dedup via on-disk marker (NOT a RAM bool).
    // This is the SOLE cross-day state. Lives on disk, date-keyed via
    // (year, day_of_year), freshly read each tick by the wrapper.
    if markers.fired_today {
        return NextAction::Sleep;
    }

    // Gate 3: startup-day veto. Recomputed per-tick from (boot_at, now).
    // Returns false the instant the calendar day advances past boot day.
    // This is the structural Bug 4 fix — no captured-once bool exists.
    if started_past_target_on_startup_day(
        &cfg.boot_at,
        now,
        cfg.target_dow,
        cfg.target_hour,
        cfg.target_minute,
    ) {
        return NextAction::Sleep;
    }

    // Gate 4: at-or-past target time on target day.
    //
    // This is INTENTIONALLY wider than strict-equality on (hour, minute).
    // Strict equality created a 60-second landing window that an NTP forward
    // jump could skip entirely — e.g., wall-clock 08:45 → 10:00 jump on
    // target Sunday would never sample 09:00 and the scheduler would wait
    // a full week. With the wider window, any sample on the target day at
    // or after the target time fires (and the on-disk fired marker dedups
    // to a single fire per day). The startup-day veto above still scopes
    // the boot-day past-target case to a one-day skip.
    let now_h = now.hour() as u32;
    let now_m = now.minute() as u32;
    let past_target =
        now_h > cfg.target_hour || (now_h == cfg.target_hour && now_m >= cfg.target_minute);
    if !past_target {
        return NextAction::Sleep;
    }

    // Fire-eligible. Apply skip predicate against the equivalent marker.
    if let Some(marker) = &markers.equivalent_marker {
        if should_skip_for_marker(marker, now, cfg.target_hour, cfg.target_minute) {
            return NextAction::Skip {
                reason: ColdRestartSkipReason::FreshAuthToday { at: marker.clone() },
            };
        }
    }

    NextAction::FireEligible
}

/// Pure: did the scheduler boot on the target weekday past the target time
/// AND has the calendar day NOT yet advanced past the boot day?
///
/// Scoped to the boot calendar day; returns false every subsequent day. This
/// is the structural Bug 4 fix — replaces the previously-captured
/// `started_past_target: bool` derived once from `Zoned::now()` at
/// construction.
pub fn started_past_target_on_startup_day(
    boot_at: &jiff::Zoned,
    now: &jiff::Zoned,
    target_dow: u32,
    target_hour: u32,
    target_minute: u32,
) -> bool {
    if boot_at.year() != now.year() || boot_at.day_of_year() != now.day_of_year() {
        return false;
    }
    let boot_dow = boot_at.weekday().to_sunday_zero_offset() as u32;
    if boot_dow != target_dow {
        return false;
    }
    let bh = boot_at.hour() as u32;
    let bm = boot_at.minute() as u32;
    bh > target_hour || (bh == target_hour && bm > target_minute)
}

/// Decide whether a cold-restart-equivalent marker matures into a "skip" for
/// today's scheduled fire.
///
/// Returns true when ALL three conditions hold (single source of truth — see
/// architect's design constraint for Bug 3):
///   1. The marker's date matches today's local date (`==`).
///   2. The marker's hour-of-day is >= 1 (excludes operator midnight sessions
///      between 00:00 and 01:00 that aren't "fresh enough" to count).
///   3. The marker's time-of-day is STRICTLY less than the scheduled target
///      time (so a marker written *after* the target hour does NOT count —
///      that case is handled by the separate `already_fired` marker which
///      records the actual cold-restart firing).
///
/// All comparisons run in the same local frame as the scheduler's wall-clock
/// (`jiff::Zoned::now()` honoring TZ). Do NOT mix UTC or Instant here.
///
/// DST fall-back ambiguity: on the night the local clock falls back an hour
/// (e.g. 02:00 EDT becomes 01:00 EST and the 01:00-01:59 window is replayed),
/// a marker written at 01:30 of the *first* pass and a `now` of 01:30 of the
/// *second* pass both report hour=1 and the same date. The predicate fires
/// Skip in both passes. This is acceptable UX (the operator did authenticate
/// recently, on the same calendar day, before the scheduled target) but is
/// formally ambiguous — the marker preserves its offset via the IANA tag in
/// `jiff::Zoned::Display`, so a downstream consumer that needs to distinguish
/// the two passes can read `marker.offset()` vs `now.offset()`.
pub fn should_skip_for_marker(
    marker: &jiff::Zoned,
    now: &jiff::Zoned,
    target_hour: u32,
    target_minute: u32,
) -> bool {
    if marker.date() != now.date() {
        return false;
    }
    if (marker.hour() as u32) < 1 {
        return false;
    }
    let target_time = match jiff::civil::Time::new(
        target_hour as i8,
        target_minute as i8,
        0,
        0,
    ) {
        Ok(t) => t,
        Err(_) => return false, // unreachable for valid parse output, fail-safe
    };
    marker.time() < target_time
}

// ---------------------------------------------------------------------------
// Configuration parsing (preserved verbatim).
// ---------------------------------------------------------------------------

/// Parse a cold restart time like "09:00" (24h format).
pub fn parse_cold_restart_time(time_str: &str) -> Option<(u32, u32)> {
    let time_str = time_str.trim();
    if time_str.is_empty() {
        return None;
    }

    let parts: Vec<&str> = time_str.split(':').collect();
    if parts.len() != 2 {
        log::warn!("Invalid cold restart time format '{}' — expected HH:MM", time_str);
        return None;
    }

    let hour: u32 = parts[0].parse().ok()?;
    let minute: u32 = parts[1].parse().ok()?;

    if hour > 23 || minute > 59 {
        log::warn!("Invalid cold restart time '{}' — hour/minute out of range", time_str);
        return None;
    }

    Some((hour, minute))
}

// ---------------------------------------------------------------------------
// IO helpers (wrapper-owned, atomic).
// ---------------------------------------------------------------------------

/// Build a [`MarkerState`] snapshot from two file reads. Called by the
/// wrapper once per tick (and once after the warning sleep). Never called
/// from [`compute_next_action`].
///
/// Takes `now` as a parameter so the `(now, markers)` snapshot is a
/// syntactic pair — preventing a future engineer from reading markers in
/// a different frame than the decision uses.
fn read_marker_state(
    marker_path: &Path,
    equiv_path: &Path,
    now: &jiff::Zoned,
) -> MarkerState {
    MarkerState {
        fired_today: already_fired(
            marker_path,
            now.year() as i32,
            now.day_of_year() as u32,
        ),
        equivalent_marker: read_cold_restart_equivalent_marker(equiv_path),
    }
}

/// Check if cold restart already fired for the given date.
/// Marker file contains "YYYY-DDD" (year-day_of_year).
fn already_fired(marker_path: &Path, year: i32, day_of_year: u32) -> bool {
    match std::fs::read_to_string(marker_path) {
        Ok(contents) => contents.trim() == format!("{}-{}", year, day_of_year),
        Err(_) => false, // fail-safe toward firing
    }
}

/// Read the cold-restart-equivalent marker, returning the parsed timestamp.
///
/// The marker is written by the state machine when it enters Connected from
/// a credential-gathering state AND a 2FA challenge was answered earlier in
/// this JVM lifecycle (see `state_machine::markers`). Returns `None` for
/// missing or unparseable files — fail-safe toward re-firing.
///
/// We deliberately do NOT call `with_time_zone(TimeZone::system())` here.
/// Re-projecting shifts the wall-clock hour-of-day across a TZ change
/// (08:30 EDT becomes 12:30 UTC), which defeats the `marker.time() <
/// target_time` skip predicate. The marker stores its own TZ (via
/// `jiff::Zoned::Display`, which writes `YYYY-MM-DDTHH:MM:SS-HH:MM[Area/Loc]`
/// when an IANA zone is known) so date/hour comparisons should run in the
/// frame the marker was written in. Callers are expected to pass `now` in
/// the same frame they want the comparison done.
///
/// Operator invariant: TZ should remain stable across container restarts.
/// Crossing TZ on the same site between marker write and read is undefined
/// behavior — operationally rare, and would only matter on the Sunday the
/// TZ change happened anyway.
fn read_cold_restart_equivalent_marker(path: &Path) -> Option<jiff::Zoned> {
    let raw = std::fs::read_to_string(path).ok()?;
    jiff::Zoned::from_str(raw.trim()).ok()
}

/// Write marker recording that cold restart fired for this date.
///
/// Writes via temp-file + rename so concurrent readers either see the prior
/// content or the new content — never a torn or empty file. Atomicity is
/// best-effort on POSIX (rename within the same filesystem is atomic) and
/// degrades to non-atomic on cross-filesystem renames; that case is not a
/// concern here because the temp file lives in the same directory as the
/// marker.
///
/// Returns Err on IO failure. The wrapper REQUIRES success before sending
/// the Fire signal — under the wider fire window (see
/// [`compute_next_action`]), a failed marker write would otherwise re-fire
/// every tick for the rest of the day, spamming 2FA. On Err, the wrapper
/// logs an error and skips the Fire send; the next tick retries the write.
fn write_fired_marker(marker_path: &Path, now: &jiff::Zoned) -> std::io::Result<()> {
    let content = format!("{}-{}", now.year(), now.day_of_year());
    match atomic_write(marker_path, content.as_bytes()) {
        Ok(()) => {
            log::info!(
                "Cold restart marker written to {}",
                marker_path.display()
            );
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "Failed to write cold restart marker to {}: {}",
                marker_path.display(),
                e
            );
            Err(e)
        }
    }
}

/// Atomic file write via temp file + rename.
///
/// Mitigates the torn-read race a concurrent reader would otherwise see if
/// `std::fs::write` were used (truncate-then-write). Without this, an empty
/// or partial file could be parsed as "no marker", momentarily wedging the
/// scheduler into a re-fire decision.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "marker path has no file name"))?;
    let mut tmp_name = file_name.to_os_string();
    tmp_name.push(".tmp");
    let tmp_path = parent.join(tmp_name);

    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all().ok(); // best-effort flush; rename is the durability point
    }
    std::fs::rename(&tmp_path, path)
}

// ---------------------------------------------------------------------------
// Thin async wrapper (IO + timing + logging).
// ---------------------------------------------------------------------------

/// Create the cold restart timer future.
///
/// Returns `None` if cold restart is not configured (empty time string).
/// The returned future should be spawned via a `JoinSet` for structured
/// concurrency — the caller owns the task lifetime.
///
/// Thin shim: parses the configuration, derives the marker path from
/// `TWS_SETTINGS_PATH`, logs the startup banner, and delegates the
/// async loop body to [`scheduler_loop`]. The loop body is the SAME
/// code path tests exercise via the injected-clock variant.
///
/// The future:
/// - Ticks every 30 seconds via `tokio::time::sleep`.
/// - Samples `jiff::Zoned::now()` EXACTLY twice per fire cycle: once at the
///   top of the tick, once after the 30s warning sleep.
/// - Delegates every fire/skip/sleep decision to [`compute_next_action`].
/// - Writes the on-disk marker BEFORE sending the channel signal.
/// - Persists via marker file in `TWS_SETTINGS_PATH` (volume-mounted).
/// - Returns only when a channel send fails (receiver dropped).
pub fn cold_restart_scheduler(
    cold_restart_time: String,
    cold_restart_day: u8,
    tx: mpsc::Sender<ColdRestartSignal>,
    cold_restart_equivalent_marker_path: PathBuf,
) -> Option<impl std::future::Future<Output = ()>> {
    let (target_hour, target_minute) = match parse_cold_restart_time(&cold_restart_time) {
        Some(t) => t,
        None => {
            log::info!("Cold restart not configured (TWS_COLD_RESTART not set)");
            return None;
        }
    };

    // Marker file: stored in settings dir so it survives container restart
    // if the settings dir is volume-mounted.
    let settings_dir = std::env::var("TWS_SETTINGS_PATH")
        .unwrap_or_else(|_| "/home/ibgateway/Jts".to_string());
    let marker_path = PathBuf::from(&settings_dir).join(".ibctl-cold-restart-marker");

    let target_dow = (cold_restart_day.min(6)) as u32;
    let day_name = DAY_NAMES[target_dow as usize];
    let tz = std::env::var("TZ").unwrap_or_else(|_| "(system default)".to_string());

    // The SOLE captured time-derived state: an immutable FACT, not a
    // predicate. `compute_next_action` recomputes interpretation per-tick.
    let cfg = SchedulerConfig {
        target_dow,
        target_hour,
        target_minute,
        boot_at: jiff::Zoned::now(),
    };

    log::info!(
        "Cold restart timer active: {}s at {:02}:{:02} (TZ={}, marker={}, cold_restart_equivalent_marker={})",
        day_name,
        target_hour,
        target_minute,
        tz,
        marker_path.display(),
        cold_restart_equivalent_marker_path.display(),
    );

    // One-shot startup log — derived from cfg.boot_at, NOT cached as a bool.
    // The result is consumed inline by the `if` and never assigned to a
    // binding outside the conditional. Purely cosmetic; the per-tick veto
    // recomputes from boot_at every call to compute_next_action.
    if started_past_target_on_startup_day(
        &cfg.boot_at,
        &cfg.boot_at,
        target_dow,
        target_hour,
        target_minute,
    ) {
        log::info!(
            "Cold restart: started after target time — will fire next {} at {:02}:{:02}",
            day_name,
            target_hour,
            target_minute,
        );
    }

    Some(scheduler_loop(
        cfg,
        day_name,
        tx,
        marker_path,
        cold_restart_equivalent_marker_path,
        jiff::Zoned::now,
    ))
}

/// Async loop body shared by production [`cold_restart_scheduler`] and
/// the regression test that drives two virtual Sundays through one
/// process lifetime.
///
/// The `now_fn` closure is the SOLE source of wall-clock time. Production
/// passes `jiff::Zoned::now`; tests pass a closure that reads from an
/// `Arc<Mutex<jiff::Zoned>>` so they can advance virtual wall-clock time
/// in lock-step with `tokio::time::advance`.
///
/// CRITICAL: the marker write MUST succeed before the Fire signal is
/// sent. Under the wider fire window (`compute_next_action`), a failed
/// write would re-fire every tick for the rest of the day. On failure,
/// the wrapper logs an error and continues without firing — the next
/// tick re-evaluates.
fn scheduler_loop<F>(
    cfg: SchedulerConfig,
    day_name: &'static str,
    tx: mpsc::Sender<ColdRestartSignal>,
    marker_path: PathBuf,
    cold_restart_equivalent_marker_path: PathBuf,
    now_fn: F,
) -> impl std::future::Future<Output = ()>
where
    F: Fn() -> jiff::Zoned + Send + 'static,
{
    use std::time::Duration;

    async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;

            // ONE wall-clock sample per tick (no double-sample drift).
            // The (now_pre, markers_pre) pair is the consistent snapshot
            // the per-tick decision runs over. Both fall out of scope at
            // `continue`, so nothing carries across tick boundaries.
            let now_pre = now_fn();
            let markers_pre = read_marker_state(
                &marker_path,
                &cold_restart_equivalent_marker_path,
                &now_pre,
            );

            match compute_next_action(&now_pre, &cfg, &markers_pre) {
                NextAction::Sleep => continue,

                NextAction::Skip { reason } => {
                    let at_str = match &reason {
                        ColdRestartSkipReason::FreshAuthToday { at } => at.to_string(),
                        ColdRestartSkipReason::DormantSite => String::new(),
                    };
                    log::info!(
                        "Cold restart skipped at {:02}:{:02} — cold-restart-equivalent completed earlier today at {}",
                        cfg.target_hour, cfg.target_minute, at_str,
                    );
                    // Best-effort marker write for Skip — even if it
                    // fails, the skip predicate itself prevents
                    // immediate re-fire (the equivalent_marker still
                    // matures the predicate).
                    let _ = write_fired_marker(&marker_path, &now_pre);
                    if tx.send(ColdRestartSignal::Skipped(reason)).await.is_err() {
                        log::warn!("Cold restart signal channel closed (Skipped path)");
                        return;
                    }
                    continue;
                }

                NextAction::FireEligible => {
                    log::warn!(
                        "Cold restart PENDING — {} {:02}:{:02} — firing in 30 seconds (2FA will be required)",
                        day_name, cfg.target_hour, cfg.target_minute,
                    );

                    // Phase 1: warning window — gives time for ntfy alert
                    // delivery + phone pickup. ONE allowed extra Zoned
                    // sample at the end of this sleep (`now_post` below).
                    tokio::time::sleep(Duration::from_secs(30)).await;

                    // Bug 3 race close: re-sample wall-clock + re-read
                    // markers. If a real cold-restart-equivalent landed
                    // during the warning window, compute_next_action
                    // returns Skip; we emit Skipped instead of Fire.
                    let now_post = now_fn();
                    let markers_post = read_marker_state(
                        &marker_path,
                        &cold_restart_equivalent_marker_path,
                        &now_post,
                    );

                    match compute_next_action(&now_post, &cfg, &markers_post) {
                        NextAction::Skip { reason } => {
                            let at_str = match &reason {
                                ColdRestartSkipReason::FreshAuthToday { at } => at.to_string(),
                                ColdRestartSkipReason::DormantSite => String::new(),
                            };
                            log::info!(
                                "Cold restart re-check after warning window — cold-restart-equivalent completed at {} — emitting Skipped instead of Fire",
                                at_str,
                            );
                            // Pre-wait timestamp — we scheduled THIS day.
                            let _ = write_fired_marker(&marker_path, &now_pre);
                            if tx.send(ColdRestartSignal::Skipped(reason)).await.is_err() {
                                log::warn!("Cold restart signal channel closed (Skipped race path)");
                                return;
                            }
                        }
                        // FireEligible (normal) OR Sleep (NTP slewed past
                        // the target day during the warning window — e.g.
                        // crossed midnight into Monday — fail-safe
                        // direction is to fire, not retry next week) →
                        // Fire, but ONLY if the marker write succeeds.
                        _ => {
                            log::info!(
                                "Cold restart firing now ({} {:02}:{:02})",
                                day_name, cfg.target_hour, cfg.target_minute,
                            );
                            // CRITICAL: under the wider fire window, the
                            // marker is the ONLY thing preventing a
                            // re-fire loop on the same day. If the write
                            // fails, we MUST skip the Fire send — the
                            // operator must fix permissions to recover.
                            match write_fired_marker(&marker_path, &now_pre) {
                                Ok(()) => {
                                    if tx.send(ColdRestartSignal::Fire).await.is_err() {
                                        log::warn!("Cold restart signal channel closed");
                                        return;
                                    }
                                }
                                Err(e) => {
                                    log::error!(
                                        "CRITICAL: cold restart marker write failed ({}); \
                                         refusing to Fire to prevent re-fire loop. \
                                         Check {} permissions. Will retry next tick.",
                                        e,
                                        marker_path.display(),
                                    );
                                    // Do NOT send Fire; loop continues
                                    // and next tick re-evaluates.
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::tz::{Offset, TimeZone};

    // -------- Fixture helpers — deterministic, no Zoned::now() calls. --------

    /// Build a Zoned in a fixed -04:00 frame at the given civil date and time.
    /// Used so tests are deterministic across season, TZ env, and CI machine.
    fn at_edt(year: i16, month: i8, day: i8, hour: i8, minute: i8) -> jiff::Zoned {
        let tz = TimeZone::fixed(Offset::constant(-4));
        jiff::civil::date(year, month, day)
            .at(hour, minute, 0, 0)
            .to_zoned(tz)
            .expect("synthetic zoned must construct")
    }

    /// Build a SchedulerConfig for a target Sunday at HH:MM with the given
    /// boot wall-clock. Sunday=0 to match `to_sunday_zero_offset`.
    fn cfg_sun(target_hour: u32, target_minute: u32, boot_at: jiff::Zoned) -> SchedulerConfig {
        SchedulerConfig {
            target_dow: 0,
            target_hour,
            target_minute,
            boot_at,
        }
    }

    fn empty_markers() -> MarkerState {
        MarkerState { fired_today: false, equivalent_marker: None }
    }

    // -------- parse_cold_restart_time — full matrix from contract. ----------

    #[test]
    fn test_parse_cold_restart_time() {
        assert_eq!(parse_cold_restart_time("09:00"), Some((9, 0)));
        assert_eq!(parse_cold_restart_time("13:30"), Some((13, 30)));
        assert_eq!(parse_cold_restart_time("00:00"), Some((0, 0)));
        assert_eq!(parse_cold_restart_time("23:59"), Some((23, 59)));
        assert_eq!(parse_cold_restart_time(""), None);
        assert_eq!(parse_cold_restart_time("invalid"), None);
        assert_eq!(parse_cold_restart_time("25:00"), None);
        assert_eq!(parse_cold_restart_time("12:60"), None);
        assert_eq!(parse_cold_restart_time("9:00"), Some((9, 0)));
        assert_eq!(parse_cold_restart_time("0900"), None);
    }

    // -------- already_fired — date-keyed dedup contract. --------------------

    #[test]
    fn test_already_fired() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("cold_restart_marker");

        // No marker file — not fired.
        assert!(!already_fired(&marker, 2026, 88));

        // Write today's marker.
        std::fs::write(&marker, "2026-88").unwrap();
        assert!(already_fired(&marker, 2026, 88));

        // Different day — not fired.
        assert!(!already_fired(&marker, 2026, 89));
    }

    #[test]
    fn test_already_fired_next_week() {
        // Writing "2026-100" must NOT block (2026, 107) — single-day dedup,
        // not lifetime dedup.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("cold_restart_marker");
        std::fs::write(&marker, "2026-100").unwrap();
        assert!(already_fired(&marker, 2026, 100));
        assert!(!already_fired(&marker, 2026, 107));
    }

    #[test]
    fn test_already_fired_year_rollover() {
        // "2026-365" must NOT block (2027, 1) — year rollover preserves the
        // fail-safe-toward-firing semantic.
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join("cold_restart_marker");
        std::fs::write(&marker, "2026-365").unwrap();
        assert!(!already_fired(&marker, 2027, 1));
    }

    #[test]
    fn test_no_marker_file_does_not_block_fire() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-marker");
        assert!(
            !already_fired(&marker, 2026, 100),
            "missing marker must report not-fired (fail-safe toward firing)",
        );
    }

    // -------- read_cold_restart_equivalent_marker — IO + TZ preservation. ---

    #[test]
    fn test_read_cold_restart_equivalent_marker_today() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");
        // Use jiff's own ISO-8601 round-trip — what the state machine writes.
        let written = at_edt(2026, 6, 14, 8, 30);
        std::fs::write(&path, written.to_string()).unwrap();

        let parsed = read_cold_restart_equivalent_marker(&path).expect("Some(parsed)");
        assert_eq!(parsed.date(), written.date());
    }

    #[test]
    fn test_read_cold_restart_equivalent_marker_unparseable() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");
        std::fs::write(&path, "this is not a timestamp").unwrap();
        assert!(read_cold_restart_equivalent_marker(&path).is_none());
    }

    #[test]
    fn test_read_cold_restart_equivalent_marker_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("definitely-not-here");
        assert!(read_cold_restart_equivalent_marker(&path).is_none());
    }

    #[test]
    fn test_read_cold_restart_equivalent_marker_preserves_offset() {
        // Cross-TZ critical fix: the prior implementation called
        // `with_time_zone(TimeZone::system())` which would re-project the
        // wall-clock hour-of-day on TZ change. Writing under offset -04:00
        // and reading must preserve the offset and hour-of-day so the skip
        // predicate (`marker.hour() >= 1 && marker.time() < target`) keeps
        // its meaning across container restarts.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-equivalent-today");

        let written = at_edt(2026, 6, 14, 8, 30);
        std::fs::write(&path, written.to_string()).unwrap();

        let parsed = read_cold_restart_equivalent_marker(&path).expect("Some(parsed)");
        assert_eq!(parsed.hour(), 8, "hour-of-day must survive read");
        assert_eq!(parsed.minute(), 30, "minute must survive read");
        assert_eq!(parsed.date(), written.date(), "date must survive read");
        assert_eq!(
            parsed.offset().seconds(),
            -4 * 3600,
            "offset must survive read — the prior with_time_zone re-projection \
             would have shifted these checks if system TZ differed"
        );
    }

    // -------- should_skip_for_marker predicate matrix. ----------------------

    #[test]
    fn test_should_skip_marker_dated_yesterday() {
        let now = at_edt(2026, 6, 14, 9, 0);
        let marker = at_edt(2026, 6, 13, 8, 30);
        assert!(
            !should_skip_for_marker(&marker, &now, 9, 0),
            "marker dated yesterday must NOT trigger skip — scheduler must fire",
        );
    }

    #[test]
    fn test_should_skip_marker_today_before_01_00_does_not_skip() {
        let now = at_edt(2026, 6, 14, 9, 0);
        let marker = at_edt(2026, 6, 14, 0, 30);
        assert!(
            !should_skip_for_marker(&marker, &now, 9, 0),
            "marker before 01:00 must NOT trigger skip",
        );
    }

    #[test]
    fn test_should_skip_marker_today_at_01_00_skips() {
        let now = at_edt(2026, 6, 14, 9, 0);
        let marker = at_edt(2026, 6, 14, 1, 0);
        assert!(
            should_skip_for_marker(&marker, &now, 9, 0),
            "marker at 01:00 (boundary inclusive) must trigger skip",
        );
    }

    #[test]
    fn test_should_skip_marker_today_at_08_59_skips() {
        let now = at_edt(2026, 6, 14, 9, 0);
        let marker = at_edt(2026, 6, 14, 8, 59);
        assert!(
            should_skip_for_marker(&marker, &now, 9, 0),
            "marker at 08:59 (just before target) must trigger skip",
        );
    }

    #[test]
    fn test_should_skip_marker_today_at_01_30_skips() {
        let now = at_edt(2026, 6, 14, 9, 0);
        let marker = at_edt(2026, 6, 14, 1, 30);
        assert!(
            should_skip_for_marker(&marker, &now, 9, 0),
            "marker at 01:30 must trigger skip",
        );
    }

    #[test]
    fn test_should_skip_marker_today_after_target_does_not_skip_via_this_predicate() {
        let now = at_edt(2026, 6, 14, 10, 0);
        let marker = at_edt(2026, 6, 14, 9, 30);
        assert!(
            !should_skip_for_marker(&marker, &now, 9, 0),
            "marker timestamped after the target time must NOT trigger the skip predicate alone — \
             dedup of post-target markers is handled by already_fired",
        );
    }

    #[test]
    fn test_should_skip_marker_today_at_23_30_does_not_skip() {
        let now = at_edt(2026, 6, 14, 23, 45);
        let marker = at_edt(2026, 6, 14, 23, 30);
        assert!(
            !should_skip_for_marker(&marker, &now, 9, 0),
            "marker at 23:30 must NOT trigger skip via this predicate",
        );
    }

    // ----------------------------------------------------------------
    // THE flagship Bug 1 + Bug 4 regression test.
    //
    // Single SchedulerConfig, two synthetic Sundays in one process
    // lifetime. Both must return FireEligible. The marker file from day 1
    // does NOT block day 8. The captured `boot_at` from day 1 does NOT
    // veto firing on day 8.
    //
    // If a future change re-introduces:
    //   - A RAM-only `fired_this_lifetime` bool (Bug 1 shape), OR
    //   - A captured-once-derived `started_past_target` bool (Bug 4 shape),
    // this test fails deterministically.
    // ----------------------------------------------------------------

    #[test]
    fn bug1_bug4_two_consecutive_sundays_same_cfg_both_fire() {
        // Boot Sun 2026-06-14 at 08:00 EDT (BEFORE 09:00 target).
        let boot = at_edt(2026, 6, 14, 8, 0);
        let cfg = cfg_sun(9, 0, boot.clone());

        // Day 1: Sun 2026-06-14 at 09:00 — FireEligible.
        let day1 = at_edt(2026, 6, 14, 9, 0);
        let m_day1 = empty_markers();
        assert_eq!(
            compute_next_action(&day1, &cfg, &m_day1),
            NextAction::FireEligible,
            "day 1 (boot Sunday before target) at 09:00 must FireEligible",
        );

        // After the wrapper writes the marker, the next tick on day 1 sees
        // fired_today=true.
        let m_day1_after = MarkerState { fired_today: true, equivalent_marker: None };
        assert_eq!(
            compute_next_action(&day1, &cfg, &m_day1_after),
            NextAction::Sleep,
            "same day after marker write must Sleep (single-day dedup)",
        );

        // Day 8: Sun 2026-06-21 at 09:00 — NEW calendar day, marker file
        // would contain day 1's "2026-165" which does NOT equal today's
        // "2026-172" — so fired_today=false. cfg.boot_at is still day 1.
        let day8 = at_edt(2026, 6, 21, 9, 0);
        let m_day8 = MarkerState { fired_today: false, equivalent_marker: None };
        assert_eq!(
            compute_next_action(&day8, &cfg, &m_day8),
            NextAction::FireEligible,
            "Bug 1 + Bug 4 regression: day 8 must FireEligible with the SAME \
             SchedulerConfig and no process restart",
        );
    }

    #[test]
    fn bug4_boot_past_target_does_not_veto_next_sunday() {
        // Boot Sun 2026-06-14 at 12:00 EDT (PAST 09:00 target). On boot day
        // we don't fire. On next Sunday we MUST fire.
        let boot = at_edt(2026, 6, 14, 12, 0);
        let cfg = cfg_sun(9, 0, boot.clone());

        // Boot day at 09:00 had already passed when we booted — veto.
        // (Aside: in practice the scheduler can't observe the past, but the
        // semantic is "if you booted on target day past target, ignore the
        // remainder of that day". The synthetic test rewinds `now` to 09:00
        // on the boot day, which is BEFORE boot_at on the same day — the
        // gate is whether boot_at was past target on the SAME day. That is
        // true, so the veto fires regardless of `now`'s time-of-day on the
        // boot day.)
        let same_day = at_edt(2026, 6, 14, 9, 0);
        let m = empty_markers();
        assert_eq!(
            compute_next_action(&same_day, &cfg, &m),
            NextAction::Sleep,
            "boot-day veto must Sleep",
        );

        // Next Sunday at 09:00 — different calendar day, veto MUST NOT apply.
        let next_sunday = at_edt(2026, 6, 21, 9, 0);
        assert_eq!(
            compute_next_action(&next_sunday, &cfg, &empty_markers()),
            NextAction::FireEligible,
            "Bug 4 regression: next Sunday must FireEligible — \
             started_past_target_on_startup_day is scoped to boot day only",
        );

        // Year boundary: Jan 3 2027 is a Sunday — also FireEligible.
        let next_year_sunday = at_edt(2027, 1, 3, 9, 0);
        assert_eq!(
            compute_next_action(&next_year_sunday, &cfg, &empty_markers()),
            NextAction::FireEligible,
            "veto must NOT cross year boundary either",
        );
    }

    // ----------------------------------------------------------------
    // Bug-class invariant: compute_next_action is a pure function.
    //
    // Determinism property: same inputs → same outputs, on every call.
    // Catches any hidden state (cached marker reads, captured booleans,
    // time-derived flags) deterministically.
    // ----------------------------------------------------------------

    #[test]
    fn bug_class_invariant_compute_next_action_is_pure() {
        let cfg = cfg_sun(9, 0, at_edt(2026, 6, 14, 8, 0));
        let now = at_edt(2026, 6, 14, 9, 0);
        let markers = empty_markers();

        let a = compute_next_action(&now, &cfg, &markers);
        let b = compute_next_action(&now, &cfg, &markers);
        let c = compute_next_action(&now, &cfg, &markers);

        assert_eq!(a, b, "second call must match first (purity)");
        assert_eq!(b, c, "third call must match second (purity)");
        assert_eq!(a, NextAction::FireEligible, "FireEligible expected at target time");
    }

    // ----------------------------------------------------------------
    // Day-of-week matrix: on target_dow, fire at-or-past target time
    // (wider window). On other days, every (hh, mm) is Sleep.
    // ----------------------------------------------------------------

    #[test]
    fn day_of_week_matrix() {
        // Anchor Sundays of June 2026: 7, 14, 21, 28 are Sundays.
        // Other weekdays in that week: 8=Mon, 9=Tue, 10=Wed, 11=Thu,
        // 12=Fri, 13=Sat.
        let boot = at_edt(2026, 6, 1, 0, 0); // Mon — not target day → no veto on Sun.
        let cfg = cfg_sun(9, 0, boot);

        // (year, month, day, expected_dow) — Sunday=0..Saturday=6
        let days = [
            (2026, 6, 14, 0), // Sun
            (2026, 6, 15, 1), // Mon
            (2026, 6, 16, 2), // Tue
            (2026, 6, 17, 3), // Wed
            (2026, 6, 18, 4), // Thu
            (2026, 6, 19, 5), // Fri
            (2026, 6, 20, 6), // Sat
        ];
        let times = [(8, 59), (9, 0), (9, 1)];

        for (y, m, d, expected_dow) in days.iter() {
            for (hour, minute) in times.iter() {
                let now = at_edt(*y, *m, *d, *hour, *minute);
                let actual = compute_next_action(&now, &cfg, &empty_markers());
                // Wider window: on Sunday, fire at-or-past 09:00.
                let is_target = *expected_dow == 0 && (*hour, *minute) >= (9, 0);
                if is_target {
                    assert_eq!(
                        actual,
                        NextAction::FireEligible,
                        "Sunday at-or-past 09:00 must FireEligible (y={}, m={}, d={}, h={}, mi={})",
                        y, m, d, hour, minute,
                    );
                } else {
                    assert_eq!(
                        actual,
                        NextAction::Sleep,
                        "non-target slot must Sleep (y={}, m={}, d={}, h={}, mi={}, dow={})",
                        y, m, d, hour, minute, expected_dow,
                    );
                }
            }
        }
    }

    // ----------------------------------------------------------------
    // Skip predicate matrix exercised through compute_next_action.
    // Yesterday / 00:30 / 01:00 boundary / 08:59 / 09:30 / 23:30
    // against target 09:00.
    // ----------------------------------------------------------------

    #[test]
    fn marker_predicate_matrix() {
        let boot = at_edt(2026, 6, 14, 8, 0);
        let cfg = cfg_sun(9, 0, boot);
        let now = at_edt(2026, 6, 14, 9, 0);

        let cases = [
            // marker (y, m, d, h, mi), expected_skip
            (2026, 6, 13, 8, 30, false), // yesterday
            (2026, 6, 14, 0, 30, false), // before 01:00 cutoff
            (2026, 6, 14, 1, 0, true),   // boundary 01:00
            (2026, 6, 14, 8, 59, true),  // just before target
            (2026, 6, 14, 9, 30, false), // after target
            (2026, 6, 14, 23, 30, false),// late evening
        ];
        for (y, m, d, h, mi, expected_skip) in cases.iter() {
            let marker = at_edt(*y, *m, *d, *h, *mi);
            let markers = MarkerState {
                fired_today: false,
                equivalent_marker: Some(marker.clone()),
            };
            let action = compute_next_action(&now, &cfg, &markers);
            match (expected_skip, &action) {
                (true, NextAction::Skip { reason: ColdRestartSkipReason::FreshAuthToday { at } }) => {
                    assert_eq!(at.date(), marker.date(), "skip must carry the marker");
                }
                (false, NextAction::FireEligible) => { /* OK */ }
                _ => panic!(
                    "marker {:?} expected_skip={} but action={:?}",
                    marker, expected_skip, action,
                ),
            }
        }
    }

    // ----------------------------------------------------------------
    // Race close: marker appears between the two reads (warning window).
    // ----------------------------------------------------------------

    #[test]
    fn race_close_marker_appears_during_warning_window() {
        let boot = at_edt(2026, 6, 14, 8, 0);
        let cfg = cfg_sun(9, 0, boot);
        let now_pre = at_edt(2026, 6, 14, 9, 0);

        // Pre-warning: empty markers → FireEligible.
        let pre = empty_markers();
        assert_eq!(
            compute_next_action(&now_pre, &cfg, &pre),
            NextAction::FireEligible,
        );

        // During the 30s warning sleep a real cold-restart-equivalent
        // landed at 08:30.
        let now_post = at_edt(2026, 6, 14, 9, 0); // still in target minute
        let marker = at_edt(2026, 6, 14, 8, 30);
        let post = MarkerState { fired_today: false, equivalent_marker: Some(marker.clone()) };
        match compute_next_action(&now_post, &cfg, &post) {
            NextAction::Skip { reason: ColdRestartSkipReason::FreshAuthToday { at } } => {
                assert_eq!(at.date(), marker.date());
            }
            other => panic!("expected Skip, got {:?}", other),
        }
    }

    // ----------------------------------------------------------------
    // NTP forward jump scenarios. The wider fire window (at-or-past
    // target on target day, with marker dedup) handles forward jumps
    // both BEFORE and DURING the fire window.
    // ----------------------------------------------------------------

    #[test]
    fn ntp_forward_jump_past_target_minute_returns_fire_eligible() {
        // Wider window: now=09:01 on target Sunday with empty markers
        // → FireEligible. The previous strict-equality contract returned
        // Sleep here, requiring the wrapper's `_ => Fire` arm to back
        // up the pure function during the warning window. The wider
        // window makes the pure function itself robust against forward
        // jumps that miss the exact target minute.
        let boot = at_edt(2026, 6, 14, 8, 0);
        let cfg = cfg_sun(9, 0, boot);
        let now_post = at_edt(2026, 6, 14, 9, 1);
        assert_eq!(
            compute_next_action(&now_post, &cfg, &empty_markers()),
            NextAction::FireEligible,
            "past-target on target day with empty markers → FireEligible (wider window)",
        );
    }

    #[test]
    fn ntp_forward_jump_before_fire_window_still_fires_via_wider_window() {
        // Reviewer's "missed week" scenario: NTP forward jumps from 08:45
        // to 10:00 on target Sunday. Strict equality on (hour, minute)
        // would never sample 09:00 and the scheduler would wait a full
        // week. The wider window fires at 10:00 (and any time after
        // 09:00 that day) until the on-disk marker is written.
        let cfg = cfg_sun(9, 0, at_edt(2026, 6, 13, 12, 0)); // boot Saturday

        // Pre-jump: 08:45 → before target → Sleep.
        let pre_jump = at_edt(2026, 6, 14, 8, 45);
        assert_eq!(
            compute_next_action(&pre_jump, &cfg, &empty_markers()),
            NextAction::Sleep,
            "before target → Sleep",
        );

        // Post-jump: 10:00 (jumped 75 minutes forward) on target Sunday
        // → FireEligible. This is the bug fix vs the previous behavior.
        let post_jump = at_edt(2026, 6, 14, 10, 0);
        assert_eq!(
            compute_next_action(&post_jump, &cfg, &empty_markers()),
            NextAction::FireEligible,
            "post-jump past target on target day → FireEligible (fixes missed-week bug)",
        );

        // Even much later in the day still FireEligible — the wrapper's
        // marker dedup is the single-fire invariant.
        let later = at_edt(2026, 6, 14, 23, 59);
        assert_eq!(
            compute_next_action(&later, &cfg, &empty_markers()),
            NextAction::FireEligible,
            "later in target day still FireEligible (marker dedup is wrapper's job)",
        );

        // Marker set → Sleep regardless of how far past target.
        let marker_set = MarkerState {
            fired_today: true,
            equivalent_marker: None,
        };
        assert_eq!(
            compute_next_action(&later, &cfg, &marker_set),
            NextAction::Sleep,
            "marker set → Sleep (dedup)",
        );
    }

    #[test]
    fn ntp_forward_jump_across_day_returns_sleep() {
        // If NTP jumps from Sunday 09:00 to Monday 00:01 (cross-day),
        // the pure function returns Sleep — Monday != target Sunday.
        // The wrapper's `_ => Fire` arm in the warning window still
        // covers the in-flight Fire decision (pre-wait marker write).
        let cfg = cfg_sun(9, 0, at_edt(2026, 6, 13, 12, 0));
        let monday = at_edt(2026, 6, 15, 0, 1);
        assert_eq!(
            compute_next_action(&monday, &cfg, &empty_markers()),
            NextAction::Sleep,
            "Monday → Sleep (different DOW from target Sunday)",
        );
    }

    // ----------------------------------------------------------------
    // DST fall-back: 01:30 EDT vs 01:30 EST replay. Marker dedup
    // prevents double-fire on the second pass.
    //
    // In America/New_York on the first Sunday of November the clock
    // falls back: 02:00 EDT → 01:00 EST, so 01:00–01:59 happens twice
    // wall-clock-wise. Both passes share the same calendar day. If the
    // scheduler fires on the first pass and writes the dated marker,
    // the second pass sees fired_today=true and returns Sleep.
    // ----------------------------------------------------------------

    #[test]
    fn dst_fall_back_second_pass_blocked_by_marker() {
        // 2026-11-01 is the first Sunday of November.
        // First pass at 01:30 in offset -04:00 (EDT).
        // Second pass at 01:30 in offset -05:00 (EST).
        let edt = TimeZone::fixed(Offset::constant(-4));
        let est = TimeZone::fixed(Offset::constant(-5));
        let first_pass = jiff::civil::date(2026, 11, 1).at(1, 30, 0, 0).to_zoned(edt).unwrap();
        let second_pass = jiff::civil::date(2026, 11, 1).at(1, 30, 0, 0).to_zoned(est).unwrap();
        assert_eq!(first_pass.date(), second_pass.date(), "same calendar day");

        // Boot just before midnight Sat — boot_at is on Saturday, not the
        // target Sunday, so the startup-day veto does not apply.
        let boot = jiff::civil::date(2026, 10, 31)
            .at(23, 0, 0, 0)
            .to_zoned(TimeZone::fixed(Offset::constant(-4)))
            .unwrap();
        let cfg = SchedulerConfig {
            target_dow: 0, // Sunday
            target_hour: 1,
            target_minute: 30,
            boot_at: boot,
        };

        // First pass — no marker yet → FireEligible.
        let m_pre = empty_markers();
        assert_eq!(
            compute_next_action(&first_pass, &cfg, &m_pre),
            NextAction::FireEligible,
            "first pass at 01:30 EDT must FireEligible",
        );

        // After the wrapper writes the marker, the second pass sees
        // fired_today=true → Sleep.
        let m_post = MarkerState { fired_today: true, equivalent_marker: None };
        assert_eq!(
            compute_next_action(&second_pass, &cfg, &m_post),
            NextAction::Sleep,
            "DST fall-back second pass at 01:30 EST must Sleep — marker dedup",
        );
    }

    // ----------------------------------------------------------------
    // DST spring-forward: target 02:30 on spring-forward Sunday.
    // In a normal DST zone, 02:00→03:00 means 02:30 never exists.
    //
    // Because we test with synthetic fixed-offset Zoned (so we can
    // construct any wall-clock value deterministically), we don't simulate
    // the real "minute never exists" — instead we assert the conceptual
    // contract: if `now` never lands on the target minute, the scheduler
    // never fires. Iterate every minute of the spring-forward day at a
    // FIXED offset and verify all return Sleep when minute=30 never
    // matches the target (here target=02:30 so a fixed-offset day DOES
    // hit 02:30; instead we set target to a never-existing minute like
    // (24,30) which compute_next_action rejects via the hour check).
    //
    // A more useful "skip a week" test: pick a target on a Sunday where
    // the on-disk marker is already set for that day from a prior fire
    // and assert every tick returns Sleep. That exercises Bug 1 + the
    // entire day after a fire — proxy for "fires once and only once".
    // ----------------------------------------------------------------

    #[test]
    fn dst_spring_forward_target_skipped_for_one_week() {
        // 2026-03-08 is the second Sunday of March (US DST spring-forward).
        // Boot the prior Sunday.
        let boot = at_edt(2026, 3, 1, 0, 0); // Sun
        let cfg = cfg_sun(2, 30, boot); // target 02:30 Sunday

        // Marker is on disk for 2026-03-08 (e.g. fired at 02:30 if the
        // minute existed). Test that EVERY tick on 2026-03-08 returns
        // Sleep when fired_today=true. We sample 24*60=1440 minutes of
        // that day — proxy for "won't double-fire".
        let m_post = MarkerState { fired_today: true, equivalent_marker: None };
        for hour in 0..24 {
            for minute in (0..60).step_by(5) {
                let now = at_edt(2026, 3, 8, hour as i8, minute as i8);
                assert_eq!(
                    compute_next_action(&now, &cfg, &m_post),
                    NextAction::Sleep,
                    "DST Sunday with marker set: every tick must Sleep (h={}, mi={})",
                    hour, minute,
                );
            }
        }

        // The following Sunday (2026-03-15) at 02:30 — marker now stale
        // (different date) → FireEligible if fired_today=false.
        let next_week = at_edt(2026, 3, 15, 2, 30);
        let m_next = empty_markers();
        assert_eq!(
            compute_next_action(&next_week, &cfg, &m_next),
            NextAction::FireEligible,
            "post-DST week target must FireEligible",
        );
    }

    // ----------------------------------------------------------------
    // Leap year + month/year boundaries (2028 is a leap year).
    // ----------------------------------------------------------------

    #[test]
    fn leap_year_and_month_year_boundaries() {
        // Leap day Feb 29 2028 is a Tuesday — not target. At 09:00 → Sleep.
        let boot = at_edt(2028, 1, 1, 0, 0); // Sat
        let cfg = cfg_sun(9, 0, boot);
        let leap_day = at_edt(2028, 2, 29, 9, 0);
        assert_eq!(
            compute_next_action(&leap_day, &cfg, &empty_markers()),
            NextAction::Sleep,
            "leap day Tuesday 2028-02-29 at 09:00 must Sleep (not target weekday)",
        );

        // Sun 2026-12-27 at 09:00 → FireEligible.
        let last_sunday_of_year = at_edt(2026, 12, 27, 9, 0);
        assert_eq!(
            compute_next_action(&last_sunday_of_year, &cfg, &empty_markers()),
            NextAction::FireEligible,
        );

        // Sun 2027-01-03 at 09:00 → FireEligible (year rollover).
        let first_sunday_of_year = at_edt(2027, 1, 3, 9, 0);
        assert_eq!(
            compute_next_action(&first_sunday_of_year, &cfg, &empty_markers()),
            NextAction::FireEligible,
        );
    }

    // ----------------------------------------------------------------
    // started_past_target_on_startup_day — focused unit coverage.
    // ----------------------------------------------------------------

    #[test]
    fn started_past_target_helper_matrix() {
        let target_dow = 0;
        let target_hour = 9;
        let target_minute = 0;

        // Boot Sunday 08:00 — NOT past target on boot day, regardless of now.
        let boot_before = at_edt(2026, 6, 14, 8, 0);
        let now_same_day_early = at_edt(2026, 6, 14, 6, 0);
        assert!(
            !started_past_target_on_startup_day(
                &boot_before, &now_same_day_early, target_dow, target_hour, target_minute,
            ),
            "boot at 08:00 is NOT past 09:00 target",
        );

        // Boot Sunday 12:00 — past target. Same boot day → veto.
        let boot_after = at_edt(2026, 6, 14, 12, 0);
        let now_same_day = at_edt(2026, 6, 14, 9, 0);
        assert!(
            started_past_target_on_startup_day(
                &boot_after, &now_same_day, target_dow, target_hour, target_minute,
            ),
            "boot at 12:00 IS past 09:00 target (same boot day)",
        );

        // Boot Sunday 12:00 — different calendar day → NO veto.
        let now_next_sun = at_edt(2026, 6, 21, 9, 0);
        assert!(
            !started_past_target_on_startup_day(
                &boot_after, &now_next_sun, target_dow, target_hour, target_minute,
            ),
            "different day → veto MUST NOT apply",
        );

        // Boot Monday 12:00 — not target dow → no veto on boot day either.
        let boot_monday = at_edt(2026, 6, 15, 12, 0);
        let now_mon_9 = at_edt(2026, 6, 15, 9, 0);
        assert!(
            !started_past_target_on_startup_day(
                &boot_monday, &now_mon_9, target_dow, target_hour, target_minute,
            ),
            "boot weekday != target dow → no veto",
        );

        // Boot Sunday exactly at target — NOT past, no veto.
        let boot_exact = at_edt(2026, 6, 14, 9, 0);
        assert!(
            !started_past_target_on_startup_day(
                &boot_exact, &boot_exact, target_dow, target_hour, target_minute,
            ),
            "boot exactly AT target is not PAST target",
        );

        // Boot Sunday 09:01 — past by one minute, same day → veto.
        let boot_just_past = at_edt(2026, 6, 14, 9, 1);
        assert!(
            started_past_target_on_startup_day(
                &boot_just_past, &boot_just_past, target_dow, target_hour, target_minute,
            ),
            "boot 09:01 IS past 09:00 target",
        );
    }

    // ----------------------------------------------------------------
    // Atomic write of the fired marker.
    // ----------------------------------------------------------------

    #[test]
    fn test_write_fired_marker_no_orphan_temp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-marker");
        let now = at_edt(2026, 6, 14, 9, 0);

        write_fired_marker(&marker, &now).expect("write must succeed");
        let raw = std::fs::read_to_string(&marker).unwrap();
        let expected = format!("{}-{}", now.year(), now.day_of_year());
        assert_eq!(raw.trim(), expected);
        let tmp = marker.with_file_name(".ibctl-cold-restart-marker.tmp");
        assert!(!tmp.exists(), "temp file must not be left behind");
    }

    #[test]
    fn test_write_fired_marker_overwrites_existing_atomically() {
        let dir = tempfile::TempDir::new().unwrap();
        let marker = dir.path().join(".ibctl-cold-restart-marker");
        std::fs::write(&marker, "2025-001").unwrap();

        let now = at_edt(2026, 4, 10, 9, 0);
        write_fired_marker(&marker, &now).expect("write must succeed");
        let raw = std::fs::read_to_string(&marker).unwrap();
        let expected = format!("{}-{}", now.year(), now.day_of_year());
        assert_eq!(raw.trim(), expected);
    }

    #[test]
    fn write_fired_marker_returns_err_on_io_failure() {
        // Writing to a non-existent parent dir surfaces an io::Error.
        // The wrapper relies on this to suppress Fire and prevent the
        // re-fire loop documented in the wider-window contract.
        let bogus = std::path::PathBuf::from("/nonexistent-cold-restart-parent-dir/marker");
        let now = at_edt(2026, 6, 14, 9, 0);
        let result = write_fired_marker(&bogus, &now);
        assert!(
            result.is_err(),
            "broken parent dir must surface Err so the wrapper refuses Fire",
        );
    }

    #[test]
    fn atomic_write_no_orphan_tmp_under_concurrent_reads() {
        // Concurrent reader never sees an empty/torn file under sequential
        // writes. Mirrors the markers.rs contract for the fired marker.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".ibctl-cold-restart-marker");
        let now = at_edt(2026, 6, 14, 9, 0);
        // Seed.
        write_fired_marker(&path, &now).expect("write must succeed");

        let path_for_reader = path.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_for_reader = stop.clone();
        let reader = std::thread::spawn(move || {
            let mut bad_reads: usize = 0;
            while !stop_for_reader.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok(raw) = std::fs::read_to_string(&path_for_reader) {
                    if raw.trim().is_empty() {
                        bad_reads += 1;
                    }
                }
            }
            bad_reads
        });

        for _ in 0..50 {
            write_fired_marker(&path, &now).expect("write must succeed");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let bad_reads = reader.join().unwrap();
        assert_eq!(bad_reads, 0, "concurrent reader observed {} empty reads", bad_reads);
    }

    // ----------------------------------------------------------------
    // read_marker_state integration: ties (now, files) → MarkerState.
    // ----------------------------------------------------------------

    #[test]
    fn read_marker_state_builds_consistent_snapshot() {
        let dir = tempfile::TempDir::new().unwrap();
        let fired_marker = dir.path().join(".ibctl-cold-restart-marker");
        let equiv_marker = dir.path().join(".ibctl-cold-restart-equivalent-today");

        // No files yet.
        let now = at_edt(2026, 6, 14, 9, 0);
        let m = read_marker_state(&fired_marker, &equiv_marker, &now);
        assert!(!m.fired_today);
        assert!(m.equivalent_marker.is_none());

        // Write fired marker for today.
        std::fs::write(
            &fired_marker,
            format!("{}-{}", now.year(), now.day_of_year()),
        )
        .unwrap();
        let m = read_marker_state(&fired_marker, &equiv_marker, &now);
        assert!(m.fired_today, "fired_today must match on-disk marker");

        // Write equivalent marker.
        let equiv = at_edt(2026, 6, 14, 8, 30);
        std::fs::write(&equiv_marker, equiv.to_string()).unwrap();
        let m = read_marker_state(&fired_marker, &equiv_marker, &now);
        assert!(m.fired_today);
        let eq_marker = m.equivalent_marker.expect("equivalent_marker must parse");
        assert_eq!(eq_marker.date(), equiv.date());
    }

    // ----------------------------------------------------------------
    // Async integration tests exercising the SAME loop body as
    // production (`scheduler_loop`) with an injected wall-clock
    // function. The clock is an `Arc<Mutex<jiff::Zoned>>` the test
    // mutates between ticks; virtual tokio time is driven via
    // `tokio::time::advance` under `start_paused = true`.
    //
    // These tests close the gap flagged by the test-completeness
    // reviewer: pure-function tests cannot catch a captured-once-then-
    // stale state introduced in the async closure body (e.g., a future
    // `let mut fired_this_lifetime = false;` in the per-tick match
    // arm). Driving the actual loop body with two virtual Sundays in
    // one process lifetime exercises the wiring AND the pure function.
    // ----------------------------------------------------------------

    #[tokio::test]
    async fn scheduler_returns_none_when_not_configured() {
        let (tx, _rx) = mpsc::channel(1);
        let dir = tempfile::TempDir::new().unwrap();
        let equiv = dir.path().join(".ibctl-cold-restart-equivalent-today");
        let fut = cold_restart_scheduler(String::new(), 0, tx, equiv);
        assert!(fut.is_none(), "empty time config must return None");
    }

    /// Build a clock pair: an `Arc<Mutex<jiff::Zoned>>` the test can
    /// mutate, and a `Fn() -> jiff::Zoned + Send + 'static` closure
    /// for the scheduler loop. Returns `(clock_handle, now_fn)`.
    fn injected_clock(
        initial: jiff::Zoned,
    ) -> (
        std::sync::Arc<std::sync::Mutex<jiff::Zoned>>,
        impl Fn() -> jiff::Zoned + Send + 'static,
    ) {
        let clock = std::sync::Arc::new(std::sync::Mutex::new(initial));
        let clock_for_fn = clock.clone();
        let now_fn = move || clock_for_fn.lock().unwrap().clone();
        (clock, now_fn)
    }

    #[tokio::test(start_paused = true)]
    async fn scheduler_tick_cadence_no_spurious_signal_before_first_30s() {
        // Inject a controlled clock fixed at Saturday 23:00 with target
        // Sunday 09:00. The clock NEVER advances during the test so
        // compute_next_action returns Sleep on every tick — no real
        // wall-clock collision possible.
        let initial = at_edt(2026, 6, 13, 23, 0);
        let (_clock, now_fn) = injected_clock(initial.clone());

        let cfg = SchedulerConfig {
            target_dow: 0,
            target_hour: 9,
            target_minute: 0,
            boot_at: initial,
        };

        let (tx, mut rx) = mpsc::channel(1);
        let tmp = tempfile::TempDir::new().unwrap();
        let marker = tmp.path().join(".ibctl-cold-restart-marker");
        let equiv = tmp.path().join(".ibctl-cold-restart-equivalent-today");

        let fut = scheduler_loop(cfg, "Sunday", tx, marker, equiv, now_fn);
        let handle = tokio::spawn(fut);

        // Before any tokio time advance, no signal should be available
        // (the future is parked on its first 30s sleep).
        assert!(rx.try_recv().is_err(), "no signal before first 30s sleep");

        // Advance virtual time by 30s — one tick processed at Saturday
        // 23:00. Saturday != target Sunday → Sleep.
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err(), "no spurious signal after first tick");

        // Advance several more ticks — still no signal.
        for _ in 0..5 {
            tokio::time::advance(std::time::Duration::from_secs(30)).await;
            tokio::task::yield_now().await;
        }
        assert!(rx.try_recv().is_err(), "no spurious signal across multiple ticks");

        handle.abort();
    }

    // ----------------------------------------------------------------
    // THE flagship async-loop-body regression test for Bug 1 + Bug 4.
    //
    // Drives `scheduler_loop` (the SAME async closure body called by
    // production `cold_restart_scheduler`) across two virtual Sundays
    // in ONE process lifetime / ONE `SchedulerConfig` and asserts two
    // `ColdRestartSignal::Fire` arrivals on the channel.
    //
    // If a future change reintroduces:
    //   - A RAM-only `fired_this_lifetime` bool inside the async closure
    //     (Bug 1 shape — captured by the FireEligible match arm), OR
    //   - A captured-once-derived "started_past_target" bool around the
    //     loop or in SchedulerConfig (Bug 4 shape), OR
    //   - A guard that skips compute_next_action after first fire,
    // this test fails deterministically.
    //
    // The pure-function regression test
    // `bug1_bug4_two_consecutive_sundays_same_cfg_both_fire` is the
    // table-driven companion of this test — together they cover both
    // the pure decision layer and the async wiring around it.
    // ----------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn bug1_bug4_async_two_virtual_sundays_both_fire_via_scheduler_loop() {
        use std::time::Duration;

        // Boot Saturday 2026-06-13 at 23:00 EDT — NOT target day, so
        // the startup-day veto doesn't apply on either virtual Sunday.
        let initial = at_edt(2026, 6, 13, 23, 0);
        let (clock, now_fn) = injected_clock(initial.clone());

        // ONE SchedulerConfig. Held across both virtual Sundays.
        let cfg = SchedulerConfig {
            target_dow: 0, // Sunday
            target_hour: 9,
            target_minute: 0,
            boot_at: initial,
        };

        let (tx, mut rx) = mpsc::channel(4);
        let tmp = tempfile::TempDir::new().unwrap();
        let marker_path = tmp.path().join(".ibctl-cold-restart-marker");
        let equiv = tmp.path().join(".ibctl-cold-restart-equivalent-today");

        let fut = scheduler_loop(
            cfg,
            "Sunday",
            tx,
            marker_path.clone(),
            equiv,
            now_fn,
        );
        let handle = tokio::spawn(fut);

        // ---------- Tick at Saturday 23:00 — Sleep. ----------
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "Saturday must not fire (different DOW from target Sunday)",
        );

        // ---------- Sunday 1: 2026-06-14 09:00. Expect Fire. ----------
        *clock.lock().unwrap() = at_edt(2026, 6, 14, 9, 0);

        // First sub-tick: 30s sleep elapses, compute_next_action returns
        // FireEligible, wrapper logs PENDING and enters warning sleep.
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "warning window has not closed yet — no signal",
        );

        // Second sub-tick: 30s warning sleep elapses, re-evaluation
        // returns FireEligible, marker write succeeds, Fire is sent.
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;

        let sig1 = rx
            .try_recv()
            .expect("Sunday 1 must produce a signal after warning window");
        assert!(
            matches!(sig1, ColdRestartSignal::Fire),
            "Sunday 1: expected Fire, got {sig1:?}",
        );

        // Marker file must be on disk now.
        assert!(
            marker_path.exists(),
            "marker file must be written after Sunday 1 fire",
        );

        // ---------- Same day post-fire: marker blocks → Sleep. ----------
        *clock.lock().unwrap() = at_edt(2026, 6, 14, 10, 30);
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "post-fire same day must not signal again (marker dedup)",
        );

        // ---------- Mid-week (Wednesday). Different DOW → Sleep. ----------
        *clock.lock().unwrap() = at_edt(2026, 6, 17, 12, 0);
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(rx.try_recv().is_err(), "Wednesday must not fire");

        // ---------- Sunday 2: 2026-06-21 09:00. Expect SECOND Fire. ----------
        //
        // SAME SchedulerConfig, SAME async closure (same `handle`),
        // SAME marker file on disk (containing "2026-165" from Sunday 1
        // which does NOT match Sunday 2's day_of_year 172, so
        // fired_today=false). If a future Bug 1/4 regression hides
        // here, this assertion fires.
        *clock.lock().unwrap() = at_edt(2026, 6, 21, 9, 0);

        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        // warning window
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;

        let sig2 = rx
            .try_recv()
            .expect("Sunday 2 must produce a signal — Bug 1 + Bug 4 async regression");
        assert!(
            matches!(sig2, ColdRestartSignal::Fire),
            "Sunday 2: expected Fire (same SchedulerConfig as Sunday 1), got {sig2:?}",
        );

        // Marker file now contains Sunday 2's day_of_year.
        let marker_contents = std::fs::read_to_string(&marker_path).expect("marker readable");
        assert_eq!(
            marker_contents.trim(),
            "2026-172",
            "marker must be updated to Sunday 2's day_of_year (172)",
        );

        handle.abort();
    }

    // ----------------------------------------------------------------
    // Async regression: marker write failure suppresses Fire.
    //
    // Under the wider fire window, an io-failing marker write would
    // otherwise re-fire every tick. We verify the wrapper logs and
    // does NOT send Fire when the marker write fails. We simulate by
    // pointing the marker path at a non-writable directory.
    // ----------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn fire_suppressed_when_marker_write_fails() {
        use std::time::Duration;

        let initial = at_edt(2026, 6, 14, 9, 0); // Sunday at target
        let (_clock, now_fn) = injected_clock(initial.clone());

        let cfg = SchedulerConfig {
            target_dow: 0,
            target_hour: 9,
            target_minute: 0,
            // Boot Saturday so no startup-day veto on Sunday.
            boot_at: at_edt(2026, 6, 13, 12, 0),
        };

        let (tx, mut rx) = mpsc::channel(1);
        let tmp = tempfile::TempDir::new().unwrap();
        // Point marker at a non-existent parent dir → atomic_write fails.
        let marker = tmp.path().join("nonexistent-subdir").join("marker");
        let equiv = tmp.path().join(".ibctl-cold-restart-equivalent-today");

        let fut = scheduler_loop(cfg, "Sunday", tx, marker.clone(), equiv, now_fn);
        let handle = tokio::spawn(fut);

        // First sub-tick: FireEligible, warning sleep starts.
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        // Warning sleep elapses: write fails, Fire suppressed.
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "Fire must be suppressed when marker write fails",
        );
        assert!(!marker.exists(), "marker file must not exist after failed write");

        // Loop continues — next tick re-evaluates. Since the write keeps
        // failing, Fire stays suppressed (no re-fire loop, no 2FA spam).
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(30)).await;
        tokio::task::yield_now().await;
        assert!(
            rx.try_recv().is_err(),
            "Fire must remain suppressed on subsequent ticks with failing marker write",
        );

        handle.abort();
    }
}
