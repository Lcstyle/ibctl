"""Monitor: alert when a mode transitions into ``recovery.phase == "given_up"``.

Watches STATUS JSON's ``recovery`` block. On the first tick where a mode is
in the ``given_up`` phase (a new give-up entry), it sends a rich ntfy
action notification with a one-shot signed callback URL back to the
dashboard.

Design differences vs ``Hitl2faEntryMonitor``:
  - Trigger: STATUS ``recovery.phase == "given_up"`` (not transition history).
  - Dedupe anchor: STATUS ``recovery.phase_entered_at`` unconditionally.
    The Rust coordinator guarantees this stamp is monotonically-newer per
    give-up cycle (resume clears state; the subsequent
    ``enter_phase(Aggressive)`` re-stamps on the next give-up), so keying
    on it avoids the ``entered:`` → ``stamp:`` drift bug that keying on
    ``giveup_alert_sent_at`` with a phase_entered_at fallback would have
    produced during the narrow race window between phase-set and stamp
    persist (see finding B-MED-4).
  - Cold-boot suppression: on the first tick after process start, a
    stamped give-up entry seeds state silently rather than re-firing —
    otherwise every unrelated dashboard bounce would look like a fresh
    give-up (see finding B-MED-3).
  - Resend cadence: ``giveup_alert_resend_interval_hours`` (default 6h) —
    much longer than HITL's 15s retry cadence, so the monitor tick rate
    can stay at a leisurely 60s without missing the send window.
  - Retry ceiling: ``_NTFY_SEND_MAX_ATTEMPTS`` bounds retry activity per
    give-up entry against a wedged ntfy transport (see finding B-HIGH-2).
  - Coalescer key: ``event_type = "reconnect_gave_up:<mode>"`` so
    simultaneous live+paper give-ups produce distinct alerts (the ntfy
    kind-keyed coalescer would otherwise collapse them).

Mixed-deploy safety: an older ibctl daemon that has no ``recovery`` block
in STATUS is a no-op — this monitor does not raise, does not log at warn
per tick, and simply skips modes without the block. That keeps the log
clean during rolling upgrades.
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass

from app.services import callback_common, reconnect_tokens
from app.services.monitor_manager import Alert, Monitor

logger = logging.getLogger("dashboard.services.monitors.reconnect_giveup")

DEFAULT_CALLBACK_VALID_HOURS = 12
DEFAULT_RESEND_INTERVAL_HOURS = 6

# Monitor tick cadence. The give-up alert timeline is measured in hours;
# a 60s tick more than suffices for both first-fire detection and the 6h
# resend gate.
INTERVAL_SECONDS = 60

# Bound on per-mode retry attempts when ns.send_alert returns False or
# raises. Without this a 24h ntfy outage would produce 1440 forced sends
# per mode (every 60s tick). Mirrors HITL's `_NTFY_SEND_RETRIES_CEILING`.
# 5 attempts at 60s spacing = ~5 min of retry activity; after that the
# monitor gives up and logs a permanent-failure line so on-call can see it.
_NTFY_SEND_MAX_ATTEMPTS = 5


@dataclass
class _PerModeState:
    """Track the last-alerted give-up entry per mode.

    ``last_alerted_key`` is derived unconditionally from
    ``phase_entered_at`` — the Rust coordinator guarantees this stamp is
    monotonically-newer per give-up cycle (resume clears state; the
    subsequent ``enter_phase(Aggressive)`` re-stamps on the next give-up),
    so keying on it avoids the ``entered:`` → ``stamp:`` drift that could
    otherwise fire a duplicate alert on the same give-up entry (see
    finding B-MED-4). ``last_alerted_wall_secs`` gates the resend cadence.
    ``send_attempts`` bounds retries against a wedged ntfy transport.
    """
    last_alerted_key: str | None = None
    last_alerted_wall_secs: float = 0.0
    # Per-key retry counter. Reset whenever last_alerted_key changes to a
    # new give-up entry so a fresh give-up gets a fresh retry budget.
    send_attempts: int = 0
    # Signals we've already announced permanent-failure so the log doesn't
    # spam on subsequent ticks once the budget is spent.
    permanent_failure_logged: bool = False


def _dedupe_key(recovery: dict) -> str | None:
    """Return a dedupe key derived from ``phase_entered_at`` only.

    Keying on the coordinator-guaranteed monotonically-newer
    ``phase_entered_at`` avoids the shape drift when
    ``giveup_alert_sent_at`` transitions from absent to populated within
    the same give-up entry (which would look like a "new give-up" under
    the old ``stamp:`` / ``entered:`` split; see finding B-MED-4). If
    ``phase_entered_at`` is missing (unreachable for any coordinator that
    emits a ``recovery`` block, but keep the guard) return None.
    """
    entered = recovery.get("phase_entered_at")
    if entered:
        return f"entered:{entered}"
    return None


def _stamp_age_secs(recovery: dict, now: float) -> float | None:
    """Best-effort age (in seconds) of ``giveup_alert_sent_at`` vs ``now``.

    Returns None if the stamp is missing, unparseable, or clearly in the
    future. Used ONLY as a cold-boot suppression heuristic — never gates
    correctness, so ``ValueError`` short-circuits to None quietly.
    """
    stamp = recovery.get("giveup_alert_sent_at")
    if not stamp or not isinstance(stamp, str):
        return None
    # ISO-8601 with `Z` suffix is what the Rust side emits.
    try:
        from datetime import datetime, timezone
        iso = stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp
        parsed = datetime.fromisoformat(iso)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age = now - parsed.timestamp()
    except (ValueError, TypeError):
        return None
    return age if age >= 0 else None


class ReconnectGiveUpMonitor(Monitor):
    """Fires when a mode enters ``recovery.phase == "given_up"``.

    Non-transition monitor: reads STATUS JSON directly rather than scanning
    state-machine transition history, because the give-up phase is a
    coordinator-internal fact (not a state-machine transition).
    """

    event_type = "reconnect_gave_up"  # base — real coalescer key adds :mode
    interval_seconds = INTERVAL_SECONDS

    def __init__(self) -> None:
        self._state: dict[str, _PerModeState] = {}
        # First-tick guard: on cold-boot the state is empty, so ANY stamped
        # give-up would look like a "new_stamp" and re-fire the alert. Skip
        # sending on the first tick and instead seed state from what STATUS
        # already shows so operators don't get "reconnection given up"
        # duplicates every time the dashboard is bounced. See finding
        # B-MED-3.
        self._initialized = False
        # Sticky flag so `recovery.monitor.missing_signing_key` warns once
        # per process rather than every 60s. On-call sees the diagnostic
        # exactly once (finding B-LOW-5).
        self._missing_key_warned = False

    async def check(self, registry, ns) -> list[Alert]:
        """One tick: scan every mode for a give-up worthy of an alert.

        Returns an empty list — the monitor drives sends via
        ``ns.send_alert`` itself (``force=True``) to bypass the 5-minute
        per-event-type cooldown, matching Hitl2faEntryMonitor's pattern.
        """
        signing_key = os.environ.get(
            "IBCTL_NTFY_ACTION_SIGNING_KEY", "",
        ).strip()
        channel = getattr(ns.config, "channel", "")
        can_use_action = bool(signing_key) and channel == "ntfy"
        base_url = ""
        if can_use_action:
            base_url, _ = callback_common.resolve_dashboard_base_url()

        if not signing_key and not self._missing_key_warned:
            # One diagnostic per PROCESS so on-call can see the misconfig
            # without drowning the log every tick.
            logger.warning(
                "recovery.monitor.missing_signing_key env=%s",
                callback_common.SIGNING_KEY_ENV,
            )
            self._missing_key_warned = True

        for mode in registry.modes():
            try:
                await self._process_mode(
                    mode, registry, ns, signing_key, can_use_action, base_url,
                )
            except Exception as e:
                # An unhandled exception in one mode must not kill the tick
                # for the other mode(s). Log at error and move on.
                logger.error(
                    "recovery.monitor.tick_failed mode=%s error=%s",
                    mode, e,
                )

        # After the first pass over every mode the monitor has observed
        # the "history" it needs — subsequent ticks may fire alerts.
        self._initialized = True
        return []

    async def _process_mode(
        self,
        mode: str,
        registry,
        ns,
        signing_key: str,
        can_use_action: bool,
        base_url: str,
    ) -> None:
        status_raw = registry.cached_status_raw(mode) or {}
        recovery = status_raw.get("recovery")

        # Older ibctl daemons don't emit recovery — silent no-op. Do NOT
        # log per tick for a missing recovery block; it would spam during
        # rolling upgrades.
        if not recovery:
            return

        phase = recovery.get("phase")
        if phase != "given_up":
            return

        dedupe_key = _dedupe_key(recovery)
        if dedupe_key is None:
            # Coordinator in given_up with no phase_entered_at — should
            # be unreachable, but no-op rather than crash.
            logger.debug(
                "recovery.monitor.giveup_detected mode=%s dedupe_key=none",
                mode,
            )
            return

        state = self._state.setdefault(mode, _PerModeState())

        # Cold-boot suppression (finding B-MED-3): on the FIRST tick after
        # process start, DO NOT send an alert for a give-up entry that was
        # already stamped by the Rust coordinator. Instead, seed our state
        # so the resend cadence honours the pre-restart stamp. Without
        # this a dashboard restart re-fires the alert every time — and
        # give-ups happen precisely when the operator is not paying
        # attention, so the last thing we need is duplicate alarms on
        # every unrelated bounce.
        if not self._initialized and state.last_alerted_key is None:
            now = time.time()
            stamp_age = _stamp_age_secs(recovery, now)
            if stamp_age is not None:
                state.last_alerted_key = dedupe_key
                state.last_alerted_wall_secs = now - stamp_age
                logger.info(
                    "recovery.monitor.cold_boot_seeded mode=%s dedupe_key=%s "
                    "stamp_age_secs=%d",
                    mode, dedupe_key, int(stamp_age),
                )
                return

        if state.last_alerted_key == dedupe_key:
            # Same give-up entry we've already alerted for (or attempted
            # to). Two distinct sub-cases discriminated by
            # last_alerted_wall_secs:
            #   > 0 — the last send SUCCEEDED at that wall time; wait out
            #         the resend cadence before firing again.
            #   == 0 — no successful send yet for this key; retry
            #          on every tick until the retry ceiling clamps.
            resend_interval_hours = int(
                recovery.get("giveup_alert_resend_interval_hours")
                or DEFAULT_RESEND_INTERVAL_HOURS
            )
            resend_interval_secs = resend_interval_hours * 3600
            now = time.time()

            if state.last_alerted_wall_secs == 0:
                # Failure case — retry unless the ceiling is spent. This
                # is what prevents the 1440-attempts/day pathology under
                # a persistent ntfy outage (finding B-HIGH-2). Once
                # exhausted, stay quiet until the next fresh give-up
                # entry replaces `last_alerted_key`.
                if state.send_attempts >= _NTFY_SEND_MAX_ATTEMPTS:
                    if not state.permanent_failure_logged:
                        logger.error(
                            "recovery.monitor.alert_send_permanent_failure "
                            "mode=%s key=%s attempts=%d ceiling=%d",
                            mode, dedupe_key, state.send_attempts,
                            _NTFY_SEND_MAX_ATTEMPTS,
                        )
                        state.permanent_failure_logged = True
                    return
                reason = "retry_after_failure"
            else:
                # Success case — check the resend cadence.
                elapsed = now - state.last_alerted_wall_secs
                if elapsed < resend_interval_secs:
                    logger.debug(
                        "recovery.monitor.alert_suppressed_by_dedupe mode=%s key=%s",
                        mode, dedupe_key,
                    )
                    return
                # Cadence elapsed — reset the retry budget for the fresh
                # send window. Setting wall_secs back to 0 drops the
                # next iteration into the failure-retry branch above
                # if this send also fails, so the ceiling still applies
                # inside the resend window.
                state.send_attempts = 0
                state.permanent_failure_logged = False
                state.last_alerted_wall_secs = 0
                reason = "resend_interval_elapsed"
        else:
            # New give-up entry: fresh retry budget.
            state.send_attempts = 0
            state.permanent_failure_logged = False
            state.last_alerted_wall_secs = 0
            reason = "new_stamp"

        logger.info(
            "recovery.monitor.giveup_detected mode=%s dedupe_key=%s reason=%s",
            mode, dedupe_key, reason,
        )

        alert = self._build_alert(
            mode, recovery, can_use_action, signing_key, base_url,
        )
        await self._send_and_stamp(mode, ns, alert, dedupe_key)

    async def _send_and_stamp(
        self,
        mode: str,
        ns,
        alert: Alert,
        dedupe_key: str,
    ) -> None:
        """Send the alert and (on success) stamp our per-mode state."""
        # force=True bypasses NotificationService's per-event_type cooldown.
        # The transport-layer kind-keyed coalescer in NtfyClient still
        # applies, but the per-mode event_type suffix keeps live/paper
        # separate.
        state = self._state.setdefault(mode, _PerModeState())
        # Bump attempt count BEFORE the send so an exception still counts
        # toward the ceiling — otherwise a persistent raise would burn
        # the budget invisibly. Stamp the KEY on entry too so a failure
        # doesn't re-enter the "new_stamp" branch on the next tick and
        # reset the retry budget infinitely (finding B-HIGH-2).
        state.send_attempts += 1
        state.last_alerted_key = dedupe_key

        try:
            success = await ns.send_alert(
                event_type=alert.event_type,
                title=alert.title,
                body=alert.body,
                priority=alert.priority,
                tags=alert.tags,
                actions=alert.actions,
                force=True,
            )
        except Exception as e:  # pragma: no cover — defence in depth
            logger.error(
                "recovery.monitor.alert_send_failed mode=%s error=%s attempts=%d",
                mode, e, state.send_attempts,
            )
            # Failure path — leave last_alerted_wall_secs unchanged (0 on
            # first fail, older on later fails) so the "resend interval
            # elapsed" branch instantly retries on the next tick until
            # the ceiling clamps.
            return

        if success:
            url_hash_prefix = ""
            if alert.actions:
                url = alert.actions[0].get("url", "")
                if url:
                    url_hash_prefix = hashlib.sha256(
                        url.encode("utf-8"),
                    ).hexdigest()[:8]
            logger.info(
                "recovery.monitor.alert_sent kind=%s mode=%s callback_hash=%s",
                alert.event_type, mode, url_hash_prefix,
            )
            state.last_alerted_wall_secs = time.time()
        else:
            logger.warning(
                "recovery.monitor.alert_send_returned_false mode=%s attempts=%d",
                mode, state.send_attempts,
            )

    def _build_alert(
        self,
        mode: str,
        recovery: dict,
        can_use_action: bool,
        signing_key: str,
        base_url: str,
    ) -> Alert:
        """Build the ntfy alert for a give-up in one mode."""
        mode_upper = mode.upper()

        aggressive_secs = int(recovery.get("aggressive_phase_max_secs") or 3600)
        backoff_secs = int(recovery.get("backoff_phase_max_secs") or 10800)
        dwell_secs = int(recovery.get("min_success_dwell_secs") or 60)
        aggressive_mins = aggressive_secs // 60
        backoff_hours = backoff_secs // 3600
        # Elapsed = aggressive + backoff, rounded to hours.
        elapsed_hours = max(1, (aggressive_secs + backoff_secs) // 3600)

        title = (
            f"ibctl {mode}: reconnection given up after ~{elapsed_hours}h"
        )
        body_lines = [
            f"{mode_upper} gave up reconnection: Aggressive retry "
            f"{aggressive_mins}m + Backoff {backoff_hours}h without a "
            f"Connected dwell >={dwell_secs}s.",
            "Tap to resume aggressive retry.",
        ]

        # Per-mode coalescer key so simultaneous give-ups don't collapse.
        event_type = f"reconnect_gave_up:{mode}"

        alert_kwargs: dict = {
            "event_type": event_type,
            "title": title,
            "priority": "urgent",
            "tags": "warning,rotating_light",
        }

        if not can_use_action:
            body_lines.append(
                "operator intervention required; open the dashboard's "
                "state-machine page to send RESUME_RECONNECT manually",
            )
            return Alert(body="\n".join(body_lines), **alert_kwargs)

        valid_hours = int(
            recovery.get("callback_valid_hours") or DEFAULT_CALLBACK_VALID_HOURS
        )
        try:
            token = reconnect_tokens.mint_token(signing_key, mode, valid_hours)
        except ValueError as e:
            logger.warning(
                "recovery.monitor.token_mint_failed mode=%s error=%s",
                mode, e,
            )
            body_lines.append(
                "operator intervention required; open the dashboard's "
                "state-machine page to send RESUME_RECONNECT manually",
            )
            return Alert(body="\n".join(body_lines), **alert_kwargs)

        url = f"{base_url}/api/reconnect/callback?t={token}&mode={mode}"
        action = {
            "action": "view",
            "label": "Resume reconnect",
            "url": url,
            "clear": True,
        }
        return Alert(
            body="\n".join(body_lines), actions=[action], **alert_kwargs,
        )
