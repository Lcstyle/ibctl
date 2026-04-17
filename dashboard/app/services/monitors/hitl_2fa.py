"""Monitor: alert once when ibctl enters WaitingForHitl2fa.

Sends a rich ntfy action notification with a one-shot callback URL
signed by IBCTL_NTFY_ACTION_SIGNING_KEY. Only fires on the ENTRY
transition (State X -> WaitingForHitl2fa) — not on every tick while
in HITL.

When the signing key is missing OR the notification channel is not
ntfy, we fall back to a plain (no-action-button) notification that
tells the operator to drive HITL_RESUME from the dashboard UI.

Retry behaviour (Item 2):
  If the ntfy push fails, the monitor retries up to
  IBCTL_TWOFA_NTFY_SEND_RETRIES times (default 1) on subsequent 15-second
  ticks, until either the send succeeds or retries are exhausted.
  State is tracked per-mode so live/paper operate independently.
"""

from __future__ import annotations

import logging
import os

from app.services import hitl_tokens
from app.services.monitor_manager import Alert, TransitionMonitor

logger = logging.getLogger("dashboard.services.monitors.hitl_2fa")

# Default when STATUS does not expose hitl.callback_valid_hours.
DEFAULT_CALLBACK_VALID_HOURS = 12

# How many extra ntfy send attempts to make after the first failure.
# Reads IBCTL_TWOFA_NTFY_SEND_RETRIES at runtime (not at import time)
# so test code can patch os.environ.
_DEFAULT_NTFY_SEND_RETRIES = 1
# Ceiling on runaway configs. Force.True bypasses the NotificationService
# cooldown, so a stuck HITL session with max_retries=1000 would spam alerts.
# 5 retries × the 15s check interval = ~75s of retry activity, which is
# already generous for transient ntfy outages.
_NTFY_SEND_RETRIES_CEILING = 5


def _ntfy_send_retries() -> int:
    """Return the configured max retries from env, floored at 0 and capped
    at `_NTFY_SEND_RETRIES_CEILING` to bound alert spam under misconfig."""
    try:
        raw = int(os.environ.get("IBCTL_TWOFA_NTFY_SEND_RETRIES", str(_DEFAULT_NTFY_SEND_RETRIES)))
    except ValueError:
        return _DEFAULT_NTFY_SEND_RETRIES
    return max(0, min(_NTFY_SEND_RETRIES_CEILING, raw))


def _resolve_dashboard_base_url() -> tuple[str, bool]:
    """Return (base_url, is_fallback).

    Preference order:
      1. IBCTL_DASHBOARD_EXTERNAL_URL — what an operator's phone can reach
      2. IBCTL_DASHBOARD_INTERNAL_URL — last-ditch fallback (warn)
      3. Construct http://localhost:<port> from IBCTL_DASHBOARD_PORT (warn)
    """
    external = os.environ.get("IBCTL_DASHBOARD_EXTERNAL_URL", "").strip().rstrip("/")
    if external:
        return external, False

    internal = os.environ.get("IBCTL_DASHBOARD_INTERNAL_URL", "").strip().rstrip("/")
    if internal:
        logger.warning(
            "IBCTL_DASHBOARD_EXTERNAL_URL not set; falling back to "
            "IBCTL_DASHBOARD_INTERNAL_URL — phone click-through may not work",
        )
        return internal, True

    port = os.environ.get("IBCTL_DASHBOARD_PORT", "8080").strip()
    logger.warning(
        "Neither IBCTL_DASHBOARD_EXTERNAL_URL nor IBCTL_DASHBOARD_INTERNAL_URL "
        "is set; HITL callback URL will point to http://localhost:%s which "
        "is not reachable from a phone",
        port,
    )
    return f"http://localhost:{port}", True


def _format_next_retry(secs: int | None) -> str:
    if secs is None:
        return "retry time unknown"
    if secs <= 0:
        return "retry pending now"
    if secs < 60:
        return f"next auto-retry in {secs}s"
    mins = secs // 60
    if mins < 120:
        return f"next auto-retry in ~{mins} min"
    hours = mins // 60
    return f"next auto-retry in ~{hours}h"


def _build_action_button(base_url: str, token: str, mode: str) -> dict:
    """Build a single ntfy 'view' action dict pointing at the callback."""
    url = f"{base_url}/api/twofa/callback?t={token}&mode={mode}"
    # clear=true tells ntfy to dismiss the notification after the click, so a
    # stale button doesn't keep sitting in the tray after it has been used.
    return {
        "action": "view",
        "label": f"Retry {mode.upper()} 2FA",
        "url": url,
        "clear": True,
    }


class Hitl2faEntryMonitor(TransitionMonitor):
    """Fires once when ibctl transitions INTO WaitingForHitl2fa.

    Retry state (per-mode dicts, keyed by "live"/"paper"):
      _entry_key         — the dedup key for the HITL entry currently being
                           tracked (same as TransitionMonitor._last_seen_key
                           but we keep our own copy to detect mode exit).
      _send_retries_remaining — how many more send attempts remain for this
                           entry.  -1 means "not yet attempted".
      _send_succeeded    — True once a send has succeeded; gate to stop retrying.
    """

    event_type = "hitl_2fa_required"
    interval_seconds = 15

    def __init__(self):
        super().__init__()
        self._entry_key: dict[str, str] = {}          # mode -> active entry dedup key
        self._send_retries_remaining: dict[str, int] = {}  # mode -> retries left
        self._send_succeeded: dict[str, bool] = {}    # mode -> whether send succeeded

    def _scan_history(self, mode, history):
        for transition in reversed(history):
            if transition.to_state != "WaitingForHitl2fa":
                continue
            if transition.from_state == "WaitingForHitl2fa":
                # Shouldn't happen — self-loop — but be defensive.
                continue
            key = f"{transition.timestamp}|{transition.from_state}|{transition.to_state}"
            # We build a stub Alert here; the real Alert (with action button
            # and retry-time body) is assembled in `check()` where we have
            # access to the registry and can read raw STATUS.
            return key, Alert(
                event_type=self.event_type,
                title="",  # filled in by check()
                body="",
                priority="urgent",
                tags="warning,key",
            )
        return None

    def _build_rich_alert(self, mode: str, status_raw: dict, can_use_action: bool, signing_key: str, base_url: str) -> Alert:
        """Build a fully-enriched Alert for one mode from STATUS data."""
        hitl_block = status_raw.get("hitl") or {}
        next_retry = hitl_block.get("next_retry_in_secs")
        valid_hours = int(hitl_block.get("callback_valid_hours") or DEFAULT_CALLBACK_VALID_HOURS)
        attempts = hitl_block.get("consecutive_2fa_timeouts") or hitl_block.get("attempts_exhausted")

        mode_upper = mode.upper()
        lines = [
            f"{mode_upper} exhausted automatic 2FA attempts "
            f"({attempts if attempts is not None else 'multiple'} in a row).",
            _format_next_retry(next_retry) + ".",
        ]
        alert_kwargs: dict = {
            "event_type": self.event_type,
            "title": f"ibctl: 2FA required for {mode_upper}",
            "priority": "urgent",
            "tags": "warning,key",
        }

        if can_use_action:
            try:
                token = hitl_tokens.mint_token(signing_key, mode, valid_hours)
            except ValueError as e:
                logger.warning("Failed to mint HITL token for %s: %s", mode, e)
                lines.append(
                    "operator intervention required; use dashboard's "
                    "state-machine dialog to send HITL_RESUME"
                )
                return Alert(body="\n".join(lines), **alert_kwargs)
            lines.append(f"Tap the button below to retry (valid {valid_hours}h).")
            action = _build_action_button(base_url, token, mode)
            return Alert(body="\n".join(lines), actions=[action], **alert_kwargs)
        else:
            reason = "signing_key unset" if not signing_key else "channel not ntfy"
            logger.info("HITL alert for %s: skipping action button (%s)", mode, reason)
            lines.append(
                "operator intervention required; use dashboard's "
                "state-machine dialog to send HITL_RESUME"
            )
            return Alert(body="\n".join(lines), **alert_kwargs)

    async def check(self, registry, ns):
        """Override TransitionMonitor.check to enrich alerts with STATUS data,
        and to retry failed ntfy sends on subsequent ticks.

        Flow per tick:
          1. Call super().check() — returns alerts only on *new* transitions.
          2. For each mode the base class flagged as new, this is attempt 1:
             reset retry state and try to send immediately (via ns.send_alert).
             If it succeeds, mark done. If it fails, record retries remaining.
          3. For modes NOT flagged by the base class but with retries remaining
             (send failed on a previous tick): attempt to send again.
          4. On mode exit (hitl block gone), clear per-mode retry state.

        We drive the send ourselves for the retry path rather than returning
        Alert objects, so the MonitorManager's send_alert call (which runs
        after check() returns) handles only the first-attempt happy path.
        The retry sends are forced (force=True) to bypass the 5-minute
        cooldown in NotificationService.
        """
        base_alerts = await super().check(registry, ns)

        signing_key = os.environ.get("IBCTL_NTFY_ACTION_SIGNING_KEY", "").strip()
        channel = getattr(ns.config, "channel", "")
        can_use_action = bool(signing_key) and channel == "ntfy"
        base_url, _ = _resolve_dashboard_base_url() if can_use_action else ("", True)

        # Determine which modes are currently in HITL according to STATUS cache.
        modes_in_hitl: set[str] = set()
        for mode in registry.modes():
            status_raw = registry.cached_status_raw(mode) or {}
            hitl_block = status_raw.get("hitl") or {}
            if hitl_block.get("active"):
                modes_in_hitl.add(mode)

        # --- Handle new transitions (first send attempt) ---
        # base_alerts is non-empty on transition into HITL.  We want to attempt
        # the send ourselves so we can observe success/failure.
        alerts_out: list[Alert] = []

        if base_alerts:
            # Build rich alerts for every mode currently in HITL.
            for mode in registry.modes():
                if mode not in modes_in_hitl:
                    # super() fired but STATUS cache hasn't caught up yet;
                    # fall back to plain placeholder (same as before).
                    continue
                status_raw = registry.cached_status_raw(mode) or {}
                alert = self._build_rich_alert(mode, status_raw, can_use_action, signing_key, base_url)

                max_retries = _ntfy_send_retries()
                attempt_num = 1
                total = 1 + max_retries
                logger.info("HITL ntfy send attempt %d/%d for mode=%s", attempt_num, total, mode)

                success = await ns.send_alert(
                    event_type=alert.event_type,
                    title=alert.title,
                    body=alert.body,
                    priority=alert.priority,
                    tags=alert.tags,
                    actions=alert.actions,
                    force=True,
                )

                if success:
                    logger.info("HITL ntfy send succeeded for mode=%s", mode)
                    self._entry_key[mode] = self._last_seen_key.get(mode, "")
                    self._send_retries_remaining[mode] = 0
                    self._send_succeeded[mode] = True
                else:
                    logger.warning(
                        "HITL ntfy send failed for mode=%s, retries_remaining=%d",
                        mode, max_retries,
                    )
                    self._entry_key[mode] = self._last_seen_key.get(mode, "")
                    self._send_retries_remaining[mode] = max_retries
                    self._send_succeeded[mode] = False

            # If STATUS cache had no hitl block for any of the alerted modes,
            # fall back to placeholders so we still surface *something*.
            if not modes_in_hitl:
                for alert in base_alerts:
                    alert.title = "ibctl: 2FA required"
                    alert.body = (
                        "ibctl entered WaitingForHitl2fa. "
                        "Open the dashboard to resume."
                    )
                    alerts_out.append(alert)

            # We drove the sends ourselves above; return empty so MonitorManager
            # doesn't double-send.
            return alerts_out

        # --- Handle retry ticks (no new transition, but prior send failed) ---
        for mode in list(self._send_retries_remaining.keys()):
            retries_left = self._send_retries_remaining.get(mode, 0)
            succeeded = self._send_succeeded.get(mode, True)
            current_key = self._last_seen_key.get(mode, "")

            # Clear retry state if mode exited HITL or key changed (new entry).
            if mode not in modes_in_hitl or current_key != self._entry_key.get(mode, ""):
                self._send_retries_remaining.pop(mode, None)
                self._send_succeeded.pop(mode, None)
                self._entry_key.pop(mode, None)
                continue

            if succeeded or retries_left <= 0:
                continue

            status_raw = registry.cached_status_raw(mode) or {}
            alert = self._build_rich_alert(mode, status_raw, can_use_action, signing_key, base_url)

            max_retries = _ntfy_send_retries()
            # total attempts already made = (max_retries - retries_left + 1);
            # this tick is attempt N+1 where N = that count.
            attempt_num = max_retries - retries_left + 2
            total = 1 + max_retries
            logger.info("HITL ntfy send attempt %d/%d for mode=%s", attempt_num, total, mode)

            success = await ns.send_alert(
                event_type=alert.event_type,
                title=alert.title,
                body=alert.body,
                priority=alert.priority,
                tags=alert.tags,
                actions=alert.actions,
                force=True,
            )

            if success:
                logger.info("HITL ntfy send succeeded for mode=%s", mode)
                self._send_retries_remaining[mode] = 0
                self._send_succeeded[mode] = True
            else:
                new_remaining = retries_left - 1
                logger.warning(
                    "HITL ntfy send failed for mode=%s, retries_remaining=%d",
                    mode, new_remaining,
                )
                self._send_retries_remaining[mode] = new_remaining

        return alerts_out
