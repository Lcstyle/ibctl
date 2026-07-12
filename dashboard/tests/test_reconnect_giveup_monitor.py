"""RED-phase tests for the ReconnectGiveUpMonitor.

The monitor watches STATUS JSON for ``recovery.phase == "given_up"`` and
sends a ntfy alert with a signed callback URL when a mode transitions
into the give-up phase. On subsequent ticks it dedupes against
``recovery.giveup_alert_sent_at`` and honours the
``giveup_alert_resend_interval_hours`` cadence (default 6h) — distinct
from HITL's 15s retry cadence.

These tests target ``app.services.monitors.reconnect_giveup``. The module
does not yet exist; the import inside each test fails as the RED signal.
Mirrors ``TestHitl2faMonitorRetry`` patterns from ``test_twofa.py``:
in-memory registry + notification-service stubs, no HTTP.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from unittest.mock import patch

import pytest


SIGNING_KEY = "test-signing-key-for-reconnect-monitor"

# The default resend cadence per stage 5 spec. If a config plumbing bug
# reduced this to 0 (or the monitor read the wrong env var), the "resend
# after configured interval" test would false-pass — the constant here
# pins the expected value from the plan.
DEFAULT_RESEND_INTERVAL_HOURS = 6


# ---------------------------------------------------------------------------
# Test doubles — kept intentionally minimal, mirroring test_twofa.py stubs.
# ---------------------------------------------------------------------------


@dataclass
class _CapturedAlert:
    """Snapshot of everything the monitor tried to send.

    NotificationService.send_alert is a kwargs-only API in production. The
    stub captures every kwarg so tests can assert on any of them — event_type
    (coalescer key), body, actions[0].url, tags, etc.
    """
    event_type: str
    title: str
    body: str
    priority: str
    tags: str
    actions: list[dict] | None
    force: bool
    kind: str | None


class _NSStub:
    """Minimal NotificationService double.

    ``send_alert`` records every call and returns ``send_result`` (default
    True). Tests that want to observe multiple sends bump the ``ticks_before_
    reject_send`` field.
    """

    class config:
        channel = "ntfy"
        enabled = True

    def __init__(self, *, event_enabled: bool = True, send_result: bool = True):
        self._event_enabled = event_enabled
        self._send_result = send_result
        self.calls: list[_CapturedAlert] = []

    def is_event_enabled(self, event_type: str) -> bool:
        return self._event_enabled

    async def send_alert(self, **kwargs) -> bool:
        # NotificationService's real signature accepts kind implicitly via
        # event_type; the monitor may or may not pass a separate ``kind``.
        # Record both to avoid over-specifying the interface.
        self.calls.append(
            _CapturedAlert(
                event_type=kwargs.get("event_type", ""),
                title=kwargs.get("title", ""),
                body=kwargs.get("body", ""),
                priority=kwargs.get("priority", "default"),
                tags=kwargs.get("tags", ""),
                actions=kwargs.get("actions"),
                force=kwargs.get("force", False),
                kind=kwargs.get("kind"),
            )
        )
        return self._send_result


class _RegistryStub:
    """Minimal InstanceRegistry double parametrised on a per-mode STATUS map.

    The monitor consumes only ``modes()`` and ``cached_status_raw(mode)`` —
    both are cheap to mock. The status dict may include a ``recovery`` block
    with ``phase``, ``phase_entered_at``, ``giveup_alert_sent_at``,
    ``aggressive_phase_max_secs``, ``backoff_phase_max_secs``,
    ``min_success_dwell_secs``, and ``giveup_alert_resend_interval_hours``.
    """

    def __init__(self, status_by_mode: dict[str, dict | None]):
        # dict[mode] → cached STATUS dict (or None to simulate "no cache
        # populated for this mode yet")
        self._status = dict(status_by_mode)

    def modes(self) -> list[str]:
        return list(self._status.keys())

    def cached_status_raw(self, mode: str) -> dict | None:
        return self._status.get(mode)

    def set_status(self, mode: str, status: dict | None) -> None:
        self._status[mode] = status


def _giveup_status(
    *,
    mode: str = "paper",  # noqa: ARG001 — kept for symmetric call sites
    phase_entered_iso: str = "2026-07-11T12:00:00-04:00",
    giveup_alert_sent_at: str | None = None,
    resend_interval_hours: int = DEFAULT_RESEND_INTERVAL_HOURS,
    aggressive_max: int = 3600,
    backoff_max: int = 10800,
    min_dwell: int = 60,
) -> dict:
    """Return a STATUS dict with the recovery block populated for give-up."""
    return {
        "recovery": {
            "phase": "given_up",
            "phase_entered_at": phase_entered_iso,
            "giveup_alert_sent_at": giveup_alert_sent_at,
            "aggressive_phase_max_secs": aggressive_max,
            "backoff_phase_max_secs": backoff_max,
            "min_success_dwell_secs": min_dwell,
            "giveup_alert_resend_interval_hours": resend_interval_hours,
        }
    }


def _aggressive_status() -> dict:
    return {
        "recovery": {
            "phase": "aggressive",
            "phase_entered_at": "2026-07-11T12:00:00-04:00",
            "giveup_alert_sent_at": None,
            "aggressive_phase_max_secs": 3600,
            "backoff_phase_max_secs": 10800,
            "min_success_dwell_secs": 60,
            "giveup_alert_resend_interval_hours": DEFAULT_RESEND_INTERVAL_HOURS,
        }
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReconnectGiveUpMonitor:
    """Give-up monitor: detects transitions, alerts, dedupes, resends."""

    @pytest.mark.asyncio
    async def test_monitor_ignores_status_without_recovery_block(self):
        """Older ibctl daemons don't emit ``recovery`` — treat as no-op.

        The monitor must handle ``status.recovery is None`` gracefully so a
        mixed-deploy (old ibctl, new dashboard) does not throw on every tick
        and drown the log in ``KeyError: 'recovery'``.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        registry = _RegistryStub({"paper": {"other_field": True}})  # NO recovery
        ns = _NSStub()

        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            alerts = await monitor.check(registry, ns)

        assert alerts == []
        assert ns.calls == [], (
            "monitor must not call send_alert when the recovery block is absent"
        )

    @pytest.mark.asyncio
    async def test_monitor_fires_alert_on_given_up_transition(self):
        """New given_up entry with no prior giveup_alert_sent_at → alert fires.

        This is the primary happy path. The first tick where the monitor sees
        ``phase == given_up`` and no ``giveup_alert_sent_at`` (or one that
        the monitor has not observed yet) must trigger a send.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        registry = _RegistryStub({"paper": _giveup_status(mode="paper")})
        ns = _NSStub()

        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(registry, ns)

        assert len(ns.calls) == 1, (
            f"expected 1 send on give_up transition, got {len(ns.calls)}"
        )
        call = ns.calls[0]
        # Title must name ibctl + mode so on-call operators can triage from
        # the notification tray alone.
        assert "paper" in call.title.lower() or "PAPER" in call.title
        # Body must mention that reconnection was given up.
        assert "given" in call.body.lower() or "gave" in call.body.lower() or "up" in call.body.lower()

    @pytest.mark.asyncio
    async def test_monitor_dedupes_via_phase_entered_at(self):
        """Two ticks with the same ``phase_entered_at`` → 1 send.

        Under finding B-MED-4 the dedupe key was simplified to key only
        on ``phase_entered_at`` (the monotonically-newer per-give-up-cycle
        stamp), eliminating the ``stamp:`` → ``entered:`` drift bug. This
        test drives the mid-run dedupe path — a "warmup" tick in the
        aggressive phase first flips ``_initialized=True`` so cold-boot
        suppression (finding B-MED-3) doesn't dedupe the first stamped
        tick.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        # Warm-up: monitor observes aggressive (no send) → _initialized = True.
        warmup_registry = _RegistryStub({"paper": _aggressive_status()})
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(warmup_registry, ns)
        assert ns.calls == []

        # Now the mode transitions into given_up.
        stamped_status = _giveup_status(
            mode="paper", giveup_alert_sent_at="2026-07-11T12:00:00Z"
        )
        registry = _RegistryStub({"paper": stamped_status})
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(registry, ns)
            await monitor.check(registry, ns)

        assert len(ns.calls) == 1, (
            f"same phase_entered_at must dedupe; got {len(ns.calls)} sends"
        )

    @pytest.mark.asyncio
    async def test_monitor_no_drift_when_stamp_appears_mid_entry(self):
        """A stamped→populated transition within the same give-up must NOT
        re-fire (finding B-MED-4).

        Reachable when the coordinator's dedupe guard skipped a re-stamp
        on an older ibctl that had ``sent_at=None`` in its persisted state
        even though ``phase==GivenUp``. Under the OLD dedupe scheme
        (``entered:`` fallback → ``stamp:`` after the coordinator re-runs
        FireGiveUpAlert), the shape change would look like a "new_stamp"
        event and re-fire the alert. Under the phase-entered-only scheme
        the key is stable across the transition.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        # Warm up so cold-boot suppression is not in play.
        warmup_registry = _RegistryStub({"paper": _aggressive_status()})
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(warmup_registry, ns)

        entered_at = "2026-07-11T12:00:00-04:00"
        # Tick 1: given_up with phase_entered_at set, NO stamp yet.
        first = _giveup_status(
            mode="paper",
            phase_entered_iso=entered_at,
            giveup_alert_sent_at=None,
        )
        # Tick 2: stamp appears (coordinator's FireGiveUpAlert re-runs).
        second = _giveup_status(
            mode="paper",
            phase_entered_iso=entered_at,
            giveup_alert_sent_at="2026-07-11T12:05:00Z",
        )
        registry = _RegistryStub({"paper": first})
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(registry, ns)
            registry.set_status("paper", second)
            await monitor.check(registry, ns)

        assert len(ns.calls) == 1, (
            "stamp-drift within one give-up must dedupe; "
            f"got {len(ns.calls)} sends"
        )

    @pytest.mark.asyncio
    async def test_monitor_resend_after_configured_interval(self):
        """After ``giveup_alert_resend_interval_hours`` elapses → resend.

        Finding C-HIGH-1: the ORIGINAL version of this test only drove a
        single ``check()`` — the resend-cadence branch was never reached,
        so deleting the entire resend gate would not have made this test
        fail (a vacuous test). This version drives TWO ticks:
          - Tick 1 seeds state at T=T0 (successful send).
          - Tick 2 at T=T0+7h asserts a second send fires (resend cadence
            of 6h elapsed).
        A companion assertion at T=T0+1h in
        ``test_monitor_no_resend_before_configured_interval`` pins the
        "still deduped" side so an "always resend" implementation would
        also fail.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        # Warm-up so cold-boot suppression is not in play.
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(
                _RegistryStub({"paper": _aggressive_status()}), ns,
            )

        registry = _RegistryStub(
            {"paper": _giveup_status(
                mode="paper",
                giveup_alert_sent_at="2026-07-11T12:00:00Z",
                resend_interval_hours=6,
            )}
        )

        T0 = time.mktime(
            time.strptime("2026-07-11 12:00:00", "%Y-%m-%d %H:%M:%S")
        )
        with patch.dict(
            os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}
        ):
            # Tick 1 at T0 — fires (first observation post-warmup) and
            # stamps last_alerted_wall_secs = T0.
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0,
            ):
                await monitor.check(registry, ns)
            assert len(ns.calls) == 1, "first observation must fire"

            # Tick 2 at T0 + 7h — resend cadence (6h) elapsed → second fire.
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0 + 7 * 3600,
            ):
                await monitor.check(registry, ns)

        assert len(ns.calls) == 2, (
            "give-up alert must resend after resend_interval_hours elapsed; "
            f"got {len(ns.calls)} sends"
        )

    @pytest.mark.asyncio
    async def test_monitor_no_resend_before_configured_interval(self):
        """Companion to the resend test — inside the interval, dedupe holds.

        Finding C-HIGH-1: without this test, an "always resend" bug
        would pass the resend-after test AND the vacuous original.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(
                _RegistryStub({"paper": _aggressive_status()}), ns,
            )

        registry = _RegistryStub(
            {"paper": _giveup_status(
                mode="paper",
                giveup_alert_sent_at="2026-07-11T12:00:00Z",
                resend_interval_hours=6,
            )}
        )
        T0 = time.mktime(
            time.strptime("2026-07-11 12:00:00", "%Y-%m-%d %H:%M:%S")
        )
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0,
            ):
                await monitor.check(registry, ns)
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0 + 1 * 3600,  # only 1h — dedupe holds.
            ):
                await monitor.check(registry, ns)

        assert len(ns.calls) == 1, (
            "inside resend cadence must dedupe; "
            f"got {len(ns.calls)} sends"
        )

    @pytest.mark.asyncio
    async def test_monitor_no_alert_in_aggressive_or_backoff(self):
        """Phase == aggressive → no alert. Phase == backoff → no alert.

        The give-up monitor is scoped strictly to ``given_up``. The
        aggressive/backoff phases have their own retry logic; alerting there
        would spam operators for phases the state machine is designed to
        self-recover from.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()

        # Aggressive phase.
        agg_registry = _RegistryStub({"paper": _aggressive_status()})
        agg_ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(agg_registry, agg_ns)
        assert agg_ns.calls == [], "aggressive phase must NOT alert"

        # Backoff phase.
        monitor2 = ReconnectGiveUpMonitor()
        backoff_status = _giveup_status(mode="paper")
        backoff_status["recovery"]["phase"] = "backoff_every_15min"
        backoff_status["recovery"]["giveup_alert_sent_at"] = None
        backoff_registry = _RegistryStub({"paper": backoff_status})
        backoff_ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor2.check(backoff_registry, backoff_ns)
        assert backoff_ns.calls == [], "backoff phase must NOT alert"

    @pytest.mark.asyncio
    async def test_monitor_action_button_url_contains_signed_token(self):
        """The ntfy action button URL contains a valid v2 reconnect token.

        The URL should:
          - Point at ``/api/reconnect/callback``
          - Include ``t=<token>`` (a v2.reconnect.<...> token)
          - Include ``mode=<mode>``
          - Be signed with the env-configured signing key
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor
        from app.services import hitl_tokens

        monitor = ReconnectGiveUpMonitor()
        registry = _RegistryStub({"paper": _giveup_status(mode="paper")})
        ns = _NSStub()

        with patch.dict(
            os.environ,
            {
                "IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY,
                "IBCTL_DASHBOARD_EXTERNAL_URL": "https://ibctl.example.com",
            },
        ):
            await monitor.check(registry, ns)

        assert len(ns.calls) == 1
        actions = ns.calls[0].actions or []
        assert len(actions) == 1, "give-up alert must have exactly one action button"
        action = actions[0]
        url = action["url"]
        assert url.startswith("https://ibctl.example.com/api/reconnect/callback")
        assert "t=" in url and "mode=paper" in url

        # Extract the token from the URL query and validate it as a
        # v2.reconnect token — proves it was minted with the right intent
        # AND the right signing key.
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        token = qs["t"][0]
        valid, reason = hitl_tokens.validate_token(
            SIGNING_KEY, token, expected_intent="reconnect"
        )
        assert valid, f"minted token must validate as reconnect intent: {reason}"

    @pytest.mark.asyncio
    async def test_monitor_coalescer_key_is_per_mode(self):
        """Dual-mode give-ups produce distinct coalescer keys.

        Spec: ``event_type = "reconnect_gave_up:<mode>"`` so simultaneous
        live+paper give-ups do NOT collapse into a single ntfy notification
        via the ntfy client's kind-keyed coalescer.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        registry = _RegistryStub({
            "paper": _giveup_status(mode="paper"),
            "live":  _giveup_status(mode="live"),
        })
        ns = _NSStub()

        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(registry, ns)

        assert len(ns.calls) == 2, "one alert per mode when both are given_up"
        keys = {c.event_type for c in ns.calls}
        assert keys == {"reconnect_gave_up:paper", "reconnect_gave_up:live"}, (
            f"per-mode coalescer keys required, got {keys}"
        )

    @pytest.mark.asyncio
    async def test_monitor_cold_boot_suppresses_stamped_giveup(self):
        """Finding B-MED-3: dashboard cold-boot must NOT re-fire an alert
        for a give-up entry that STATUS already shows as stamped.

        Scenario: ibctl was already in give_up with sent_at populated
        BEFORE the dashboard started. The monitor's per-mode state is
        empty at construction; without this suppression the first tick
        would fire "again". With it, the first tick seeds state silently.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        # Stamp 30 min old — well inside the 6h resend window.
        T0 = time.mktime(
            time.strptime("2026-07-11 12:00:00", "%Y-%m-%d %H:%M:%S")
        )
        stamp_iso = "2026-07-11T11:30:00Z"
        registry = _RegistryStub({
            "paper": _giveup_status(
                mode="paper", giveup_alert_sent_at=stamp_iso,
                resend_interval_hours=6,
            )
        })
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0,
            ):
                await monitor.check(registry, ns)
        assert ns.calls == [], (
            "cold-boot with a stamped give-up must NOT re-fire the alert"
        )

    @pytest.mark.asyncio
    async def test_monitor_cold_boot_seeded_stamp_still_resends_after_interval(self):
        """A cold-boot-seeded stamp still resends once the cadence elapses.

        Companion to the cold-boot suppression test — this proves the
        suppression is not a permanent silence but a "wait out the
        resend cadence" delay.
        """
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        # Stamp 30 min old at boot; wait 6h30m → resend cadence elapses.
        T0 = time.mktime(
            time.strptime("2026-07-11 12:00:00", "%Y-%m-%d %H:%M:%S")
        )
        stamp_iso = "2026-07-11T11:30:00Z"
        registry = _RegistryStub({
            "paper": _giveup_status(
                mode="paper", giveup_alert_sent_at=stamp_iso,
                resend_interval_hours=6,
            )
        })
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0,
            ):
                await monitor.check(registry, ns)
            assert ns.calls == []
            # Advance 7h — the seeded wall_secs (T0 - 30min) is now
            # 7h30m in the past → resend cadence (6h) elapsed.
            with patch(
                "app.services.monitors.reconnect_giveup.time.time",
                return_value=T0 + 7 * 3600,
            ):
                await monitor.check(registry, ns)
        assert len(ns.calls) == 1, (
            "cold-boot-seeded stamp must eventually resend after cadence"
        )

    @pytest.mark.asyncio
    async def test_monitor_bounds_retries_on_persistent_send_failure(self):
        """Finding B-HIGH-2: a persistent ntfy outage must NOT drive
        1440 sends/day. The monitor caps retry attempts per give-up entry
        and logs a permanent-failure line when the ceiling is hit.
        """
        from app.services.monitors.reconnect_giveup import (
            ReconnectGiveUpMonitor,
            _NTFY_SEND_MAX_ATTEMPTS,
        )

        monitor = ReconnectGiveUpMonitor()
        # Warm-up so cold-boot suppression doesn't dedupe the first fire.
        ns = _NSStub(send_result=False)
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(
                _RegistryStub({"paper": _aggressive_status()}), ns,
            )

        # Now stamp given_up with no sent_at (so cold-boot suppression
        # doesn't apply even on next tick).
        registry = _RegistryStub({
            "paper": _giveup_status(mode="paper", giveup_alert_sent_at=None),
        })
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            # Drive many ticks — every one fails.
            for _ in range(_NTFY_SEND_MAX_ATTEMPTS + 20):
                await monitor.check(registry, ns)

        assert len(ns.calls) == _NTFY_SEND_MAX_ATTEMPTS, (
            f"retry ceiling must clamp to {_NTFY_SEND_MAX_ATTEMPTS}; "
            f"got {len(ns.calls)}"
        )

    @pytest.mark.asyncio
    async def test_monitor_permanent_failure_log_fires_once(self, caplog):
        """Finding B-HIGH-2: once the retry ceiling is hit, the permanent-
        failure line is emitted exactly ONCE so on-call doesn't get spam
        for the remainder of the give-up entry."""
        import logging as _logging
        from app.services.monitors.reconnect_giveup import (
            ReconnectGiveUpMonitor,
            _NTFY_SEND_MAX_ATTEMPTS,
        )

        monitor = ReconnectGiveUpMonitor()
        ns = _NSStub(send_result=False)
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(
                _RegistryStub({"paper": _aggressive_status()}), ns,
            )

        registry = _RegistryStub({
            "paper": _giveup_status(mode="paper", giveup_alert_sent_at=None),
        })
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            with caplog.at_level(
                _logging.ERROR,
                logger="dashboard.services.monitors.reconnect_giveup",
            ):
                for _ in range(_NTFY_SEND_MAX_ATTEMPTS + 15):
                    await monitor.check(registry, ns)

        permanent = [
            r for r in caplog.records
            if "alert_send_permanent_failure" in r.getMessage()
        ]
        assert len(permanent) == 1, (
            f"permanent-failure log must fire exactly once; got {len(permanent)}"
        )

    @pytest.mark.asyncio
    async def test_monitor_missing_signing_key_warns_only_once(self, caplog):
        """Finding B-LOW-5: the missing_signing_key diagnostic must warn
        exactly once per process rather than every tick."""
        import logging as _logging
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        registry = _RegistryStub({"paper": _giveup_status(mode="paper")})
        ns = _NSStub()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IBCTL_NTFY_ACTION_SIGNING_KEY", None)
            with caplog.at_level(
                _logging.WARNING,
                logger="dashboard.services.monitors.reconnect_giveup",
            ):
                for _ in range(5):
                    await monitor.check(registry, ns)

        missing_key_warns = [
            r for r in caplog.records
            if "missing_signing_key" in r.getMessage()
        ]
        assert len(missing_key_warns) == 1, (
            f"missing_signing_key warn must be one-shot; "
            f"got {len(missing_key_warns)}"
        )

    @pytest.mark.asyncio
    async def test_monitor_tick_failure_in_one_mode_does_not_kill_other(self):
        """Finding C-MED-4: an exception in one mode's _process_mode
        must not abort the whole tick — the other mode(s) still get
        processed."""
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        ns = _NSStub()

        # Warm up so cold-boot suppression is not in play for live.
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(
                _RegistryStub({
                    "paper": _aggressive_status(),
                    "live": _aggressive_status(),
                }), ns,
            )

        # Now paper's cached_status_raw raises; live is a fresh give-up.
        class _BustedRegistry(_RegistryStub):
            def cached_status_raw(self, mode):
                if mode == "paper":
                    raise RuntimeError("cache corrupted")
                return super().cached_status_raw(mode)

        registry = _BustedRegistry({
            "paper": _giveup_status(mode="paper"),
            "live": _giveup_status(mode="live", giveup_alert_sent_at=None),
        })
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(registry, ns)

        # Live should have received an alert despite paper crashing.
        assert any(
            c.event_type == "reconnect_gave_up:live" for c in ns.calls
        ), "live's alert must fire even though paper's tick raised"

    @pytest.mark.asyncio
    async def test_monitor_no_phase_entered_at_is_silent_noop(self, caplog):
        """Finding C-MED-4: a recovery block with neither the stamp nor
        phase_entered_at must be a silent no-op, not a crash."""
        import logging as _logging
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        # Warm-up.
        ns = _NSStub()
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            await monitor.check(
                _RegistryStub({"paper": _aggressive_status()}), ns,
            )

        registry = _RegistryStub({
            "paper": {
                "recovery": {
                    "phase": "given_up",
                    "phase_entered_at": None,
                    "giveup_alert_sent_at": None,
                }
            },
        })
        with patch.dict(os.environ, {"IBCTL_NTFY_ACTION_SIGNING_KEY": SIGNING_KEY}):
            with caplog.at_level(
                _logging.DEBUG,
                logger="dashboard.services.monitors.reconnect_giveup",
            ):
                # Must NOT raise.
                await monitor.check(registry, ns)
        assert ns.calls == []

    @pytest.mark.asyncio
    async def test_monitor_no_signing_key_logs_error_no_crash(self, caplog):
        """No IBCTL_NTFY_ACTION_SIGNING_KEY → structured log, no crash.

        Without the signing key the monitor can't build the action button.
        It must still process the tick without raising (an uncaught exception
        would kill the MonitorManager loop and silence every monitor).
        The unsigned-alert fallback (plain text, no callback) is acceptable
        but not asserted here — this test only pins "no crash".
        """
        import logging
        from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor

        monitor = ReconnectGiveUpMonitor()
        registry = _RegistryStub({"paper": _giveup_status(mode="paper")})
        ns = _NSStub()

        # Force the env var to be unset regardless of test-runner state.
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IBCTL_NTFY_ACTION_SIGNING_KEY", None)
            with caplog.at_level(logging.WARNING):
                # Must NOT raise.
                await monitor.check(registry, ns)

        # Some diagnostic log must be present so on-call can figure out
        # why the button is missing. Check for either the env var name or
        # the phrase "signing key".
        merged = "\n".join(r.getMessage() for r in caplog.records)
        assert (
            "IBCTL_NTFY_ACTION_SIGNING_KEY" in merged
            or "signing key" in merged.lower()
            or "signing_key" in merged.lower()
        ), (
            "monitor must log a diagnostic about the missing signing key; "
            f"captured records: {[r.getMessage() for r in caplog.records]}"
        )
