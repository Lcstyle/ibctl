"""Golden-JSON shape tests for STATUS v1 including the recovery block.

Pins the STATUS wire format the Rust ibctl daemon emits so a future
refactor that renames a field cannot silently drift the dashboard's
parser out of sync with the daemon. The fixture at
``tests/fixtures/status_v1_with_recovery.json`` IS the schema — every
key here is asserted present with the expected type.

RED-PHASE STATE
---------------

Every test here is expected to FAIL in the RED half of the TDD cycle:

* The ``Recovery`` and ``GatewayStatus``-with-recovery models don't
  exist in ``app.domain.models`` yet. ``from_json`` currently drops
  the ``recovery`` field entirely (extra keys are ignored by frozen
  dataclasses).
* ``dashboard/app/templates/base.html`` doesn't render a
  ``recovery-badge`` element yet, and the SSE ``status`` handler
  doesn't consume ``status.recovery.*``.

GREEN implements the model, wires it through ``from_json``, and adds
the badge markup + SSE handler.

FIXTURE COMPATIBILITY
---------------------

The fixture is REQUIRED to be a superset of the schema an older ibctl
daemon (without recovery) would emit — dashboard-side deserialization
of the missing-recovery case must succeed with ``status.recovery is
None`` so a mixed live/paper deploy (live on old Rust, paper on new
Rust) doesn't crash the older instance's monitoring path. See
:func:`test_recovery_defaults_to_none_when_absent`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "status_v1_with_recovery.json"


def _load_fixture() -> dict:
    """Load and parse the pinned STATUS JSON fixture."""
    with FIXTURE_PATH.open() as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Fixture presence / basic shape
# ---------------------------------------------------------------------------


def test_fixture_file_exists_and_parses():
    """The golden fixture must live on disk and parse as valid JSON.

    Pins the fixture location so a rename doesn't silently make all
    downstream tests pass on an empty dict.
    """
    assert FIXTURE_PATH.exists(), (
        f"golden fixture missing at {FIXTURE_PATH} — the whole test file "
        f"depends on it. Recreate from the stage-4 spec if lost."
    )
    data = _load_fixture()
    assert isinstance(data, dict), "STATUS payload must be a JSON object"


def test_fixture_carries_recovery_block():
    """The fixture must include the recovery block; it's the reason
    this file exists.
    """
    data = _load_fixture()
    assert "recovery" in data, (
        "fixture is missing the 'recovery' top-level key — "
        "the golden fixture is the source of truth for the new schema"
    )
    recovery = data["recovery"]
    assert isinstance(recovery, dict)
    for field in [
        "phase",
        "phase_entered_at",
        "phase_elapsed_secs",
        "last_full_success_at",
        "giveup_alert_sent_at",
        "next_retry_at",
        "blocked_awaiting_resume",
    ]:
        assert field in recovery, (
            f"fixture's 'recovery' block missing '{field}'. keys: {list(recovery.keys())}"
        )


def test_fixture_recovery_field_types_locked():
    """Pin the JSON type of each recovery field. A silent type drift
    (int → float, bool → int) would corrupt the dashboard's rendering
    without any parse error.
    """
    data = _load_fixture()
    r = data["recovery"]

    # phase: string, from RecoveryPhase::as_str
    assert isinstance(r["phase"], str)
    assert r["phase"] in ("aggressive", "backoff_every_15min", "given_up")

    # phase_entered_at: Zoned wire format (string with [tz] suffix)
    assert isinstance(r["phase_entered_at"], str)
    assert "T" in r["phase_entered_at"]

    # phase_elapsed_secs: non-negative integer
    assert isinstance(r["phase_elapsed_secs"], int)
    assert not isinstance(r["phase_elapsed_secs"], bool)  # bool is subclass of int
    assert r["phase_elapsed_secs"] >= 0

    # last_full_success_at: None or Zoned string
    assert r["last_full_success_at"] is None or isinstance(r["last_full_success_at"], str)

    # giveup_alert_sent_at: None or Timestamp UTC ISO string
    assert r["giveup_alert_sent_at"] is None or isinstance(r["giveup_alert_sent_at"], str)

    # next_retry_at: None or Zoned string, ONLY set when phase == backoff_every_15min
    assert r["next_retry_at"] is None or isinstance(r["next_retry_at"], str)
    if r["phase"] != "backoff_every_15min":
        assert r["next_retry_at"] is None, (
            "next_retry_at MUST be null outside the backoff_every_15min phase"
        )

    # blocked_awaiting_resume: strict bool
    assert isinstance(r["blocked_awaiting_resume"], bool)


# ---------------------------------------------------------------------------
# Dashboard-side deserialization
# ---------------------------------------------------------------------------


def test_recovery_model_class_exists():
    """The dashboard MUST expose a ``Recovery`` domain model that
    consumers can import for typed access to recovery fields.

    RED: the class doesn't exist yet.
    """
    from app.domain.models import Recovery  # noqa: F401


def test_recovery_from_json_parses_all_fields():
    """``Recovery.from_json`` must round-trip every field in the
    fixture's recovery block.

    RED: the parser doesn't exist yet.
    """
    from app.domain.models import Recovery

    data = _load_fixture()
    recovery = Recovery.from_json(data["recovery"])

    assert recovery.phase == "backoff_every_15min"
    assert recovery.phase_entered_at == "2026-07-11T10:00:00-04:00[America/New_York]"
    assert recovery.phase_elapsed_secs == 3600
    assert recovery.last_full_success_at is None
    assert recovery.giveup_alert_sent_at is None
    assert recovery.next_retry_at == "2026-07-11T11:15:00-04:00[America/New_York]"
    assert recovery.blocked_awaiting_resume is False


def test_recovery_from_empty_dict_uses_defaults():
    """``Recovery.from_json`` must accept ``{}`` and default every
    Optional to None so a downgraded ibctl daemon that omits nested
    keys doesn't crash the parser.

    RED: parser doesn't exist yet.
    """
    from app.domain.models import Recovery

    recovery = Recovery.from_json({})
    assert recovery.phase in (None, "unknown", "aggressive")  # GREEN chooses one
    # Every optional field defaults to None
    assert recovery.last_full_success_at is None
    assert recovery.giveup_alert_sent_at is None
    assert recovery.next_retry_at is None
    assert recovery.blocked_awaiting_resume is False


def test_gateway_status_exposes_recovery_field():
    """``GatewayStatus.from_json`` on the fixture must surface a
    ``recovery`` attribute containing the parsed ``Recovery`` model.

    RED: the field doesn't exist on ``GatewayStatus`` yet.
    """
    from app.domain.models import GatewayStatus, Recovery

    data = _load_fixture()
    status = GatewayStatus.from_json(data)

    # New attribute must exist even before we assert its content —
    # a silent AttributeError here means GatewayStatus wasn't updated.
    assert hasattr(status, "recovery"), (
        "GatewayStatus must expose a 'recovery' attribute after stage 4"
    )
    assert isinstance(status.recovery, Recovery)
    assert status.recovery.phase == "backoff_every_15min"
    assert status.recovery.blocked_awaiting_resume is False


def test_recovery_defaults_to_none_when_absent():
    """Mixed-deploy compat: a STATUS from an older ibctl daemon
    (without a ``recovery`` block) must deserialize successfully with
    ``status.recovery is None`` so a paper-on-new / live-on-old
    dashboard rollout doesn't crash the older instance's card.

    RED: the field doesn't exist yet, so ``.recovery`` raises
    AttributeError.
    """
    from app.domain.models import GatewayStatus

    data = _load_fixture()
    data.pop("recovery")  # simulate an older ibctl daemon
    status = GatewayStatus.from_json(data)

    # Requirement: no crash, and the attribute must be None (NOT
    # missing) so consumers can `if status.recovery:` safely.
    assert hasattr(status, "recovery"), (
        "GatewayStatus.recovery must always exist as an attribute "
        "(possibly None) so consumers can rely on hasattr semantics"
    )
    assert status.recovery is None


# ---------------------------------------------------------------------------
# base.html: recovery-badge markup + SSE handler
# ---------------------------------------------------------------------------


def test_base_html_contains_recovery_badge_element():
    """``base.html`` must render a ``recovery-badge`` element in the
    header bar so the SSE ``status`` handler has a stable target to
    populate.

    RED: no such element exists yet.
    """
    from app.main import TEMPLATES_DIR

    base_html = (TEMPLATES_DIR / "base.html").read_text()
    assert 'id="recovery-badge"' in base_html, (
        "base.html must contain a header-bar span with id='recovery-badge' "
        "so the SSE status handler can populate it. See stage-4 spec §4."
    )
    assert 'id="recovery-badge-text"' in base_html, (
        "base.html must contain a child span with id='recovery-badge-text' "
        "for the badge text — the outer badge holds styling classes."
    )


def test_base_html_status_handler_references_recovery():
    """The SSE ``status`` event listener in base.html must read
    ``status.recovery`` so the badge is populated on every heartbeat.

    RED: the SSE handler doesn't touch recovery yet.
    """
    from app.main import TEMPLATES_DIR

    base_html = (TEMPLATES_DIR / "base.html").read_text()
    # The SSE handler for 'status' currently only extracts .version.
    # Stage 4 GREEN adds a .recovery consumer. The exact JS snippet is
    # implementation-flexible, but SOME reference to `.recovery`
    # inside the status listener is required — an empty grep here
    # means the badge will never update.
    assert ".recovery" in base_html, (
        "base.html must reference '.recovery' in the SSE status handler "
        "so the badge updates on every push. Stage 4 GREEN spec §4."
    )


# ---------------------------------------------------------------------------
# End-to-end: fixture round-trips through the client + registry cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fixture_survives_registry_cache_roundtrip():
    """Planting the fixture into the InstanceRegistry cache must round
    trip the ``recovery`` block byte-for-byte via the cache-read path
    used by the SSE endpoint.

    RED: registry passes the raw dict through, so this test's assertion
    is not strictly new-code-dependent — but we ALSO assert typed
    access via ``GatewayStatus.from_json`` at the end, which IS
    new-code-dependent and fails in RED.
    """
    from app.domain.instance import InstanceEndpoint
    from app.domain.models import GatewayStatus
    from app.instance_registry import InstanceRegistry, _CachedResponse

    class _NullFactory:
        def __init__(self, *_, **__):
            pass

    reg = InstanceRegistry(
        endpoints=[InstanceEndpoint(mode="paper", host="127.0.0.1", port=7462)],
        client_factory=_NullFactory,
    )
    data = _load_fixture()
    reg._cache["paper:STATUS"] = _CachedResponse(data, ttl=60.0)

    cached = reg.cached_status_raw("paper")
    assert cached is not None
    # Byte-for-byte round-trip of the recovery block through the cache.
    assert cached["recovery"] == data["recovery"]

    # Typed deserialization — RED-half assertion.
    status = GatewayStatus.from_json(cached)
    assert status.recovery is not None
    assert status.recovery.phase == "backoff_every_15min"
