"""Tests for the kind-keyed coalescer on NtfyClient.

The coalescer suppresses duplicate notifications keyed on the optional
``kind`` argument to ``NtfyClient.send``. Critical invariant: the
last-sent timestamp is updated ONLY on a successful POST. A failed POST
does not consume the window, so legitimate retries fire as expected.

These tests patch ``httpx.AsyncClient`` (imported inside ``send``) with a
fake whose ``post`` returns a configurable status code and increments a
call counter. ``time.monotonic`` (also imported in the module) is patched
when window-expiry behaviour is exercised.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services import notification_service
from app.services.notification_service import NtfyClient


class _FakeResponse:
    """Minimal stand-in for httpx.Response — only the bits NtfyClient reads."""

    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


def _make_fake_httpx(status_codes: list[int] | None = None):
    """Build a (fake_httpx_module, post_call_counter) tuple.

    The returned ``fake_httpx`` has an ``AsyncClient`` factory that, when
    used as an async context manager, yields a client whose ``post()``
    returns a _FakeResponse. Status codes are taken from ``status_codes``
    in order; once exhausted the last value repeats (default 200).
    """
    codes = list(status_codes) if status_codes else [200]
    counter = {"post_calls": 0, "post_urls": []}

    async def _fake_post(url, *args, **kwargs):
        counter["post_calls"] += 1
        counter["post_urls"].append(url)
        idx = min(counter["post_calls"] - 1, len(codes) - 1)
        return _FakeResponse(status_code=codes[idx])

    class _FakeAsyncClientCtx:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            inner = MagicMock()
            inner.post = AsyncMock(side_effect=_fake_post)
            return inner

        async def __aexit__(self, exc_type, exc, tb):
            return False

    fake_httpx = MagicMock()
    fake_httpx.AsyncClient = _FakeAsyncClientCtx
    return fake_httpx, counter


# ---------------------------------------------------------------------------
# Same-kind suppression within the window
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coalesce_suppresses_same_kind_within_window():
    """Two same-kind sends inside the window → only one POST, both True."""
    fake_httpx, counter = _make_fake_httpx([200, 200])
    client = NtfyClient("https://ntfy.sh", "testtopic", coalesce_window_secs=30)

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        first = await client.send("t1", "b1", kind="hitl_2fa_required")
        second = await client.send("t2", "b2", kind="hitl_2fa_required")

    assert first is True
    assert second is True
    assert counter["post_calls"] == 1, (
        f"expected exactly one POST, got {counter['post_calls']}"
    )


# ---------------------------------------------------------------------------
# Window expiry — same kind allowed once the window has elapsed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coalesce_allows_same_kind_after_window():
    """After the window elapses, a same-kind send fires again."""
    fake_httpx, counter = _make_fake_httpx([200, 200])
    client = NtfyClient("https://ntfy.sh", "testtopic", coalesce_window_secs=30)

    # Hand-rolled monotonic clock so we control the window precisely.
    clock = {"t": 1000.0}

    def fake_monotonic():
        return clock["t"]

    with patch.dict("sys.modules", {"httpx": fake_httpx}), \
            patch.object(notification_service.time, "monotonic", side_effect=fake_monotonic):
        first = await client.send("t1", "b1", kind="hitl_2fa_required")
        # Jump beyond the coalesce window (30s).
        clock["t"] = 1031.0
        second = await client.send("t2", "b2", kind="hitl_2fa_required")

    assert first is True
    assert second is True
    assert counter["post_calls"] == 2, (
        f"expected two POSTs after window expiry, got {counter['post_calls']}"
    )


# ---------------------------------------------------------------------------
# Different kinds — independent buckets
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coalesce_does_not_suppress_different_kinds():
    """Different ``kind`` values do not interfere with each other."""
    fake_httpx, counter = _make_fake_httpx([200, 200])
    client = NtfyClient("https://ntfy.sh", "testtopic", coalesce_window_secs=30)

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        a = await client.send("ta", "ba", kind="kind_a")
        b = await client.send("tb", "bb", kind="kind_b")

    assert a is True
    assert b is True
    assert counter["post_calls"] == 2, (
        f"expected two POSTs for two different kinds, got {counter['post_calls']}"
    )


# ---------------------------------------------------------------------------
# Failure invariant — failed sends do NOT consume the window
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_send_does_not_consume_window():
    """A failed POST must not update the per-kind timestamp, so the next
    same-kind call within the window still fires (retry semantics)."""
    fake_httpx, counter = _make_fake_httpx([500, 200])
    client = NtfyClient("https://ntfy.sh", "testtopic", coalesce_window_secs=30)

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        first = await client.send("t1", "b1", kind="hitl_2fa_required")
        second = await client.send("t2", "b2", kind="hitl_2fa_required")

    # First send failed (500) → returns False; second send fires again (200).
    assert first is False
    assert second is True
    assert counter["post_calls"] == 2, (
        f"expected two POSTs (failure does not consume window), got {counter['post_calls']}"
    )
    # And the kind is now stamped, so a third send within the window IS
    # suppressed.
    fake_httpx2, counter2 = _make_fake_httpx([200])
    with patch.dict("sys.modules", {"httpx": fake_httpx2}):
        third = await client.send("t3", "b3", kind="hitl_2fa_required")
    assert third is True
    assert counter2["post_calls"] == 0, (
        "third same-kind send within window should have been coalesced"
    )


# ---------------------------------------------------------------------------
# Backward compatibility — no kind means no coalescing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_kind_means_no_coalescing():
    """Without a ``kind`` argument the coalescer is bypassed entirely."""
    fake_httpx, counter = _make_fake_httpx([200, 200])
    client = NtfyClient("https://ntfy.sh", "testtopic", coalesce_window_secs=30)

    with patch.dict("sys.modules", {"httpx": fake_httpx}):
        first = await client.send("t1", "b1")
        second = await client.send("t2", "b2")

    assert first is True
    assert second is True
    assert counter["post_calls"] == 2, (
        f"expected two POSTs when no kind is passed, got {counter['post_calls']}"
    )
