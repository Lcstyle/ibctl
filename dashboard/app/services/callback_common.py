"""Shared machinery for ntfy callback endpoints (HITL 2FA and reconnect).

Both the HITL 2FA resume callback (``/api/twofa/callback``) and the
recovery-give-up resume callback (``/api/reconnect/callback``) need the
same three pieces:

  1. Resolve the externally-reachable dashboard base URL so the ntfy action
     button links back to something an operator's phone can hit.
  2. Rate-limit the callback endpoint per IP so a bad actor can't brute-force
     tokens.
  3. Render a small confirmation HTML page after a successful dispatch.

Rather than duplicate any of that between the two endpoints, all three
helpers live here and are re-exported from the legacy modules under their
original names for backward-compat with existing tests and callers.

This module is intentionally free of FastAPI / route-handler code so it
can be imported from both ``app.api.twofa`` (endpoint) and
``app.services.monitors.hitl_2fa`` (monitor that builds callback URLs)
without dragging FastAPI into the monitor layer.
"""

from __future__ import annotations

import html
import logging
import os
import time
from collections import deque

logger = logging.getLogger("dashboard.services.callback_common")


# ---------------------------------------------------------------------------
# Dashboard base URL resolution
# ---------------------------------------------------------------------------


def resolve_dashboard_base_url() -> tuple[str, bool]:
    """Return ``(base_url, is_fallback)`` for building callback URLs.

    Preference order:
      1. ``IBCTL_DASHBOARD_EXTERNAL_URL`` — what an operator's phone can reach
      2. ``IBCTL_DASHBOARD_INTERNAL_URL`` — last-ditch fallback (warn)
      3. Construct ``http://localhost:<port>`` from ``IBCTL_DASHBOARD_PORT``
         (warn)

    ``is_fallback`` is True whenever an operator's phone would probably not
    be able to reach the URL — callers use it to decide whether to include
    the ntfy action button at all.
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
        "is set; callback URL will point to http://localhost:%s which is not "
        "reachable from a phone",
        port,
    )
    return f"http://localhost:{port}", True


# ---------------------------------------------------------------------------
# Confirmation HTML page
# ---------------------------------------------------------------------------


def confirmation_html(mode: str, *, action_label: str) -> str:
    """Render a confirmation page after a successful callback dispatch.

    ``mode`` is HTML-escaped and rendered in the body so operators know which
    instance they just resumed. ``action_label`` becomes both the browser tab
    title and the page heading — HITL uses ``"Retry triggered"``, reconnect
    uses ``"Reconnect resumed"`` (or similar).
    """
    safe_mode = html.escape(mode.upper())
    safe_label = html.escape(action_label)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ibctl: {safe_label}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
            Roboto, Helvetica, Arial, sans-serif;
            margin: 0; padding: 2rem;
            background: #0f172a; color: #e2e8f0; }}
    .card {{ max-width: 28rem; margin: 3rem auto; background: #1e293b;
             border-radius: 0.75rem; padding: 2rem;
             box-shadow: 0 10px 20px rgba(0,0,0,0.3); }}
    h1 {{ margin: 0 0 0.5rem 0; font-size: 1.5rem; }}
    p  {{ line-height: 1.5; color: #cbd5e1; }}
    .ok {{ color: #4ade80; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="card">
    <h1 class="ok">{safe_label}</h1>
    <p>The command was dispatched to the <strong>{safe_mode}</strong> ibctl
       instance.</p>
    <p>You may close this tab.</p>
  </div>
</body>
</html>
"""


def confirmation_prompt_html(
    mode: str,
    *,
    token: str,
    form_action: str,
    action_label: str,
    prompt: str,
    submit_label: str,
) -> str:
    """Render a "please confirm" page with a POST form.

    Split-flow defence (finding A-HIGH-1): a link preview / URL-defense
    crawler / mobile prefetch follows a GET but almost never a POST.
    Rendering the confirmation as an idempotent GET and requiring an
    explicit POST to dispatch RESUME_RECONNECT ensures such a fetch
    cannot auto-consume the one-shot token.

    ``token`` is embedded as a hidden field so the POST carries it
    verbatim; ``form_action`` is the endpoint the browser POSTs to;
    ``prompt`` is the operator-facing sentence; ``submit_label`` is the
    button text. Every string is HTML-escaped before insertion.
    """
    safe_mode = html.escape(mode.upper())
    safe_label = html.escape(action_label)
    safe_action = html.escape(form_action, quote=True)
    safe_token = html.escape(token, quote=True)
    safe_mode_val = html.escape(mode, quote=True)
    safe_prompt = html.escape(prompt)
    safe_submit = html.escape(submit_label)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ibctl: {safe_label}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
            Roboto, Helvetica, Arial, sans-serif;
            margin: 0; padding: 2rem;
            background: #0f172a; color: #e2e8f0; }}
    .card {{ max-width: 28rem; margin: 3rem auto; background: #1e293b;
             border-radius: 0.75rem; padding: 2rem;
             box-shadow: 0 10px 20px rgba(0,0,0,0.3); }}
    h1 {{ margin: 0 0 0.5rem 0; font-size: 1.5rem; color: #fbbf24; }}
    p  {{ line-height: 1.5; color: #cbd5e1; }}
    button {{ background: #4ade80; color: #0f172a; border: 0;
              padding: 0.75rem 1.25rem; border-radius: 0.5rem;
              font-size: 1rem; font-weight: 600; cursor: pointer;
              margin-top: 1rem; }}
    button:hover {{ background: #22c55e; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{safe_label}</h1>
    <p>{safe_prompt} <strong>{safe_mode}</strong></p>
    <form method="POST" action="{safe_action}">
      <input type="hidden" name="t" value="{safe_token}">
      <input type="hidden" name="mode" value="{safe_mode_val}">
      <button type="submit">{safe_submit}</button>
    </form>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Per-IP sliding-window rate limiter
# ---------------------------------------------------------------------------


# Bounds the IP table to prevent unbounded memory growth from port scans /
# many unique clients. When exceeded, the IP with the oldest most-recent hit
# is evicted — it won't have hit us in a while anyway.
_IP_TABLE_MAX_SIZE = 1024


class RateLimiter:
    """In-memory sliding-window rate limiter with per-IP buckets.

    Each instance owns its own ``_ip_timestamps`` dict so HITL and reconnect
    endpoints can have INDEPENDENT counters — a 2FA burst must not lock out a
    legitimate reconnect resume, and vice versa.

    Not shared across multiple uvicorn workers. Single-worker uvicorn is the
    deployment target, so no lock is needed. Behind a reverse proxy this keys
    on the proxy's IP — TODO when ingress lands.
    """

    def __init__(
        self,
        window_secs: float,
        max_requests: int,
        *,
        table_max_size: int = _IP_TABLE_MAX_SIZE,
    ) -> None:
        self._window_secs = float(window_secs)
        self._max_requests = int(max_requests)
        self._table_max_size = int(table_max_size)
        # IP → deque of request timestamps in the last WINDOW seconds.
        # Public-ish for test fixtures that need to reset state or seed
        # stale timestamps between tests (see test_callback_common.py).
        self._ip_timestamps: dict[str, deque[float]] = {}

    @property
    def window_secs(self) -> float:
        return self._window_secs

    @property
    def max_requests(self) -> int:
        return self._max_requests

    def clear(self) -> None:
        """Drop all per-IP state. Test fixtures call this between requests."""
        self._ip_timestamps.clear()

    def _evict_if_needed(self) -> None:
        """Drop the IP with the oldest last-hit when the table exceeds cap."""
        if len(self._ip_timestamps) <= self._table_max_size:
            return
        # Cheapest "oldest" heuristic: rightmost timestamp per bucket.
        oldest_ip = min(
            self._ip_timestamps,
            key=lambda k: self._ip_timestamps[k][-1] if self._ip_timestamps[k] else 0.0,
        )
        self._ip_timestamps.pop(oldest_ip, None)

    def check(self, ip: str) -> bool:
        """Return True if the request is allowed, False if rate-limited.

        Cleans up stale timestamps for the given IP opportunistically on
        each call.
        """
        now = time.time()
        cutoff = now - self._window_secs

        if ip not in self._ip_timestamps:
            self._ip_timestamps[ip] = deque()
            self._evict_if_needed()

        bucket = self._ip_timestamps[ip]

        # Drop timestamps older than the window.
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        # If the bucket is now empty AND we're above the cap, drop it entirely
        # to aid eviction. Cheap, happens at most once per burst.
        if not bucket and len(self._ip_timestamps) > self._table_max_size:
            self._ip_timestamps.pop(ip, None)
            self._ip_timestamps[ip] = bucket

        if len(bucket) >= self._max_requests:
            return False  # rate-limited

        bucket.append(now)
        return True


# ---------------------------------------------------------------------------
# Signing-key helper
# ---------------------------------------------------------------------------


SIGNING_KEY_ENV = "IBCTL_NTFY_ACTION_SIGNING_KEY"


def get_signing_key() -> str:
    """Return the HMAC signing key from env, stripped. Empty string if unset.

    Callers should return HTTP 503 with ``signing_key_not_configured`` when
    this is empty — the callback cannot validate anything without it.
    """
    return os.environ.get(SIGNING_KEY_ENV, "").strip()
