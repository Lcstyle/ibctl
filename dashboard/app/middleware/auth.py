"""Dashboard authentication middleware.

When `IBCTL_DASHBOARD_TOKEN` is set, requests are authorized by any of:
- `Authorization: Bearer <token>`
- HTTP Basic auth with the configured token as the password
- `ibctl_dashboard_auth` cookie set by the login form

When GitHub OAuth is configured, requests are also authorized by a signed
OAuth session cookie.

When no auth is configured, all requests pass through (open access).
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

logger = logging.getLogger("dashboard.auth")

AUTH_COOKIE_NAME = "ibctl_dashboard_auth"
OAUTH_COOKIE_NAME = "ibctl_dashboard_oauth"
OAUTH_STATE_COOKIE_NAME = "ibctl_dashboard_oauth_state"


def _b64encode(data: bytes) -> str:
    return urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return urlsafe_b64decode(data + padding)


def sign_data(payload: dict, secret: str) -> str:
    encoded = _b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    sig = hmac.new(secret.encode("utf-8"), encoded.encode("utf-8"), "sha256").hexdigest()
    return f"{encoded}.{sig}"


def unsign_data(value: str, secret: str, max_age_seconds: int | None = None) -> dict | None:
    try:
        encoded, signature = value.rsplit(".", 1)
    except ValueError:
        return None
    expected = hmac.new(secret.encode("utf-8"), encoded.encode("utf-8"), "sha256").hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        payload = json.loads(_b64decode(encoded))
    except (ValueError, json.JSONDecodeError):
        return None
    if max_age_seconds is not None:
        issued_at = payload.get("iat")
        if not isinstance(issued_at, int):
            return None
        if time.time() - issued_at > max_age_seconds:
            return None
    return payload


def build_oauth_state(next_path: str, secret: str) -> str:
    return sign_data({"next": next_path, "iat": int(time.time())}, secret)


def parse_oauth_state(value: str, secret: str) -> dict | None:
    return unsign_data(value, secret, max_age_seconds=600)


def build_oauth_session(login: str, secret: str) -> str:
    return sign_data({"login": login, "iat": int(time.time())}, secret)


def parse_oauth_session(value: str, secret: str) -> dict | None:
    return unsign_data(value, secret, max_age_seconds=60 * 60 * 24 * 7)


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Enforce dashboard auth while preserving Bearer token compatibility."""

    @staticmethod
    def _is_static_or_public(path: str) -> bool:
        return (
            path.startswith("/static")
            or path == "/login"
            or path == "/logout"
            or path == "/auth/github"
            or path == "/auth/github/callback"
            or path == "/auth/oidc"
            or path == "/auth/oidc/callback"
            # HITL 2FA callback is authenticated by an HMAC-signed token
            # embedded in the URL — phones clicking the ntfy action button
            # don't carry the dashboard session cookie.
            or path == "/api/twofa/callback"
        )

    @staticmethod
    def _is_api_request(request: Request) -> bool:
        path = request.url.path
        if path.startswith("/api/"):
            return True
        accept = request.headers.get("Accept", "")
        return "application/json" in accept

    @staticmethod
    def _valid_bearer(auth_header: str, token: str) -> bool:
        return hmac.compare_digest(auth_header, f"Bearer {token}")

    @staticmethod
    def _valid_basic(auth_header: str, token: str) -> bool:
        if not auth_header.startswith("Basic "):
            return False
        try:
            encoded = auth_header[6:].strip()
            decoded = base64.b64decode(encoded).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            return False
        _, _, password = decoded.partition(":")
        return hmac.compare_digest(password, token)

    @staticmethod
    def _valid_cookie(request: Request, token: str) -> bool:
        cookie = request.cookies.get(AUTH_COOKIE_NAME, "")
        return bool(cookie) and hmac.compare_digest(cookie, token)

    @staticmethod
    def _valid_oauth_cookie(request: Request, signing_secret: str) -> bool:
        if not signing_secret:
            return False
        cookie = request.cookies.get(OAUTH_COOKIE_NAME, "")
        return parse_oauth_session(cookie, signing_secret) is not None

    def _is_authorized(self, request: Request, token: str, signing_secret: str) -> bool:
        auth_header = request.headers.get("Authorization", "")
        return (
            (bool(token) and self._valid_bearer(auth_header, token))
            or (bool(token) and self._valid_basic(auth_header, token))
            or (bool(token) and self._valid_cookie(request, token))
            or self._valid_oauth_cookie(request, signing_secret)
        )

    async def dispatch(self, request: Request, call_next):
        settings = request.app.state.settings
        token = settings.token
        auth_enabled = bool(token or settings.github_oauth_enabled or settings.oidc_enabled)

        # No auth configured — open access
        if not auth_enabled:
            return await call_next(request)

        if self._is_static_or_public(request.url.path):
            return await call_next(request)

        if self._is_authorized(request, token, settings.auth_secret.get_secret_value()):
            return await call_next(request)

        if not self._is_api_request(request) and request.method == "GET":
            next_path = request.url.path
            if request.url.query:
                next_path = f"{next_path}?{request.url.query}"
            login_url = request.url_for("login_page")
            return RedirectResponse(url=f"{login_url}?next={next_path}", status_code=303)

        client_ip = request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")
        logger.warning("Unauthorized request: %s %s from %s", request.method, request.url.path, client_ip)
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": "Bearer, Basic"},
        )
