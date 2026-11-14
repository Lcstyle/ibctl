"""Dashboard authentication middleware.

Deny by default. Every route needs a login except a short, explicit public
allow-list (`PUBLIC_PATHS`, `PUBLIC_PREFIXES`), so a route added later is
protected without anyone remembering to protect it.

A "login" is a configured method (dashboard password, GitHub OAuth or OIDC)
plus a valid signed session cookie from having signed in through it:
- the password login form (IBCTL_DASHBOARD_TOKEN) sets `ibctl_dashboard_auth`;
- GitHub OAuth / OIDC set `ibctl_dashboard_oauth`.

Each cookie is signed by `app.session_cookies` (itsdangerous), with a salt of its
own, so one kind of signed value never validates as another. This module checks
the claims inside: `iat`, `act`, the age limits and, for OAuth, the `login`.

The dashboard password itself is accepted only by the login form. It is not a
cookie value, an `Authorization: Bearer` token or an HTTP Basic password.

A bearer API token is a different thing and is never a login: it is recognised
in one place (`TokenAuthMiddleware._recognise_api_token`, against the hashed
tokens saved on the API access page). Every token has a type, and a type is a
fixed bundle of (METHOD, path) routes (`app.services.api_access.TOKEN_TYPES`,
inverted here as `TOKEN_ROUTES`). A token is admitted only to a route its own
type has, and only while the operator has enabled that type. A route that is in
no type, and every route added later until someone puts it in one, is refused
to every token with the same 401 as no credentials. A recognised token on a
route that is another type's, or whose type is switched off, gets a 403 that
says why. Every token request, accepted or refused, is logged with the token's
name, its type and the caller's address.

A session also ends after a stretch with no user activity (`dashboard.session_idle_minutes`,
default 5, 0 = never). The cookie carries `iat` (issued) and `act` (last activity); it is valid
while `now - act <= idle` and `now - iat <= SESSION_MAX_AGE_SECONDS`. Only requests that are the
person doing something move `act` (`counts_as_activity`): a page navigation or any request that
is not a GET or HEAD, the browser's heartbeat (`POST /api/session/touch`) included. Background
polling of an open page is checked like any request but never extends the session, or an open
tab would never time out. API tokens are not sessions and are unaffected.

When no login method is configured, nobody can log in: protected requests get
a 403 that says how to enable one (or, for a page, a redirect to the public
health summary at `/`).

Websockets are different: Starlette's `BaseHTTPMiddleware` never runs for them,
so deny-by-default does not cover a websocket route. Each websocket route
depends on `require_websocket_login`, which applies the same login test
(`login_for`, the function the middleware uses) and refuses before the socket is
accepted. `PUBLIC_WEBSOCKET_PATHS` lists the websocket routes exempt from that;
it is empty, and a test sweeps the route table to keep it honest.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, NamedTuple
from urllib.parse import quote

from starlette import status
from starlette.exceptions import WebSocketException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import HTTPConnection, Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.websockets import WebSocket

from app.services.api_access import TOKEN_TYPES, find_token_type
from app.session_cookies import Kind, sign, unsign
from app.urls import app_url, cookie_path, root_path

logger = logging.getLogger("dashboard.auth")

AUTH_COOKIE_NAME = "ibctl_dashboard_auth"
OAUTH_COOKIE_NAME = "ibctl_dashboard_oauth"
OAUTH_STATE_COOKIE_NAME = "ibctl_dashboard_oauth_state"

# A signed session stays valid this long after it was issued.
SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7
# The default idle limit, in minutes (`dashboard.session_idle_minutes`); 0 turns it off.
DEFAULT_SESSION_IDLE_MINUTES = 5
# The browser's keep-alive: a POST, so it counts as activity and refreshes the cookie.
SESSION_TOUCH_PATH = "/api/session/touch"
# A session cookie is re-issued at most this often, however busy the person is.
REISSUE_INTERVAL_SECONDS = 15
# Reasons the login page can be told about (`?reason=`); anything else is ignored.
LOGIN_REASONS = ("idle", "logout")


def now() -> float:
    """The wall clock, in epoch seconds. Tests replace this to move time without sleeping."""
    return time.time()


def _read(kind: Kind, value: str, secret: str, max_age_seconds: int) -> dict | None:
    """The payload of a correctly signed `kind` value that was issued no more than `max_age_seconds` ago."""
    payload = unsign(kind, value, secret)
    if payload is None:
        return None
    issued_at = payload.get("iat")
    if not isinstance(issued_at, int):
        return None
    if now() - issued_at > max_age_seconds:
        return None
    return payload


def build_oauth_state(next_path: str, secret: str) -> str:
    return sign(Kind.OAUTH_STATE, {"next": next_path, "iat": int(now())}, secret)


def parse_oauth_state(value: str, secret: str) -> dict | None:
    return _read(Kind.OAUTH_STATE, value, secret, max_age_seconds=600)


def build_oauth_session(login: str, secret: str) -> str:
    issued = int(now())
    return sign(Kind.OAUTH_SESSION, {"login": login, "iat": issued, "act": issued}, secret)


def parse_oauth_session(value: str, secret: str) -> dict | None:
    payload = _read(Kind.OAUTH_SESSION, value, secret, max_age_seconds=SESSION_MAX_AGE_SECONDS)
    # A session names who signed in; a payload with no login is not one.
    if payload is None or not isinstance(payload.get("login"), str) or not payload["login"]:
        return None
    return payload


def build_password_session(secret: str) -> str:
    """The cookie the password login form sets: signed, with an issue time and a last-activity time."""
    issued = int(now())
    return sign(Kind.PASSWORD_SESSION, {"auth": "password", "iat": issued, "act": issued}, secret)


def parse_password_session(value: str, secret: str) -> dict | None:
    payload = _read(Kind.PASSWORD_SESSION, value, secret, max_age_seconds=SESSION_MAX_AGE_SECONDS)
    if payload is None or payload.get("auth") != "password":
        return None
    return payload


# Reachable without a login. Keep it short: anything not listed needs one.
PUBLIC_PATHS = frozenset({
    # Anonymous visitors get only the health summary here; a logged-in one gets
    # the full overview. The handler picks by `request.state.login`.
    "/",
    # The same summary as JSON, for health probes.
    "/api/v1/health",
    # IB's own system status, which monitoring services poll. Anonymous
    # callers get a fixed list of fields; a logged-in person gets the full reply.
    # The routes beside it (audit log, override, scraper config) are not public.
    "/api/v1/ib-status",
    # ibctl's restart timetable (daily restart time, weekly cold restart, time zone).
    # Fixed configuration with nothing in it that depends on who asks; monitors read
    # it to tell an expected restart from an outage.
    "/api/v1/schedule",
    # Signing in and out.
    "/login",
    "/logout",
    "/auth/github",
    "/auth/github/callback",
    "/auth/oidc",
    "/auth/oidc/callback",
    # Notification links: each carries an HMAC-signed token in the URL and its
    # handler rejects a missing or invalid one. Phones tapping a notification
    # action button have no dashboard session.
    "/api/twofa/callback",
    "/api/reconnect/callback",  # GET and POST
})
PUBLIC_PREFIXES = ("/static/",)
# Websocket routes reachable without a login. None: VNC is the only websocket.
PUBLIC_WEBSOCKET_PATHS: frozenset[str] = frozenset()

def _routes_by_type() -> dict[tuple[str, str], frozenset[str]]:
    routes: dict[tuple[str, str], frozenset[str]] = {}
    for token_type in TOKEN_TYPES:
        for route in token_type.routes:
            routes[route] = routes.get(route, frozenset()) | {token_type.name}
    return routes


# (METHOD, path) -> the names of the token types that may call it. This is the whole
# list of routes a bearer API token can reach: a route that is not here is login-only.
TOKEN_ROUTES: dict[tuple[str, str], frozenset[str]] = _routes_by_type()

NO_LOGIN_HELP = (
    "Set IBCTL_DASHBOARD_TOKEN to a dashboard password, or configure GitHub OAuth or OIDC, "
    "then restart the dashboard."
)


def client_ip(request: HTTPConnection) -> str:
    """The caller's address, for the audit log: the proxy's X-Real-IP, else the socket's."""
    return request.headers.get("X-Real-IP", request.client.host if request.client else "unknown")


def bearer_credential(request: Request) -> str | None:
    """The secret in an `Authorization: Bearer <secret>` header, or None."""
    scheme, _, credential = request.headers.get("Authorization", "").partition(" ")
    credential = credential.strip()
    if scheme.lower() != "bearer" or not credential:
        return None
    return credential


class Login(NamedTuple):
    """Who is logged in: how they signed in and a name for the audit log."""

    method: str  # "password" or "oauth"
    name: str


class SessionState(NamedTuple):
    """What the session cookies on a connection amount to.

    `login` is who is signed in, or None. `idle_expired` is True when a
    correctly signed session was found but has been idle too long: that visitor
    is signed out like any other, but the refusal can say why. `cookie_name`,
    `kind` and `payload` are the live session's cookie, for re-issuing it.
    """

    login: Login | None = None
    idle_expired: bool = False
    cookie_name: str | None = None
    kind: Kind | None = None
    payload: dict | None = None


def idle_limit_seconds(settings) -> int:
    """The idle limit in seconds; 0 when idle logout is off."""
    return max(0, int(getattr(settings, "session_idle_minutes", DEFAULT_SESSION_IDLE_MINUTES))) * 60


def last_activity(payload: dict) -> float:
    """When the person last did something in this session.

    A cookie issued before idle logout existed has no `act`: its issue time is
    the last activity we know of.
    """
    act = payload.get("act")
    if isinstance(act, bool) or not isinstance(act, (int, float)):
        return payload["iat"]
    return act


def is_idle_expired(payload: dict, idle_seconds: int, at: float | None = None) -> bool:
    """True when `idle_seconds` (0 = never) have passed since the last activity."""
    if idle_seconds <= 0:
        return False
    return (now() if at is None else at) - last_activity(payload) > idle_seconds


def cookie_values(connection: HTTPConnection, name: str) -> list[str]:
    """Every value the browser sent for the cookie `name`, in the order sent.

    A browser holding the same cookie at two paths sends both, and a plain
    `connection.cookies[name]` keeps only the last. That let a stale cookie from
    an earlier path shadow the live one.
    """
    values: list[str] = []
    for header in connection.headers.getlist("cookie"):
        for part in header.split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                values.append(value.strip().strip('"'))
    return values


def _freshest(connection: HTTPConnection, name: str, parse: Callable[[str], dict | None]) -> dict | None:
    """The correctly signed session among the cookies named `name` with the latest activity."""
    payloads = [payload for value in cookie_values(connection, name) if (payload := parse(value)) is not None]
    return max(payloads, key=last_activity, default=None)


def _password_payload(connection: HTTPConnection, settings) -> dict | None:
    secret = settings.signing_secret
    if not settings.password_enabled or not secret:
        return None
    return _freshest(connection, AUTH_COOKIE_NAME, lambda value: parse_password_session(value, secret))


def _oauth_payload(connection: HTTPConnection, settings) -> dict | None:
    secret = settings.signing_secret
    if not (settings.github_oauth_enabled or settings.oidc_enabled) or not secret:
        return None
    return _freshest(connection, OAUTH_COOKIE_NAME, lambda value: parse_oauth_session(value, secret))


# (cookie, what it is signed as, how to read it, how to name who it belongs to)
_SESSION_KINDS: tuple[tuple[str, Kind, Callable, Callable[[dict], Login]], ...] = (
    (AUTH_COOKIE_NAME, Kind.PASSWORD_SESSION, _password_payload, lambda payload: Login("password", "dashboard user")),
    (OAUTH_COOKIE_NAME, Kind.OAUTH_SESSION, _oauth_payload, lambda payload: Login("oauth", payload["login"])),
)


def session_state(connection: HTTPConnection, settings) -> SessionState:
    """Read the signed session cookies: who is signed in, or why nobody is.

    A cookie counts only when it is correctly signed, within the absolute age
    limit and not idle for longer than the idle limit. A password session that
    has gone idle does not hide a live OAuth one.
    """
    idle_seconds = idle_limit_seconds(settings)
    at = now()
    idle_expired = False
    for cookie_name, kind, read, who in _SESSION_KINDS:
        payload = read(connection, settings)
        if payload is None:
            continue
        if is_idle_expired(payload, idle_seconds, at):
            idle_expired = True
            continue
        return SessionState(login=who(payload), cookie_name=cookie_name, kind=kind, payload=payload)
    return SessionState(idle_expired=idle_expired)


def login_for(connection: HTTPConnection, settings) -> Login | None:
    """Who is logged in on this request or websocket, or None.

    The one logged-in test: the middleware applies it to every HTTP request and
    `require_websocket_login` to every websocket. It reads only the signed
    session cookies, so a bearer API token, the dashboard password in a header
    and a dashboard with no login configured all come out as None. An idle or
    over-age session is not a login.
    """
    return session_state(connection, settings).login


def session_cookie_attributes(connection: HTTPConnection) -> dict:
    """The attributes every session cookie is set with, at login and when it is refreshed."""
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": connection.url.scheme == "https",
        "path": cookie_path(connection),
    }


def refreshed_session_cookie(kind: Kind, payload: dict, secret: str) -> str:
    """The same session (same `iat`, same kind), with its last activity set to now."""
    return sign(kind, {**payload, "act": int(now())}, secret)


def counts_as_activity(request: Request) -> bool:
    """True when this request is the person doing something, not the page polling.

    Anything that is not a GET or HEAD is (a click on a button, the heartbeat).
    A GET is when the browser is navigating to a page (it asks for HTML, or says
    `Sec-Fetch-Mode: navigate`), except under `/partials/`, which pages fetch on
    a timer. JSON reads, the event stream and static files never count.
    """
    if request.method not in ("GET", "HEAD"):
        return True
    if request.method == "HEAD" or request.url.path.startswith("/partials/"):
        return False
    return (
        "text/html" in request.headers.get("Accept", "")
        or request.headers.get("Sec-Fetch-Mode", "").lower() == "navigate"
    )


async def require_websocket_login(websocket: WebSocket) -> Login:
    """Dependency for every websocket route: refuse a visitor who is not logged in.

    Raised before the route accepts, so the server answers the handshake with a
    403 and no socket opens.
    """
    login = login_for(websocket, websocket.app.state.settings)
    if login is None:
        logger.warning("Refused websocket %s from %s: not logged in", websocket.url.path, client_ip(websocket))
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION, reason="login required")
    return login


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Work out who is logged in, then admit, redirect or refuse the request.

    Sets `request.state.login` (a `Login`, or None for an anonymous visitor),
    `request.state.session_idle_expired` and `request.state.api_token` on every
    request, public routes included. A request that is the person acting
    (`counts_as_activity`) also re-issues the session cookie with a fresh `act`.
    """

    @staticmethod
    def _is_public(path: str) -> bool:
        return path in PUBLIC_PATHS or path == "/static" or path.startswith(PUBLIC_PREFIXES)

    @staticmethod
    def _is_api_request(request: Request) -> bool:
        path = request.url.path
        if path.startswith("/api/"):
            return True
        accept = request.headers.get("Accept", "")
        return "application/json" in accept

    def _recognise_api_token(self, request: Request, settings):
        """The one place a bearer API token is recognised.

        Returns the token's record, or None. A token is never a login: the
        caller admits it only to `TOKEN_ROUTES`. The dashboard password in an
        `Authorization` header is deliberately not one, and with no login
        configured nothing is recognised: tokens belong to a dashboard that
        has someone to manage them.
        """
        credential = bearer_credential(request)
        store = getattr(request.app.state, "api_access", None)
        if credential is None or store is None or not settings.login_configured:
            return None
        return store.recognise(credential)

    def _token_refusal(self, request: Request, token, route: tuple[str, str]):
        """A 403 if this token may not call this token route, else None.

        The token's type must be one of the route's, and enabled on the API
        access page. Either way the answer is logged with the token's name and
        type and the caller's address, never the token itself.
        """
        ip = client_ip(request)
        if token.type not in TOKEN_ROUTES[route]:
            logger.warning(
                "Rejected API request: %s %s by token %r (type %s) from %s: the route is not one of its type's",
                request.method, request.url.path, token.name, token.type, ip,
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "wrong_token_type",
                    "detail": f"This token is of type '{token.type}', which cannot call {request.method} {request.url.path}.",
                },
            )
        store = getattr(request.app.state, "api_access", None)
        if store is None or not store.is_enabled(token.type):
            logger.warning(
                "Rejected API request: %s %s by token %r (type %s) from %s: the type is not enabled on the API access page",
                request.method, request.url.path, token.name, token.type, ip,
            )
            known = find_token_type(token.type)
            label = f"{known.label} ({known.name})" if known else token.type
            return JSONResponse(
                status_code=403,
                content={
                    "error": "not_allowed",
                    "detail": f"API tokens of type '{label}' are not enabled on this dashboard. "
                    "Enable the type on the API access page.",
                },
            )
        logger.info(
            "Accepted API request: %s %s by token %r (type %s) from %s",
            request.method, request.url.path, token.name, token.type, ip,
        )
        return None

    def _redirect_home(self, request: Request) -> RedirectResponse:
        return RedirectResponse(url=app_url(request, "/"), status_code=303)

    @staticmethod
    def _is_background_request(request: Request) -> bool:
        """A page's own timer or script asking, not the person navigating."""
        return request.url.path.startswith("/partials/") or request.headers.get("HX-Request", "").lower() == "true"

    @staticmethod
    def _login_url(request: Request, reason: str | None = None) -> str:
        """The login page for this request: back to the page asked for, saying why when `reason` is given."""
        next_path = request.url.path
        if request.url.query:
            next_path = f"{next_path}?{request.url.query}"
        url = f"{app_url(request, '/login')}?next={quote(next_path, safe='/?=')}"
        return f"{url}&reason={reason}" if reason else url

    def _refuse_idle(self, request: Request):
        """The refusal for a correctly signed session that has been idle too long."""
        logger.info("Refused request, session idle too long: %s %s from %s", request.method, request.url.path, client_ip(request))
        if request.method == "GET" and not self._is_api_request(request) and not self._is_background_request(request):
            return RedirectResponse(url=self._login_url(request, "idle"), status_code=303)
        return JSONResponse(
            status_code=401,
            content={"detail": "Your session expired from inactivity. Sign in again.", "reason": "idle"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @staticmethod
    def _strip_prefix(request: Request) -> None:
        """Serve `/ibctl/x` as `/x` when the proxy prefix is in the URL itself.

        Behind the proxy the prefix is already gone. Reached directly (a local
        client on the dashboard's own port) it is still there, and without this
        the login redirect, which carries the prefix, matched no route.
        """
        prefix = root_path(request)
        path = request.scope["path"]
        if prefix and (path == prefix or path.startswith(prefix + "/")):
            request.scope["path"] = path[len(prefix):] or "/"
            raw = request.scope.get("raw_path")
            if raw and (raw == prefix.encode() or raw.startswith(prefix.encode() + b"/")):
                request.scope["raw_path"] = raw[len(prefix):] or b"/"

    def _refuse(self, request: Request, settings):
        ip = client_ip(request)
        wants_page = not self._is_api_request(request) and request.method == "GET"

        if not settings.login_configured:
            # Nobody can log in, so a login page would lead nowhere.
            logger.info("Refused request, no login configured: %s %s from %s", request.method, request.url.path, ip)
            if wants_page:
                return self._redirect_home(request)
            return JSONResponse(
                status_code=403,
                content={
                    "detail": f"No login is configured, so this request is refused. {NO_LOGIN_HELP}",
                    "login_configured": False,
                },
            )

        if request.state.session_idle_expired:
            return self._refuse_idle(request)

        if wants_page:
            return RedirectResponse(url=self._login_url(request), status_code=303)

        token = request.state.api_token
        if token is not None:
            logger.warning(
                "Rejected API request: %s %s by token %r (type %s) from %s: not a route API tokens may use",
                request.method, request.url.path, token.name, token.type, ip,
            )
        else:
            logger.warning(
                "Unauthorized request: %s %s from %s%s",
                request.method, request.url.path, ip,
                " (the API token is not recognised: unknown or revoked)" if bearer_credential(request) else "",
            )
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @staticmethod
    def _keep_session_alive(request: Request, response: Response, session: SessionState, settings) -> None:
        """Re-issue the session cookie with `act` = now when the person just did something.

        Skipped when idle logout is off (there is nothing to extend), when the
        cookie was re-issued within `REISSUE_INTERVAL_SECONDS`, and when the
        response itself sets or clears that cookie (login, logout).
        """
        if session.login is None or idle_limit_seconds(settings) == 0 or not counts_as_activity(request):
            return
        if now() - last_activity(session.payload) < REISSUE_INTERVAL_SECONDS:
            return
        if any(h.startswith(f"{session.cookie_name}=") for h in response.headers.getlist("set-cookie")):
            return
        response.set_cookie(
            key=session.cookie_name,
            value=refreshed_session_cookie(session.kind, session.payload, settings.signing_secret),
            **session_cookie_attributes(request),
        )

    async def dispatch(self, request: Request, call_next):
        self._strip_prefix(request)
        settings = request.app.state.settings
        session = session_state(request, settings)
        request.state.login = session.login
        request.state.session_idle_expired = session.idle_expired
        request.state.api_token = self._recognise_api_token(request, settings)

        if self._is_public(request.url.path) or request.state.login is not None:
            response = await call_next(request)
            self._keep_session_alive(request, response, session, settings)
            return response

        route = (request.method, request.url.path)
        if request.state.api_token is not None and route in TOKEN_ROUTES:
            refusal = self._token_refusal(request, request.state.api_token, route)
            return await call_next(request) if refusal is None else refusal

        return self._refuse(request, settings)
