"""VNC reaches the Gateway only through the dashboard, and only after a login.

The browser's websocket goes to the dashboard's `/websockify`, which proxies it
to websockify inside the container. Starlette's `BaseHTTPMiddleware` never runs
for websockets, so the route checks the login itself. These tests prove an
anonymous visitor, an API token, a forged cookie and a dashboard with no login
configured are all turned away before the socket is accepted, and that a
logged-in person's bytes travel both ways.

The dashboard runs under a real uvicorn server on a loopback port and the tests
talk to it with a real websocket client, so what is checked is what a browser
meets: an HTTP 403 on the handshake, or an open socket. A second real websocket
server on another loopback port stands in for websockify.
"""

from __future__ import annotations

import asyncio
import queue
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed, ConnectionClosedOK, InvalidStatus
from websockets.sync.client import connect as ws_connect

from app.api.vnc_proxy import DEFAULT_NOVNC_PORT, upstream_url
from app.main import create_app
from app.middleware.auth import (
    AUTH_COOKIE_NAME,
    OAUTH_COOKIE_NAME,
    PUBLIC_WEBSOCKET_PATHS,
    build_oauth_session,
    build_password_session,
)
from app.session_cookies import Kind, sign
from app.services.api_access import ApiAccessStore
from tests.auth_helpers import (
    TEST_AUTH_SECRET,
    TEST_PASSWORD,
    authed_settings,
    log_in,
    websocket_route_table,
)

GREETING = b"RFB 003.008\n"
VNC_PASSWORD = "zq-sentinel-vnc-pass"  # nosecret: test value


class FakeWebsockify:
    """A websocket server on a loopback port, run on its own thread and event loop.

    It says hello first, echoes every frame back with a prefix, and records
    what it was sent and who connected, so a test can tell the two directions apart.
    """

    def __init__(self):
        self.connections = 0
        self.frames: queue.Queue = queue.Queue()
        self.request_headers = None
        self.subprotocol = None
        self.disconnected = threading.Event()
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._server = None

    async def _handle(self, connection):
        self.connections += 1
        self.request_headers = connection.request.headers
        self.subprotocol = connection.subprotocol
        await connection.send(GREETING)
        try:
            async for frame in connection:
                self.frames.put(frame)
                if frame == b"hang up":
                    await connection.close()
                    return
                await connection.send((b"echo:" if isinstance(frame, bytes) else "echo:") + frame)
        except ConnectionClosed:
            pass  # the dashboard went away mid-frame: nothing to report
        finally:
            self.disconnected.set()

    async def _listen(self):
        self._server = await serve(self._handle, "127.0.0.1", 0, subprotocols=["binary"])
        self.port = self._server.sockets[0].getsockname()[1]

    def _run(self, started: threading.Event):
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._listen())
        started.set()
        self._loop.run_forever()

    def start(self):
        started = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(started,), daemon=True)
        self._thread.start()
        assert started.wait(5), "the stand-in websockify did not start"

    async def _shutdown(self):
        self._server.close(close_connections=False)
        for connection in list(self._server.all_connections):
            connection.transport.abort()  # a peer that is gone can't finish a close handshake
        await self._server.wait_closed()

    def stop(self):
        asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop).result(5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
        self._loop.close()


@pytest.fixture
def websockify(monkeypatch):
    server = FakeWebsockify()
    server.start()
    monkeypatch.setenv("IBCTL_NOVNC_PORT", str(server.port))
    yield server
    server.stop()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def dashboard_on_loopback(app):
    """The app under a real uvicorn server on a loopback port; yields its ws:// base URL.

    The socket is bound and listening before the server starts, so a client can
    connect straight away and nothing waits or polls for startup.
    """
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        yield f"ws://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def build_app(**settings):
    return create_app(settings=authed_settings(**settings))


def no_login_app():
    """A dashboard with no password, GitHub or OIDC configured: nobody can sign in."""
    return build_app(token="", auth_secret=SecretStr(TEST_AUTH_SECRET))


def session_cookie() -> dict[str, str]:
    """The cookie the password login form sets, as a request header."""
    return {"Cookie": f"{AUTH_COOKIE_NAME}={build_password_session(TEST_AUTH_SECRET)}"}


def open_websocket(base: str, path: str = "/websockify", headers: dict[str, str] | None = None):
    return ws_connect(f"{base}{path}", subprotocols=["binary"], additional_headers=headers or {})


def handshake_status(base: str, path: str = "/websockify", headers: dict[str, str] | None = None) -> int:
    """The HTTP status the dashboard answered the websocket handshake with; fails if it opened."""
    with pytest.raises(InvalidStatus) as refusal:
        with open_websocket(base, path, headers):
            pytest.fail(f"{path} accepted the websocket")
    return refusal.value.response.status_code


class TestAnonymousIsRefused:
    def test_no_credentials(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            assert handshake_status(base) == 403
        assert websockify.connections == 0, "an anonymous visitor reached websockify"

    def test_a_forged_session_cookie(self, websockify):
        forged = {"Cookie": f"{AUTH_COOKIE_NAME}={build_password_session('not the signing secret')}"}
        with dashboard_on_loopback(build_app()) as base:
            assert handshake_status(base, headers=forged) == 403
        assert websockify.connections == 0

    def test_a_session_idle_for_longer_than_the_limit(self, websockify):
        long_ago = int(time.time()) - 3600
        idle = {"Cookie": f"{AUTH_COOKIE_NAME}={sign(Kind.PASSWORD_SESSION, {'auth': 'password', 'iat': long_ago, 'act': long_ago}, TEST_AUTH_SECRET)}"}
        with dashboard_on_loopback(build_app()) as base:
            assert handshake_status(base, headers=idle) == 403
        assert websockify.connections == 0

    def test_an_idle_oauth_session_too(self, websockify):
        long_ago = int(time.time()) - 3600
        idle = {"Cookie": f"{OAUTH_COOKIE_NAME}={sign(Kind.OAUTH_SESSION, {'login': 'octocat', 'iat': long_ago, 'act': long_ago}, TEST_AUTH_SECRET)}"}
        app = build_app(github_client_id="client-id", github_client_secret=SecretStr("client-secret"))
        with dashboard_on_loopback(app) as base:
            assert handshake_status(base, headers=idle) == 403
        assert websockify.connections == 0

    def test_the_dashboard_password_is_not_a_credential(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            assert handshake_status(base, headers={"Authorization": f"Bearer {TEST_PASSWORD}"}) == 403
        assert websockify.connections == 0

    def test_a_recognised_api_token_alone_does_not_open_it(self, websockify, tmp_path):
        app = build_app()
        app.state.api_access = ApiAccessStore(tmp_path / "api_access.json")
        _, plaintext = app.state.api_access.create_token("ci-bot", created_by="test")
        assert app.state.api_access.recognise(plaintext) is not None

        with dashboard_on_loopback(app) as base:
            assert handshake_status(base, headers={"Authorization": f"Bearer {plaintext}"}) == 403
        assert websockify.connections == 0


class TestNoLoginConfigured:
    """With no password, GitHub or OIDC configured nobody can sign in, so nobody may use VNC."""

    def test_anonymous_is_refused(self, websockify):
        with dashboard_on_loopback(no_login_app()) as base:
            assert handshake_status(base) == 403
        assert websockify.connections == 0

    def test_a_cookie_signed_with_the_secret_is_still_refused(self, websockify):
        with dashboard_on_loopback(no_login_app()) as base:
            assert handshake_status(base, headers=session_cookie()) == 403
        assert websockify.connections == 0


class TestLoggedInProxies:
    def test_an_old_session_with_recent_activity_is_a_login(self, websockify):
        now = int(time.time())
        cookie = {"Cookie": f"{AUTH_COOKIE_NAME}={sign(Kind.PASSWORD_SESSION, {'auth': 'password', 'iat': now - 86400, 'act': now}, TEST_AUTH_SECRET)}"}
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=cookie) as ws:
                assert ws.recv() == GREETING

    def test_bytes_travel_both_ways(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=session_cookie()) as ws:
                assert ws.recv() == GREETING  # websockify -> browser, unprompted
                ws.send(b"\x00\x01rfb")  # browser -> websockify
                assert websockify.frames.get(timeout=5) == b"\x00\x01rfb"
                assert ws.recv() == b"echo:\x00\x01rfb"

    def test_text_frames_pass_as_text(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=session_cookie()) as ws:
                ws.recv()
                ws.send("hello")
                assert websockify.frames.get(timeout=5) == "hello"
                assert ws.recv() == "echo:hello"

    def test_the_subprotocol_websockify_picks_is_the_one_the_browser_gets(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=session_cookie()) as ws:
                assert ws.subprotocol == "binary"
        assert websockify.subprotocol == "binary"

    def test_the_login_is_not_passed_on_to_websockify(self, websockify):
        headers = {**session_cookie(), "Authorization": "Bearer something"}
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=headers) as ws:
                ws.recv()
        assert "cookie" not in websockify.request_headers
        assert "authorization" not in websockify.request_headers

    def test_the_browser_hanging_up_hangs_up_on_websockify(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=session_cookie()) as ws:
                ws.recv()
            assert websockify.disconnected.wait(5), "websockify was left connected"

    def test_websockify_hanging_up_closes_the_browser_socket(self, websockify):
        with dashboard_on_loopback(build_app()) as base:
            with open_websocket(base, headers=session_cookie()) as ws:
                ws.recv()
                ws.send(b"hang up")
                with pytest.raises(ConnectionClosedOK):
                    ws.recv()

    def test_an_oauth_session_is_a_login_too(self, websockify):
        app = create_app(settings=authed_settings(
            token="",
            github_client_id="client-id",
            github_client_secret=SecretStr("client-secret"),  # nosecret: test value
        ))
        cookie = {"Cookie": f"{OAUTH_COOKIE_NAME}={build_oauth_session('octocat', TEST_AUTH_SECRET)}"}
        with dashboard_on_loopback(app) as base:
            with open_websocket(base, headers=cookie) as ws:
                assert ws.recv() == GREETING

    def test_websockify_being_down_refuses_the_socket(self, monkeypatch):
        monkeypatch.setenv("IBCTL_NOVNC_PORT", str(free_port()))
        with dashboard_on_loopback(build_app()) as base:
            assert handshake_status(base, headers=session_cookie()) == 403


class TestUpstreamAddress:
    def test_websockify_is_on_loopback_at_the_novnc_port(self, monkeypatch):
        monkeypatch.setenv("IBCTL_NOVNC_PORT", "6123")
        assert upstream_url() == "ws://127.0.0.1:6123/"

    def test_the_default_port_is_6080(self, monkeypatch):
        monkeypatch.delenv("IBCTL_NOVNC_PORT", raising=False)
        assert DEFAULT_NOVNC_PORT == 6080
        assert upstream_url() == "ws://127.0.0.1:6080/"


class TestEveryWebsocketRoute:
    """A websocket route added later is refused to anonymous visitors unless it is listed as public."""

    def test_the_public_list_is_empty(self):
        assert PUBLIC_WEBSOCKET_PATHS == frozenset()

    def test_the_sweep_finds_the_vnc_route(self):
        assert "/websockify" in websocket_route_table(build_app())

    @pytest.mark.parametrize("make_app", [build_app, no_login_app], ids=["login-configured", "no-login"])
    def test_every_websocket_route_refuses_anonymous_visitors(self, websockify, make_app):
        app = make_app()
        with dashboard_on_loopback(app) as base:
            for path in websocket_route_table(app):
                if path not in PUBLIC_WEBSOCKET_PATHS:
                    assert handshake_status(base, path) == 403, path
        assert websockify.connections == 0


class TestVncPage:
    """The page that carries the VNC password is for logged-in people only."""

    @pytest.fixture(autouse=True)
    def vnc_password(self, monkeypatch):
        monkeypatch.setenv("VNC_SERVER_PASSWORD", VNC_PASSWORD)

    @staticmethod
    def asgi_client(app) -> AsyncClient:
        return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")

    async def test_logged_in_gets_the_page_with_the_password(self):
        async with self.asgi_client(build_app()) as c:
            await log_in(c)
            resp = await c.get("/vnc")
        assert resp.status_code == 200
        assert VNC_PASSWORD in resp.text

    async def test_the_page_talks_to_the_dashboard_never_to_port_6080(self):
        async with self.asgi_client(build_app()) as c:
            await log_in(c)
            body = (await c.get("/vnc")).text
        assert "ROOT_PATH + '/websockify'" in body
        assert "6080" not in body
        assert "location.hostname + ':'" not in body

    async def test_anonymous_gets_neither_the_page_nor_the_password(self):
        async with self.asgi_client(build_app()) as c:
            resp = await c.get("/vnc")
        assert resp.status_code == 303
        assert VNC_PASSWORD not in resp.text

    async def test_no_login_configured_refuses_the_page_and_the_password(self):
        async with self.asgi_client(no_login_app()) as c:
            resp = await c.get("/vnc")
            api = await c.get("/vnc", headers={"Accept": "application/json"})
        assert resp.status_code == 303 and VNC_PASSWORD not in resp.text
        assert api.status_code == 403 and VNC_PASSWORD not in api.text
