"""static/session.js: the browser half of idle logout, run under node.

The page script is a few pure decisions (when to send a heartbeat, how many
seconds are left, where the login page is) and a controller that takes its
clock, storage, network and navigation as arguments. Both run here against a
clock the test moves by hand, so nothing sleeps and no browser is needed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

SESSION_JS = Path(__file__).resolve().parents[1] / "app" / "static" / "session.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

SECOND = 1000
MINUTE = 60 * SECOND

# A controller with a fake world: a clock `w.advance(ms)` moves, a storage, a
# network that answers by URL (`w.answers`), and a record of what it was asked.
HARNESS = """
const S = require(process.argv[1]);
const tick = () => new Promise((resolve) => setImmediate(resolve));
function world(options = {}) {
  const w = { t: 1000000, store: {}, fetches: [], navigations: [], banner: [], timers: [],
              answers: {}, hang: false, offline: false, login: false };
  w.advance = (ms) => { w.t += ms; };
  w.env = {
    now: () => w.t,
    storage: { get: (k) => w.store[k], set: (k, v) => { w.store[k] = String(v); } },
    fetch: (url, opts) => {
      w.fetches.push({ url, method: opts.method });
      if (w.hang) return new Promise(() => {});
      if (w.offline) return Promise.reject(new Error('offline'));
      return Promise.resolve({ status: w.answers[url] || 200 });
    },
    navigate: (url) => w.navigations.push(url),
    setTimeout: (fn, ms) => { w.timers.push({ fn, ms }); },
    location: () => ({ pathname: options.pathname || '/ibctl/config', search: options.search || '' }),
    onLoginPage: () => w.login,
    banner: { show: (text) => w.banner.push(text), hide: () => w.banner.push('hidden') },
  };
  w.ctl = S.createController({ idleSeconds: options.idle || 300, root: options.root === undefined ? '/ibctl' : options.root }, w.env);
  return w;
}
"""


def run(expr: str, *, setup: str = ""):
    """Evaluate ``expr`` (may use await) in the harness; return it as JSON."""
    script = HARNESS + f"(async () => {{ {setup}\n console.log(JSON.stringify(await ({expr}))); }})();"
    out = subprocess.run([NODE, "-e", script, str(SESSION_JS)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def test_the_script_parses():
    subprocess.run([NODE, "--check", str(SESSION_JS)], check=True, capture_output=True)


class TestDecisions:
    @pytest.mark.parametrize(("idle", "expected"), [(60, 15 * SECOND), (300, 75 * SECOND), (1200, 300 * SECOND), (30, 15 * SECOND)])
    def test_the_heartbeat_interval_is_a_quarter_of_the_limit_but_at_least_15_seconds(self, idle, expected):
        assert run(f"S.heartbeatEveryMs({idle})") == expected

    @pytest.mark.parametrize(
        ("now", "activity", "heartbeat", "idle", "expected"),
        [
            (100 * SECOND, 100 * SECOND, 0, 300, True),  # active, last heartbeat long ago
            (100 * SECOND, 100 * SECOND, 90 * SECOND, 300, False),  # one was sent 10 s ago
            (100 * SECOND, 20 * SECOND, 50 * SECOND, 300, False),  # nothing since the last one
            (125 * SECOND, 100 * SECOND, 50 * SECOND, 300, True),  # activity after it, interval (75 s) up
            (124 * SECOND, 100 * SECOND, 50 * SECOND, 300, False),  # interval not up yet
            (100 * SECOND, 100 * SECOND, 0, 0, False),  # idle logout off
        ],
    )
    def test_when_a_heartbeat_is_due(self, now, activity, heartbeat, idle, expected):
        assert run(f"S.shouldSendHeartbeat({now}, {activity}, {heartbeat}, {idle})") == expected

    @pytest.mark.parametrize(
        ("now", "activity", "idle", "expected"),
        [(0, 0, 300, 300), (100 * SECOND, 0, 300, 200), (299500, 0, 300, 1), (300 * SECOND, 0, 300, 0), (900 * SECOND, 0, 300, 0)],
    )
    def test_seconds_until_logout(self, now, activity, idle, expected):
        assert run(f"S.secondsUntilLogout({now}, {activity}, {idle})") == expected

    def test_no_limit_means_never(self):
        assert run("S.secondsUntilLogout(9e9, 0, 0) === Infinity") is True

    @pytest.mark.parametrize(("left", "shown"), [(31, False), (30, True), (1, True), (0, False)])
    def test_the_banner_shows_for_the_last_30_seconds(self, left, shown):
        assert run(f"S.shouldShowBanner({left})") == shown

    def test_the_banner_text(self):
        assert run("S.bannerText(12)") == (
            "Signing out in 12 s because of inactivity. Move the mouse or press a key to stay signed in."
        )

    @pytest.mark.parametrize(("now", "last", "expected"), [(1000, 0, True), (1999, 1000, False), (2000, 1000, True)])
    def test_input_is_recorded_at_most_once_a_second(self, now, last, expected):
        assert run(f"S.shouldRecordActivity({now}, {last})") == expected

    def test_a_pointer_that_has_not_moved_is_not_a_person(self):
        assert run("[S.pointerMoved(null, 5, 5), S.pointerMoved({x: 5, y: 5}, 5, 5), S.pointerMoved({x: 5, y: 5}, 6, 5)]") == [True, False, True]

    def test_scroll_alone_is_not_activity_so_a_self_scrolling_log_cannot_keep_a_session_alive(self):
        events = run("S.events")
        assert "scroll" not in events
        assert {"mousemove", "mousedown", "keydown", "wheel", "touchstart"} <= set(events)

    @pytest.mark.parametrize(
        ("root", "pathname", "search", "expected"),
        [
            ("/ibctl", "/ibctl/config", "", "/ibctl/login?next=/config&reason=idle"),
            ("/ibctl", "/ibctl/state", "?mode=paper&x=1", "/ibctl/login?next=/state?mode=paper%26x=1&reason=idle"),
            ("/ibctl/", "/ibctl/logs", "", "/ibctl/login?next=/logs&reason=idle"),
            ("", "/config", "", "/login?next=/config&reason=idle"),
            ("/ibctl", "/ibctl/", "", "/ibctl/login?reason=idle"),
            ("/ibctl", "/ibctl", "", "/ibctl/login?reason=idle"),
            ("/ibctl", "/other/place", "", "/ibctl/login?reason=idle"),
            ("", "//evil.example/x", "", "/login?reason=idle"),
        ],
    )
    def test_the_login_url_comes_back_to_the_page_under_the_prefix(self, root, pathname, search, expected):
        assert run(f"S.loginUrl({json.dumps(root)}, 'idle', {json.dumps(pathname)}, {json.dumps(search)})") == expected

    @pytest.mark.parametrize(
        ("pathname", "root", "expected"),
        [("/ibctl/login", "/ibctl", True), ("/login", "", True), ("/ibctl/config", "/ibctl", False), ("/login", "/ibctl", False)],
    )
    def test_it_knows_the_login_page_so_it_never_redirects_in_a_loop(self, pathname, root, expected):
        assert run(f"S.isLoginPage({json.dumps(pathname)}, {json.dumps(root)})") == expected


class TestTheController:
    def test_it_does_nothing_while_the_person_is_there(self):
        got = run(
            "[w.fetches, w.navigations, w.banner]",
            setup="const w = world(); for (let i = 0; i < 20; i++) { w.advance(60 * 1000); w.ctl.noteActivity(); w.ctl.tick(); await tick(); }",
        )

        assert got[1] == [] and got[2] == []

    def test_after_the_idle_period_it_logs_out_then_goes_to_the_login_page(self):
        got = run(
            "[w.fetches.filter(f => f.url.endsWith('/logout')), w.navigations]",
            setup="const w = world(); w.advance(300 * 1000); w.ctl.tick(); await tick();",
        )

        assert got[0] == [{"url": "/ibctl/logout", "method": "POST"}]
        assert got[1] == ["/ibctl/login?next=/config&reason=idle"]

    def test_it_waits_until_the_period_is_up(self):
        got = run("w.navigations", setup="const w = world(); w.advance(299 * 1000); w.ctl.tick(); await tick();")

        assert got == []

    def test_the_warning_appears_30_seconds_before_and_counts_down(self):
        got = run(
            "w.banner",
            setup="const w = world(); w.advance(269 * 1000); w.ctl.tick(); w.advance(270 * 1000 - 269 * 1000); w.ctl.tick(); w.advance(10 * 1000); w.ctl.tick();",
        )

        assert got == [
            "Signing out in 30 s because of inactivity. Move the mouse or press a key to stay signed in.",
            "Signing out in 20 s because of inactivity. Move the mouse or press a key to stay signed in.",
        ]

    def test_activity_takes_the_warning_down_and_the_session_carries_on(self):
        got = run(
            "[w.banner.slice(-1), w.navigations, S.secondsUntilLogout(w.t, Number(w.store[S.keys.activity]), 300)]",
            setup="const w = world(); w.advance(280 * 1000); w.ctl.tick(); w.ctl.noteActivity(); w.advance(60 * 1000); w.ctl.tick(); await tick();",
        )

        assert got[0] == ["hidden"]
        assert got[1] == []
        assert got[2] == 240

    def test_the_logout_goes_ahead_even_if_the_server_never_answers(self):
        got = run(
            "[w.navigations, w.timers.map(t => t.ms)]",
            setup="const w = world(); w.hang = true; w.advance(300 * 1000); w.ctl.tick(); await tick(); w.timers.forEach(t => t.fn());",
        )

        assert got[0] == ["/ibctl/login?next=/config&reason=idle"]
        assert got[1] == [3000]

    def test_it_logs_out_once(self):
        got = run(
            "[w.navigations.length, w.fetches.length]",
            setup="const w = world(); w.advance(300 * 1000); w.ctl.tick(); w.ctl.tick(); w.ctl.tick(); await tick(); w.timers.forEach(t => t.fn());",
        )

        assert got == [1, 1]

    def test_another_tabs_activity_keeps_this_one_signed_in(self):
        got = run(
            "[w.navigations, w.banner]",
            setup="const w = world(); w.advance(290 * 1000); w.store[S.keys.activity] = String(w.t - 5 * 1000); w.ctl.tick(); w.advance(100 * 1000); w.ctl.tick(); await tick();",
        )

        assert got[0] == []
        assert got[1] == []

    def test_a_heartbeat_follows_activity_once_the_interval_is_up(self):
        got = run(
            "w.fetches",
            setup="const w = world(); w.advance(10 * 1000); w.ctl.noteActivity(); w.advance(70 * 1000); w.ctl.noteActivity(); await tick();",
        )

        assert got == [{"url": "/ibctl/api/session/touch", "method": "POST"}]

    def test_no_heartbeat_without_activity(self):
        got = run("w.fetches", setup="const w = world(); for (let i = 0; i < 100; i++) { w.advance(2000); w.ctl.tick(); await tick(); }")

        assert got == []

    def test_activity_just_after_a_heartbeat_is_reported_when_the_interval_is_up(self):
        got = run(
            "w.fetches.map(f => f.url)",
            setup=(
                "const w = world(); w.advance(80 * 1000); w.ctl.noteActivity(); await tick();"  # heartbeat 1
                "w.advance(5 * 1000); w.ctl.noteActivity(); await tick();"  # too soon
                "w.advance(60 * 1000); w.ctl.tick(); await tick();"  # still < 75 s since #1
                "w.advance(15 * 1000); w.ctl.tick(); await tick();"  # trailing heartbeat
            ),
        )

        assert got == ["/ibctl/api/session/touch", "/ibctl/api/session/touch"]

    def test_input_is_recorded_at_most_once_a_second(self):
        got = run(
            "Number(w.store[S.keys.activity]) - 1000000",
            setup="const w = world(); w.advance(1000); w.ctl.noteActivity(); w.advance(400); w.ctl.noteActivity(); w.advance(400); w.ctl.noteActivity();",
        )

        assert got == 1000

    def test_a_heartbeat_another_tab_just_sent_is_not_sent_again(self):
        got = run(
            "w.fetches.length",
            setup="const w = world(); w.advance(80 * 1000); w.store[S.keys.heartbeat] = String(w.t); w.ctl.noteActivity(); w.ctl.tick(); await tick();",
        )

        assert got == 0

    def test_a_401_from_the_heartbeat_means_the_session_ended(self):
        got = run(
            "w.navigations",
            setup="const w = world(); w.answers['/ibctl/api/session/touch'] = 401; w.advance(80 * 1000); w.ctl.noteActivity(); await tick();",
        )

        assert got == ["/ibctl/login?next=/config&reason=idle"]

    def test_a_failed_heartbeat_is_retried_in_a_few_seconds_not_every_tick(self):
        got = run(
            "w.fetches.length",
            setup=(
                "const w = world(); w.offline = true; w.advance(80 * 1000); w.ctl.noteActivity(); await tick();"  # fails
                "for (let i = 0; i < 4; i++) { w.advance(1000); w.ctl.tick(); await tick(); }"  # inside the retry delay
                "w.advance(2000); w.ctl.tick(); await tick();"  # 6 s after the failure: tries again
            ),
        )

        assert got == 2

    def test_a_401_from_anything_else_goes_to_login_once(self):
        got = run(
            "w.navigations",
            setup="const w = world(); w.ctl.handleUnauthorized(); w.ctl.handleUnauthorized(); w.ctl.handleUnauthorized();",
        )

        assert got == ["/ibctl/login?next=/config&reason=idle"]

    def test_on_the_login_page_nothing_redirects(self):
        got = run(
            "[w.navigations, w.fetches]",
            setup="const w = world({ pathname: '/ibctl/login' }); w.login = true; w.ctl.handleUnauthorized(); w.advance(900 * 1000); w.ctl.tick(); await tick();",
        )

        assert got == [[], []]

    def test_without_a_prefix_the_paths_have_none(self):
        got = run(
            "[w.fetches.map(f => f.url), w.navigations]",
            setup="const w = world({ root: '', pathname: '/state', search: '?mode=paper' }); w.advance(80 * 1000); w.ctl.noteActivity(); w.advance(300 * 1000); w.ctl.tick(); await tick();",
        )

        assert got[0] == ["/api/session/touch", "/logout"]
        assert got[1] == ["/login?next=/state?mode=paper&reason=idle"]


# The page glue, run in a sandbox that stands in for the browser: a window that
# records the listeners, timers and fetches the script sets up.
PAGE = """
const fs = require('fs');
const vm = require('vm');
const tick = () => new Promise((resolve) => setImmediate(resolve));
function page(options = {}) {
  const p = { t: 5000000, listeners: {}, docListeners: {}, intervals: [], navigations: [], fetches: [], store: {} };
  const attrs = { 'data-idle-seconds': options.idle === undefined ? '300' : String(options.idle),
                  'data-root': options.root === undefined ? '/ibctl' : options.root };
  const win = {
    location: { pathname: options.pathname || '/ibctl/config', search: '', href: 'http://dash.test/ibctl/config',
                origin: 'http://dash.test', assign: (u) => p.navigations.push(u) },
    addEventListener: (name, fn, opts) => { (p.listeners[name] = p.listeners[name] || []).push({ fn, opts }); },
    setInterval: (fn, ms) => { p.intervals.push(ms); p.tick = fn; return 1; },
    setTimeout: () => 1,
    fetch: (url, opts) => { p.fetches.push({ url: String(url), method: opts && opts.method });
                            return Promise.resolve({ status: (options.answers || {})[url] || 200 }); },
    localStorage: { getItem: (k) => p.store[k] === undefined ? null : p.store[k], setItem: (k, v) => { p.store[k] = String(v); } },
    document: {
      currentScript: { getAttribute: (k) => attrs[k] === undefined ? null : attrs[k] },
      addEventListener: (name, fn) => { (p.docListeners[name] = p.docListeners[name] || []).push(fn); },
      body: { appendChild() {} },
      createElement: () => ({ style: {}, setAttribute() {}, appendChild() {} }),
    },
    URL, Promise, Date: { now: () => p.t },
  };
  win.window = win;
  p.win = win;
  p.originalFetch = win.fetch;
  p.fire = (name, event) => (p.listeners[name] || []).forEach((l) => l.fn(Object.assign({ type: name }, event)));
  vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), win);
  return p;
}
"""


def run_page(expr: str, *, setup: str = ""):
    script = PAGE + f"(async () => {{ {setup}\n console.log(JSON.stringify(await ({expr}))); }})();"
    out = subprocess.run([NODE, "-e", script, str(SESSION_JS)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


class TestThePage:
    def test_it_listens_for_real_input_in_the_capture_phase_and_not_for_scroll(self):
        got = run_page(
            "[Object.keys(p.listeners).sort(), p.listeners.keydown[0].opts, p.intervals]",
            setup="const p = page();",
        )

        names = got[0]
        assert {"mousemove", "mousedown", "keydown", "wheel", "touchstart"} <= set(names)
        assert "scroll" not in names
        assert got[1] == {"capture": True, "passive": True}  # still seen when a widget stops propagation
        assert got[2] == [1000]

    def test_zero_turns_everything_off(self):
        got = run_page("[p.listeners, p.intervals, p.win.fetch === p.originalFetch]", setup="const p = page({ idle: 0 });")

        assert got == [{}, [], True]

    def test_the_login_page_gets_no_timers(self):
        got = run_page("[p.listeners, p.intervals]", setup="const p = page({ pathname: '/ibctl/login' });")

        assert got == [{}, []]

    def test_a_401_from_a_fetch_to_this_site_goes_to_the_login_page(self):
        got = run_page(
            "p.navigations",
            setup="const p = page({ answers: { '/ibctl/partials/overview': 401 } }); await p.win.fetch('/ibctl/partials/overview'); await tick();",
        )

        assert got == ["/ibctl/login?next=/config&reason=idle"]

    def test_the_caller_still_gets_the_response(self):
        got = run_page(
            "status",
            setup="const p = page({ answers: { '/ibctl/x': 401 } }); const status = (await p.win.fetch('/ibctl/x')).status;",
        )

        assert got == 401

    @pytest.mark.parametrize("url", ["https://elsewhere.example/api", "/ibctl/ok"])
    def test_a_401_from_another_site_or_no_401_at_all_does_nothing(self, url):
        got = run_page(
            "p.navigations",
            setup=f"const p = page({{ answers: {{ 'https://elsewhere.example/api': 401 }} }}); await p.win.fetch({json.dumps(url)}); await tick();",
        )

        assert got == []

    def test_a_401_from_htmx_goes_to_the_login_page_but_a_500_does_not(self):
        got = run_page(
            "p.navigations",
            setup=(
                "const p = page(); const fire = (status) => p.docListeners['htmx:responseError'].forEach((fn) => fn({ detail: { xhr: { status } } }));"
                "fire(500); fire(404);"
            ),
        )
        assert got == []

        got = run_page(
            "p.navigations",
            setup="const p = page(); p.docListeners['htmx:responseError'].forEach((fn) => fn({ detail: { xhr: { status: 401 } } }));",
        )
        assert got == ["/ibctl/login?next=/config&reason=idle"]

    def test_a_pointer_that_has_not_moved_does_not_count(self):
        got = run_page(
            "[Number(p.store['ibctl.session.activity']) - 5000000]",
            setup=(
                "const p = page(); p.t += 2000; p.fire('mousemove', { screenX: 10, screenY: 10 });"  # a person: first position
                "p.t += 2000; p.fire('mousemove', { screenX: 10, screenY: 10 });"  # the page moved under a still pointer
            ),
        )

        assert got == [2000]

    def test_a_moved_pointer_a_key_and_the_wheel_count(self):
        got = run_page(
            "Number(p.store['ibctl.session.activity']) - 5000000",
            setup=(
                "const p = page(); p.t += 2000; p.fire('mousemove', { screenX: 1, screenY: 1 });"
                "p.t += 2000; p.fire('mousemove', { screenX: 2, screenY: 1 });"
                "p.t += 2000; p.fire('keydown', {}); p.t += 2000; p.fire('wheel', {});"
            ),
        )

        assert got == 8000
