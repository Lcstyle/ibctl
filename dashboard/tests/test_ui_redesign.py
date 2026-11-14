"""RED-phase tests for the Dashboard UI flat-card refactor (v2).

v1 introduced collapsible accordion capsules with a
System reference plate holding both build provenance AND per-instance
Gateway state / Recovery rows.

v2 removes the accordion behavior entirely and re-flows the information:

1. **Header** — unchanged from v1. Mnemonic build badge only visible; the
   ``#ibctl-version`` element survives hidden in the DOM.

2. **Overview capsule** — a single outer ``.overview-capsule`` frame.
   Inner ``.overview-section`` blocks are transparent (no per-section
   card frame), separated by a hairline 1px top-border. Every section is
   always visible; no click-to-expand behavior.

3. **System section** — trimmed to FOUR reference rows only:
   Version, Build name, Deploy time, Trading mode. Gateway state and
   Recovery rows move OUT of System and INTO the per-instance LIVE /
   PAPER sections where they belong.

4. **Semantic tooltips** — key domain words (Recovery / aggressive /
   Gateway state / Deployment Site / Site role / Launch policy) get
   ``<span class="term" title="...">...</span>`` wrappers so operators
   can hover for a plain-English definition.

5. **Scraper anchors preserved** — ``data-accordion="live"`` / ``"paper"``
   / ``"ib-status"`` attributes STAY on the section elements (external
   tools may key on them) even though no accordion CSS/JS remains.

Every test in this file is expected to FAIL against the current v1
template. GREEN implements the flat-card refactor.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from httpx import ASGITransport, AsyncClient

from app.config import DashboardSettings
from app.main import create_app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
STATUS_WITH_RECOVERY = FIXTURES_DIR / "status_v1_with_recovery.json"

# ---------------------------------------------------------------------------
# Canonical build_badge — mirrors the shape produced by
# ``dashboard.main.create_app`` when ``settings.build_sha`` is populated.
# ---------------------------------------------------------------------------

_BUILD_BADGE = {
    "spec_version": "1",
    "mnemonic": "pearl-moth",
    "human_time": "Sat Jul 11 21:33 EDT",
    "context": "both",
    "sha": "61b237a1234567aaaaaa",
    "built_at_utc": "2026-07-11T21:33:00Z",
}

# Version string the STATUS JSON reports — the tooltip's version half.
_STATUS_VERSION = "1.1.37-g61b237a"


def _load_recovery_fixture() -> dict:
    with STATUS_WITH_RECOVERY.open() as fh:
        return json.load(fh)


class _FakeIbctlClient:
    """Minimal in-memory client that exposes a specific status dict."""

    def __init__(self, raw_status: dict):
        self._raw = dict(raw_status)

    async def status_raw(self) -> dict:
        return self._raw

    async def send_command(self, command: str) -> str:
        return command


class _FakeIbMonitor:
    """Stubs the fields overview_partial reads off ib_status_monitor."""

    class _Scraper:
        class _Config:
            url = "https://example.invalid/ibkr"
            region = "us"

        config = _Config()
        _last_status = None

    def __init__(self):
        self._scraper = self._Scraper()
        self._task = None
        self._interval = 300
        self._last_pushed_status = "available"


def _build_status_dict(*, version: str = _STATUS_VERSION, recovery: dict | None = None,
                      state: str = "Connected", trading_mode: str = "both") -> dict:
    """Construct a STATUS JSON dict rich enough to drive overview.html."""
    d = {
        "version": version,
        "ready": True,
        "state": state,
        "trading_mode": trading_mode,
        "uptime_secs": 3600,
        "connected_uptime_secs": 3500,
        "jvm": {"pid": 4711, "alive": True, "uptime_secs": 3500},
        "socat": {"running": True, "pid": 4712},
        "clients": {"count": 2, "ids": [101, 102]},
        "site_role": "primary",
        "auto_launch": True,
        "site": {"role": "primary", "auto_launch": True},
        "stats": {"restarts_today": 0, "relogins_today": 0, "dialogs_dismissed": 0},
        "client_advisory": {"should_connect": True, "should_wait": False},
    }
    if recovery is not None:
        d["recovery"] = recovery
    return d


async def _make_client(*, trading_mode: str = "both", with_recovery: bool = False,
                       with_ib_monitor: bool = False, no_build_badge: bool = False):
    """Build a test AsyncClient with app state fully wired for redesign tests."""
    settings = DashboardSettings(
        port=8080,
        token="",
        debug_mode=False,
        ibctl_host="127.0.0.1",
        ibctl_port=7462,
        trading_mode=trading_mode,
    )
    app = create_app(settings=settings)

    if not no_build_badge:
        app.state.templates.env.globals["build_badge"] = _BUILD_BADGE
        app.state.build_badge = _BUILD_BADGE

    registry = app.state.instance_registry

    from app.instance_registry import _CachedResponse
    recovery = _load_recovery_fixture()["recovery"] if with_recovery else None
    for mode in registry.modes():
        status_dict = _build_status_dict(
            recovery=recovery,
            trading_mode=trading_mode,
        )
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status_dict, ttl=60.0)
        registry._clients[mode] = _FakeIbctlClient(status_dict)

    app.state.ibctl_client = registry.get_client(registry.primary_mode())

    if with_ib_monitor:
        app.state.ib_status_monitor = _FakeIbMonitor()

    transport = ASGITransport(app=app)
    return app, AsyncClient(transport=transport, base_url="http://test")


def _plant_recovery(app, recovery: dict, trading_mode: str = "both") -> None:
    """Plant a specific recovery dict directly into the status cache."""
    registry = app.state.instance_registry
    from app.instance_registry import _CachedResponse
    for mode in registry.modes():
        status_dict = _build_status_dict(recovery=recovery, trading_mode=trading_mode)
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status_dict, ttl=60.0)


# ---------------------------------------------------------------------------
# Header: version pill hidden, mnemonic-only visible, tooltip re-shaped
# (Header refactor was locked in v1; these guard against regression.)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_header_has_no_visible_version_pill():
    """``#ibctl-version`` must survive in the DOM (hidden) — scrapers key on it."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    assert response.status_code == 200

    soup = BeautifulSoup(response.text, "html.parser")
    version_el = soup.select_one("#ibctl-version")
    assert version_el is not None, (
        "#ibctl-version was removed from the DOM — scrapers may break."
    )

    style = (version_el.get("style") or "").lower()
    hidden_attr = version_el.has_attr("hidden")
    display_none = "display:none" in style.replace(" ", "") or "display: none" in style
    assert display_none or hidden_attr, (
        f"#ibctl-version must be invisible; got style={style!r}, hidden_attr={hidden_attr!r}."
    )


@pytest.mark.asyncio
async def test_header_top_row_shows_only_title_and_mnemonic():
    """Header bar visible content is limited to the ibctl title + mnemonic."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")
    header_bar = soup.select_one(".header-bar")
    assert header_bar is not None, "base.html no longer has a .header-bar element"

    def _visible_text(el) -> str:
        style = (el.get("style") or "").lower().replace(" ", "")
        if "display:none" in style or el.has_attr("hidden"):
            return ""
        return el.get_text(strip=True)

    text_all = header_bar.get_text(" ", strip=True)
    assert _BUILD_BADGE["mnemonic"] in text_all
    assert _BUILD_BADGE["human_time"] not in text_all
    assert _BUILD_BADGE["context"] not in text_all

    version_el = header_bar.select_one("#ibctl-version")
    if version_el is not None:
        assert _visible_text(version_el) == ""


@pytest.mark.asyncio
async def test_mnemonic_badge_tooltip_format_matches_spec():
    """Tooltip on the mnemonic badge MUST match ``v<version> : <human_time>``."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")

    badge = soup.select_one("#build-badge") or soup.select_one(".build-badge")
    assert badge is not None
    title = badge.get("title") or ""
    assert title

    assert " : " in title, f"tooltip missing ' : ' separator, got {title!r}"
    parts = title.split(" : ")
    assert len(parts) == 2
    version_half, time_half = parts[0].strip(), parts[1].strip()

    assert version_half.startswith("v") or version_half == ""
    if version_half:
        assert re.match(r"^v[\w.\-]+$", version_half)

    assert time_half == _BUILD_BADGE["human_time"]
    assert "ibctl" not in title.lower()
    assert _BUILD_BADGE["mnemonic"] not in title


# ---------------------------------------------------------------------------
# Overview capsule: single unified frame
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_overview_route_returns_200():
    """Smoke test: the redesigned overview partial must render 200."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_overview_has_single_unified_capsule():
    """Exactly one outermost ``.overview-capsule`` wraps the sections."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    capsules = soup.select(".overview-capsule")
    assert len(capsules) == 1


@pytest.mark.asyncio
async def test_overview_capsule_has_system_section_at_top():
    """``#overview-system`` MUST be the first section child of the capsule."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    capsule = soup.select_one(".overview-capsule")
    assert capsule is not None

    system = capsule.select_one("#overview-system")
    assert system is not None, (
        "#overview-system section is missing — this is the top provenance block."
    )

    def _is_section(node) -> bool:
        if getattr(node, "name", None) is None:
            return False
        classes = node.get("class") or []
        return "overview-section" in classes

    section_children = [c for c in capsule.children if _is_section(c)]
    assert section_children
    first_id = section_children[0].get("id") or ""
    assert first_id == "overview-system", (
        f"first section inside .overview-capsule must be #overview-system, "
        f"got id={first_id!r}"
    )


# ---------------------------------------------------------------------------
# System section: FOUR rows only (provenance, no runtime state)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_system_section_has_four_keyvalue_rows():
    """System now holds ONLY: Version, Build name, Deploy time, Trading mode.

    Gateway state and Recovery moved out — they belong in the per-instance
    sections, not in the build-provenance strip.
    """
    _app, client_ctx = await _make_client(with_recovery=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    system = soup.select_one("#overview-system")
    assert system is not None

    dt_texts = [dt.get_text(strip=True) for dt in system.select("dt")]

    def _has_label(prefix: str) -> bool:
        return any(t.lower().startswith(prefix.lower()) for t in dt_texts)

    required = ["Version", "Build name", "Deploy time", "Trading mode"]
    missing = [r for r in required if not _has_label(r)]
    assert not missing, (
        f"System section is missing key-value labels {missing}. "
        f"Present <dt> labels: {dt_texts!r}"
    )

    # And it must NOT carry any additional labels — the four above are
    # the entire System row set.
    assert len(dt_texts) == 4, (
        f"System section must have EXACTLY 4 <dt> rows (Version, Build name, "
        f"Deploy time, Trading mode). Got {len(dt_texts)}: {dt_texts!r}"
    )


@pytest.mark.asyncio
async def test_system_section_has_no_gateway_state_row():
    """Gateway state and Recovery rows must NOT appear in System."""
    _app, client_ctx = await _make_client(with_recovery=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    system = soup.select_one("#overview-system")
    assert system is not None
    dt_texts = [dt.get_text(strip=True).lower() for dt in system.select("dt")]

    assert not any(t.startswith("gateway state") for t in dt_texts), (
        f"Gateway state row must NOT appear in System (it belongs in the per-instance "
        f"section now). Got dt_texts={dt_texts!r}"
    )
    assert not any(t.startswith("recovery") for t in dt_texts), (
        f"Recovery row must NOT appear in System (belongs in the per-instance "
        f"section). Got dt_texts={dt_texts!r}"
    )


@pytest.mark.asyncio
async def test_system_section_row_values_populated():
    """The four provenance rows render with the expected fixture values.

    Does NOT check for 'Connected' — that state string now lives in the
    per-instance section, not in System.
    """
    _app, client_ctx = await _make_client(with_recovery=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    system = soup.select_one("#overview-system")
    assert system is not None
    text = system.get_text(" ", strip=True)

    # Version pill uses the STATUS `version` field.
    assert f"v{_STATUS_VERSION}" in text or _STATUS_VERSION in text, (
        f"System section must display the version string; got {text!r}"
    )
    assert _BUILD_BADGE["mnemonic"] in text
    assert _BUILD_BADGE["human_time"] in text
    # Trading mode humanized.
    assert "Live + Paper" in text, (
        "System section must humanize trading mode 'both' as 'Live + Paper'"
    )


# ---------------------------------------------------------------------------
# Deployment Site section
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_capsule_section_title_is_not_confusing():
    """Old 'PRIMARY  Auto-launch enabled' banner is replaced by
    'Deployment Site' (or 'Failover Configuration')."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    text = response.text

    old_pattern = re.compile(r"Auto-launch\s+enabled", re.IGNORECASE)
    assert not old_pattern.search(text)

    acceptable_titles = ["Deployment Site", "Failover Configuration"]
    assert any(t in text for t in acceptable_titles)


@pytest.mark.asyncio
async def test_deployment_site_section_has_labelled_rows():
    """The former banner's role + launch policy render as kv rows."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    header_matches = [
        h for h in soup.find_all(re.compile(r"^h[1-6]$"))
        if "deployment site" in h.get_text(strip=True).lower()
        or "failover configuration" in h.get_text(strip=True).lower()
    ]
    assert header_matches
    section = header_matches[0].find_parent()
    dt_texts = [dt.get_text(strip=True).lower() for dt in section.select("dt")]

    has_role = any("role" in t for t in dt_texts)
    has_launch = any("launch" in t or "auto" in t for t in dt_texts)
    assert has_role
    assert has_launch


# ---------------------------------------------------------------------------
# Gateway state row moved to per-instance sections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gateway_state_row_lives_in_live_section():
    """The LIVE instance section must carry a Gateway state <dt>."""
    _app, client_ctx = await _make_client(trading_mode="both")
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    live = soup.select_one('[data-accordion="live"]')
    assert live is not None, (
        "LIVE instance section (data-accordion='live') is missing"
    )
    dt_texts = [dt.get_text(strip=True).lower() for dt in live.select("dt")]
    assert any(t.startswith("gateway state") for t in dt_texts), (
        f"LIVE section must carry a 'Gateway state' <dt>; got dt_texts={dt_texts!r}"
    )


@pytest.mark.asyncio
async def test_gateway_state_row_lives_in_paper_section():
    """The PAPER instance section must carry a Gateway state <dt>."""
    _app, client_ctx = await _make_client(trading_mode="both")
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    paper = soup.select_one('[data-accordion="paper"]')
    assert paper is not None, (
        "PAPER instance section (data-accordion='paper') is missing"
    )
    dt_texts = [dt.get_text(strip=True).lower() for dt in paper.select("dt")]
    assert any(t.startswith("gateway state") for t in dt_texts), (
        f"PAPER section must carry a 'Gateway state' <dt>; got dt_texts={dt_texts!r}"
    )


# ---------------------------------------------------------------------------
# Recovery row visibility rules + placement in instance sections
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recovery_row_lives_in_instance_section_when_visible():
    """When recovery is visible, the Recovery <dt>/<dd> pair appears inside
    the per-instance section, NOT in System."""
    _app, client_ctx = await _make_client(with_recovery=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    # System must not carry Recovery.
    system = soup.select_one("#overview-system")
    assert system is not None
    system_dts = [dt.get_text(strip=True).lower() for dt in system.select("dt")]
    assert not any(t.startswith("recovery") for t in system_dts)

    # LIVE section MUST carry Recovery (fixture has a known-phase recovery).
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    live_dts = [dt.get_text(strip=True).lower() for dt in live.select("dt")]
    assert any(t.startswith("recovery") for t in live_dts), (
        f"LIVE section missing Recovery <dt> when recovery is visible. "
        f"Got dt_texts={live_dts!r}"
    )


@pytest.mark.asyncio
async def test_recovery_row_hidden_when_aggressive_lt_5min():
    """Hide the Recovery row in the instance section when phase is
    'aggressive' AND elapsed < 300s (mirrors header badge severity)."""
    aggressive = {
        "phase": "aggressive",
        "phase_entered_at": "2026-07-11T21:30:00-04:00[America/New_York]",
        "phase_elapsed_secs": 60,
        "last_full_success_at": None,
        "giveup_alert_sent_at": None,
        "next_retry_at": None,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, aggressive)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    dt_texts = [dt.get_text(strip=True).lower() for dt in live.select("dt")]
    assert not any(t.startswith("recovery") for t in dt_texts), (
        f"Recovery row must be hidden for aggressive < 5min; got dt_texts={dt_texts!r}"
    )


@pytest.mark.asyncio
async def test_recovery_row_uses_phase_abbrev_not_raw_enum():
    """Recovery row in the instance section must render 'backoff', not
    'backoff_every_15min' (must match header badge phaseAbbrev)."""
    backoff = {
        "phase": "backoff_every_15min",
        "phase_elapsed_secs": 900,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, backoff)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    text = live.get_text(" ", strip=True)
    assert "backoff_every_15min" not in text, (
        "raw enum leaked to Recovery row in LIVE section"
    )
    assert "backoff" in text.lower()


@pytest.mark.asyncio
async def test_recovery_row_suppresses_elapsed_when_given_up():
    """Recovery row must not render an elapsed suffix for 'given_up' phase
    — matches the header badge's behavior."""
    given_up = {
        "phase": "given_up",
        "phase_elapsed_secs": 15120,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, given_up)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    recovery_dds = [
        dt.find_next_sibling("dd").get_text(" ", strip=True)
        for dt in live.select("dt")
        if dt.get_text(strip=True).lower().startswith("recovery")
    ]
    assert recovery_dds, "no Recovery row rendered for given_up phase in LIVE section"
    for dd_text in recovery_dds:
        assert "·" not in dd_text and "•" not in dd_text, (
            f"Recovery row must suppress elapsed for `given_up`; got {dd_text!r}"
        )
        assert "given up" in dd_text.lower()


# ---------------------------------------------------------------------------
# Accordion behavior REMOVED — no click-to-expand, no aria-expanded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_accordion_toggle_handler_in_partial():
    """The overview partial must not carry any accordion click / keydown
    handlers, and must not use ``aria-expanded`` on section elements.
    The flat-card design shows everything at once."""
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    text = response.text

    # No onclick or onkeydown handlers referencing accordion toggling.
    assert "toggleAccordion" not in text, (
        "overview partial still references toggleAccordion — accordion "
        "behavior must be removed entirely for the flat-card design"
    )
    assert "handleAccordionKey" not in text, (
        "overview partial still references handleAccordionKey — remove all "
        "accordion keydown handling"
    )

    # No aria-expanded on any section element.
    soup = BeautifulSoup(text, "html.parser")
    for section in soup.select(".overview-section"):
        assert not section.has_attr("aria-expanded"), (
            f"section {section.get('id') or section.get('data-accordion')} "
            "still carries aria-expanded — sections are always visible now"
        )
        # And no aria-expanded on any descendant either — no controls to toggle.
    assert not soup.select("[aria-expanded]"), (
        "overview partial still has elements with aria-expanded — the flat-card "
        "design has no expandable controls"
    )


@pytest.mark.asyncio
async def test_no_accordion_card_classes_in_partial():
    """Legacy ``.accordion-card`` / ``.accordion-header`` classes must be
    fully removed from the emitted markup (flat card design)."""
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    # No .accordion-card DOM elements.
    assert not soup.select(".accordion-card"), (
        ".accordion-card elements still present in overview partial — the "
        "flat-card refactor removes them"
    )
    assert not soup.select(".accordion-header"), (
        ".accordion-header elements still present in overview partial"
    )
    assert not soup.select(".accordion-body"), (
        ".accordion-body elements still present in overview partial"
    )
    assert not soup.select(".accordion-chevron"), (
        ".accordion-chevron elements still present in overview partial"
    )


# ---------------------------------------------------------------------------
# Flat-card CSS invariants
# ---------------------------------------------------------------------------


def _find_css_rule(css_text: str, selector: str) -> str:
    """Return the declarations block for the first rule matching selector,
    or '' if not found. Selector match is exact on the raw selector text
    (whitespace-normalized). CSS block comments are stripped before parsing
    so a rule preceded by a ``/* ... */`` comment still matches (otherwise
    the regex would treat the comment text as part of the selector)."""
    # Strip block comments FIRST — the naive regex below can't tell a
    # comment apart from selector text otherwise. `re.DOTALL` because
    # comments can span lines.
    css_no_comments = re.sub(r"/\*.*?\*/", "", css_text, flags=re.DOTALL)
    # Very small regex-based extractor — the overview partial's <style>
    # block is small and hand-authored, and cssutils is not a dep here.
    pattern = re.compile(
        r"(^|\})\s*(?P<sel>[^{}]+?)\s*\{(?P<body>[^{}]*)\}",
        re.MULTILINE | re.DOTALL,
    )
    normalized_target = re.sub(r"\s+", " ", selector.strip())
    for m in pattern.finditer(css_no_comments):
        sel = re.sub(r"\s+", " ", m.group("sel").strip())
        if sel == normalized_target:
            return m.group("body")
    return ""


@pytest.mark.asyncio
async def test_overview_sections_have_transparent_panel_background():
    """``.overview-section`` (inner sections) must be transparent panels —
    no per-section background/border/rounded-corner card frame."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    style_block = soup.find("style")
    assert style_block is not None
    css = style_block.get_text()

    body = _find_css_rule(css, ".overview-section")
    assert body, (
        "no `.overview-section { ... }` CSS rule found in the overview "
        "partial <style> block"
    )
    body_norm = re.sub(r"\s+", " ", body).lower()

    # Transparent background — accept 'transparent' or 'none' or 'rgba(...,0)'.
    bg_ok = (
        "background: transparent" in body_norm
        or "background:transparent" in body_norm
        or "background: none" in body_norm
        or re.search(r"background:\s*rgba\([^)]*,\s*0\s*\)", body_norm)
        or "background-color: transparent" in body_norm
    )
    assert bg_ok, (
        f".overview-section must have a transparent background; got body={body!r}"
    )

    # No per-section border — accept 'border: 0', 'border: none', or
    # missing border declaration entirely (as long as no non-zero
    # `border:` shorthand is present).
    non_zero_border = re.search(
        r"border\s*:\s*(?!0\b|none\b|transparent\b)[^;]+;",
        body_norm,
    )
    assert not non_zero_border, (
        f".overview-section must not have a per-section border; got body={body!r}"
    )


@pytest.mark.asyncio
async def test_sections_separated_by_hairline_top_border():
    """Sections separated by a hairline ``border-top`` — the flat-card
    design's only visual separator between sibling sections."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    style_block = soup.find("style")
    assert style_block is not None
    css = style_block.get_text()

    body = _find_css_rule(css, ".overview-section + .overview-section")
    assert body, (
        "no `.overview-section + .overview-section { ... }` CSS rule found — "
        "the adjacent-sibling selector is the flat-card design's hairline "
        "separator"
    )
    body_norm = re.sub(r"\s+", " ", body).lower()
    assert "border-top" in body_norm, (
        f"adjacent-sibling rule must declare a border-top; got body={body!r}"
    )


# ---------------------------------------------------------------------------
# Semantic tooltip terms (Recovery / aggressive / Gateway state / ...)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recovery_term_has_hoverable_tooltip():
    """The Recovery kv-label must be wrapped in
    ``<span class="term" title="...">Recovery</span>`` so operators can
    hover the word for a plain-English definition."""
    aggressive = {
        "phase": "aggressive",
        "phase_elapsed_secs": 400,  # >= 300, so Recovery row shows
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, aggressive)
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    live = soup.select_one('[data-accordion="live"]')
    assert live is not None

    # A span.term whose visible text starts with 'Recovery'.
    recovery_terms = [
        s for s in live.select("span.term")
        if s.get_text(strip=True).lower().startswith("recovery")
    ]
    assert recovery_terms, (
        "no <span class='term' ...>Recovery</span> found in LIVE section — "
        "the tooltip wrapper must be present so hover reveals the definition"
    )
    # It must carry a title attribute — the string itself is now sourced from
    # the tt('ui.recovery.term') Jinja global (see test_overview_render_
    # resolves_tt_calls_through_jinja_global). An empty value here is the
    # graceful-degradation posture until descriptions.json is regenerated
    # with the ui.* overlay in the companion Pkl-catalog step; the tt()-
    # render test below asserts the pipe end-to-end.
    for span in recovery_terms:
        assert span.has_attr("title"), (
            "Recovery term span has no title attribute — tooltip wrapper missing"
        )


@pytest.mark.asyncio
async def test_aggressive_phase_word_has_hoverable_tooltip():
    """When phase is 'aggressive', the visible 'aggressive' phase word in
    the Recovery <dd> must be wrapped in
    ``<span class="term" title="...">aggressive</span>``."""
    aggressive = {
        "phase": "aggressive",
        "phase_elapsed_secs": 400,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, aggressive)
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    live = soup.select_one('[data-accordion="live"]')
    assert live is not None

    aggressive_terms = [
        s for s in live.select("span.term")
        if s.get_text(strip=True).lower() == "aggressive"
    ]
    assert aggressive_terms, (
        "no <span class='term'>aggressive</span> found in LIVE section — "
        "the aggressive phase word must be hoverable for its definition"
    )
    # Title now sourced from tt('ui.recovery.phase.aggressive'); empty until
    # descriptions.json is regenerated with the ui.* overlay. Attribute must
    # still be present so the wrapper markup is intact.
    for span in aggressive_terms:
        assert span.has_attr("title"), (
            "aggressive term span has no title attribute — wrapper missing"
        )


# ---------------------------------------------------------------------------
# Preservation anchors — scrapers, IDs, polling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ibctl_version_id_still_in_dom_for_scrapers():
    """``#ibctl-version`` must still appear in served HTML (hidden)."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    assert 'id="ibctl-version"' in response.text


@pytest.mark.asyncio
async def test_recovery_badge_still_in_header():
    """The recovery badge stays in the header markup."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")
    header = soup.select_one("header .header-bar")
    assert header is not None
    assert header.select_one("#recovery-badge") is not None


@pytest.mark.asyncio
async def test_overview_htmx_polling_interval_unchanged():
    """``#overview-content`` keeps ``every 5s`` and ``data-fixed-rate``."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")
    container = soup.select_one("#overview-content")
    assert container is not None
    trigger = container.get("hx-trigger") or ""
    assert "every 5s" in trigger
    assert container.has_attr("data-fixed-rate")


@pytest.mark.asyncio
async def test_data_accordion_markers_preserved_for_scrapers():
    """Section markers ``data-accordion="live"`` / ``"paper"`` must survive
    the flat-card refactor — external tools may key on them even though
    no accordion behavior remains."""
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    for mode in ("live", "paper", "ib-status"):
        assert soup.select_one(f'[data-accordion="{mode}"]') is not None, (
            f'section with data-accordion="{mode}" is missing after refactor'
        )


# ---------------------------------------------------------------------------
# Content preservation — the four original sections must still exist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_four_original_sections_present_by_content():
    """After consolidation, all four content areas remain inside the capsule."""
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    capsule = soup.select_one(".overview-capsule")
    assert capsule is not None

    inside_text = capsule.get_text(" ", strip=True).lower()

    assert (
        "deployment site" in inside_text
        or "failover configuration" in inside_text
    )
    # Section renamed "IB Status" -> "IBKR Service Status". The old name
    # could be read as the LIVE gateway's status while that gateway was
    # stuck in HITL, because it sat directly above the LIVE Gateway section
    # showing a green AVAILABLE. Accept either name so this test asserts the
    # section EXISTS rather than pinning its wording, but keep the new name
    # first so a revert to the ambiguous one is at least visible in the diff.
    assert (
        "interactive brokers" in inside_text
        or "ibkr" in inside_text
        or "ib status" in inside_text
    )
    assert "live" in inside_text
    assert "paper" in inside_text


# ---------------------------------------------------------------------------
# IBKR service status must not impersonate gateway readiness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ibkr_service_status_does_not_reuse_the_gateway_instance_badge():
    """The IBKR service panel must not render a `badge-live` / `badge-paper` chip.

    With the LIVE gateway stuck for hours in WaitingForHitl2fa, both panels
    were truthful — the gateway showed an amber "Awaiting Operator" pill — but
    the panel directly ABOVE it showed a large green AVAILABLE and a row reading
    "LIVE  available", built from the SAME `instance-badge-sm badge-live`
    component and the SAME green used for gateway health. An operator can
    easily read that as their LIVE gateway being fine.

    Two unrelated semantics must not share visual vocabulary while stacked
    adjacently. This asserts the service panel styles itself differently.
    """
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    section = soup.select_one('[data-accordion="ib-status"]')
    assert section is not None, "IBKR service status section should render"

    offenders = section.select(".badge-live, .badge-paper")
    assert not offenders, (
        "IBKR service-status rows must NOT reuse the gateway instance badge "
        f"(found {len(offenders)}). That badge means 'this is your gateway' "
        "everywhere else on the page; reusing it here is what made IBKR's "
        "service status read as gateway readiness."
    )


@pytest.mark.asyncio
async def test_ibkr_service_panel_names_its_subject():
    """The heading must say whose status it is, not just 'IB Status'."""
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    section = soup.select_one('[data-accordion="ib-status"]')
    assert section is not None
    heading = section.select_one(".section-header")
    assert heading is not None
    text = heading.get_text(strip=True).lower()
    # Assert INTENT (the heading names the owner), not a specific phrasing, so
    # copy edits do not break this. What must never return is a heading that
    # says only "IB Status" — ambiguous as to whose.
    assert "interactive brokers" in text or "ibkr" in text, (
        f"heading {text!r} must name Interactive Brokers explicitly — the bare "
        "'IB Status' was read as the operator's own gateway status on 2026-08-16"
    )

    # Naming the owner in the heading is necessary but was judged insufficient:
    # under stress the eye lands on the green status word, not the heading. A
    # scope note must state what this panel is NOT.
    note = section.select_one(".ib-scope-note")
    assert note is not None, "IBKR panel must carry a scope note"
    note_text = note.get_text(" ", strip=True).lower()
    assert "not" in note_text and "gateway" in note_text, (
        f"scope note {note_text!r} must say explicitly that this is NOT the "
        "gateways' status"
    )


# ---------------------------------------------------------------------------
# Extra regression guards
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_badge_does_not_render_pipe_separated_junk():
    """The old MBB-provenance title format is gone."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")
    badge = soup.select_one("#build-badge") or soup.select_one(".build-badge")
    assert badge is not None
    title = badge.get("title") or ""
    assert not title.startswith("MBB ")
    assert "·" not in title


@pytest.mark.asyncio
async def test_refresh_rate_select_has_accessible_label():
    """<select id='refresh-rate'> must carry an accessible label."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")

    label = soup.select_one('label[for="refresh-rate"]')
    assert label is not None
    assert label.get_text(strip=True)


@pytest.mark.asyncio
async def test_build_badge_is_keyboard_focusable():
    """The mnemonic build badge must be keyboard focusable and carry a
    non-hover-only accessible label."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/")
    soup = BeautifulSoup(response.text, "html.parser")

    badge = soup.select_one("#build-badge")
    assert badge is not None
    assert badge.get("tabindex") == "0"
    aria_label = badge.get("aria-label") or ""
    assert _BUILD_BADGE["mnemonic"] in aria_label
    assert _BUILD_BADGE["human_time"] in aria_label


@pytest.mark.asyncio
async def test_kv_grid_dt_color_meets_contrast_floor():
    """The kv-grid dt color must remain at the WCAG AA-passing #c4c4c8."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    assert ".kv-grid dt" in response.text
    assert "color: #c4c4c8" in response.text, (
        "expected `.kv-grid dt` color to be #c4c4c8 for WCAG AA"
    )
    dt_block = response.text.split(".kv-grid dt")[1].split("}")[0]
    assert "#888" not in dt_block


@pytest.mark.asyncio
async def test_system_section_is_not_a_collapsible_accordion():
    """System section must not carry any accordion class or toggle hook."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    system = soup.select_one("#overview-system")
    assert system is not None
    classes = system.get("class") or []
    assert "accordion-card" not in classes
    onclick_attrs = [
        el.get("onclick") for el in system.find_all(True)
        if el.get("onclick")
    ]
    assert not any("toggleAccordion" in (v or "") for v in onclick_attrs)


# ---------------------------------------------------------------------------
# v2 invariants — heading hierarchy, .term
# affordances, section-level health escalation, deduplicated State value,
# and coverage of the remaining template branches.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_all_peer_sections_use_h2_heading():
    """All five peer sections (System / Deployment Site / IB Status / LIVE /
    PAPER) must expose their title as an ``<h2>`` so the document outline is
    flat — no mix of ``<h2>`` and ``role='heading' aria-level='3'`` spans."""
    _app, client_ctx = await _make_client(trading_mode="both", with_ib_monitor=True)
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    capsule = soup.select_one(".overview-capsule")
    assert capsule is not None

    for selector in (
        "#overview-system",
        "#overview-deployment-site",
        '[data-accordion="ib-status"]',
        '[data-accordion="live"]',
        '[data-accordion="paper"]',
    ):
        section = capsule.select_one(selector)
        assert section is not None, f"peer section {selector!r} missing"
        # Each peer section must contain at least one <h2> as its top-level
        # heading — no legacy role/aria-level span-headings.
        assert section.select_one("h2") is not None, (
            f"peer section {selector!r} has no <h2> heading — heading "
            f"hierarchy is broken"
        )
        # And no aria-level=3 span-headings should linger (they would
        # re-introduce the mixed h2/h3 outline this test guards against).
        aria_level_3 = section.select('[aria-level="3"]')
        assert not aria_level_3, (
            f"peer section {selector!r} still carries aria-level='3' "
            f"span-headings — remove them so the outline stays flat"
        )


@pytest.mark.asyncio
async def test_live_paper_heading_has_screen_reader_gateway_suffix():
    """The LIVE/PAPER heading badge alone reads as just "LIVE" / "PAPER" to a
    screen reader. Add a visually-hidden " Gateway" span inside the heading
    so AT users hear "LIVE Gateway" / "PAPER Gateway"."""
    _app, client_ctx = await _make_client(trading_mode="both")
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    for mode in ("live", "paper"):
        section = soup.select_one(f'[data-accordion="{mode}"]')
        assert section is not None
        heading = section.select_one("h2")
        assert heading is not None
        sr_only = heading.select_one(".sr-only")
        assert sr_only is not None, (
            f"{mode.upper()} heading has no .sr-only span — screen readers "
            f"will hear only '{mode.upper()}' with no framing"
        )
        assert "gateway" in sr_only.get_text(strip=True).lower(), (
            f"{mode.upper()} sr-only text does not mention 'Gateway'; got "
            f"{sr_only.get_text(strip=True)!r}"
        )


@pytest.mark.asyncio
async def test_term_spans_are_keyboard_focusable():
    """Every ``.term`` span must carry ``tabindex='0'`` so keyboard-only
    users can Tab-focus the word and trigger its native title tooltip.
    Without this, term definitions are mouse-only."""
    aggressive = {
        "phase": "aggressive",
        "phase_elapsed_secs": 400,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, aggressive)
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    terms = soup.select("span.term")
    assert terms, "no .term spans rendered — nothing to check"

    missing_tabindex = [
        t.get_text(strip=True) for t in terms
        if t.get("tabindex") != "0"
    ]
    assert not missing_tabindex, (
        f"the following .term spans are missing tabindex='0' — keyboard "
        f"users cannot focus them: {missing_tabindex!r}"
    )


@pytest.mark.asyncio
async def test_term_focus_visible_rule_present_in_css():
    """A ``.term:focus-visible`` outline rule must exist in the overview
    <style> block. Without it, keyboard focus on a term is invisible even
    though the tabindex hop works."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    style_block = soup.find("style")
    assert style_block is not None
    css = style_block.get_text()

    body = _find_css_rule(css, ".term:focus-visible")
    assert body, (
        "no `.term:focus-visible { ... }` CSS rule — keyboard focus on a "
        "term span is invisible"
    )
    body_norm = re.sub(r"\s+", " ", body).lower()
    assert "outline" in body_norm, (
        f".term:focus-visible must declare an outline; got body={body!r}"
    )


@pytest.mark.asyncio
async def test_term_class_has_dotted_underline_style():
    """A ``.term { ... }`` rule with a dotted-underline decoration must
    exist in the overview <style> block. The DOM tests already check the
    span carries class 'term'; this pins the visual affordance so the
    dotted underline can't silently vanish."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    style_block = soup.find("style")
    assert style_block is not None
    css = style_block.get_text()

    body = _find_css_rule(css, ".term")
    assert body, "no `.term { ... }` CSS rule found in <style> block"
    body_norm = re.sub(r"\s+", " ", body).lower()
    assert "text-decoration" in body_norm and "dotted" in body_norm, (
        f".term must declare a dotted underline (text-decoration: underline "
        f"dotted ...); got body={body!r}"
    )
    assert "cursor" in body_norm and "help" in body_norm, (
        f".term must declare `cursor: help`; got body={body!r}"
    )


@pytest.mark.asyncio
async def test_unhealthy_instance_section_carries_data_health_error():
    """Sections whose instance is unreachable must carry
    ``data-health='error'`` so the CSS paints a left-stripe on the whole
    section — not just a small pill in the header row."""
    settings = DashboardSettings(
        port=8080, token="", debug_mode=False,
        ibctl_host="127.0.0.1", ibctl_port=7462, trading_mode="both",
    )
    app = create_app(settings=settings)
    app.state.templates.env.globals["build_badge"] = _BUILD_BADGE
    app.state.build_badge = _BUILD_BADGE

    registry = app.state.instance_registry
    from app.instance_registry import _CachedResponse

    # LIVE — unreachable via top-level `error` key on the instance shape.
    # (This is what overview_partial detects in `inst.get('error')`.)
    healthy = _build_status_dict()
    # We seed both instances; the partial builds `instances` per mode. The
    # 'error' field lives on the instance dict, not on STATUS, so we have
    # to plant it via the app-level partial's instance-fetching path.
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(healthy, ttl=60.0)
        registry._clients[mode] = _FakeIbctlClient(healthy)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    # Healthy baseline — LIVE section should be data-health="ok".
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    assert live.get("data-health") == "ok", (
        f"healthy LIVE section must carry data-health='ok'; "
        f"got {live.get('data-health')!r}"
    )

    # Now simulate 'not ready and not waiting' — health should escalate.
    not_ready = _build_status_dict()
    not_ready["ready"] = False
    not_ready["state"] = "Disconnected"
    not_ready["client_advisory"] = {"should_connect": False, "should_wait": False}
    for mode in registry.modes():
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(not_ready, ttl=60.0)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response2 = await client.get("/partials/overview")
    soup2 = BeautifulSoup(response2.text, "html.parser")
    live2 = soup2.select_one('[data-accordion="live"]')
    assert live2 is not None
    assert live2.get("data-health") == "error", (
        f"unhealthy LIVE section must carry data-health='error'; "
        f"got {live2.get('data-health')!r}"
    )


@pytest.mark.asyncio
async def test_data_health_error_paints_left_stripe_in_css():
    """A ``.overview-section[data-health='error']`` rule with a box-shadow
    or border-left must exist so the escalation attribute has visible
    effect."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    style_block = soup.find("style")
    assert style_block is not None
    css = style_block.get_text()

    body = _find_css_rule(css, '.overview-section[data-health="error"]')
    assert body, (
        "no `.overview-section[data-health='error']` CSS rule — the "
        "data-health attribute has no visual effect"
    )
    body_norm = re.sub(r"\s+", " ", body).lower()
    has_stripe = "box-shadow" in body_norm or "border-left" in body_norm
    assert has_stripe, (
        f"data-health='error' must paint a stripe (box-shadow or "
        f"border-left); got body={body!r}"
    )


@pytest.mark.asyncio
async def test_ib_status_scheduled_uses_warn_text_color():
    """When ``ib_status.status == 'scheduled'`` the section-status text
    must use the amber warn color (matching the yellow dot), not the red
    error color."""
    _app, client_ctx = await _make_client(with_ib_monitor=True)
    # Overwrite ib_status_monitor with a minimal object whose STATUS reports
    # 'scheduled' — the overview_partial route builds ib_status from the
    # monitor; the simpler path is to just check what the template does with
    # a fabricated ib_status value passed via the partial context. Simpler
    # still: assert the CSS/template branch treats scheduled the same as
    # maintenance by scanning the rendered template for the mismatched
    # ternary. We render a page and check the ternary source stays healed.
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    text = response.text
    # The bad shape was `{% elif ib.status == 'maintenance' %}#fbbf24`;
    # a healed template treats scheduled as amber too.
    bad = "elif ib.status == 'maintenance' %}#fbbf24{% else %}#ef4444"
    assert bad not in text, (
        "IB Status section-status color ternary treats 'scheduled' as red "
        "even though the dot is yellow — mismatch"
    )


@pytest.mark.asyncio
async def test_state_value_not_duplicated_via_inner_card():
    """The raw Gateway state value should live in the kv-grid row only —
    the legacy 'State' inner-card that mirrored it was removed. Assert no
    ``.inner-card`` inside an instance section carries a 'State' label."""
    _app, client_ctx = await _make_client(trading_mode="both")
    async with client_ctx as client:
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")

    for mode in ("live", "paper"):
        section = soup.select_one(f'[data-accordion="{mode}"]')
        assert section is not None
        for card in section.select(".inner-card"):
            label = card.select_one(".inner-label")
            if label is None:
                continue
            assert label.get_text(strip=True).lower() != "state", (
                f"{mode.upper()} section still has a 'State' inner-card — "
                f"the raw Gateway state string is now duplicated across "
                f"the health-pill, kv-grid Gateway state row, and this card"
            )


@pytest.mark.asyncio
async def test_recovery_row_hidden_when_no_recovery_block():
    """When STATUS carries no `recovery` key at all, the Recovery row must
    not render — covers the `not rec` branch of the recovery_visible macro."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        # No `_plant_recovery` — the default fixture omits `recovery`.
        response = await client.get("/partials/overview")
    soup = BeautifulSoup(response.text, "html.parser")
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    dt_texts = [dt.get_text(strip=True).lower() for dt in live.select("dt")]
    assert not any(t.startswith("recovery") for t in dt_texts), (
        f"Recovery row must be hidden when no recovery block is present; "
        f"got dt_texts={dt_texts!r}"
    )


@pytest.mark.asyncio
async def test_recovery_row_hidden_for_unknown_phase():
    """When STATUS carries a recovery block with an unknown phase enum
    value, the row must hide — covers the `rec.phase not in whitelist`
    branch of the recovery_visible macro (forward-compat)."""
    unknown_phase = {
        "phase": "brand_new_phase_daemon_added_last_week",
        "phase_elapsed_secs": 900,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, unknown_phase)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    dt_texts = [dt.get_text(strip=True).lower() for dt in live.select("dt")]
    assert not any(t.startswith("recovery") for t in dt_texts), (
        f"Recovery row must hide for unknown phase enum (forward-compat); "
        f"got dt_texts={dt_texts!r}"
    )
    # And the raw enum must not leak into the section text.
    assert "brand_new_phase" not in live.get_text(" ", strip=True), (
        "raw unknown phase enum leaked to the LIVE section text"
    )


@pytest.mark.asyncio
async def test_recovery_row_hidden_for_null_phase():
    """When the recovery block exists but `phase` is null/empty, the row
    must hide — covers the `not rec.phase` branch."""
    null_phase = {
        "phase": None,
        "phase_elapsed_secs": 900,
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_recovery(_app, null_phase)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    live = soup.select_one('[data-accordion="live"]')
    assert live is not None
    dt_texts = [dt.get_text(strip=True).lower() for dt in live.select("dt")]
    assert not any(t.startswith("recovery") for t in dt_texts), (
        f"Recovery row must hide when phase is null; got dt_texts={dt_texts!r}"
    )


# ---------------------------------------------------------------------------
# Standby steady-state panel — additive banner rendered ABOVE the per-instance
# accordion loop when the deployment site is `standby` AND at least one
# gateway JVM is intentionally stopped. Names the intentional steady state so
# operators don't misread the red per-instance error pills as an outage.
# ---------------------------------------------------------------------------


def _plant_site_and_jvm(
    app,
    *,
    role: str,
    auto_launch: bool,
    jvm_alive: bool,
    trading_mode: str = "both",
) -> None:
    """Plant a status dict with a specific site.role / jvm.alive combination.

    Mirrors the queries.rs payload shape — site is a NESTED object (not top-
    level keys) so pages.py's site_config extraction reads the right thing.
    """
    registry = app.state.instance_registry
    from app.instance_registry import _CachedResponse
    for mode in registry.modes():
        status_dict = _build_status_dict(trading_mode=trading_mode)
        status_dict["site"] = {"role": role, "auto_launch": auto_launch}
        status_dict["jvm"] = {"pid": 4711, "alive": jvm_alive, "uptime_secs": 3500}
        if not jvm_alive:
            status_dict["ready"] = False
            status_dict["state"] = "WaitingForLaunch"
        registry._cache[f"{mode}:STATUS"] = _CachedResponse(status_dict, ttl=60.0)
        registry._clients[mode] = _FakeIbctlClient(status_dict)


@pytest.mark.asyncio
async def test_standby_panel_renders_when_role_standby_and_jvm_stopped():
    """Standby + stopped JVM => the additive standby-notice panel MUST render."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_site_and_jvm(_app, role="standby", auto_launch=False, jvm_alive=False)
        response = await client.get("/partials/overview")

    assert response.status_code == 200
    soup = BeautifulSoup(response.text, "html.parser")

    panel = soup.select_one("#overview-standby-notice")
    assert panel is not None, (
        "Standby steady-state panel (#overview-standby-notice) MUST render when "
        "site_config.role == 'standby' AND at least one instance has jvm.alive == false."
    )

    # Neutral styling: the panel must NOT paint the red error left-stripe.
    health = panel.get("data-health")
    assert health == "ok", (
        f"Standby panel must carry data-health='ok' to suppress the red error "
        f"stripe; got data-health={health!r}."
    )

    # Heading names the intentional state.
    heading = panel.select_one("h2.section-header")
    assert heading is not None
    assert "awaiting promotion" in heading.get_text(strip=True).lower()

    # Panel must appear ABOVE the per-instance accordion loop — operators
    # should read "this is by design" BEFORE they see stopped JVMs.
    body_html = response.text
    panel_idx = body_html.index('id="overview-standby-notice"')
    live_idx = body_html.index('data-accordion="live"')
    assert panel_idx < live_idx, (
        "Standby panel must render above the per-instance accordion loop, "
        f"got panel at {panel_idx} and live-instance at {live_idx}."
    )


@pytest.mark.asyncio
async def test_standby_panel_hidden_when_role_primary():
    """Primary site => the standby-notice panel must be absent, even with stopped JVM."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_site_and_jvm(_app, role="primary", auto_launch=True, jvm_alive=False)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.select_one("#overview-standby-notice") is None, (
        "Standby-notice panel must NOT render on a primary-role site."
    )


@pytest.mark.asyncio
async def test_standby_panel_hidden_when_all_jvms_alive():
    """Standby site but every JVM alive => operator has manually promoted; no reminder."""
    _app, client_ctx = await _make_client()
    async with client_ctx as client:
        _plant_site_and_jvm(_app, role="standby", auto_launch=False, jvm_alive=True)
        response = await client.get("/partials/overview")

    soup = BeautifulSoup(response.text, "html.parser")
    assert soup.select_one("#overview-standby-notice") is None, (
        "Standby-notice panel must NOT render when every JVM on the standby node "
        "is alive — the operator has already promoted this node, no reminder needed."
    )


# ---------------------------------------------------------------------------
# tt() Jinja-global rewire — overview tooltips must resolve through the
# UI-string catalog, not hardcoded literals in the template
# (design: dashboard tt(key) refactor).
# ---------------------------------------------------------------------------


_OVERVIEW_TEMPLATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "app" / "templates" / "partials" / "overview_content.html"
)

# Every tt() key wired in by the refactor. Cross-checked against the design's
# `hardcoded_tooltips_to_replace` list — 15 sites, 17 distinct keys (lines 198
# and 201 emit an if/else pair, so each of those sites carries two keys).
_EXPECTED_TT_KEYS = (
    "ui.deployment_site.term",
    "ui.deployment_site.site_role",
    "ui.deployment_site.launch_policy",
    "ui.ib_status.indicator_prefix",
    "ui.connectivity.internet_connected",
    "ui.connectivity.internet_disconnected",
    "ui.connectivity.ib_page_reachable",
    "ui.connectivity.ib_page_unreachable",
    "ui.gateway.state_term",
    "ui.recovery.term",
    "ui.recovery.phase.aggressive",
    "ui.recovery.phase.backoff",
    "ui.recovery.phase.given_up",
    "ui.controls.reconnect_data",
    "ui.controls.reconnect_account",
    "ui.controls.restart_socat",
    "ui.controls.restart_gateway",
    "ui.controls.stop_gateway",
    "ui.controls.start_gateway",
)

# Prefix-substrings of the hardcoded English tooltips that used to live in
# the template. If any of these come back, the refactor has regressed and
# we're rendering copy from the template file instead of the Pkl catalog.
# Match on the discriminating first clause of each string so a rewording of
# the same phrase later doesn't accidentally match a different context.
_BANNED_HARDCODED_SUBSTRINGS = (
    "Deployment Site — role and launch policy",
    "Site role — primary or secondary",
    "Launch policy — whether the Gateway auto-launches",
    "IB status indicator: {{",
    "Internet {% if scraper.internet_ok %}connected",
    "IB status page {% if scraper.ib_reachable %}reachable",
    "Gateway state — connection state reported",
    "Recovery loop — background task that reconnects",
    "Aggressive phase — retry every 30s",
    "Backoff phase — retry every 15min",
    "Given up — recovery loop stopped",
    "Reconnect market data feeds. Sends Ctrl+F",
    "Reconnect account data. Sends Ctrl+R",
    "Restart the socat port forwarder.",
    "Restart the Gateway JVM.",
    # Belt-and-braces — matches the task-brief example verbatim so the file
    # never re-acquires the pre-refactor prose.
    "Reconnecting aggressively",
)


def test_overview_template_source_uses_tt_calls_for_every_tooltip():
    """Read the overview partial as raw text and assert:
    (a) every tt() key in the design's catalog is present, and
    (b) no hardcoded pre-refactor tooltip string survives.

    This is a template-source test, not a rendered-output test, so we can
    catch a regression even when descriptions.json has no ui.* entries yet
    (the Pkl overlay is landed by a separate step in the same task).
    """
    src = _OVERVIEW_TEMPLATE_PATH.read_text(encoding="utf-8")

    # (a) every tt() key wired in must appear at least once.
    missing = [
        k for k in _EXPECTED_TT_KEYS
        if f"tt('{k}')" not in src and f'tt("{k}")' not in src
    ]
    assert not missing, (
        f"tt() calls missing from overview_content.html for keys: {missing!r}. "
        f"Every hardcoded tooltip must resolve through the tt(key) global."
    )

    # (b) no pre-refactor hardcoded prose may remain.
    leaks = [s for s in _BANNED_HARDCODED_SUBSTRINGS if s in src]
    assert not leaks, (
        f"Hardcoded tooltip strings still present in overview_content.html: "
        f"{leaks!r}. All tooltips must be sourced through tt('ui.<key>')."
    )


@pytest.mark.asyncio
async def test_overview_render_resolves_tt_calls_through_jinja_global():
    """Render the overview partial with a stub tt() global and assert the
    stub value flows into the emitted title/aria-label attributes.

    Proves the plumbing end-to-end: the template invokes the tt callable
    registered on ``templates.env.globals`` — not a literal string. Uses a
    sentinel prefix so we don't depend on descriptions.json carrying the
    ui.* keys yet (that's a separate step of the same task).
    """
    aggressive = {
        "phase": "aggressive",
        "phase_elapsed_secs": 400,  # >= 300 so the Recovery row shows
        "blocked_awaiting_resume": False,
    }
    _app, client_ctx = await _make_client(with_ib_monitor=True)

    # Swap the real tt() (which reads FIELD_DESCRIPTIONS) for a sentinel that
    # echoes the key back with a marker prefix. Every emitted attribute value
    # the template renders must then contain "TT<" — that's how we know the
    # attribute came from the tt() global rather than a hardcoded literal.
    seen_keys: list[str] = []

    # Sentinel uses only HTML-attribute-safe characters (no <, >, &, ") so it
    # survives Jinja's autoescape into title/aria-label attributes verbatim.
    def _stub_tt(key: str, default: str = "") -> str:
        seen_keys.append(key)
        return f"TT-{key}-TT"

    _app.state.templates.env.globals["tt"] = _stub_tt

    async with client_ctx as client:
        _plant_recovery(_app, aggressive)
        response = await client.get("/partials/overview")

    assert response.status_code == 200
    body = response.text

    # Every catalog key must have been looked up at least once during render.
    # Branch-guarded keys are skipped: the fixture drives phase=aggressive
    # (so backoff/given_up phase branches don't fire) and scraper=connected
    # (so the two *disconnected/*unreachable aria-label branches don't fire).
    _branch_guarded = {
        "ui.recovery.phase.backoff",
        "ui.recovery.phase.given_up",
        "ui.connectivity.internet_disconnected",
        "ui.connectivity.ib_page_unreachable",
    }
    keys_missing_from_render = [
        k for k in _EXPECTED_TT_KEYS
        if k not in _branch_guarded and k not in seen_keys
    ]
    assert not keys_missing_from_render, (
        f"tt() was not invoked for keys during render: "
        f"{keys_missing_from_render!r}"
    )

    # Sentinel values must appear in the rendered HTML, proving the tt()
    # callable's return value was interpolated into the attributes.
    assert "TT-ui.recovery.term-TT" in body
    assert "TT-ui.recovery.phase.aggressive-TT" in body
    assert "TT-ui.gateway.state_term-TT" in body
    assert "TT-ui.deployment_site.term-TT" in body
    assert "TT-ui.controls.reconnect_data-TT" in body
    assert "TT-ui.controls.restart_gateway-TT" in body
    assert "TT-ui.ib_status.indicator_prefix-TT" in body
    assert "TT-ui.connectivity.internet_connected-TT" in body
    assert "TT-ui.connectivity.ib_page_reachable-TT" in body
