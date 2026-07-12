"""Failing tests — Pkl-canonical descriptions rollout.

These tests describe the behaviour the renderer patch + dashboard wiring must
deliver:

  1. Pkl `///` doc comments are the single source of truth for field descriptions.
  2. The TOML renderer emits `dashboard/app/preflight/descriptions.json`, a flat
     map of `"<section>.<key>": "<description>"` entries.
  3. The dashboard reads that file at boot in `pages.py::_extract_items` and
     attaches each field's description to its config item.
  4. The config-content template renders those descriptions as hoverable
     tooltips on the key label.

Every test in this module MUST fail until the rollout ships. Do NOT relax the
assertions to make them pass green now — that is the whole point.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

# Repo-relative anchors — resolved once and reused by every test.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DESCRIPTIONS_PATH = _REPO_ROOT / "dashboard" / "app" / "preflight" / "descriptions.json"
_DOCKER_TOML = _REPO_ROOT / "docker" / "ibctl.toml"


def _load_descriptions() -> dict:
    """Load descriptions.json, or raise a clear pytest failure if absent."""
    if not _DESCRIPTIONS_PATH.exists():
        pytest.fail(
            f"expected descriptions.json at {_DESCRIPTIONS_PATH} — "
            "the toml_renderer patch must emit it"
        )
    return json.loads(_DESCRIPTIONS_PATH.read_text())


def _toml_sections_and_keys() -> dict[str, list[str]]:
    """Parse docker/ibctl.toml and return {section: [key, ...]}.

    Deliberately hand-rolled (no tomllib) so we can enumerate every key
    exactly as it appears in the emitted TOML, including keys that live inside
    dotted section headers like `[twofa.backoff]`.
    """
    sections: dict[str, list[str]] = {}
    current: str | None = None
    section_re = re.compile(r"^\[([A-Za-z0-9_.]+)\]\s*$")
    key_re = re.compile(r"^([a-z_][a-z0-9_]*)\s*=")
    for raw in _DOCKER_TOML.read_text().splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        sm = section_re.match(line)
        if sm:
            current = sm.group(1)
            sections.setdefault(current, [])
            continue
        km = key_re.match(line)
        if km and current is not None:
            sections[current].append(km.group(1))
    return sections


# ------------------------------------------------------------------ #
#  1. descriptions.json artifact                                     #
# ------------------------------------------------------------------ #

def test_descriptions_json_file_exists():
    """The renderer must emit dashboard/app/preflight/descriptions.json."""
    assert _DESCRIPTIONS_PATH.exists(), (
        f"{_DESCRIPTIONS_PATH} not found — toml_renderer must write it "
        "alongside docker/ibctl.toml"
    )
    payload = json.loads(_DESCRIPTIONS_PATH.read_text())
    assert isinstance(payload, dict), "descriptions.json must be a JSON object"
    assert payload, "descriptions.json must not be empty"


def test_descriptions_json_covers_every_twofa_field():
    """Every key in [twofa] and [twofa.backoff] must have a non-empty description."""
    descriptions = _load_descriptions()
    sections = _toml_sections_and_keys()
    missing: list[str] = []
    for section in ("twofa", "twofa.backoff"):
        assert section in sections, f"expected section [{section}] in docker/ibctl.toml"
        for key in sections[section]:
            dotted = f"{section}.{key}"
            desc = descriptions.get(dotted)
            if not (isinstance(desc, str) and desc.strip()):
                missing.append(dotted)
    assert not missing, f"descriptions.json missing/empty for: {missing}"


def test_descriptions_json_covers_every_timing_field():
    """Every key in [timing] and [timing.recovery] must have a non-empty description."""
    descriptions = _load_descriptions()
    sections = _toml_sections_and_keys()
    missing: list[str] = []
    for section in ("timing", "timing.recovery"):
        assert section in sections, f"expected section [{section}] in docker/ibctl.toml"
        for key in sections[section]:
            dotted = f"{section}.{key}"
            desc = descriptions.get(dotted)
            if not (isinstance(desc, str) and desc.strip()):
                missing.append(dotted)
    assert not missing, f"descriptions.json missing/empty for: {missing}"


def test_descriptions_json_covers_all_sections():
    """Every top-level TOML section must contribute at least one description key.

    Coarse guard against a whole section being silently dropped from the
    renderer. Per-field coverage is enforced by
    ``test_descriptions_json_covers_every_field``.
    """
    descriptions = _load_descriptions()
    sections = _toml_sections_and_keys()
    uncovered: list[str] = []
    for section, keys in sections.items():
        if not keys:
            # section with no keys (unusual) — nothing to cover
            continue
        prefix = f"{section}."
        if not any(dotted.startswith(prefix) for dotted in descriptions):
            uncovered.append(section)
    assert not uncovered, (
        f"sections with zero description coverage in descriptions.json: {uncovered}"
    )


def test_descriptions_json_covers_every_field():
    """Every key in every emitted TOML section must have a non-empty description.

    This is the strong per-field coverage guard requested by the dashboard-
    integration review. Without it a new field can land in ``types.pkl`` and
    the emitted ``docker/ibctl.toml`` with no ``///`` block — the field
    silently ships without an operator tooltip and the per-section
    ``covers_every_*`` tests above only cover ``twofa`` and ``timing``.
    """
    descriptions = _load_descriptions()
    sections = _toml_sections_and_keys()
    missing: list[str] = []
    for section, keys in sections.items():
        for key in keys:
            dotted = f"{section}.{key}"
            desc = descriptions.get(dotted)
            if not (isinstance(desc, str) and desc.strip()):
                missing.append(dotted)
    assert not missing, (
        "descriptions.json missing/empty for the following fields — every "
        "emitted TOML key must have a Pkl `///` doc block:\n  "
        + "\n  ".join(missing[:40])
    )


def test_descriptions_preserve_env_var_hints():
    """Fields with a Pkl ``@env`` annotation must surface it in the tooltip.

    Before the Pkl-canonical consolidation the operator-facing TOML embedded
    env-var names inline in comments (``# TCP port (env: IBCTL_COMMAND_PORT)``).
    After consolidation ``pkl_docs.py`` captures ``@env`` annotations as
    structured metadata and both the renderer and the tooltip strings surface
    it — the description carries an ``(env: FOO)`` suffix.
    """
    descriptions = _load_descriptions()
    # A representative sample — every one of these MUST carry its env-var
    # hint in the tooltip string. Add to this list when a new @env-annotated
    # field lands and you want it explicitly guarded.
    checks = {
        "logging.level": "IBCTL_LOG_LEVEL",
        "command_server.port": "IBCTL_COMMAND_PORT",
        "gateway.tws_settings_path": "TWS_SETTINGS_PATH",
        "gateway.gateway_or_tws": "GATEWAY_OR_TWS",
        "dashboard.external_url": "IBCTL_DASHBOARD_EXTERNAL_URL",
        "twofa.exit_interval": "TWOFA_EXIT_INTERVAL",
    }
    missing: list[str] = []
    for dotted, env in checks.items():
        desc = descriptions.get(dotted, "")
        if f"(env: {env})" not in desc:
            missing.append(f"{dotted!r} lacks `(env: {env})` — got: {desc!r}")
    assert not missing, (
        "descriptions.json is not surfacing @env var hints for the sampled "
        "fields:\n  " + "\n  ".join(missing)
    )


def test_docker_toml_preserves_env_var_hints():
    """Every ``@env`` annotation in types.pkl must appear as a trailing
    ``# @env: FOO`` comment in the emitted docker/ibctl.toml.

    Operators looking at the generated TOML must still be able to discover
    which env var overrides each field without reading the Pkl source.
    """
    text = _DOCKER_TOML.read_text()
    for env in ("IBCTL_LOG_LEVEL", "TWS_SETTINGS_PATH", "IBCTL_DASHBOARD_EXTERNAL_URL"):
        needle = f"# @env: {env}"
        assert needle in text, (
            f"expected trailing comment `{needle}` in docker/ibctl.toml — "
            "the toml_renderer must promote Pkl `@env` annotations to trailing "
            "comments so operators keep the env-var pointer"
        )


# ------------------------------------------------------------------ #
#  2. pages.py wiring                                                #
# ------------------------------------------------------------------ #

def _call_extract_items(section_name: str, section_data: dict) -> list[dict]:
    """Call _extract_items tolerantly across signature variants.

    The pre-rollout signature is `_extract_items(section_data, secret_keys)`.
    Post-rollout it must be able to attach the description for each key —
    either by taking the section name explicitly or by looking it up via
    a module-level map. This helper accepts either shape.
    """
    from app.api import pages as pages_mod  # deferred so import failures are visible per-test

    fn = pages_mod._extract_items
    import inspect
    sig = inspect.signature(fn)
    params = list(sig.parameters)
    secret_keys = {"password", "secret", "token"}

    # Try: (section_name, section_data, secret_keys)
    try:
        return fn(section_name, section_data, secret_keys)  # type: ignore[misc]
    except TypeError:
        pass
    # Try: (section_data, secret_keys, section_name=...)
    try:
        return fn(section_data, secret_keys, section_name=section_name)  # type: ignore[misc]
    except TypeError:
        pass
    # Legacy: (section_data, secret_keys)
    return fn(section_data, secret_keys)


def test_config_page_items_include_description():
    """_extract_items must attach a `description` field to every item.

    The description comes from descriptions.json — items whose key has an
    entry get the string, others get None (see next test).
    """
    # Use a sample section that we know is covered by descriptions.json.
    section = "twofa"
    sample_data = {
        "provider": "oathtool",
        "device": "",
        "relogin_after_timeout": False,
    }
    items = _call_extract_items(section, sample_data)
    assert items, "_extract_items returned no items"
    for item in items:
        assert "description" in item, (
            f"item {item.get('key')!r} missing 'description' field — "
            "pages.py must attach descriptions from descriptions.json"
        )
    # And at least one description should be populated (non-empty string) —
    # we chose twofa because the consolidation report says all its keys are covered.
    populated = [i for i in items if isinstance(i.get("description"), str) and i["description"]]
    assert populated, (
        "no items had a populated description — pages.py isn't loading "
        "descriptions.json or isn't matching by dotted key"
    )


def test_config_page_missing_description_returns_none_not_crash():
    """A key with no entry in descriptions.json must yield description=None, not crash."""
    section = "twofa"
    sample_data = {
        # Deliberately fabricated key that should NOT exist in descriptions.json.
        "__nonexistent_field_for_test__": "some-value",
    }
    items = _call_extract_items(section, sample_data)
    assert len(items) == 1
    item = items[0]
    assert "description" in item, "missing description key — must be present even when None"
    assert item["description"] is None, (
        f"expected description=None for unknown key, got {item['description']!r}"
    )


# ------------------------------------------------------------------ #
#  3. template tooltip rendering                                     #
# ------------------------------------------------------------------ #

def _render_config_template(sections):
    """Shared render helper for the config-content template tests."""
    try:
        from jinja2 import Environment, FileSystemLoader
    except ImportError:  # pragma: no cover
        pytest.skip("jinja2 not installed")

    template_dir = _REPO_ROOT / "dashboard" / "app" / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)
    tmpl = env.get_template("partials/config_content.html")
    return tmpl.render(sections=sections, error=None)


def _sample_sections():
    return [
        {
            "key": "identity",
            "label": "Identity & Auth",
            "summary": "paper — testuser",
            "default_open": True,
            "subsections": [
                {
                    "label": "2FA",
                    "items": [
                        {
                            "key": "provider",
                            "value": "oathtool",
                            "masked": False,
                            "description": "oathtool (shells out) or builtin (not yet implemented)",
                        },
                        {
                            "key": "no_description_key",
                            "value": "x",
                            "masked": False,
                            "description": None,
                        },
                    ],
                }
            ],
        }
    ]


def test_config_template_renders_tooltip_span_when_description_present():
    """partials/config_content.html must emit a hoverable span for keys with descriptions.

    Contract: when an item carries a non-empty `description`, the template
    renders the key label with (a) a `title="<description>"` attribute — the
    native browser tooltip — and (b) a dotted underline (from a CSS class or
    inline style) so the affordance is visible. Keys with no description
    render without either.
    """
    html = _render_config_template(_sample_sections())

    # (a) title attribute carrying the description
    assert 'title="oathtool (shells out) or builtin' in html or (
        'title="oathtool' in html and "shells out" in html
    ), "template must emit title=<description> for keys with descriptions"

    # (b) visible tooltip affordance — dotted underline (via CSS class or inline).
    assert (
        "border-bottom: 1px dotted" in html
        or "text-decoration: underline dotted" in html
        or "text-decoration-style: dotted" in html
        or "cfg-key-tip" in html
    ), "template must render a dotted-underline affordance on tooltipped keys"

    # Keys without a description must NOT carry a leaking `title="None"`.
    assert 'title="None"' not in html, (
        "template rendered title=\"None\" for a description-less key — "
        "guard the title attribute on truthy description only"
    )


def test_config_template_tooltip_is_keyboard_and_screen_reader_accessible():
    """Description-carrying keys must be reachable by keyboard AND surface
    the description to assistive technology.

    Contract, from the dashboard-integration accessibility review:
      1. Focusable — the tooltipped span carries ``tabindex="0"`` so keyboard
         users can Tab to it.
      2. Announced — the span carries an ``aria-label`` (or
         ``aria-describedby``) that reproduces the description; the native
         ``title`` attribute is not reliably announced by screen readers.
      3. Visually reinforced — a glyph (ⓘ) is present next to the key so
         sighted users don't rely on the low-contrast dotted underline alone
         to notice that a tooltip is available. The glyph is
         ``aria-hidden="true"`` so it doesn't double-announce.
      4. Non-tooltip keys DO NOT gain any of these attributes.
    """
    html = _render_config_template(_sample_sections())

    # (1) focusable
    assert 'tabindex="0"' in html, "tooltipped key must be keyboard-focusable"

    # (2) announced via aria-label (belt) and title (suspenders)
    assert "aria-label=" in html, (
        "tooltipped key must expose the description via aria-label — native "
        "`title` is unreliable across screen readers"
    )
    assert "provider — oathtool" in html, (
        "aria-label must include the key name and the description text"
    )

    # (3) visible glyph, hidden from AT
    assert "&#9432;" in html or "ⓘ" in html, (
        "tooltipped key must display a visible info glyph (ⓘ) to reinforce "
        "the dotted underline for sighted users"
    )
    assert 'aria-hidden="true"' in html, (
        "info glyph must be marked aria-hidden to prevent double-announcing"
    )

    # (4) no leaking accessibility attrs on description-less keys.
    # Confirm the description-less key rendered as a plain cfg-key span.
    assert "no_description_key" in html
    # The description-less span must not carry the tip class or tabindex.
    plain_marker = '<span class="cfg-key">no_description_key</span>'
    assert plain_marker in html, (
        "keys without a description must render as plain cfg-key spans — "
        f"expected {plain_marker!r} in the rendered HTML"
    )
