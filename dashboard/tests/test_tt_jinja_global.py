"""Tests for the ``tt(key)`` Jinja global.

The ``tt`` global is registered by ``app.main.create_app`` on the
``Jinja2Templates.env`` object. It resolves a dotted key against the
module-level ``FIELD_DESCRIPTIONS`` dict loaded at boot from
``dashboard/app/preflight/descriptions.json`` and returns ``""`` on miss so
templates that reference an undefined key render cleanly.

Contract:
    1. ``tt("known_key")`` returns the mapped description string.
    2. ``tt("missing_key")`` returns ``""`` (never raises).
    3. A Jinja template that calls ``{{ tt("known_key") }}`` renders the
       description, and ``{{ tt("missing") }}`` renders as empty string.
    4. The global is actually installed on the FastAPI templates env
       returned by ``create_app`` — i.e. any template loaded by the app can
       call it, not just tests that construct their own env.
"""

from __future__ import annotations

from jinja2 import DictLoader, Environment

from app.api import pages as pages_mod
from app.main import create_app
from tests.auth_helpers import authed_settings


_SAMPLE_DESCRIPTIONS: dict[str, str] = {
    "ui.recovery.phase.aggressive": (
        "Aggressive phase — retry every 30s to reconnect fast after a fresh outage."
    ),
    "ui.recovery.term": (
        "Recovery loop — background task that reconnects the Gateway after outages."
    ),
    "twofa.provider": "oathtool (shells out) or builtin (not yet implemented)",
}


def _make_tt(descriptions: dict[str, str]):
    """Build a tt(key) callable bound to the given descriptions dict.

    Mirrors the closure installed by ``create_app`` so this test asserts
    the same semantics without depending on FastAPI/uvicorn boot.
    """

    def _tt(key: str, default: str = "") -> str:
        return descriptions.get(key, default)

    return _tt


def test_tt_returns_mapped_description_for_known_key():
    tt = _make_tt(_SAMPLE_DESCRIPTIONS)
    result = tt("ui.recovery.phase.aggressive")
    assert result == (
        "Aggressive phase — retry every 30s to reconnect fast after a fresh outage."
    )


def test_tt_returns_empty_string_for_missing_key():
    tt = _make_tt(_SAMPLE_DESCRIPTIONS)
    # Never raise on missing key — degrade to "".
    assert tt("ui.does.not.exist") == ""
    assert tt("") == ""


def test_tt_does_not_raise_on_none_or_weird_input():
    """The helper's default posture is graceful-degradation — dict.get(key, "")
    tolerates any hashable input without raising.
    """
    tt = _make_tt(_SAMPLE_DESCRIPTIONS)
    # dict.get with a bogus key returns default silently — no KeyError.
    assert tt("totally.unknown") == ""


def test_tt_renders_in_jinja_template_for_known_and_missing_keys():
    """End-to-end: register tt on a Jinja env and render a small template."""
    env = Environment(
        loader=DictLoader(
            {
                "t.html": (
                    "known={{ tt('ui.recovery.phase.aggressive') }}|"
                    "missing={{ tt('ui.no.such.key') }}"
                )
            }
        ),
        autoescape=False,
    )
    env.globals["tt"] = _make_tt(_SAMPLE_DESCRIPTIONS)
    rendered = env.get_template("t.html").render()
    assert (
        rendered
        == "known=Aggressive phase — retry every 30s to reconnect fast after a fresh outage.|missing="
    )


def test_tt_is_registered_on_create_app_templates_env(monkeypatch):
    """The tt global must be installed on the FastAPI templates env by create_app.

    Uses monkeypatch to inject a controlled FIELD_DESCRIPTIONS dict so the
    assertion is independent of whether descriptions.json has been
    regenerated in the working tree.
    """
    monkeypatch.setattr(pages_mod, "FIELD_DESCRIPTIONS", dict(_SAMPLE_DESCRIPTIONS))

    app = create_app(settings=authed_settings())

    templates = app.state.templates
    tt = templates.env.globals.get("tt")
    assert callable(tt), "create_app must install a callable `tt` on templates.env.globals"

    # The closure captured the live FIELD_DESCRIPTIONS reference — monkeypatch
    # already swapped it before create_app ran, so lookups resolve against the
    # sample dict.
    assert (
        tt("ui.recovery.phase.aggressive")
        == "Aggressive phase — retry every 30s to reconnect fast after a fresh outage."
    )
    assert tt("ui.no.such.key") == ""
