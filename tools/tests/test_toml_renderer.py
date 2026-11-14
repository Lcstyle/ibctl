"""Failing tests — Pkl-canonical descriptions rollout, renderer side.

The renderer at `tools/renderers/toml_renderer.py` must walk every `///` doc
comment in `config/pkl/types.pkl` and emit it verbatim above the matching
field in the generated TOML (and mirror it into descriptions.json — that side
is exercised in `dashboard/tests/test_config_descriptions.py`).

Both tests here operate on the committed `docker/ibctl.toml` artifact because
that is what CI's `configs-drift` step compares against. Once the renderer
patch lands and `docker/ibctl.toml` is regenerated, these tests will pass.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOCKER_TOML = _REPO_ROOT / "docker" / "ibctl.toml"
_TYPES_PKL = _REPO_ROOT / "config" / "pkl" / "types.pkl"

# Put ``tools/`` and ``tools/renderers/`` on sys.path so we can import the
# UI-descriptions walker directly (the renderer package is not installed).
# ``generate_configs.py`` uses this same layout at run-time.
_TOOLS_DIR = _REPO_ROOT / "tools"
for _p in (_TOOLS_DIR, _TOOLS_DIR / "renderers"):
    _sp = str(_p)
    if _sp not in sys.path:
        sys.path.insert(0, _sp)

_SECTION_RE = re.compile(r"^\[([A-Za-z0-9_.]+)\]\s*$")
_KEY_RE = re.compile(r"^([a-z_][a-z0-9_]*)\s*=")


def _leaf_lines_missing_comment() -> list[tuple[int, str]]:
    """Return every leaf `key = value` line in docker/ibctl.toml with no
    preceding `# ...` comment on the line immediately above (blank lines OK
    if a comment sits above the blanks) and no inline `# comment` on the
    same line.
    """
    lines = _DOCKER_TOML.read_text().splitlines()
    missing: list[tuple[int, str]] = []
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or _SECTION_RE.match(stripped):
            continue
        km = _KEY_RE.match(stripped)
        if not km:
            continue
        # Inline `#` comment counts as documentation for this test's purpose.
        # Look for `#` that is NOT inside a string.
        in_str = False
        has_inline_comment = False
        for ch in raw:
            if ch == '"':
                in_str = not in_str
            elif ch == "#" and not in_str:
                has_inline_comment = True
                break
        if has_inline_comment:
            continue
        # Walk backwards past blank lines to find the nearest previous non-blank line.
        prev_idx = idx - 1
        while prev_idx >= 0 and not lines[prev_idx].strip():
            prev_idx -= 1
        if prev_idx < 0:
            missing.append((idx + 1, raw))
            continue
        prev = lines[prev_idx].lstrip()
        if not prev.startswith("#"):
            missing.append((idx + 1, raw))
    return missing


def test_toml_output_has_comment_above_every_field():
    """Every leaf-value line in docker/ibctl.toml must have a preceding `# ...` comment."""
    missing = _leaf_lines_missing_comment()
    assert not missing, (
        "docker/ibctl.toml has leaf-value lines with no preceding `#` comment — "
        "the renderer must emit the Pkl `///` doc comment above every field:\n  "
        + "\n  ".join(f"L{lineno}: {line}" for lineno, line in missing[:20])
    )


# ------------------------------------------------------------------ #
#  Pkl → TOML content parity                                         #
# ------------------------------------------------------------------ #

def _pkl_field_docs() -> dict[str, list[str]]:
    """Extract Pkl `///` doc comments grouped by field name.

    Returns {fieldName: [line1, line2, ...]} where each list is the block of
    `///` lines that immediately precede the field's declaration. Lines are
    stripped of the `/// ` prefix and trimmed. `@env` annotation lines are
    skipped — those are structural, not descriptive.
    """
    lines = _TYPES_PKL.read_text().splitlines()
    docs: dict[str, list[str]] = {}
    buffer: list[str] = []
    field_decl_re = re.compile(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*[A-Z]")
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("///"):
            text = stripped[3:].lstrip()
            if text.startswith("@env"):
                # structural annotation — don't treat as descriptive text
                continue
            buffer.append(text)
            continue
        m = field_decl_re.match(raw)
        if m and buffer:
            docs[m.group(1)] = buffer
            buffer = []
            continue
        # Any other non-blank, non-doc line resets the buffer.
        if stripped and not stripped.startswith("///"):
            buffer = []
    return docs


# A few well-known Pkl doc-comment phrases that MUST appear verbatim in
# the generated TOML once the renderer is patched. Keep this list small
# and highly distinctive so a partial regression is obvious.
_REQUIRED_PHRASES_IN_TOML = [
    # deployment.autoLaunch → [site].auto_launch
    "Auto-launch Gateway on container startup",
    # runtime.ibStatus.kickActiveSession
    "Set to true only to restore the historical behavior",
    # runtime.ibStatus.kickActiveSession — trailing sentence promoted from
    # Rust config.rs during the Pkl-canonical consolidation. Anchor is
    # deliberately short so the substring lands on one comment line
    # (the full sentence soft-wraps in the emitted TOML).
    "Only useful if you trust the",
    # runtime.dashboard.externalUrl — its description must round-trip
    # through Pkl.
    "External URL used to build ntfy action-button callback targets",
    # runtime.timing.recovery.enabled
    "master enable",  # already in TOML; anchoring baseline
    # runtime.timing.recovery.fingerprintStreakForcingHitl
    "same-error streak forcing HITL",  # baseline anchor
]


def test_toml_comments_match_pkl_doc_comments():
    """Distinctive Pkl `///` phrases must appear in the generated docker/ibctl.toml.

    Baseline anchors (e.g. `master enable`) verify our extraction is looking at
    the right file; the newly-consolidated phrases (e.g. the kickActiveSession
    three-paragraph rationale) must also show up after the renderer patch lands.
    """
    toml_text = _DOCKER_TOML.read_text()
    missing: list[str] = []
    for phrase in _REQUIRED_PHRASES_IN_TOML:
        if phrase not in toml_text:
            missing.append(phrase)
    assert not missing, (
        "docker/ibctl.toml is missing Pkl `///` doc-comment phrases — the "
        "renderer must emit them verbatim above the matching field:\n  "
        + "\n  ".join(missing)
    )

    # Also sanity-check the extractor — if it can't find any field docs at
    # all, the test above is toothless and needs debugging.
    docs = _pkl_field_docs()
    assert docs, "extracted zero Pkl field-doc blocks — regex is wrong"
    # And confirm we can find at least a handful of the fields we care about.
    for field in ("autoLaunch", "kickActiveSession", "enabled", "provider"):
        assert field in docs, (
            f"Pkl field `{field}` had no `///` block captured by the extractor "
            "— fix the regex before trusting the phrase assertions above"
        )


# ------------------------------------------------------------------ #
#  ui.* descriptions overlay — from config/pkl/ui_strings.pkl        #
# ------------------------------------------------------------------ #

def test_render_ui_descriptions_emits_ui_keys():
    """``render_ui_descriptions`` overlays ``ui.*`` entries from ``ui_strings.pkl``.

    Exercises the walker in isolation (no Pkl runtime needed) — the
    ``ui_strings.pkl`` module is regex-parsed and every ``String``-typed
    leaf becomes a ``ui.<snake.dotted.path>`` key in the descriptions dict.
    A spot-check on distinctive keys catches structural regressions in the
    walker (missing top-level property, wrong camel→snake conversion,
    missed nested class recursion, dropped backtick-quoted field name).
    """
    from toml_renderer import render_ui_descriptions

    descriptions: dict[str, str] = {}
    render_ui_descriptions(descriptions)

    # Every key emitted by the walker must live under the ui.* namespace.
    non_ui = [k for k in descriptions if not k.startswith("ui.")]
    assert not non_ui, f"walker leaked non-ui.* keys: {non_ui[:5]}"

    # Nested-class recursion + camel→snake conversion (``givenUp`` → ``given_up``).
    assert (
        descriptions.get("ui.recovery.phase.aggressive")
        == "Aggressive phase — retry every 30s to reconnect fast after a fresh outage."
    )
    assert "ui.recovery.phase.given_up" in descriptions

    # Deeper camelCase (deploymentSite → deployment_site, siteRole → site_role,
    # role.primary from the nested SiteRoleStrings class).
    assert "ui.deployment_site.site_role" in descriptions
    assert "ui.deployment_site.role.primary" in descriptions

    # Backtick-quoted Pkl reserved word ``unknown`` in IbStatusEnumStrings —
    # the regex must strip the backticks and still emit the key.
    assert "ui.ib_status.status.unknown" in descriptions

    # ``ib_status`` split (ibStatus module prop → ib_status prefix).
    assert "ui.ib_status.indicator_prefix" in descriptions


def test_docker_toml_has_no_ui_keys():
    """``ui.*`` strings must NEVER surface in ``docker/ibctl.toml``.

    The overlay path in ``generate_configs.py`` writes ``ui.*`` entries into
    ``descriptions.json`` only. Config artifacts (``docker/ibctl.toml``,
    ``ibctl.toml.example``) must stay uncontaminated so operators reading
    the TOML don't confuse UI copy with runtime config.
    """
    toml_text = _DOCKER_TOML.read_text()
    # Distinctive UI-only phrases — none of these ever belong to a config
    # field description, so any match indicates the split has broken.
    leaked = [
        p
        for p in (
            "Aggressive phase — retry every 30s",
            "Reconnect market data feeds",
            "IB status indicator",
            "Live + Paper — dual-instance deployment",
        )
        if p in toml_text
    ]
    assert not leaked, (
        "docker/ibctl.toml contains UI-strings copy — the renderer split has "
        "broken and ui.* entries are leaking into the config artifact:\n  "
        + "\n  ".join(leaked)
    )
