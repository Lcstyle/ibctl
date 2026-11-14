"""Every setting agrees across its layers.

A setting lives in several places: the Pkl schema (and the TOML and tooltips
rendered from it), the preflight model, ENV_MAP (its env override), the env
overlay (how that override's text becomes a value), docs/env-vars.md and the
Config page. These tests walk all of them generically, so a new setting that
misses a layer fails here rather than in production.
"""

from __future__ import annotations

import json
import tomllib
import typing
from pathlib import Path

import pytest

from app.api import pages
from app.preflight import models
from app.preflight.env_overlay import apply_env_overrides

REPO = Path(__file__).resolve().parents[2]
DOCKER_TOML = REPO / "docker" / "ibctl.toml"
DESCRIPTIONS = json.loads((REPO / "dashboard" / "app" / "preflight" / "descriptions.json").read_text())
ENV_DOC = (REPO / "docs" / "env-vars.md").read_text()


def _leaf_keys(d: dict, prefix: str = "") -> list[str]:
    out = []
    for k, v in d.items():
        path = f"{prefix}.{k}" if prefix else k
        out.extend(_leaf_keys(v, path) if isinstance(v, dict) else [path])
    return out


def _field_type(path: str):
    cls = models.IbctlConfig
    *sections, leaf = path.split(".")
    for name in sections:
        ann = cls.model_fields[name].annotation
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        cls = args[0] if args else ann
    return cls.model_fields[leaf].annotation


@pytest.mark.parametrize("path,env", sorted(models.ENV_MAP.items()))
def test_every_env_override_is_named_in_its_tooltip(path, env):
    # The tooltip text comes from the Pkl `///` block; `@env NAME` adds "(env: NAME)".
    assert f"(env: {env})" in DESCRIPTIONS.get(path, ""), f"types.pkl: add `/// @env {env}` to {path}"


@pytest.mark.parametrize("env", sorted(set(models.ENV_MAP.values())))
def test_every_env_override_is_documented(env):
    assert f"`{env}`" in ENV_DOC, f"docs/env-vars.md has no row for {env}"


# Overrides the image sets itself: install paths, the Gateway build, the agent socket.
IMAGE_INTERNAL = {"TWS_PATH", "TWS_SETTINGS_PATH", "TWS_MAJOR_VRSN", "GATEWAY_OR_TWS", "IBCTL_AGENT_SOCKET"}


@pytest.mark.parametrize("env", sorted(set(models.ENV_MAP.values()) - IMAGE_INTERNAL))
def test_every_env_override_reaches_the_container(env):
    # docker-compose.yml lists each override; one it doesn't list never reaches ibctl.
    compose = (REPO / "docker-compose.yml").read_text()
    assert f"      {env}: " in compose, f"docker-compose.yml: add `{env}: ${{{env}:-}}`"


@pytest.mark.parametrize("path,env", sorted(models.ENV_MAP.items()))
def test_every_env_override_becomes_the_type_preflight_expects(path, env, monkeypatch):
    t = _field_type(path)
    sample, expected = {
        bool: ("true", True),
        int: ("7", 7),
        list[int]: ("30, 60", [30, 60]),
    }.get(t, (None, None))
    if sample is None:
        pytest.skip(f"{path} is a {t}; text is used as is")
    for other in models.ENV_MAP.values():
        monkeypatch.delenv(other, raising=False)
    monkeypatch.setenv(env, sample)

    got = apply_env_overrides({})
    for part in path.split("."):
        got = got[part]

    assert got == expected and type(got) is type(expected)


@pytest.mark.parametrize("path,env", sorted((p, e) for p, e in models.ENV_MAP.items() if _field_type(p) is int))
def test_a_bad_number_in_env_keeps_the_toml_value_like_ibctl_does(path, env, monkeypatch):
    # Rust parses the override and ignores it when it isn't a non-negative number.
    monkeypatch.setenv(env, "soon")
    config = {}
    node = config
    *sections, leaf = path.split(".")
    for name in sections:
        node = node.setdefault(name, {})
    node[leaf] = 5

    got = apply_env_overrides(config)
    for part in path.split("."):
        got = got[part]

    assert got == 5


def test_an_intervals_list_from_env_passes_preflight(monkeypatch):
    monkeypatch.setenv("IBCTL_TWOFA_INTERVALS_MINUTES", "30,60")
    config = apply_env_overrides(tomllib.loads(DOCKER_TOML.read_text()))
    config["auth"]["tws_userid"] = "someone"

    cfg = models.IbctlConfig.model_validate(config)

    assert cfg.twofa.backoff.intervals_minutes == [30, 60]


def test_every_shipped_setting_is_on_the_config_page_with_a_tooltip():
    groups = pages._build_config_groups(tomllib.loads(DOCKER_TOML.read_text()))
    shown = {(sub["label"], item["key"]): item["description"] for g in groups for sub in g["subsections"] for item in sub["items"]}
    labels = {sub["label"] for g in groups for sub in g["subsections"]}

    missing, untipped = [], []
    for key in _leaf_keys(tomllib.loads(DOCKER_TOML.read_text())):
        section, rest = key.split(".", 1)
        label = next((lbl for sk, lbl in pages.SECTION_LABELS.items() if sk == section), section)
        if (label, rest) not in shown:
            missing.append(key)
        elif not shown[(label, rest)]:
            untipped.append(key)

    assert labels and not missing, f"not on the Config page: {missing}"
    assert not untipped, f"on the Config page without a tooltip: {untipped}"
