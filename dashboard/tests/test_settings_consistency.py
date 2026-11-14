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
from app.preflight.env_overlay import _STRICT_INT_FIELDS, apply_env_overrides

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


@pytest.mark.parametrize(
    "path,env",
    sorted(
        (p, e)
        for p, e in models.ENV_MAP.items()
        if _field_type(p) is int and p not in _STRICT_INT_FIELDS
    ),
)
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


# --- Gateway session time zones ---

TIME_ZONE_PATHS = {
    "gateway.time_zone": "TIME_ZONE",
    "gateway.time_zone_live": "TIME_ZONE_LIVE",
    "gateway.time_zone_paper": "TIME_ZONE_PAPER",
}


def _shipped_config(**gateway) -> dict:
    config = tomllib.loads(DOCKER_TOML.read_text())
    config["auth"]["tws_userid"] = "someone"
    config["gateway"].update(gateway)
    return config


def test_the_time_zone_settings_ship_empty():
    gateway = tomllib.loads(DOCKER_TOML.read_text())["gateway"]

    assert {leaf: gateway[leaf.removeprefix("gateway.")] for leaf in TIME_ZONE_PATHS} == dict.fromkeys(TIME_ZONE_PATHS, "")


def test_the_time_zone_settings_have_their_env_overrides():
    assert all(models.ENV_MAP[path] == env for path, env in TIME_ZONE_PATHS.items())


def test_preflight_checks_the_same_time_zone_shape_as_pkl():
    pkl = (REPO / "config" / "pkl" / "types.pkl").read_text()
    start = pkl.index("typealias OptionalTimeZone")
    pkl_pattern = pkl[start:].split('Regex(#"', 1)[1].split('"#)', 1)[0]

    assert models._TIME_ZONE_SHAPE.pattern == pkl_pattern


@pytest.mark.parametrize("leaf", sorted(p.removeprefix("gateway.") for p in TIME_ZONE_PATHS))
@pytest.mark.parametrize(
    "name",
    ["", "America/New_York", "Europe/London", "America/Argentina/Buenos_Aires", "Etc/GMT+5", "UTC", "GMT"],
)
def test_a_known_time_zone_name_or_empty_passes_preflight(leaf, name):
    cfg = models.IbctlConfig.model_validate(_shipped_config(**{leaf: name}))

    assert getattr(cfg.gateway, leaf) == name


@pytest.mark.parametrize("leaf", sorted(p.removeprefix("gateway.") for p in TIME_ZONE_PATHS))
@pytest.mark.parametrize(
    "name",
    [
        "Nowhere/Atlantis",  # right shape, no such zone
        "America/Nowhere",
        "EST",  # a real tz database name, but not the Area/Location shape Pkl accepts
        "New_York",
        "America/",
        "/America/New_York",
        "../America/New_York",
        "America/New York",
        "America/New_York ",
        "a/b/c/d",
    ],
)
def test_an_unknown_or_malformed_time_zone_fails_preflight(leaf, name):
    with pytest.raises(Exception) as err:
        models.IbctlConfig.model_validate(_shipped_config(**{leaf: name}))

    assert f"gateway.{leaf}" in str(err.value)


def test_an_unknown_time_zone_message_names_the_env_override():
    with pytest.raises(Exception, match="TIME_ZONE_PAPER"):
        models.IbctlConfig.model_validate(_shipped_config(time_zone_paper="Nowhere/Atlantis"))


@pytest.mark.parametrize("path,env", sorted(TIME_ZONE_PATHS.items()))
def test_a_time_zone_from_env_overrides_the_toml_and_passes_preflight(path, env, monkeypatch):
    for other in models.ENV_MAP.values():
        monkeypatch.delenv(other, raising=False)
    monkeypatch.setenv(env, "Europe/Paris")

    config = apply_env_overrides(_shipped_config())
    cfg = models.IbctlConfig.model_validate(config)

    assert getattr(cfg.gateway, path.removeprefix("gateway.")) == "Europe/Paris"


def test_an_unknown_time_zone_from_env_fails_preflight(monkeypatch):
    monkeypatch.setenv("TIME_ZONE", "Nowhere/Atlantis")

    config = apply_env_overrides(_shipped_config())

    with pytest.raises(Exception, match="gateway.time_zone"):
        models.IbctlConfig.model_validate(config)


# --- Command access ---

ALLOWED_COMMANDS = [
    "STOP", "START", "RESTART", "RECONNECTDATA", "RECONNECTACCOUNT", "ENABLEAPI",
    "EXIT", "RESTARTSOCAT", "PAUSE", "RESUME", "HITL_RESUME", "RESUME_RECONNECT",
    "MAINT_HOLD", "MAINT_RELEASE", "SETSTATE", "IBSTATUS", "SETRESTART",
]


def test_the_allowed_commands_ship_as_every_action_command():
    shipped = tomllib.loads(DOCKER_TOML.read_text())["command_server"]["allowed_commands"]

    assert shipped == ALLOWED_COMMANDS
    assert models.CommandServerConfig().allowed_commands == ALLOWED_COMMANDS


def test_the_allowed_commands_match_what_ibctl_gates():
    rust = (REPO / "ibctl" / "src" / "command_access.rs").read_text()
    body = rust.split("ACTION_COMMANDS", 1)[1].split("];", 1)[0]

    assert [name for name in ALLOWED_COMMANDS if f'"{name}"' in body] == ALLOWED_COMMANDS
    assert body.count('"') == 2 * len(ALLOWED_COMMANDS)


def test_the_allowed_commands_in_pkl_are_the_same_names():
    pkl = (REPO / "config" / "pkl" / "types.pkl").read_text()
    start = pkl.index("typealias CommandName")
    alias = pkl[start:].split("\n\n", 1)[0]

    assert [name for name in ALLOWED_COMMANDS if f'"{name}"' in alias] == ALLOWED_COMMANDS
    assert alias.count('"') == 2 * len(ALLOWED_COMMANDS)


def test_an_allowed_commands_list_from_env_passes_preflight(monkeypatch):
    monkeypatch.setenv("IBCTL_ALLOWED_COMMANDS", "setrestart, reconnectdata ,")
    config = apply_env_overrides(tomllib.loads(DOCKER_TOML.read_text()))
    config["auth"]["tws_userid"] = "someone"

    cfg = models.IbctlConfig.model_validate(config)

    assert cfg.command_server.allowed_commands == ["SETRESTART", "RECONNECTDATA"]


def test_an_unknown_command_in_env_fails_preflight(monkeypatch):
    monkeypatch.setenv("IBCTL_ALLOWED_COMMANDS", "STOP,STPO")
    config = apply_env_overrides(tomllib.loads(DOCKER_TOML.read_text()))
    config["auth"]["tws_userid"] = "someone"

    with pytest.raises(Exception, match="STPO"):
        models.IbctlConfig.model_validate(config)


# --- Dashboard idle logout ---


def test_the_idle_logout_ships_at_five_minutes():
    shipped = tomllib.loads(DOCKER_TOML.read_text())["dashboard"]["session_idle_minutes"]

    assert shipped == 5
    assert models.DashboardConfig().session_idle_minutes == 5


def test_the_idle_logout_tooltip_says_what_zero_and_the_range_mean():
    text = DESCRIPTIONS["dashboard.session_idle_minutes"]

    assert "0 turns the idle logout off" in text
    assert "0..1440" in text
    assert "(env: IBCTL_SESSION_IDLE_MINUTES)" in text


@pytest.mark.parametrize("path", sorted(_STRICT_INT_FIELDS))
def test_a_strict_number_that_is_not_one_reaches_preflight_as_text_not_as_the_toml_value(path, monkeypatch):
    # The dashboard-only setting that decides when a login ends is not silently
    # replaced by a default when its env var is mistyped; preflight refuses it.
    env = models.ENV_MAP[path]
    monkeypatch.setenv(env, "soon")

    got = apply_env_overrides({"dashboard": {"session_idle_minutes": 5}})

    assert got["dashboard"]["session_idle_minutes"] == "soon"


def test_an_idle_minutes_value_from_env_passes_preflight(monkeypatch):
    monkeypatch.setenv("IBCTL_SESSION_IDLE_MINUTES", "0")
    config = apply_env_overrides(tomllib.loads(DOCKER_TOML.read_text()))
    config["auth"]["tws_userid"] = "someone"

    assert models.IbctlConfig.model_validate(config).dashboard.session_idle_minutes == 0


@pytest.mark.parametrize("raw", ["1441", "-1", "abc"])
def test_a_bad_idle_minutes_value_in_env_fails_preflight(raw, monkeypatch):
    monkeypatch.setenv("IBCTL_SESSION_IDLE_MINUTES", raw)
    config = apply_env_overrides(tomllib.loads(DOCKER_TOML.read_text()))
    config["auth"]["tws_userid"] = "someone"

    with pytest.raises(Exception, match="IBCTL_SESSION_IDLE_MINUTES"):
        models.IbctlConfig.model_validate(config)


@pytest.mark.parametrize("compose", sorted((REPO / "examples").glob("docker-compose.*.yml")) + [REPO / "docker-compose.yml"], ids=lambda p: p.name)
def test_every_compose_file_passes_the_idle_minutes_through_empty_so_the_toml_applies(compose):
    # An empty value is "unset" to the overlay; a baked-in 5 would silently beat a TOML edit.
    assert "      IBCTL_SESSION_IDLE_MINUTES: ${IBCTL_SESSION_IDLE_MINUTES:-}\n" in compose.read_text()
