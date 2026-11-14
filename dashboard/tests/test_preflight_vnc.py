"""Pre-flight: a VNC port reachable from the network needs a VNC password.

Compose publishes the VNC port on IBCTL_VNC_BIND (loopback unless the operator
opts in). Bound to anything else, with no VNC password, anyone who can reach the
port gets the Gateway's desktop, so the container refuses to start.
"""

from __future__ import annotations

import pytest

from app.preflight.validator import _check_vnc_exposure, validate_config

PASSWORD_VARS = ("VNC_SERVER_PASSWORD", "VNC_SERVER_PASSWORD_FILE")


@pytest.fixture(autouse=True)
def clean_vnc_env(monkeypatch):
    monkeypatch.delenv("IBCTL_VNC_BIND", raising=False)
    for var in PASSWORD_VARS:
        monkeypatch.delenv(var, raising=False)


def test_loopback_and_unset_need_no_password(monkeypatch):
    for bind in (None, "", "   ", "127.0.0.1", "127.0.1.1", "::1", "[::1]", "localhost", " LOCALHOST "):
        if bind is None:
            monkeypatch.delenv("IBCTL_VNC_BIND", raising=False)
        else:
            monkeypatch.setenv("IBCTL_VNC_BIND", bind)
        assert _check_vnc_exposure() == [], bind


@pytest.mark.parametrize("bind", ["0.0.0.0", "198.51.100.20", "192.0.2.5", "::", "[::]", "vnc.example.net"])
def test_a_network_bind_without_a_password_is_an_error(monkeypatch, bind):
    monkeypatch.setenv("IBCTL_VNC_BIND", bind)

    errors = _check_vnc_exposure()

    assert len(errors) == 1
    error = errors[0]
    assert error.env_var == "IBCTL_VNC_BIND"
    assert "VNC_SERVER_PASSWORD" in error.message
    assert bind in error.message
    assert "127.0.0.1" in error.message, "the message says how to fix it"


@pytest.mark.parametrize("password", ["", "   "])
def test_a_blank_password_counts_as_none(monkeypatch, password):
    monkeypatch.setenv("IBCTL_VNC_BIND", "0.0.0.0")
    monkeypatch.setenv("VNC_SERVER_PASSWORD", password)

    assert len(_check_vnc_exposure()) == 1


def test_a_network_bind_with_a_password_is_fine(monkeypatch):
    monkeypatch.setenv("IBCTL_VNC_BIND", "0.0.0.0")
    monkeypatch.setenv("VNC_SERVER_PASSWORD", "hunter2")  # nosecret: test value

    assert _check_vnc_exposure() == []


def test_a_password_from_a_secrets_file_counts(monkeypatch, tmp_path):
    secret = tmp_path / "vnc"
    secret.write_text("from-a-file\n")  # nosecret: test value
    monkeypatch.setenv("IBCTL_VNC_BIND", "198.51.100.20")
    monkeypatch.setenv("VNC_SERVER_PASSWORD_FILE", str(secret))

    assert _check_vnc_exposure() == []


def test_an_empty_secrets_file_is_no_password(monkeypatch, tmp_path):
    secret = tmp_path / "vnc"
    secret.write_text("\n")
    monkeypatch.setenv("IBCTL_VNC_BIND", "198.51.100.20")
    monkeypatch.setenv("VNC_SERVER_PASSWORD_FILE", str(secret))

    assert len(_check_vnc_exposure()) == 1


def test_the_container_refuses_to_start_through_validate_config(monkeypatch, tmp_path):
    monkeypatch.setenv("TWS_USERID", "testuser")
    monkeypatch.setenv("TWS_PASSWORD", "testpass")  # nosecret: test value
    monkeypatch.setenv("TWOFACTOR_CODE", "JBSWY3DPEHPK3PXP")  # nosecret: test value
    missing_file = str(tmp_path / "absent.toml")

    ok = validate_config(toml_path=missing_file, check_env=True)
    assert ok.ok, ok.errors

    monkeypatch.setenv("IBCTL_VNC_BIND", "0.0.0.0")
    refused = validate_config(toml_path=missing_file, check_env=True)
    assert not refused.ok
    assert [e.env_var for e in refused.errors] == ["IBCTL_VNC_BIND"]

    monkeypatch.setenv("VNC_SERVER_PASSWORD", "hunter2")  # nosecret: test value
    assert validate_config(toml_path=missing_file, check_env=True).ok


def test_tooling_that_skips_env_does_not_trip_the_check(monkeypatch, tmp_path):
    monkeypatch.setenv("IBCTL_VNC_BIND", "0.0.0.0")
    monkeypatch.setenv("TWS_USERID", "testuser")

    result = validate_config(toml_path=str(tmp_path / "absent.toml"), check_env=False)

    assert not any(e.env_var == "IBCTL_VNC_BIND" for e in result.errors)
