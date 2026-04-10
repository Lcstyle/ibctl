"""Tests for pre-flight config validation."""

from __future__ import annotations

import os
import tempfile

import pytest

from app.preflight.validator import validate_config


def _write_toml(content: str) -> str:
    """Write TOML content to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False)
    f.write(content)
    f.close()
    return f.name


class TestValidConfig:
    def test_minimal_valid_config(self):
        path = _write_toml("[auth]\ntrading_mode = \"live\"\n")
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        os.unlink(path)

    def test_empty_config_uses_defaults(self):
        path = _write_toml("")
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        os.unlink(path)

    def test_nonexistent_toml_uses_defaults(self):
        result = validate_config(toml_path="/nonexistent/path.toml", check_env=False)
        assert result.ok


class TestInvalidEnum:
    def test_invalid_trading_mode(self):
        path = _write_toml('[auth]\ntrading_mode = "invalid"\n')
        result = validate_config(toml_path=path, check_env=False)
        assert not result.ok
        assert any("trading_mode" in e.field for e in result.errors)
        os.unlink(path)

    def test_invalid_gateway_program(self):
        path = _write_toml('[gateway]\ngateway_or_tws = "something"\n')
        result = validate_config(toml_path=path, check_env=False)
        assert not result.ok
        assert any("gateway_or_tws" in e.field for e in result.errors)
        os.unlink(path)

    def test_invalid_log_level(self):
        path = _write_toml('[logging]\nlevel = "verbose"\n')
        result = validate_config(toml_path=path, check_env=False)
        assert not result.ok
        os.unlink(path)


class TestPortConflict:
    def test_duplicate_ports_rejected(self):
        path = _write_toml(
            "[gateway]\nlive_api_port = 4001\npaper_api_port = 4001\n"
        )
        result = validate_config(toml_path=path, check_env=False)
        assert not result.ok
        assert any("conflict" in e.message.lower() for e in result.errors)
        os.unlink(path)

    def test_unique_ports_accepted(self):
        path = _write_toml(
            "[gateway]\nlive_api_port = 4001\npaper_api_port = 4002\n"
        )
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        os.unlink(path)


class TestDualModeWarning:
    def test_both_mode_no_paper_warns(self):
        path = _write_toml('[auth]\ntrading_mode = "both"\n')
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        assert any("paper" in w.lower() for w in result.warnings)
        os.unlink(path)

    def test_both_mode_with_paper_no_warning(self):
        path = _write_toml(
            '[auth]\ntrading_mode = "both"\n\n'
            '[auth.paper]\ntws_userid = "paperuser"\n'
        )
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        assert not result.warnings
        os.unlink(path)


class TestColdRestartFormat:
    def test_valid_cold_restart(self):
        path = _write_toml('[session]\ntws_cold_restart = "09:00"\n')
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        os.unlink(path)

    def test_empty_cold_restart(self):
        path = _write_toml('[session]\ntws_cold_restart = ""\n')
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        os.unlink(path)

    def test_invalid_cold_restart_format(self):
        path = _write_toml('[session]\ntws_cold_restart = "9AM"\n')
        result = validate_config(toml_path=path, check_env=False)
        assert not result.ok
        os.unlink(path)


class TestEnvOverride:
    def test_env_overrides_toml(self, monkeypatch):
        path = _write_toml('[auth]\ntrading_mode = "live"\n')
        monkeypatch.setenv("TRADING_MODE", "paper")
        result = validate_config(toml_path=path, check_env=True)
        assert result.ok
        os.unlink(path)

    def test_invalid_env_override_caught(self, monkeypatch):
        path = _write_toml('[auth]\ntrading_mode = "live"\n')
        monkeypatch.setenv("TRADING_MODE", "invalid")
        result = validate_config(toml_path=path, check_env=True)
        assert not result.ok
        assert any("TRADING_MODE" in (e.env_var or "") for e in result.errors)
        os.unlink(path)

    def test_bool_coercion_yes(self, monkeypatch):
        path = _write_toml("")
        monkeypatch.setenv("RELOGIN_AFTER_TWOFA_TIMEOUT", "yes")
        result = validate_config(toml_path=path, check_env=True)
        assert result.ok
        os.unlink(path)

    def test_bool_coercion_true(self, monkeypatch):
        path = _write_toml("")
        monkeypatch.setenv("RELOGIN_AFTER_TWOFA_TIMEOUT", "true")
        result = validate_config(toml_path=path, check_env=True)
        assert result.ok
        os.unlink(path)

    def test_bool_coercion_1(self, monkeypatch):
        path = _write_toml("")
        monkeypatch.setenv("RELOGIN_AFTER_TWOFA_TIMEOUT", "1")
        result = validate_config(toml_path=path, check_env=True)
        assert result.ok
        os.unlink(path)


class TestFileSecret:
    def test_file_variant_reads_contents(self, monkeypatch, tmp_path):
        secret_file = tmp_path / "secret.txt"
        secret_file.write_text("paper_user\n")
        monkeypatch.setenv("TWS_USERID_PAPER_FILE", str(secret_file))
        path = _write_toml('[auth]\ntrading_mode = "both"\n')
        result = validate_config(toml_path=path, check_env=True)
        assert result.ok
        assert not any("paper" in w.lower() for w in result.warnings)
        os.unlink(path)


class TestUnknownSections:
    def test_unknown_sections_ignored(self):
        path = _write_toml(
            '[auth]\ntrading_mode = "live"\n\n'
            '[dashboard]\nenabled = true\nport = 8080\n\n'
            '[some_future_feature]\nkey = "value"\n'
        )
        result = validate_config(toml_path=path, check_env=False)
        assert result.ok
        os.unlink(path)


class TestInvalidToml:
    def test_malformed_toml_caught(self):
        path = _write_toml("this is not valid toml {{{}}")
        result = validate_config(toml_path=path, check_env=False)
        assert not result.ok
        assert any("TOML" in e.message for e in result.errors)
        os.unlink(path)
