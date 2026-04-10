"""Tests for pre-flight config validation."""

from __future__ import annotations

import pytest

from app.preflight.validator import validate_config


@pytest.fixture
def toml_file(tmp_path):
    """Yields a helper that writes TOML content to a temp file.

    Files are cleaned up automatically by tmp_path — no manual os.unlink.
    """
    def _write(content: str) -> str:
        path = tmp_path / "test.toml"
        path.write_text(content)
        return str(path)
    return _write


def _set_valid_creds(monkeypatch):
    """Set minimum valid credentials for env-checking tests."""
    monkeypatch.setenv("TWS_USERID", "testuser")
    monkeypatch.setenv("TWS_PASSWORD", "testpass")


class TestValidConfig:
    def test_minimal_valid_config(self, toml_file):
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "live"\n'), check_env=False)
        assert result.ok

    def test_empty_config_uses_defaults(self, toml_file):
        result = validate_config(toml_path=toml_file(""), check_env=False)
        assert result.ok

    def test_nonexistent_toml_uses_defaults(self):
        result = validate_config(toml_path="/nonexistent/path.toml", check_env=False)
        assert result.ok


class TestInvalidEnum:
    def test_invalid_trading_mode(self, toml_file):
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "invalid"\n'), check_env=False)
        assert not result.ok
        assert any("trading_mode" in e.field for e in result.errors)

    def test_invalid_gateway_program(self, toml_file):
        result = validate_config(toml_path=toml_file('[gateway]\ngateway_or_tws = "something"\n'), check_env=False)
        assert not result.ok
        assert any("gateway_or_tws" in e.field for e in result.errors)

    def test_invalid_log_level(self, toml_file):
        result = validate_config(toml_path=toml_file('[logging]\nlevel = "verbose"\n'), check_env=False)
        assert not result.ok


class TestPortConflict:
    def test_duplicate_ports_rejected(self, toml_file):
        result = validate_config(
            toml_path=toml_file("[gateway]\nlive_api_port = 4001\npaper_api_port = 4001\n"),
            check_env=False,
        )
        assert not result.ok
        assert any("conflict" in e.message.lower() for e in result.errors)

    def test_unique_ports_accepted(self, toml_file):
        result = validate_config(
            toml_path=toml_file("[gateway]\nlive_api_port = 4001\npaper_api_port = 4002\n"),
            check_env=False,
        )
        assert result.ok


class TestDualModeWarning:
    def test_both_mode_no_paper_warns_toml_only(self, toml_file):
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "both"\n'), check_env=False)
        assert result.ok
        assert any("paper" in w.lower() for w in result.warnings)

    def test_both_mode_with_paper_no_warning(self, toml_file):
        result = validate_config(
            toml_path=toml_file('[auth]\ntrading_mode = "both"\n\n[auth.paper]\ntws_userid = "paperuser"\n'),
            check_env=False,
        )
        assert result.ok
        assert not result.warnings


class TestCredentialValidation:
    def test_missing_userid_with_env_check(self, monkeypatch, toml_file):
        monkeypatch.delenv("TWS_USERID", raising=False)
        monkeypatch.delenv("TWS_USERID_FILE", raising=False)
        monkeypatch.delenv("TWS_PASSWORD", raising=False)
        monkeypatch.delenv("TWS_PASSWORD_FILE", raising=False)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert not result.ok
        assert any("TWS_USERID" in (e.env_var or "") for e in result.errors)

    def test_missing_password_with_env_check(self, monkeypatch, toml_file):
        monkeypatch.setenv("TWS_USERID", "testuser")
        monkeypatch.delenv("TWS_PASSWORD", raising=False)
        monkeypatch.delenv("TWS_PASSWORD_FILE", raising=False)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert not result.ok
        assert any("TWS_PASSWORD" in (e.env_var or "") for e in result.errors)

    def test_valid_credentials_pass(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok

    def test_both_mode_requires_paper_creds(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TRADING_MODE", "both")
        monkeypatch.delenv("TWS_USERID_PAPER", raising=False)
        monkeypatch.delenv("TWS_USERID_PAPER_FILE", raising=False)
        monkeypatch.delenv("TWS_PASSWORD_PAPER", raising=False)
        monkeypatch.delenv("TWS_PASSWORD_PAPER_FILE", raising=False)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert not result.ok
        assert any("TWS_USERID_PAPER" in (e.env_var or "") for e in result.errors)
        assert any("TWS_PASSWORD_PAPER" in (e.env_var or "") for e in result.errors)

    def test_both_mode_with_all_creds_passes(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TRADING_MODE", "both")
        monkeypatch.setenv("TWS_USERID_PAPER", "paperuser")
        monkeypatch.setenv("TWS_PASSWORD_PAPER", "paperpass")
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok

    def test_live_mode_doesnt_need_paper_creds(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TRADING_MODE", "live")
        monkeypatch.delenv("TWS_USERID_PAPER", raising=False)
        monkeypatch.delenv("TWS_PASSWORD_PAPER", raising=False)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok


class TestColdRestartFormat:
    def test_valid_cold_restart(self, toml_file):
        result = validate_config(toml_path=toml_file('[session]\ntws_cold_restart = "09:00"\n'), check_env=False)
        assert result.ok

    def test_empty_cold_restart(self, toml_file):
        result = validate_config(toml_path=toml_file('[session]\ntws_cold_restart = ""\n'), check_env=False)
        assert result.ok

    def test_invalid_cold_restart_format(self, toml_file):
        result = validate_config(toml_path=toml_file('[session]\ntws_cold_restart = "9AM"\n'), check_env=False)
        assert not result.ok


class TestEnvOverride:
    def test_env_overrides_toml(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TRADING_MODE", "paper")
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "live"\n'), check_env=True)
        assert result.ok

    def test_invalid_env_override_caught(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TRADING_MODE", "invalid")
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "live"\n'), check_env=True)
        assert not result.ok
        assert any("TRADING_MODE" in (e.env_var or "") for e in result.errors)

    @pytest.mark.parametrize("value", ["yes", "true", "1"])
    def test_bool_coercion(self, monkeypatch, toml_file, value):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("RELOGIN_AFTER_TWOFA_TIMEOUT", value)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok


class TestFileSecret:
    def test_file_variant_reads_contents(self, monkeypatch, tmp_path, toml_file):
        _set_valid_creds(monkeypatch)
        secret_file = tmp_path / "userid.txt"
        secret_file.write_text("paper_user\n")
        pass_file = tmp_path / "pass.txt"
        pass_file.write_text("paper_pass\n")
        monkeypatch.setenv("TWS_USERID_PAPER_FILE", str(secret_file))
        monkeypatch.setenv("TWS_PASSWORD_PAPER_FILE", str(pass_file))
        monkeypatch.setenv("TRADING_MODE", "both")
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok


class TestDashboardRequiresCommandServer:
    def test_dashboard_without_command_server_fails(self, toml_file):
        result = validate_config(
            toml_path=toml_file('[dashboard]\nenabled = true\n\n[command_server]\nenabled = false\n'),
            check_env=False,
        )
        assert not result.ok
        assert any("command_server" in e.message for e in result.errors)

    def test_dashboard_with_command_server_passes(self, toml_file):
        result = validate_config(
            toml_path=toml_file('[dashboard]\nenabled = true\n\n[command_server]\nenabled = true\n'),
            check_env=False,
        )
        assert result.ok


class TestUnknownSections:
    def test_known_sections_accepted(self, toml_file):
        result = validate_config(
            toml_path=toml_file(
                '[auth]\ntrading_mode = "live"\n\n'
                '[command_server]\nenabled = true\n\n'
                '[dashboard]\nenabled = true\nport = 8080\n\n'
                '[ib_system_status]\nenabled = true\n'
            ),
            check_env=False,
        )
        assert result.ok

    def test_unknown_top_level_section_rejected(self, toml_file):
        result = validate_config(
            toml_path=toml_file('[auth]\ntrading_mode = "live"\n\n[some_future_feature]\nkey = "value"\n'),
            check_env=False,
        )
        assert not result.ok

    def test_unknown_field_in_section_rejected(self, toml_file):
        """Old/unknown field names inside known sections are hard errors."""
        result = validate_config(
            toml_path=toml_file('[auth]\nusername = "myuser"\n'),
            check_env=False,
        )
        assert not result.ok
        assert any("username" in e.field and "not permitted" in e.message for e in result.errors)


class TestInvalidToml:
    def test_malformed_toml_caught(self, toml_file):
        result = validate_config(toml_path=toml_file("this is not valid toml {{{}}"), check_env=False)
        assert not result.ok
        assert any("TOML" in e.message for e in result.errors)
