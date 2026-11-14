"""Tests for pre-flight config validation."""

from __future__ import annotations

import pytest

from app.preflight.validator import validate_config


import re


@pytest.fixture
def toml_file(tmp_path):
    """Yields a helper that writes TOML content to a temp file.

    Post-migration ergonomic: injects a valid top-level `tws_userid` into
    the [auth] section unless the content already defines one there. This
    preserves the pre-migration "minimal TOML is valid" ergonomic while
    letting the migration tests (which set `tws_userid = ""` explicitly)
    still exercise the invariant.

    Files are cleaned up automatically by tmp_path — no manual os.unlink.
    """
    def _write(content: str) -> str:
        auth_match = re.search(r"^\[auth\]\s*$", content, re.MULTILINE)
        if auth_match:
            # Extract just the [auth] section body — up to the next `[…]` header.
            start = auth_match.end()
            next_hdr = re.search(r"^\[", content[start:], re.MULTILINE)
            end = start + next_hdr.start() if next_hdr else len(content)
            auth_body = content[start:end]
            if "tws_userid" not in auth_body:
                content = content[:start] + '\ntws_userid = "test_user"' + content[start:]
        elif "tws_userid" not in content:
            content = '[auth]\ntws_userid = "test_user"\n\n' + content
        path = tmp_path / "test.toml"
        path.write_text(content)
        return str(path)
    return _write


def _set_valid_creds(monkeypatch):
    """Set minimum valid credentials for env-checking tests.

    Includes the TOTP secret env var (TWOFACTOR_CODE), which
    validator.py::_check_credentials now requires by default — the
    twofa.secret_env presence check catches env-name rename foot-guns.
    """
    monkeypatch.setenv("TWS_USERID", "testuser")
    monkeypatch.setenv("TWS_PASSWORD", "testpass")
    monkeypatch.setenv("TWOFACTOR_CODE", "JBSWY3DPEHPK3PXP")


class TestValidConfig:
    def test_minimal_valid_config(self, toml_file):
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "live"\n'), check_env=False)
        assert result.ok

    def test_empty_config_uses_defaults(self, toml_file):
        result = validate_config(toml_path=toml_file(""), check_env=False)
        assert result.ok

    def test_nonexistent_toml_defaults_fail_userid_invariant(self):
        # Post-migration: nonexistent TOML falls back to defaults where
        # auth.tws_userid is empty, and the @model_validator on IbctlConfig
        # now raises. This test locks in the new invariant so we don't
        # silently regress to accepting default-empty userid.
        result = validate_config(toml_path="/nonexistent/path.toml", check_env=False)
        assert not result.ok
        assert any(
            "tws_userid" in e.message.lower() or "TWS_USERID" in e.message
            for e in result.errors
        )


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
    def test_both_mode_no_paper_raises_post_migration(self, toml_file):
        # Post-migration: trading_mode=both without a paper.tws_userid
        # is now a hard error (not a soft warning) at the model layer.
        # This test locks in that raise.
        result = validate_config(toml_path=toml_file('[auth]\ntrading_mode = "both"\n'), check_env=False)
        assert not result.ok
        assert any("TWS_USERID_PAPER" in e.message for e in result.errors)

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
        # Explicit empty userid in TOML — bypasses the fixture's auto-inject
        # so the @model_validator on IbctlConfig actually sees an empty value.
        result = validate_config(
            toml_path=toml_file('[auth]\ntws_userid = ""\n'),
            check_env=True,
        )
        assert not result.ok
        # tws_userid presence lives in a @model_validator on IbctlConfig — its
        # ValueError may surface with env_var=None but the message names TWS_USERID.
        assert any(
            "TWS_USERID" in (e.env_var or "") or "TWS_USERID" in e.message
            for e in result.errors
        )

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
        # The paper-userid ValueError from the IbctlConfig model_validator
        # fires early and short-circuits the model — it lands in `message`,
        # not `env_var`. Paper-password enforcement remains in validator.py.
        assert any(
            "TWS_USERID_PAPER" in (e.env_var or "") or "TWS_USERID_PAPER" in e.message
            for e in result.errors
        )

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


class TestPklCanonicalDescriptions:
    """Pkl `///` doc comments are the single source of truth for descriptions.

    Historically some descriptions rode along on Pydantic `Field(description=...)`
    strings. After the consolidation those strings move to Pkl and the
    renderer emits `dashboard/app/preflight/descriptions.json`. This test is
    intentionally *lenient*: it does NOT forbid Pydantic descriptions (removing
    them is a nice-to-have, not a contract); it only requires that the
    canonical artifact exists on disk so the dashboard can read it.
    """

    def test_pydantic_field_descriptions_dropped(self):
        """The descriptions.json artifact — the new source of truth — must exist."""
        from pathlib import Path
        repo_root = Path(__file__).resolve().parents[2]
        descriptions_path = repo_root / "dashboard" / "app" / "preflight" / "descriptions.json"
        assert descriptions_path.exists(), (
            f"expected {descriptions_path} — the toml_renderer must emit it "
            "so pages.py can read descriptions at boot"
        )


class TestTradingModeUserIdMigration:
    """The trading_mode → tws_userid invariant must fire even under check_env=False.

    Historically the check lived in validator.py::_check_credentials, which is
    gated behind check_env=True. --no-env callers (tests, tooling) bypassed it.
    Migration moves the check to a @model_validator on IbctlConfig so it runs
    regardless of the check_env flag. Password presence stays validator.py's
    concern (env-only secret).
    """

    def test_trading_mode_live_no_userid_fails_under_no_env(self, monkeypatch, toml_file):
        monkeypatch.delenv("TWS_USERID", raising=False)
        monkeypatch.delenv("TWS_USERID_FILE", raising=False)
        result = validate_config(
            toml_path=toml_file('[auth]\ntrading_mode = "live"\ntws_userid = ""\n'),
            check_env=False,
        )
        assert not result.ok
        # Expect a message pointing at tws_userid / TWS_USERID env var
        assert any(
            "tws_userid" in e.message.lower() or "TWS_USERID" in e.message
            for e in result.errors
        )

    def test_trading_mode_both_no_paper_userid_fails_under_no_env(self, monkeypatch, toml_file):
        monkeypatch.delenv("TWS_USERID_PAPER", raising=False)
        monkeypatch.delenv("TWS_USERID_PAPER_FILE", raising=False)
        result = validate_config(
            toml_path=toml_file(
                '[auth]\ntrading_mode = "both"\ntws_userid = "primary_user"\n\n'
                '[auth.paper]\ntws_userid = ""\n'
            ),
            check_env=False,
        )
        assert not result.ok
        # Expect an error mentioning the paper-side env var TWS_USERID_PAPER
        assert any("TWS_USERID_PAPER" in e.message for e in result.errors)


class TestTotpSecretEnvPresence:
    """validator.py hoists TOTP secret env presence into _check_credentials
    to catch env-name rename foot-guns (`twofa.secret_env='TOTP_V2'` but the
    operator forgot to export TOTP_V2)."""

    def test_twofa_secret_env_unset_fails(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        # Ensure the default TOTP secret env var name is not populated.
        monkeypatch.delenv("TWOFACTOR_CODE", raising=False)
        monkeypatch.delenv("TWOFACTOR_CODE_FILE", raising=False)
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert not result.ok
        assert any(
            (e.env_var == "TWOFACTOR_CODE") or ("TWOFACTOR_CODE" in e.message)
            for e in result.errors
        )

    def test_twofa_secret_env_custom_var_check(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        # TOML picks a custom env var name.
        monkeypatch.delenv("TWOFACTOR_CODE", raising=False)
        monkeypatch.delenv("TOTP_V2", raising=False)
        monkeypatch.delenv("TOTP_V2_FILE", raising=False)
        result = validate_config(
            toml_path=toml_file('[twofa]\nsecret_env = "TOTP_V2"\n'),
            check_env=True,
        )
        assert not result.ok
        # The error must name the custom var, not the default.
        assert any("TOTP_V2" in e.message for e in result.errors)
        assert not any(
            e.env_var == "TWOFACTOR_CODE" or "TWOFACTOR_CODE" in e.message
            for e in result.errors
        )


class TestNtfyCallbackEnvChecks:
    """_check_ntfy_callback_env escalates the ntfy_callback strategy's env-only
    wiring (signing key + external URL) from warnings to hard errors — the
    strategy is architecturally broken without either piece, so booting is
    a foot-gun with no transitional-deploy justification."""

    _COMMON_TOML: str = (
        '[command_server]\nenabled = true\n\n'
        '[dashboard]\nenabled = true\nnotifications_enabled = true\n'
        'notification_channel = "ntfy"\nexternal_url = "https://ibctl.example.com"\n\n'
        '[twofa.backoff]\nstrategy = "ntfy_callback"\nintervals_minutes = [60]\n'
    )

    def test_ntfy_callback_missing_signing_key_hard_error(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TWOFACTOR_CODE", "JBSWY3DPEHPK3PXP")
        monkeypatch.delenv("IBCTL_NTFY_ACTION_SIGNING_KEY", raising=False)
        monkeypatch.delenv("IBCTL_NTFY_ACTION_SIGNING_KEY_FILE", raising=False)
        result = validate_config(
            toml_path=toml_file(self._COMMON_TOML),
            check_env=True,
        )
        assert not result.ok
        assert any(e.field == "twofa.backoff.strategy" for e in result.errors)

    def test_ntfy_callback_missing_external_url_hard_error(self, monkeypatch, toml_file):
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("TWOFACTOR_CODE", "JBSWY3DPEHPK3PXP")
        monkeypatch.setenv("IBCTL_NTFY_ACTION_SIGNING_KEY", "0" * 32)
        monkeypatch.delenv("IBCTL_DASHBOARD_EXTERNAL_URL", raising=False)
        toml = (
            '[command_server]\nenabled = true\n\n'
            '[dashboard]\nenabled = true\nnotifications_enabled = true\n'
            'notification_channel = "ntfy"\nexternal_url = ""\n\n'
            '[twofa.backoff]\nstrategy = "ntfy_callback"\nintervals_minutes = [60]\n'
        )
        result = validate_config(toml_path=toml_file(toml), check_env=True)
        assert not result.ok
        assert any(e.field == "dashboard.external_url" for e in result.errors)

    def test_ntfy_callback_env_checks_skipped_under_no_env(self, monkeypatch, toml_file):
        # Both env pieces missing; but no env-mode → no env-only enforcement.
        monkeypatch.delenv("IBCTL_NTFY_ACTION_SIGNING_KEY", raising=False)
        monkeypatch.delenv("IBCTL_DASHBOARD_EXTERNAL_URL", raising=False)
        result = validate_config(
            toml_path=toml_file(self._COMMON_TOML),
            check_env=False,
        )
        assert result.ok


# ---------------------------------------------------------------------------
# Schema-layer coverage — pydantic_package field_validator / model_validator.
# Each test locks in one constraint the schema layer enforces.
# ---------------------------------------------------------------------------


class TestSiteConfigSplitBrain:
    """site.role='standby' + auto_launch=true (HA split-brain).

    Two nodes race the IB session on boot. Escape hatch
    IBCTL_STANDBY_AUTO_LAUNCH_OK=1 for niche hot-standby setups.
    """

    def test_site_config_standby_auto_launch_split_brain(self, monkeypatch, toml_file):
        monkeypatch.delenv("IBCTL_STANDBY_AUTO_LAUNCH_OK", raising=False)
        toml = '[site]\nrole = "standby"\nauto_launch = true\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("split-brain" in e.message.lower() for e in result.errors), (
            f"expected 'split-brain' in error message; got: {result.errors}"
        )

    def test_site_config_standby_auto_launch_escape_hatch(self, monkeypatch, toml_file):
        monkeypatch.setenv("IBCTL_STANDBY_AUTO_LAUNCH_OK", "1")
        toml = '[site]\nrole = "standby"\nauto_launch = true\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert result.ok, f"expected escape hatch to allow standby+auto_launch; got: {result.errors}"


class TestTwoFaCrossField:
    """TwoFaConfig cross-field invariants."""

    def test_twofa_relogin_after_timeout_conflicts_with_exit(self, toml_file):
        toml = '[twofa]\ntimeout_action = "exit"\nrelogin_after_timeout = true\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("incompatible" in e.message.lower() for e in result.errors), (
            f"expected 'incompatible' in error message; got: {result.errors}"
        )


class TestIbStatusKickActiveSession:
    """ib_status.kick_active_session is not accepted with zero context checks."""

    _COMMON_TOML_LIVE: str = (
        '[auth]\ntrading_mode = "live"\ntws_userid = "u"\n\n'
        '[ib_status]\nkick_active_session = true\n'
    )
    _COMMON_TOML_PAPER: str = (
        '[auth]\ntrading_mode = "paper"\ntws_userid = "u"\n\n'
        '[ib_status]\nkick_active_session = true\n'
    )

    def test_ib_status_kick_active_session_blocked_in_live(self, monkeypatch, toml_file):
        monkeypatch.delenv("IBCTL_KICK_LIVE_SESSION_OK", raising=False)
        result = validate_config(toml_path=toml_file(self._COMMON_TOML_LIVE), check_env=False)
        assert not result.ok
        assert any("foot-gun" in e.message.lower() or "kick_active_session" in e.message
                   for e in result.errors), (
            f"expected foot-gun/kick error; got: {result.errors}"
        )

    def test_ib_status_kick_active_session_escape_hatch(self, monkeypatch, toml_file):
        monkeypatch.setenv("IBCTL_KICK_LIVE_SESSION_OK", "1")
        result = validate_config(toml_path=toml_file(self._COMMON_TOML_LIVE), check_env=False)
        assert result.ok, f"escape hatch should let live+kick pass; got: {result.errors}"

    def test_ib_status_kick_active_session_paper_mode_warns(self, monkeypatch, toml_file):
        monkeypatch.delenv("IBCTL_KICK_LIVE_SESSION_OK", raising=False)
        result = validate_config(toml_path=toml_file(self._COMMON_TOML_PAPER), check_env=False)
        assert result.ok, f"paper+kick should pass; got: {result.errors}"
        assert any("kick_active_session" in w for w in result.warnings), (
            f"expected kick_active_session warning in paper mode; got warnings: {result.warnings}"
        )


class TestDashboardTokenEnvOnly:
    """dashboard.token security invariant — env-only."""

    def test_dashboard_token_non_empty_rejected(self, toml_file):
        toml = '[dashboard]\ntoken = "real-secret"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("IBCTL_DASHBOARD_TOKEN" in e.message for e in result.errors), (
            f"expected IBCTL_DASHBOARD_TOKEN mention; got: {result.errors}"
        )


class TestAuthUseridPattern:
    """AuthConfig.tws_userid regex."""

    @pytest.mark.parametrize("bad", ["foo bar", "foo;rm"])
    def test_auth_tws_userid_pattern_rejects_bad(self, toml_file, bad):
        toml = f'[auth]\ntws_userid = "{bad}"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok, f"expected {bad!r} to be rejected"

    @pytest.mark.parametrize("good", ["user_123", ""])
    def test_auth_tws_userid_pattern_accepts_good(self, toml_file, good):
        toml = f'[auth]\ntws_userid = "{good}"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        # Empty is allowed at the pattern layer; the trading-mode → userid
        # invariant is a separate check (owned by validator_package).
        # Filter out only the pattern error surface.
        pattern_errs = [e for e in result.errors if "auth.tws_userid" in e.field
                        and "pattern" in e.message.lower()]
        assert not pattern_errs, (
            f"expected {good!r} to pass the pattern check; got: {result.errors}"
        )


class TestTwoFaSecretEnvPattern:
    """secret_env regex."""

    @pytest.mark.parametrize("bad", ["twofactor_code", "1TOTP"])
    def test_twofa_secret_env_pattern_rejects_bad(self, toml_file, bad):
        toml = f'[twofa]\nsecret_env = "{bad}"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok, f"expected {bad!r} to be rejected"

    def test_twofa_secret_env_pattern_accepts_valid(self, toml_file):
        toml = '[twofa]\nsecret_env = "TOTP_V2"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        pattern_errs = [e for e in result.errors if "twofa.secret_env" in e.field
                        and "pattern" in e.message.lower()]
        assert not pattern_errs


class TestDashboardOidcIssuerUrl:
    """Field validators for URLs."""

    def test_dashboard_oidc_issuer_must_be_url(self, toml_file):
        toml = '[dashboard]\noidc_issuer = "not-a-url"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok

    def test_dashboard_oidc_issuer_valid_url_accepted(self, toml_file):
        toml = (
            '[command_server]\nenabled = true\n\n'
            '[dashboard]\nenabled = true\noidc_enabled = true\n'
            'oidc_issuer = "https://auth.example.com/"\n'
        )
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        # Field-level oidc_issuer validator should not fail.
        issuer_errs = [e for e in result.errors if "oidc_issuer" in e.field
                       and "URL" in e.message]
        assert not issuer_errs, f"unexpected oidc_issuer URL error: {result.errors}"

    def test_dashboard_oidc_issuer_empty_ok_when_disabled(self, toml_file):
        toml = '[dashboard]\noidc_issuer = ""\noidc_enabled = false\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        issuer_errs = [e for e in result.errors if "oidc_issuer" in e.field]
        assert not issuer_errs


class TestCommandServerNetworkValidators:
    """Field validators for IP/CIDR values."""

    def test_command_server_bind_address_invalid_ip(self, toml_file):
        toml = '[command_server]\nbind_address = "999.0.0.1"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("bind_address" in e.field for e in result.errors), (
            f"expected bind_address error; got: {result.errors}"
        )

    def test_command_server_bind_address_valid_accepted(self, toml_file):
        toml = '[command_server]\nbind_address = "0.0.0.0"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        bind_errs = [e for e in result.errors if "bind_address" in e.field]
        assert not bind_errs

    def test_command_server_control_from_invalid_cidr(self, toml_file):
        toml = '[command_server]\ncontrol_from = ["not-a-cidr"]\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("control_from" in e.field for e in result.errors), (
            f"expected control_from error; got: {result.errors}"
        )

    def test_command_server_control_from_valid_accepted(self, toml_file):
        toml = (
            '[command_server]\n'
            'control_from = ["127.0.0.1", "10.0.0.0/8"]\n'
        )
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        cf_errs = [e for e in result.errors if "control_from" in e.field]
        assert not cf_errs


class TestAgentSocketAbsolute:
    """Field validators for absolute paths."""

    def test_agent_socket_path_must_be_absolute(self, toml_file):
        toml = '[agent]\nsocket_path = "run/ibctl.sock"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("socket_path" in e.field for e in result.errors)

    def test_agent_socket_path_absolute_accepted(self, toml_file):
        toml = '[agent]\nsocket_path = "/run/ibctl/agent.sock"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        sp_errs = [e for e in result.errors if "socket_path" in e.field]
        assert not sp_errs


class TestLoggingFuturesWithoutLogDirWarn:
    """dead-config futures rotation without log_dir."""

    def test_logging_futures_session_no_log_dir_warn(self, toml_file):
        toml = '[logging]\nfutures_session_logging = true\nlog_dir = ""\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert result.ok, f"unexpected error: {result.errors}"
        assert any("stdout has no rotation surface" in w for w in result.warnings), (
            f"expected 'stdout has no rotation surface' warning; got: {result.warnings}"
        )


class TestColdRestartTighterRegex:
    """Format constraint on twsColdRestart (tighter regex)."""

    @pytest.mark.parametrize("bad", ["99:99", "25:00"])
    def test_tws_cold_restart_tighter_regex_rejects_bad(self, toml_file, bad):
        toml = f'[session]\ntws_cold_restart = "{bad}"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok, f"expected {bad!r} to be rejected"

    @pytest.mark.parametrize("good", ["09:00", ""])
    def test_tws_cold_restart_tighter_regex_accepts_good(self, toml_file, good):
        toml = f'[session]\ntws_cold_restart = "{good}"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        # No format-level error should surface (other cross-field errors may;
        # filter to the cold-restart error surface).
        cr_errs = [e for e in result.errors
                   if "tws_cold_restart" in e.message and "HH:MM" in e.message]
        assert not cr_errs


class TestTotpProviderBuiltinRejected:
    """twofa.provider='builtin' unimplemented at runtime."""

    def test_totp_provider_builtin_rejected(self, toml_file):
        toml = '[twofa]\nprovider = "builtin"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        # Literal mismatch should mention 'oathtool'.
        assert any("oathtool" in e.message for e in result.errors), (
            f"expected 'oathtool' in error; got: {result.errors}"
        )


class TestPortConflictActionable:
    """port-conflict actionable message."""

    def test_port_conflict_message_actionable(self, toml_file):
        toml = (
            '[gateway]\nlive_api_port = 8080\n\n'
            '[dashboard]\nport = 8080\n'
        )
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        msgs = " | ".join(e.message for e in result.errors)
        assert "collides" in msgs, f"expected 'collides' in message; got: {msgs}"
        assert "see docker/ibctl.toml" in msgs, (
            f"expected 'see docker/ibctl.toml' in message; got: {msgs}"
        )


class TestOidcScopesRequireOpenid:
    """oidc_scopes must include 'openid' when OIDC enabled."""

    def test_oidc_scopes_missing_openid(self, toml_file):
        toml = (
            '[command_server]\nenabled = true\n\n'
            '[dashboard]\nenabled = true\noidc_enabled = true\n'
            'oidc_issuer = "https://auth.example.com/"\n'
            'oidc_scopes = "profile email"\n'
        )
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok
        assert any("openid" in e.message for e in result.errors), (
            f"expected 'openid' in error; got: {result.errors}"
        )


class TestExternalUrlDeadConfigWarn:
    """external_url dead-config warning."""

    def test_external_url_with_dashboard_disabled_warn(self, toml_file):
        toml = (
            '[dashboard]\nenabled = false\n'
            'external_url = "https://ibctl.example.com"\n'
        )
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert result.ok, f"unexpected error: {result.errors}"
        assert any("not running" in w for w in result.warnings), (
            f"expected 'not running' in warning; got: {result.warnings}"
        )


class TestIbSystemStatusRegionClosed:
    """region is a closed union."""

    @pytest.mark.parametrize("bad", ["na", "US"])
    def test_ib_system_status_region_typo_rejected(self, toml_file, bad):
        toml = f'[ib_system_status]\nregion = "{bad}"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        assert not result.ok, f"expected {bad!r} to be rejected"

    def test_ib_system_status_region_valid_accepted(self, toml_file):
        toml = '[ib_system_status]\nregion = "NA"\n'
        result = validate_config(toml_path=toml_file(toml), check_env=False)
        region_errs = [e for e in result.errors if "region" in e.field]
        assert not region_errs


class TestWarningsUsePrivateAttr:
    """warnings-via-__dict__ hack replaced with PrivateAttr."""

    def test_get_warnings_uses_private_attr_not_dict_hack(self):
        from app.preflight.models import IbctlConfig

        # Construct a config that produces at least one warning without
        # tripping the trading_mode/userid raise. The
        # "paper.tws_userid set but trading_mode='live' doesn't use it"
        # branch is a clean warning-only path.
        cfg = IbctlConfig(
            auth={
                "trading_mode": "live",
                "tws_userid": "u",
                "paper": {"tws_userid": "unused_paper_user"},
            },
        )
        # PrivateAttr must be excluded from model_dump.
        assert "_warnings" not in cfg.model_dump(), (
            "_warnings must NOT surface in model_dump() (PrivateAttr guarantee)"
        )
        warnings = cfg.get_warnings()
        assert isinstance(warnings, list)
        assert any("paper" in w.lower() for w in warnings), (
            f"expected the paper-userid warning; got: {warnings}"
        )


class TestUnattendedHours:
    """The window in which a failed 2FA round parks after one push."""

    _BASE = '[auth]\ntrading_mode = "live"\n[twofa.backoff]\n'

    @pytest.mark.parametrize("value", ["22:00-08:00", "01:00-05:00", "", "off"])
    def test_accepted(self, toml_file, value):
        result = validate_config(
            toml_path=toml_file(self._BASE + f'unattended_hours = "{value}"\n'), check_env=False
        )
        assert result.ok, result.errors

    @pytest.mark.parametrize("value", ["22:00", "9pm-7am", "24:00-08:00", "8:00-9:00", "09:00-09:00"])
    def test_rejected(self, toml_file, value):
        result = validate_config(
            toml_path=toml_file(self._BASE + f'unattended_hours = "{value}"\n'), check_env=False
        )
        assert not result.ok, f"{value!r} accepted"

    def test_shipped_config_sets_the_overnight_window(self):
        import tomllib
        from pathlib import Path

        shipped = Path(__file__).resolve().parents[2] / "docker" / "ibctl.toml"
        data = tomllib.loads(shipped.read_text())
        assert data["twofa"]["backoff"]["unattended_hours"] == "22:00-08:00"
        # The whole file needs TWS_USERID from the environment; the backoff
        # table validates on its own.
        from app.preflight.models import TwoFaBackoffConfig

        TwoFaBackoffConfig(**data["twofa"]["backoff"])
