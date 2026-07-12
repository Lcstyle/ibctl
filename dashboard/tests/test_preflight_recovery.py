"""RED-phase tests for PR-C stage 3 preflight-recovery gaps.

These tests exercise the four HIGH- and one MED-tier findings from the
PR-C audit:

- HIGH-1: `[timing.recovery]` TOML section is rejected by preflight
          (`extra="forbid"` on `TimingConfig`).
- HIGH-4: env_overlay does not know about `IBCTL_RECOVERY_*` — booleans
          would silently land as strings and ints as strings, tripping
          Pydantic type coercion.
- MED-1:  `gateway.tws_settings_path` pointing at a missing/ephemeral
          directory silently breaks the marker persistence layer and
          regresses the GivenUp latch on every restart.

Every test asserts one behaviour, uses only the pytest fixture surface
(`monkeypatch`, `tmp_path`) and the `toml_file` helper below, and does
not touch the real filesystem outside `tmp_path`.

All tests here MUST FAIL against the pre-fix code (RED). GREEN will
land model + env_overlay + validator changes.
"""

from __future__ import annotations

import pytest

from app.preflight.validator import validate_config


@pytest.fixture
def toml_file(tmp_path):
    """Yields a helper that writes TOML content to a temp file."""
    def _write(content: str) -> str:
        path = tmp_path / "test.toml"
        path.write_text(content)
        return str(path)
    return _write


# ---------------------------------------------------------------------------
# HIGH-1: Pydantic preflight rejects [timing.recovery]
# ---------------------------------------------------------------------------


class TestTimingRecoveryBlockAccepted:
    """[timing.recovery] must be a first-class subsection of [timing]."""

    def test_preflight_accepts_populated_timing_recovery_block(self, toml_file):
        """A fully-populated [timing.recovery] block must pass preflight.

        Fields mirror Rust's RecoveryTimingConfig with matching defaults.
        """
        content = (
            "[timing.recovery]\n"
            "enabled = true\n"
            "aggressive_phase_max_secs = 3600\n"
            "backoff_phase_max_secs = 10800\n"
            "backoff_interval_secs = 900\n"
            "min_success_dwell_secs = 60\n"
            "fingerprint_streak_forcing_hitl = 8\n"
            'giveup_ntfy_kind = "reconnect_gave_up"\n'
            "giveup_callback_valid_hours = 12\n"
            "giveup_alert_resend_interval_hours = 6\n"
        )
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert result.ok, f"expected preflight to accept full [timing.recovery]; got errors: {result.errors}"

    def test_preflight_accepts_partial_timing_recovery_block(self, toml_file):
        """A subset of fields must be accepted — defaults fill the rest."""
        content = (
            "[timing.recovery]\n"
            "aggressive_phase_max_secs = 7200\n"
            "fingerprint_streak_forcing_hitl = 12\n"
        )
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert result.ok, f"expected partial [timing.recovery] to pass; got errors: {result.errors}"

    def test_preflight_rejects_unknown_recovery_field(self, toml_file):
        """Typos / stale fields inside [timing.recovery] must be hard errors.

        After GREEN, `timing.recovery` is a known subsection, so its own
        `extra="forbid"` on RecoveryConfig kicks in — the offending key
        name (`bogus_field`) must land in the error path itself. Before
        GREEN this also fails, but for the wrong reason: `recovery`
        itself is the extra key on TimingConfig, so the error path
        is `timing.recovery`, not `timing.recovery.bogus_field`. Both
        the RED and GREEN checks live under the same assertion so this
        test locks in the correct behaviour once the fix lands.
        """
        content = (
            "[timing.recovery]\n"
            "bogus_field = 1\n"
        )
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert not result.ok
        assert any(
            "bogus_field" in e.field
            for e in result.errors
        ), f"expected error whose field path names bogus_field; got: {result.errors}"

    def test_preflight_accepts_empty_timing_with_recovery_default(self, toml_file):
        """When TOML has no [timing.recovery], defaults must materialise silently.

        Extra guard so GREEN cannot ship a required-field regression.
        """
        result = validate_config(toml_path=toml_file(""), check_env=False)
        assert result.ok, f"expected empty TOML with recovery defaults to pass; got: {result.errors}"


# ---------------------------------------------------------------------------
# HIGH-4: env_overlay accepts the seven IBCTL_RECOVERY_* env vars
# ---------------------------------------------------------------------------


def _set_valid_creds(monkeypatch) -> None:
    """Set minimum valid credentials so env-checking tests get past cred gate."""
    monkeypatch.setenv("TWS_USERID", "testuser")
    monkeypatch.setenv("TWS_PASSWORD", "testpass")


class TestRecoveryBoolEnvOverride:
    """The two boolean IBCTL_RECOVERY_* vars are Rust-only knobs (no TOML mapping).

    Behavioral contract — audit-fix HIGH:
      (1) `apply_env_overrides({})` must NEVER leak `IBCTL_RECOVERY_DISABLED`
          or `IBCTL_RECOVERY_FORCE_RESET` into the config dict as a landing
          under `timing.recovery.{enabled,force_reset}`. That would be
          option (a) semantics — Python inverts DISABLED — but the audit
          picked option (b): Rust owns the semantic and the overlay stays
          out. A regression to (a) would silently double-invert.
      (2) Preflight stays ok whether the value is valid, invalid, or absent
          — Rust falls back to its own default. Preflight is NOT the
          gatekeeper for these vars.
      (3) The env var is *known* to the overlay: `_BOOL_ENV_VARS` still
          holds registration for downstream audits (env-var registry
          drift-check, docker-compose.yml passthrough sync). Membership
          is now backed by real code — `apply_env_overrides` reads the
          set — so removing entries actually breaks behavior.
    """

    @pytest.mark.parametrize("value", ["yes", "true", "1", "on"])
    def test_env_overlay_bool_recovery_disabled_valid_value_not_leaked(
        self, monkeypatch, toml_file, value
    ):
        """Valid IBCTL_RECOVERY_DISABLED must not create a `timing.recovery.enabled`
        landing (option (b) — Rust does the inversion)."""
        from app.preflight.env_overlay import apply_env_overrides

        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("IBCTL_RECOVERY_DISABLED", value)

        overlaid = apply_env_overrides({})
        recovery = overlaid.get("timing", {}).get("recovery", {})
        assert "enabled" not in recovery, (
            f"IBCTL_RECOVERY_DISABLED={value!r} must NOT populate "
            f"timing.recovery.enabled (option (b) leaves Python out of the "
            f"picture; Rust to_runtime() inverts). Got: {recovery!r}"
        )
        assert "force_reset" not in recovery, (
            f"unexpected timing.recovery.force_reset key from bool env: {recovery!r}"
        )

        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, f"IBCTL_RECOVERY_DISABLED={value!r} rejected: {result.errors}"

    @pytest.mark.parametrize("value", ["maybe", "off", "0", "false", "no", "definitely-not"])
    def test_env_overlay_bool_recovery_disabled_typo_not_leaked_as_string(
        self, monkeypatch, toml_file, value
    ):
        """A typo like IBCTL_RECOVERY_DISABLED=maybe must not leak the raw string
        into the config dict — Rust owns the value and treats it as false, so the
        overlay must not inject a stray `"enabled": "maybe"`.

        The RED-signal for future refactors: someone drops
        `_BOOL_ENV_VARS` and adds `IBCTL_RECOVERY_DISABLED` to ENV_MAP via the
        default (else) branch. Suddenly `"maybe"` lands at
        `timing.recovery.enabled` as a raw string, Pydantic coerces however
        it feels, and behavior drifts silently.
        """
        from app.preflight.env_overlay import apply_env_overrides

        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("IBCTL_RECOVERY_DISABLED", value)

        overlaid = apply_env_overrides({})
        recovery = overlaid.get("timing", {}).get("recovery", {})
        assert "enabled" not in recovery, (
            f"IBCTL_RECOVERY_DISABLED={value!r} leaked into config dict as "
            f"timing.recovery.enabled={recovery.get('enabled')!r}. This is the "
            "double-inversion / silent-string-through bug the audit closed. "
            "Do not add IBCTL_RECOVERY_DISABLED to ENV_MAP."
        )

        # Preflight must still pass — Rust falls back to its own default.
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, (
            f"typo IBCTL_RECOVERY_DISABLED={value!r} should be silently ignored "
            f"(Rust behavior); got: {result.errors}"
        )

    @pytest.mark.parametrize("value", ["yes", "true", "1", "on", "maybe", "0"])
    def test_env_overlay_bool_recovery_force_reset_never_leaks(
        self, monkeypatch, toml_file, value
    ):
        """IBCTL_RECOVERY_FORCE_RESET is Rust-only (one-shot marker wipe).
        No TOML round-trip — the overlay must never populate a landing zone
        for it, regardless of value validity."""
        from app.preflight.env_overlay import apply_env_overrides

        _set_valid_creds(monkeypatch)
        monkeypatch.setenv("IBCTL_RECOVERY_FORCE_RESET", value)

        overlaid = apply_env_overrides({})
        recovery = overlaid.get("timing", {}).get("recovery", {})
        assert "force_reset" not in recovery, (
            f"IBCTL_RECOVERY_FORCE_RESET={value!r} leaked into dict: {recovery!r}. "
            "This var is Rust-only; the overlay must not create a landing zone."
        )

        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, (
            f"IBCTL_RECOVERY_FORCE_RESET={value!r} should be silently ignored; "
            f"got: {result.errors}"
        )

    def test_bool_env_vars_registration_membership(self):
        """The registration set exists and covers both Rust-only bool env vars.

        This is the cheap sanity check — the *behavioral* contracts above
        are what defend against regression. This test only fires if someone
        drops registration entirely.
        """
        from app.preflight import env_overlay

        assert "IBCTL_RECOVERY_DISABLED" in env_overlay._BOOL_ENV_VARS
        assert "IBCTL_RECOVERY_FORCE_RESET" in env_overlay._BOOL_ENV_VARS


class TestRecoveryIntEnvOverride:
    """The five *_SECS / *_STREAK vars must reach Pydantic as ints, not strings.

    Without _INT_FIELDS registration, env_overlay's default branch calls
    _set_nested with the raw string. Pydantic then rejects the string
    because the fields are typed as int.
    """

    def _assert_int_env_reaches_dict(
        self,
        monkeypatch,
        env_var: str,
        toml_dotted_path: str,
        raw: str,
        expected: int,
    ) -> None:
        """Shared assertion: env var must reach the config dict as int.

        The RED signal: today the seven IBCTL_RECOVERY_* vars are not in
        ENV_MAP, so env_overlay silently drops them and the value never
        materialises at `toml.timing.recovery.<field>` — the getter
        returns None instead of `expected`.
        """
        from app.preflight.env_overlay import apply_env_overrides

        monkeypatch.setenv(env_var, raw)
        overlaid = apply_env_overrides({})
        # Walk the dotted path defensively so a missing intermediate dict
        # gives a nice error rather than a KeyError traceback.
        cur: object = overlaid
        for part in toml_dotted_path.split("."):
            if not isinstance(cur, dict):
                cur = None
                break
            cur = cur.get(part)
        assert cur == expected and isinstance(cur, int) and not isinstance(cur, bool), (
            f"expected {env_var}={raw!r} to land at "
            f"{toml_dotted_path}={expected!r} (int); got {cur!r} "
            f"(type={type(cur).__name__}). Overlaid dict: {overlaid!r}"
        )

    def test_env_overlay_int_recovery_aggressive_max_secs_typed_correctly(
        self, monkeypatch, toml_file
    ):
        _set_valid_creds(monkeypatch)
        self._assert_int_env_reaches_dict(
            monkeypatch,
            "IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS",
            "timing.recovery.aggressive_phase_max_secs",
            "7200",
            7200,
        )
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, f"AGGRESSIVE_MAX_SECS=7200 rejected: {result.errors}"

    def test_env_overlay_int_recovery_backoff_max_secs_typed_correctly(
        self, monkeypatch, toml_file
    ):
        _set_valid_creds(monkeypatch)
        self._assert_int_env_reaches_dict(
            monkeypatch,
            "IBCTL_RECOVERY_BACKOFF_MAX_SECS",
            "timing.recovery.backoff_phase_max_secs",
            "21600",
            21600,
        )
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, f"BACKOFF_MAX_SECS=21600 rejected: {result.errors}"

    def test_env_overlay_int_recovery_backoff_interval_typed_correctly(
        self, monkeypatch, toml_file
    ):
        _set_valid_creds(monkeypatch)
        self._assert_int_env_reaches_dict(
            monkeypatch,
            "IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS",
            "timing.recovery.backoff_interval_secs",
            "1800",
            1800,
        )
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, f"BACKOFF_INTERVAL_SECS=1800 rejected: {result.errors}"

    def test_env_overlay_int_recovery_min_dwell_typed_correctly(
        self, monkeypatch, toml_file
    ):
        _set_valid_creds(monkeypatch)
        self._assert_int_env_reaches_dict(
            monkeypatch,
            "IBCTL_RECOVERY_MIN_SUCCESS_DWELL_SECS",
            "timing.recovery.min_success_dwell_secs",
            "120",
            120,
        )
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, f"MIN_SUCCESS_DWELL_SECS=120 rejected: {result.errors}"

    def test_env_overlay_int_recovery_fingerprint_streak_typed_correctly(
        self, monkeypatch, toml_file
    ):
        _set_valid_creds(monkeypatch)
        self._assert_int_env_reaches_dict(
            monkeypatch,
            "IBCTL_RECOVERY_FINGERPRINT_STREAK",
            "timing.recovery.fingerprint_streak_forcing_hitl",
            "12",
            12,
        )
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, f"FINGERPRINT_STREAK=12 rejected: {result.errors}"

    @pytest.mark.parametrize(
        "env_var",
        [
            "IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS",
            "IBCTL_RECOVERY_BACKOFF_MAX_SECS",
            "IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS",
            "IBCTL_RECOVERY_MIN_SUCCESS_DWELL_SECS",
            "IBCTL_RECOVERY_FINGERPRINT_STREAK",
        ],
    )
    def test_env_overlay_invalid_int_recovery_rejected(
        self, monkeypatch, toml_file, env_var
    ):
        """Non-numeric int env vars follow the existing 'silently ignore' pattern.

        env_overlay's `_INT_FIELDS` branch swallows ValueError and leaves
        the TOML default in place. The overall preflight therefore stays
        ok — matches how e.g. IBCTL_RESTART_DELAY behaves with junk input.
        This test exists to lock in the behaviour rather than let a
        follow-up 'improvement' turn junk into a hard error and regress
        every prod deploy with a typo in a docker-compose file.

        Parametrized across all five int recovery vars so all branches of
        the silent-ignore code path stay pinned (Review C GAP LOW).
        """
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv(env_var, "abc")
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, (
            f"non-numeric {env_var} should be silently ignored "
            "(matches Rust behavior + IBCTL_RESTART_DELAY precedent); got: "
            f"{result.errors}"
        )

    @pytest.mark.parametrize(
        "env_var",
        [
            "IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS",
            "IBCTL_RECOVERY_BACKOFF_MAX_SECS",
            "IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS",
            "IBCTL_RECOVERY_MIN_SUCCESS_DWELL_SECS",
            "IBCTL_RECOVERY_FINGERPRINT_STREAK",
        ],
    )
    def test_env_overlay_negative_int_recovery_silently_ignored(
        self, monkeypatch, toml_file, env_var
    ):
        """Negative-int env vars are silently ignored — same as non-numeric.

        Audit review A LOW: Rust `u64/u32.parse()` fails on negatives with
        a warn-and-fall-back. Before this fix, Python treated negatives as
        valid `int(...)` values then let Pydantic's `ge=0` reject them,
        turning a Rust soft-warn into a preflight hard-error. Now the
        overlay drops sub-zero values in the same silent branch as
        ValueError. Locks in the parity.
        """
        _set_valid_creds(monkeypatch)
        monkeypatch.setenv(env_var, "-1")
        result = validate_config(toml_path=toml_file(""), check_env=True)
        assert result.ok, (
            f"negative {env_var}=-1 should be silently ignored (parity with "
            f"Rust env_u64 warn-and-fallback); got: {result.errors}"
        )

    def test_env_overlay_recovery_int_via_file_secret(
        self, monkeypatch, tmp_path, toml_file
    ):
        """Docker secrets `_FILE` variant is supported for recovery int knobs.

        The failover ops pattern reads secrets from `/run/secrets/...`; the
        int env vars flow through `env_or_file()` too, so a
        `IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS_FILE=/run/secrets/foo` with
        contents `1800\n` must land at
        `timing.recovery.backoff_interval_secs=1800`.
        """
        from app.preflight.env_overlay import apply_env_overrides

        secret_file = tmp_path / "backoff_secs.txt"
        secret_file.write_text("1800\n")
        monkeypatch.setenv("IBCTL_RECOVERY_BACKOFF_INTERVAL_SECS_FILE", str(secret_file))

        overlaid = apply_env_overrides({})
        value = (
            overlaid.get("timing", {}).get("recovery", {}).get("backoff_interval_secs")
        )
        assert value == 1800 and isinstance(value, int), (
            f"expected _FILE-sourced int 1800; got {value!r} (type={type(value).__name__})"
        )

    def test_env_overlay_int_recovery_reaches_pydantic_as_int(
        self, monkeypatch, toml_file
    ):
        """Direct assertion that env_overlay produces an int for a *_SECS var.

        Extra test beyond the spec because the current codepath's silent
        failure mode is 'string reaches Pydantic, error message is opaque'
        — locking in the int coercion at the overlay layer makes the
        contract explicit and cheap to enforce in GREEN.
        """
        from app.preflight.env_overlay import apply_env_overrides

        monkeypatch.setenv("IBCTL_RECOVERY_AGGRESSIVE_MAX_SECS", "7200")
        overlaid = apply_env_overrides({})
        value = (
            overlaid.get("timing", {}).get("recovery", {}).get(
                "aggressive_phase_max_secs"
            )
        )
        assert value == 7200, (
            f"expected int 7200 after env overlay; got {value!r} "
            f"(type={type(value).__name__})"
        )


# ---------------------------------------------------------------------------
# MED-1: settings_dir soft-warn for missing/ephemeral marker directory
# ---------------------------------------------------------------------------


class TestSettingsDirSoftWarn:
    """A missing marker directory silently breaks GivenUp persistence.

    The recovery marker is written under the Gateway settings dir
    (gateway.tws_settings_path, falling back to tws_path). If the dir
    doesn't exist, marker I/O fails silently and the GivenUp latch
    regresses on every container restart.

    The soft-warn contract: preflight stays ok, but result.warnings
    contains a message that surfaces the misconfig to the operator.
    """

    def test_settings_dir_missing_soft_warn(self, monkeypatch, toml_file, tmp_path):
        """A tws_settings_path that doesn't exist emits a soft-warn."""
        missing = tmp_path / "does-not-exist" / "Jts"
        content = f'[gateway]\ntws_settings_path = "{missing}"\n'
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert result.ok, (
            "missing settings dir should be a WARN, not an error; "
            f"got errors: {result.errors}"
        )
        assert any(
            "settings" in w.lower() or "marker" in w.lower() or "persist" in w.lower()
            for w in result.warnings
        ), (
            "expected a soft-warn mentioning settings/marker/persistence "
            f"for a nonexistent tws_settings_path; got warnings: {result.warnings}"
        )

    def test_settings_dir_existing_no_warn(self, monkeypatch, toml_file, tmp_path):
        """An existing directory must NOT trip the settings-dir warn.

        Extra test beyond the spec — pins down the false-positive
        surface so GREEN cannot land a bare
        `if tws_settings_path: warn()` and pass CI.
        """
        existing = tmp_path / "Jts_live"
        existing.mkdir()
        content = f'[gateway]\ntws_settings_path = "{existing}"\n'
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert result.ok
        assert not any(
            ("settings" in w.lower() or "marker" in w.lower() or "persist" in w.lower())
            for w in result.warnings
        ), (
            "existing settings dir should NOT emit a settings/marker warn; "
            f"got warnings: {result.warnings}"
        )


# ---------------------------------------------------------------------------
# Audit-fix additions — MED / LOW findings that survived triage
# ---------------------------------------------------------------------------


class TestRecoveryFieldBounds:
    """Pydantic `giveup_callback_valid_hours` enforces ge=1, le=168.

    Note: Rust `u32` and Pkl `UInt` do NOT enforce this range — the
    bounds live only in Pydantic (matches the pre-existing `twofa.backoff.
    callback_valid_hours` pattern). The asymmetry is intentional:
    preflight is the stricter gate, and blocking a config Rust would run
    is preferable to letting a nonsense value like `giveup_callback_valid_
    hours = 0` reach production. Locked in here so a future refactor
    can't accidentally drop the bounds (Review C GAP MED).
    """

    @pytest.mark.parametrize("hours", [1, 12, 168])
    def test_recovery_giveup_valid_hours_in_range_accepted(self, toml_file, hours):
        content = (
            "[timing.recovery]\n"
            f"giveup_callback_valid_hours = {hours}\n"
        )
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert result.ok, (
            f"giveup_callback_valid_hours={hours} should be in-range; "
            f"got errors: {result.errors}"
        )

    @pytest.mark.parametrize("hours", [0, 169, 999])
    def test_recovery_giveup_valid_hours_out_of_range_rejected(self, toml_file, hours):
        content = (
            "[timing.recovery]\n"
            f"giveup_callback_valid_hours = {hours}\n"
        )
        result = validate_config(toml_path=toml_file(content), check_env=False)
        assert not result.ok, (
            f"giveup_callback_valid_hours={hours} should be out-of-range but was accepted"
        )
        assert any(
            "giveup_callback_valid_hours" in e.field for e in result.errors
        ), f"expected bounds error on giveup_callback_valid_hours; got: {result.errors}"


class TestRecoveryPydanticDefaultsMatchRust:
    """Pydantic `RecoveryConfig()` defaults MUST match Rust
    `RecoveryTimingConfig::default()`.

    Rust owns the runtime and Pkl generates the shipping TOML; the two
    sides can silently drift when TOML omits the section entirely
    (Rust falls back to its own default). Encoded here as constants so
    a Rust-side bump surfaces in preflight test failure rather than at
    prod-deploy diff-eyeball time (Review B silent-default risk + Review
    C GAP MED).

    When changing any Rust default in
    `ibctl/src/config.rs::RecoveryTimingConfig::default_*` functions,
    update this table AND `dashboard/app/preflight/models.py::RecoveryConfig`
    AND `config/pkl/types.pkl::RecoveryTimingConfig` in the same commit.
    """

    # Extracted from ibctl/src/config.rs::RecoveryTimingConfig::impl (lines 613-621).
    RUST_DEFAULTS: dict = {
        "enabled": True,
        "aggressive_phase_max_secs": 3600,
        "backoff_phase_max_secs": 10800,
        "backoff_interval_secs": 900,
        "min_success_dwell_secs": 60,
        "fingerprint_streak_forcing_hitl": 8,
        "giveup_ntfy_kind": "reconnect_gave_up",
        "giveup_callback_valid_hours": 12,
        "giveup_alert_resend_interval_hours": 6,
    }

    def test_pydantic_recovery_defaults_match_rust(self):
        from app.preflight.models import RecoveryConfig

        rc = RecoveryConfig()
        py_defaults = {name: getattr(rc, name) for name in self.RUST_DEFAULTS}
        assert py_defaults == self.RUST_DEFAULTS, (
            "Rust ↔ Pydantic default drift detected. When Rust "
            "`RecoveryTimingConfig::default_*` changes, this constant AND "
            "`RecoveryConfig` field defaults AND Pkl `RecoveryTimingConfig` "
            "must be updated together. Rust says "
            f"{self.RUST_DEFAULTS!r}; Pydantic says {py_defaults!r}."
        )

    def test_pydantic_recovery_field_set_matches_rust(self):
        from app.preflight.models import RecoveryConfig

        py_fields = set(RecoveryConfig.model_fields.keys())
        expected = set(self.RUST_DEFAULTS.keys())
        assert py_fields == expected, (
            "Rust ↔ Pydantic field-set drift. Pydantic has "
            f"{py_fields - expected} extra and {expected - py_fields} missing "
            "vs. the Rust struct."
        )


class TestRootDockerComposeRecoveryPassthrough:
    """The repo-root `docker-compose.yml` must declare a passthrough env
    for every recovery env var the overlay knows about.

    Review C GAP HIGH: `make check-configs` only inspects the generated
    `examples/*.yml`; the hand-authored `docker-compose.yml` at repo root
    is the primary production compose file. A future PR that adds a
    recovery knob to `ENV_MAP`/`_BOOL_ENV_VARS` but forgets root compose
    would ship a recovery override that silently doesn't reach the
    container — Rust falls back to its default, operator thinks the env
    is applied, coordinator behaves unexpectedly.

    This test walks the ENV_MAP + _BOOL_ENV_VARS registry surface,
    filters to `IBCTL_RECOVERY_*`, and asserts every such env name
    appears as an `environment:` key in the root docker-compose.yml.
    """

    def test_all_recovery_env_vars_declared_in_root_compose(self):
        from pathlib import Path as _Path

        from app.preflight.env_overlay import _BOOL_ENV_VARS
        from app.preflight.models import ENV_MAP

        recovery_env_names = {
            v for v in ENV_MAP.values() if v.startswith("IBCTL_RECOVERY_")
        }
        recovery_env_names |= {
            v for v in _BOOL_ENV_VARS if v.startswith("IBCTL_RECOVERY_")
        }

        # Locate repo-root docker-compose.yml relative to this test file.
        compose_path = (
            _Path(__file__).resolve().parents[2] / "docker-compose.yml"
        )
        assert compose_path.exists(), (
            f"cannot find repo-root docker-compose.yml at {compose_path}"
        )
        compose_text = compose_path.read_text()

        missing = sorted(
            name for name in recovery_env_names if f"{name}:" not in compose_text
        )
        assert not missing, (
            "Recovery env vars registered in env_overlay/ENV_MAP but NOT "
            f"passed through in docker-compose.yml: {missing}. Add them to "
            "the `# --- Reconnect recovery coordinator ---` block."
        )


class TestRecoveryTomlRendererSmoke:
    """Direct unit assertion that the TOML renderer emits [timing.recovery].

    Review C GAP MED: without this, the only gate on renderer regressions
    is `check-configs` Pkl-round-trip drift detection in CI — which
    doesn't run per-commit locally. Cheap to add, catches "removed the
    render block" at test time.
    """

    def test_render_docker_toml_emits_recovery_block(self):
        import sys
        from pathlib import Path as _Path

        # Renderers import as `renderers.*` from tools/; add path.
        tools_dir = _Path(__file__).resolve().parents[2] / "tools"
        if str(tools_dir) not in sys.path:
            sys.path.insert(0, str(tools_dir))

        try:
            import pkl as _pkl  # type: ignore[import-not-found]
        except ImportError:
            pytest.skip("pkl module unavailable in this environment")

        from renderers.toml_renderer import render_docker_toml  # noqa: E402

        base_pkl = _Path(__file__).resolve().parents[2] / "config" / "pkl" / "base.pkl"
        cfg = _pkl.load(str(base_pkl))
        toml = render_docker_toml(cfg)

        assert "[timing.recovery]" in toml, (
            "docker/ibctl.toml render missing [timing.recovery] section"
        )
        # Sanity-check every field name lands in the output.
        expected_fields = [
            "enabled",
            "aggressive_phase_max_secs",
            "backoff_phase_max_secs",
            "backoff_interval_secs",
            "min_success_dwell_secs",
            "fingerprint_streak_forcing_hitl",
            "giveup_ntfy_kind",
            "giveup_callback_valid_hours",
            "giveup_alert_resend_interval_hours",
        ]
        # Grab the [timing.recovery] block only (until the next section header).
        idx = toml.index("[timing.recovery]")
        # Section ends at next line starting with "[" after our start.
        tail = toml[idx:]
        next_section = tail.find("\n[", 1)
        block = tail if next_section == -1 else tail[:next_section]
        for field in expected_fields:
            assert f"{field} =" in block, (
                f"[timing.recovery] block missing field {field!r}; block:\n{block}"
            )
