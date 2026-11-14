"""Tests for env_overlay — Docker-secrets `_FILE` handling.

The env_overlay layer sits between the OS environment and both the
apply_env_overrides pipeline and validator.py's credential/env checks. It
must not silently substitute a plaintext env var for an intentionally
file-sourced secret when the file is unreadable — that path swaps a stale
value for the intended secret with no signal to the operator. These tests
lock the raise-instead-of-swallow contract at the primitive layer.

The companion validator.py catch (turning EnvFileReadError into a
PreflightError) is covered in test_preflight.py once that edit lands;
these tests focus on the env_overlay primitive.
"""

from __future__ import annotations

import pytest

from app.preflight.env_overlay import EnvFileReadError, env_or_file
from app.preflight.validator import validate_config


@pytest.fixture
def toml_file(tmp_path):
    """Yields a helper that writes TOML content to a temp file.

    Same auto-userid-inject as test_preflight.py — the post-migration
    @model_validator on IbctlConfig requires a non-empty auth.tws_userid.
    """
    import re

    def _write(content: str) -> str:
        auth_match = re.search(r"^\[auth\]\s*$", content, re.MULTILINE)
        if auth_match:
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


class TestEnvOrFile:
    """env_or_file — the Docker-secrets `_FILE` primitive."""

    def test_env_or_file_unreadable_path_raises(self, monkeypatch):
        """A `*_FILE` env pointing at a missing/permission-denied path must
        raise EnvFileReadError with the env-var name, the offending path,
        and the underlying OSError attached.

        Guards against the silently-swallow-OSError regression: dropping
        the raise would let env_or_file fall back to the plain env var and
        substitute a stale value for the intended secret with no signal.
        """
        monkeypatch.delenv("TWS_PASSWORD", raising=False)
        monkeypatch.setenv(
            "TWS_PASSWORD_FILE", "/nonexistent/does-not-exist/secret"
        )
        with pytest.raises(EnvFileReadError) as excinfo:
            env_or_file("TWS_PASSWORD")
        err = excinfo.value
        assert err.env_var == "TWS_PASSWORD"
        assert err.path == "/nonexistent/does-not-exist/secret"
        assert isinstance(err.cause, OSError)
        # The message must call out the env var, the path, and a fix path
        # so an operator reading the log knows exactly what to touch.
        msg = str(err)
        assert "TWS_PASSWORD_FILE" in msg
        assert "/nonexistent/does-not-exist/secret" in msg
        assert "unset TWS_PASSWORD_FILE" in msg

    def test_env_or_file_readable_path_returns_content(
        self, monkeypatch, tmp_path
    ):
        """Happy path — a readable `*_FILE` yields its trimmed contents.

        Locks in that the raise branch does not break normal Docker-secrets
        operation. Also confirms trailing whitespace is stripped (secrets
        written by `echo "value" > file` carry a trailing newline).
        """
        secret_file = tmp_path / "password.txt"
        secret_file.write_text("secretvalue\n")
        monkeypatch.setenv("TWS_PASSWORD_FILE", str(secret_file))
        # Ensure the plain env var can't be what we're reading.
        monkeypatch.delenv("TWS_PASSWORD", raising=False)
        assert env_or_file("TWS_PASSWORD") == "secretvalue"

    def test_env_or_file_file_takes_precedence_over_plain(
        self, monkeypatch, tmp_path
    ):
        """Docker-secrets pattern — `*_FILE` wins when both are set."""
        secret_file = tmp_path / "password.txt"
        secret_file.write_text("from-file\n")
        monkeypatch.setenv("TWS_PASSWORD_FILE", str(secret_file))
        monkeypatch.setenv("TWS_PASSWORD", "from-plain")
        assert env_or_file("TWS_PASSWORD") == "from-file"

    def test_env_or_file_falls_back_to_plain_when_file_unset(
        self, monkeypatch
    ):
        """No `*_FILE`, plain env set — returns plain value verbatim.

        Complements the raise-path test: unset `*_FILE` must still hit the
        plain env fallback and not spuriously raise.
        """
        monkeypatch.delenv("TWS_PASSWORD_FILE", raising=False)
        monkeypatch.setenv("TWS_PASSWORD", "just-plain")
        assert env_or_file("TWS_PASSWORD") == "just-plain"

    def test_env_or_file_returns_none_when_neither_set(self, monkeypatch):
        """Neither `*_FILE` nor plain set — returns None (not empty string).

        Downstream callers (`_check_credentials`) treat None as 'missing';
        an accidental empty string could be interpreted as 'set-but-empty'
        and skip the required-credential error path.
        """
        monkeypatch.delenv("TWS_PASSWORD_FILE", raising=False)
        monkeypatch.delenv("TWS_PASSWORD", raising=False)
        assert env_or_file("TWS_PASSWORD") is None


class TestValidateConfigNoEnvIgnoresEnvFileError:
    """check_env=False must not touch env vars at all.

    Confirms the exception is only observed under env-mode. `--no-env`
    callers (tests, tooling) rely on this contract so they can leave a
    broken Docker-secrets path in the environment while still exercising
    the TOML-only validation surface.
    """

    def test_check_env_false_ignores_broken_env_file(
        self, monkeypatch, toml_file
    ):
        """A broken `TWS_PASSWORD_FILE` with check_env=False is invisible.

        Under check_env=False, apply_env_overrides is skipped AND
        _check_credentials is skipped, so no env_or_file call fires and no
        EnvFileReadError can propagate. This test defends the boundary.
        """
        monkeypatch.setenv("TWS_PASSWORD_FILE", "/nonexistent/x")
        # An empty TOML must still validate OK when the env layer is off.
        result = validate_config(toml_path=toml_file(""), check_env=False)
        assert result.ok, f"expected ok=True; got errors={result.errors}"


class TestModuleDocstringPolicyNote:
    """The module docstring records the notification-severity policy.

    models.py sharpens the warning message text; the docstring records the
    rationale so a future review doesn't re-open the question of
    'why isn't a missing Slack webhook a hard error?'. Locking the note in
    prevents someone from stripping it during an unrelated cleanup.
    """

    def test_docstring_mentions_warn_vs_error_boundary(self):
        from app.preflight import env_overlay

        doc = env_overlay.__doc__ or ""
        # Actionable message text — must survive future edits.
        assert "notification-channel" in doc.lower()
        assert "warnings" in doc.lower() and "errors" in doc.lower()
        # The hard-error boundary must be named so its intent is discoverable.
        assert "ntfy_callback" in doc
