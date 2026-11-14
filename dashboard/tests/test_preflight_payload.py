"""Pre-flight: can this image launch the Gateway it carries?

The 10.50.1f image passed every config check and still crash-looped in
production, because nothing before the swap ran the Gateway's own payload:
its install folder, jars and Java. `python -m app.preflight` is what the
deploy runs against a new image before swapping it in, and what the container
runs at start, so the payload check belongs there.

These tests drive the real `app.preflight` code against a stand-in `ibctl`
binary, so they need no Gateway install.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from app.preflight import __main__ as preflight_cli
from app.preflight.payload import check_payload


def fake_ibctl(tmp_path: Path, *, exit_code: int = 0, output: str = "", sleep: float = 0) -> Path:
    """A stand-in `ibctl` that records its arguments and answers as told."""
    script = tmp_path / "ibctl"
    args_file = tmp_path / "ibctl.args"
    script.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > "{args_file}"\n'
        f"sleep {sleep}\n"
        f"cat <<'OUT'\n{output}\nOUT\n"
        f"exit {exit_code}\n"
    )
    script.chmod(0o755)
    return script


PASSED = "  ok    java       /home/ibgateway/Jts/ibgateway/10.50.1f/jre/bin/java (bundled with the install)\npayload preflight passed"
NO_JAVA = (
    "  FAIL  launch plan no Gateway Java found; looked at /home/ibgateway/Jts/ibgateway/10.50.1f/jre/bin/java\n"
    "PAYLOAD PREFLIGHT FAILED: this image cannot launch its Gateway"
)


class TestCheckPayload:
    def test_a_launchable_payload_passes(self, tmp_path):
        ok, output = check_payload(str(fake_ibctl(tmp_path, output=PASSED)), "/opt/ibctl/ibctl.toml")

        assert ok
        assert "payload preflight passed" in output

    def test_a_payload_that_cannot_launch_fails_with_its_reason(self, tmp_path):
        ok, output = check_payload(str(fake_ibctl(tmp_path, exit_code=1, output=NO_JAVA)), "/opt/ibctl/ibctl.toml")

        assert not ok
        assert "no Gateway Java found" in output

    def test_it_checks_the_same_config_the_container_runs_with(self, tmp_path):
        check_payload(str(fake_ibctl(tmp_path, output=PASSED)), "/etc/custom/ibctl.toml")

        args = (tmp_path / "ibctl.args").read_text().split()
        assert args == ["preflight", "--payload", "--config", "/etc/custom/ibctl.toml"]

    def test_a_missing_ibctl_binary_fails_instead_of_passing(self, tmp_path):
        ok, output = check_payload(str(tmp_path / "absent"), "/opt/ibctl/ibctl.toml")

        assert not ok
        assert "not found" in output

    def test_a_check_that_hangs_fails_on_its_timeout(self, tmp_path):
        ok, output = check_payload(
            str(fake_ibctl(tmp_path, output=PASSED, sleep=30)), "/opt/ibctl/ibctl.toml", timeout=0.3
        )

        assert not ok
        assert "did not finish" in output


@pytest.fixture
def valid_toml(tmp_path):
    path = tmp_path / "ibctl.toml"
    path.write_text('[auth]\ntws_userid = "test_user"\ntrading_mode = "live"\n')  # nosecret
    return str(path)


def run_main(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["preflight", *argv])
    try:
        preflight_cli.main()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


class TestPreflightCommand:
    def test_valid_config_and_a_launchable_payload_pass(self, monkeypatch, tmp_path, valid_toml, capsys):
        ibctl = fake_ibctl(tmp_path, output=PASSED)

        code = run_main(monkeypatch, "--config", valid_toml, "--no-env", "--ibctl-bin", str(ibctl))

        assert code == 0
        assert "payload preflight passed" in capsys.readouterr().out

    def test_valid_config_with_an_unlaunchable_payload_fails(self, monkeypatch, tmp_path, valid_toml, capsys):
        """The production failure: config was fine, the Gateway could not start."""
        ibctl = fake_ibctl(tmp_path, exit_code=1, output=NO_JAVA)

        code = run_main(monkeypatch, "--config", valid_toml, "--no-env", "--ibctl-bin", str(ibctl))

        assert code == 1
        err = capsys.readouterr().err
        assert "PRE-FLIGHT FAILED" in err
        assert "no Gateway Java found" in err

    def test_no_payload_skips_the_check_and_says_so(self, monkeypatch, tmp_path, valid_toml, capsys):
        code = run_main(
            monkeypatch, "--config", valid_toml, "--no-env", "--no-payload", "--ibctl-bin", str(tmp_path / "absent")
        )

        assert code == 0
        assert "payload check skipped" in capsys.readouterr().err

    def test_the_payload_runs_by_default(self, monkeypatch, tmp_path, valid_toml):
        """The deploy's pre-swap gate calls `python -m app.preflight` with no
        arguments, so the payload check must be on unless turned off."""
        monkeypatch.setattr(preflight_cli, "DEFAULT_IBCTL_BIN", str(tmp_path / "absent"))

        code = run_main(monkeypatch, "--config", valid_toml, "--no-env")

        assert code == 1
