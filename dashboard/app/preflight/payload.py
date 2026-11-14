"""Can this image launch the Gateway it carries?

Config validation alone let the 10.50.1f image through: its config was fine,
but ibctl could not find the Gateway's Java, and the container crash-looped in
production. This asks the ibctl binary itself (`ibctl preflight --payload`),
which resolves the launch through the same code a real launch uses, so the
answer cannot drift from what production does.
"""

from __future__ import annotations

import os
import subprocess

DEFAULT_TIMEOUT_SECS = 120.0


def check_payload(
    ibctl_bin: str, config_path: str, timeout: float = DEFAULT_TIMEOUT_SECS
) -> tuple[bool, str]:
    """Run `ibctl preflight --payload`. Returns (passed, what it printed).

    A missing binary, a crash or a hang is a failure, never a pass: this is
    the check that stands between a broken image and production.
    """
    if not os.path.isfile(ibctl_bin):
        return False, f"ibctl binary not found at {ibctl_bin}; cannot check the Gateway payload"
    try:
        proc = subprocess.run(
            [ibctl_bin, "preflight", "--payload", "--config", config_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, f"ibctl preflight --payload did not finish within {timeout:g}s"
    except OSError as exc:
        return False, f"cannot run {ibctl_bin}: {exc}"
    output = "\n".join(part.strip() for part in (proc.stdout, proc.stderr) if part.strip())
    return proc.returncode == 0, output
