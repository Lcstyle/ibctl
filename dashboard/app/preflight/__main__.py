"""Pre-flight validation CLI: the config, then the Gateway payload.

Usage:
    python -m app.preflight                     # validate /opt/ibctl/ibctl.toml + env, then the payload
    python -m app.preflight --config path.toml  # validate specific file
    python -m app.preflight --no-env            # validate TOML only, no env overrides
    python -m app.preflight --no-payload        # skip the Gateway payload check

The deploy runs this against a new image before swapping it in, and the
container runs it at start, so the payload check is on by default.

Exit codes:
    0 = config valid and the image can launch its Gateway
    1 = validation failed
"""

from __future__ import annotations

import argparse
import os
import sys

from .payload import check_payload
from .validator import validate_config

DEFAULT_IBCTL_BIN = os.environ.get("IBCTL_BIN", "/opt/ibctl/ibctl")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pre-flight config validation for ibctl"
    )
    parser.add_argument(
        "--config",
        default="/opt/ibctl/ibctl.toml",
        help="Path to TOML config file (default: /opt/ibctl/ibctl.toml)",
    )
    parser.add_argument(
        "--no-env",
        action="store_true",
        help="Skip environment variable overrides (validate TOML only)",
    )
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Skip checking that this image can launch its Gateway",
    )
    parser.add_argument(
        "--ibctl-bin",
        default=None,
        help="ibctl binary to run the payload check with (default: $IBCTL_BIN or /opt/ibctl/ibctl)",
    )
    args = parser.parse_args()

    result = validate_config(
        toml_path=args.config,
        check_env=not args.no_env,
    )

    if result.warnings:
        for w in result.warnings:
            print(f"  WARN: {w}", file=sys.stderr)

    if not result.ok:
        print("PRE-FLIGHT FAILED:", file=sys.stderr)
        for err in result.errors:
            env_hint = f" (env: {err.env_var})" if err.env_var else ""
            val_hint = f" [got: {err.actual_value}]" if err.actual_value else ""
            print(
                f"  ERROR: {err.field}{env_hint}: {err.message}{val_hint}",
                file=sys.stderr,
            )
        sys.exit(1)

    print("Pre-flight config validation passed")

    if args.no_payload:
        print("  WARN: Gateway payload check skipped (--no-payload)", file=sys.stderr)
        return
    passed, output = check_payload(args.ibctl_bin or DEFAULT_IBCTL_BIN, args.config)
    if not passed:
        print("PRE-FLIGHT FAILED: this image cannot launch its Gateway", file=sys.stderr)
        print(output, file=sys.stderr)
        sys.exit(1)
    print(output)


if __name__ == "__main__":
    main()
