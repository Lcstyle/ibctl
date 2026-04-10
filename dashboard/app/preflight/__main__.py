"""Pre-flight config validation CLI.

Usage:
    python -m app.preflight                     # validate /opt/ibctl/ibctl.toml + env
    python -m app.preflight --config path.toml  # validate specific file
    python -m app.preflight --no-env            # validate TOML only, no env overrides

Exit codes:
    0 = config valid
    1 = validation failed
"""

from __future__ import annotations

import argparse
import sys

from .validator import validate_config


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


if __name__ == "__main__":
    main()
