#!/usr/bin/env python3
"""Generate ibctl config artifacts from Pkl source models.

Usage:
    python tools/generate_configs.py                     # generate all from base profile
    python tools/generate_configs.py --profile live       # generate from live profile
    python tools/generate_configs.py --profile dashboard  # generate from dashboard profile
    python tools/generate_configs.py --dry-run             # print to stdout, don't write files
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pkl

from renderers.toml_renderer import render_docker_toml, render_example_toml
from renderers.compose_renderer import render_compose
from renderers.env_renderer import render_env_example

ROOT = Path(__file__).resolve().parents[1]
PKL_DIR = ROOT / "config" / "pkl"

PROFILES = {
    "base": PKL_DIR / "base.pkl",
    "live": PKL_DIR / "profiles" / "live.pkl",
    "paper": PKL_DIR / "profiles" / "paper.pkl",
    "both": PKL_DIR / "profiles" / "both.pkl",
    "dashboard": PKL_DIR / "profiles" / "dashboard.pkl",
    "standby": PKL_DIR / "profiles" / "standby.pkl",
}

# Output targets and their generators.
# Each entry: (output_path_relative_to_ROOT, renderer_function)
TARGETS = {
    "docker_toml": ("docker/ibctl.toml", render_docker_toml),
    "example_toml": ("ibctl.toml.example", render_example_toml),
    "compose": (None, render_compose),  # path depends on profile
    "env_example": ("examples/.env.example", render_env_example),
}


def load_profile(profile: str):
    """Load a Pkl profile and return the evaluated config object."""
    pkl_path = PROFILES.get(profile)
    if pkl_path is None:
        print(f"Unknown profile: {profile}", file=sys.stderr)
        print(f"Available profiles: {', '.join(PROFILES)}", file=sys.stderr)
        sys.exit(1)
    if not pkl_path.exists():
        print(f"Profile file not found: {pkl_path}", file=sys.stderr)
        sys.exit(1)
    return pkl.load(str(pkl_path))


def write_or_print(path: Path, content: str, dry_run: bool) -> None:
    """Write content to file, or print to stdout in dry-run mode."""
    if dry_run:
        print(f"--- {path} ---")
        print(content)
        print()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(f"  wrote {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ibctl config artifacts from Pkl models."
    )
    parser.add_argument(
        "--profile",
        default="base",
        choices=list(PROFILES),
        help="Pkl profile to use (default: base)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated output to stdout instead of writing files",
    )
    parser.add_argument(
        "--target",
        choices=["all", "toml", "compose", "env", "failover"],
        default="all",
        help="Which artifacts to generate (default: all)",
    )
    args = parser.parse_args()

    print(f"Loading profile: {args.profile}")
    cfg = load_profile(args.profile)
    print(f"  name={cfg.name} profile={cfg.profile} mode={cfg.deployment.tradingMode}")

    targets_to_run = args.target

    # TOML generation
    if targets_to_run in ("all", "toml"):
        print("Generating TOML configs...")
        docker_toml = render_docker_toml(cfg)
        write_or_print(ROOT / "docker" / "ibctl.toml", docker_toml, args.dry_run)

        example_toml = render_example_toml(cfg)
        write_or_print(ROOT / "ibctl.toml.example", example_toml, args.dry_run)

    # Compose generation
    if targets_to_run in ("all", "compose"):
        print("Generating Compose files...")
        compose_content = render_compose(cfg)
        compose_filename = f"docker-compose.{args.profile}.yml"
        write_or_print(
            ROOT / "examples" / compose_filename, compose_content, args.dry_run
        )

    # Env example generation
    if targets_to_run in ("all", "env"):
        print("Generating .env.example...")
        env_content = render_env_example(cfg)
        write_or_print(ROOT / "examples" / ".env.example", env_content, args.dry_run)

    # Failover manifest generation
    if targets_to_run in ("all", "failover"):
        print("Generating failover sync manifest...")
        from renderers.failover_manifest import generate_manifest
        manifest_content = generate_manifest()
        write_or_print(ROOT / "docker" / "failover-sync-manifest.json", manifest_content, args.dry_run)

    if not args.dry_run:
        print("Done.")


if __name__ == "__main__":
    main()
