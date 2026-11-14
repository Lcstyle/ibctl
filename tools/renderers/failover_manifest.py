"""Generate failover sync manifest from Pydantic models.

Produces a machine-readable JSON file describing ibctl's configuration
surface area for automated deployment tools: what to sync between sites,
what secrets are required, what to validate before promotion.

Derived from the schema — regenerate when config fields change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "dashboard"))

from app.preflight.models import ENV_MAP, SECRET_ENV_VARS


def generate_manifest() -> str:
    """Generate the failover sync manifest as JSON."""

    must_sync_prefixes = {
        "auth.", "twofa.", "session.", "gateway.gateway_or_tws",
        "gateway.java_heap_size", "command_server.enabled", "command_server.port",
        "dashboard.enabled", "dashboard.port", "site.",
        "timing.restart_delay_secs", "timing.relogin_failure_action",
        "timing.relogin_max_attempts", "timing.login_dialog_timeout_secs",
    }

    must_sync_vars = {}
    optional_sync_vars = {}
    for toml_path, env_var in ENV_MAP.items():
        entry = {"toml_path": toml_path, "env_var": env_var}
        if any(toml_path.startswith(p) for p in must_sync_prefixes):
            must_sync_vars[env_var] = entry
        else:
            optional_sync_vars[env_var] = entry

    extra_must_sync = {
        "TZ": {"description": "Timezone"},
        "AUTO_RESTART_TIME": {"description": "Daily restart time (UTC)"},
        "READ_ONLY_API": {"description": "API write access"},
    }

    manifest = {
        "_generated": "tools/renderers/failover_manifest.py",

        "must_sync": {
            "env_vars": {**must_sync_vars, **extra_must_sync},
        },

        "secrets": {
            "env_vars": sorted(SECRET_ENV_VARS),
            "file_suffix": "_FILE",
        },

        "optional_sync": {
            "env_vars": optional_sync_vars,
        },

        "files": {
            "sync": [
                "/opt/ibctl/persist/config/notifications.json",
                "/opt/ibctl/persist/config/scraper_overrides.json",
            ],
            "sync_gateway_state": [
                "$TWS_SETTINGS_PATH/jts.ini",
            ],
            "never_sync": [
                "/opt/ibctl/persist/config/ib_status_audit.json",
                "/opt/ibctl/persist/logs/",
                "/run/ibctl/*.sock",
                "$TWS_SETTINGS_PATH/.iborder",
                "$TWS_SETTINGS_PATH/.cold_restart_marker",
            ],
        },

        "standby_overrides": {
            "IBCTL_SITE_ROLE": "standby",
            "IBCTL_AUTO_LAUNCH": "false",
        },

        "promotion": {
            "command": "START",
            "overrides": {
                "IBCTL_SITE_ROLE": "primary",
                "IBCTL_AUTO_LAUNCH": "true",
            },
            "pre_checks": [
                "env_parity",
                "secrets_present",
                "jts_ini_synced",
                "primary_stopped",
                "command_server_responds",
            ],
        },

        "ports": {
            "command_server": {"live": 7462, "paper": 7463},
            "zmq_pub": 5556,
            "api": {"live": 4003, "paper": 4004},
            "dashboard": 3080,
        },
    }

    return json.dumps(manifest, indent=2)


if __name__ == "__main__":
    print(generate_manifest())
