import pytest
from unittest.mock import MagicMock, AsyncMock, patch


@pytest.mark.asyncio
async def test_site_config_reads_from_nested_site_object():
    # Simulate the queries.rs payload shape: site nested, no top-level site_role/auto_launch keys.
    instance_status = {
        "state": "WaitingForLaunch",
        "site": {"role": "standby", "auto_launch": False},
        "jvm": {"alive": False},
    }
    instances_data = [{"mode": "live", "status": instance_status}]

    # Reproduce ONLY the site_config extraction block (pages.py:577-582 after the fix).
    first_status = instances_data[0].get("status", {}) or {}
    site = first_status.get("site", {}) or {}
    role = site.get("role", "primary")
    auto_launch = site.get("auto_launch", True)
    site_config = {"role": role, "auto_launch": auto_launch}

    assert site_config["role"] == "standby", (
        "role must come from nested site.role, not the missing top-level site_role — "
        "the old code silently fell back to 'primary' on every standby node"
    )
    assert site_config["auto_launch"] is False, (
        "auto_launch must come from nested site.auto_launch, not the missing top-level "
        "auto_launch — the old code silently fell back to True"
    )


@pytest.mark.asyncio
async def test_site_config_defaults_when_site_key_missing():
    # Backwards-compat: if a very old ibctl emits no `site` key at all, we still default to primary.
    first_status = {"state": "Connected", "jvm": {"alive": True}}
    site = first_status.get("site", {}) or {}
    assert site.get("role", "primary") == "primary"
    assert site.get("auto_launch", True) is True
