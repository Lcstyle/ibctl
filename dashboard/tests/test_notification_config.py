"""Notification config — a saved file must not silently switch off newer events."""

from __future__ import annotations

import json

from app.services.notification_service import NotificationConfig


def test_an_event_added_after_the_file_was_saved_keeps_its_default(tmp_path):
    # A file saved before the gateway version events existed.
    saved = {"enabled": True, "events": {"connection_lost": {"enabled": True}}}
    path = tmp_path / "notifications.json"
    path.write_text(json.dumps(saved))

    config = NotificationConfig.load(str(path))

    assert config.events["gateway_desupport"] == {"enabled": True}
    assert config.events["gateway_update"] == {"enabled": True}


def test_a_saved_choice_still_wins_over_the_default(tmp_path):
    saved = {"enabled": True, "events": {"gateway_update": {"enabled": False}}}
    path = tmp_path / "notifications.json"
    path.write_text(json.dumps(saved))

    config = NotificationConfig.load(str(path))

    assert config.events["gateway_update"] == {"enabled": False}
    assert config.events["gateway_desupport"] == {"enabled": True}


def test_a_saved_event_the_code_no_longer_knows_is_kept(tmp_path):
    saved = {"events": {"retired_event": {"enabled": True, "timeout_minutes": 5}}}
    path = tmp_path / "notifications.json"
    path.write_text(json.dumps(saved))

    config = NotificationConfig.load(str(path))

    assert config.events["retired_event"] == {"enabled": True, "timeout_minutes": 5}
