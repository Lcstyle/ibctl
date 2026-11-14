"""Tests for domain models."""

from app.domain.models import ClientAdvisory, GatewayStatus, StateMachineState


def test_gateway_status_from_json():
    data = {
        "ready": True,
        "state": "Connected",
        "trading_mode": "both",
        "uptime_secs": 3600,
        "socat_running": True,
        "jvm_running": True,
        "stats": {"restarts_today": 1, "dialogs_dismissed": 4},
        "client_advisory": {
            "should_connect": True,
            "should_wait": False,
            "wait_reason": None,
            "client_id_likely_stale": False,
        },
    }
    status = GatewayStatus.from_json(data)

    assert status.ready is True
    assert status.state == "Connected"
    assert status.stats.restarts_today == 1
    assert status.client_advisory.should_connect is True
    assert status.client_advisory.should_wait is False


def test_gateway_status_from_empty_json():
    status = GatewayStatus.from_json({})
    assert status.ready is False
    assert status.state == "unknown"
    assert status.client_advisory.should_wait is True


def test_state_machine_state_from_json():
    data = {
        "current": "Connected",
        "history": [
            {"timestamp": "123456", "from": "Init", "to": "Launching"},
            {"timestamp": "123457", "from": "Launching", "to": "Connected"},
        ],
    }
    state = StateMachineState.from_json(data)

    assert state.current == "Connected"
    assert len(state.history) == 2
    assert state.history[0].from_state == "Init"
    assert state.history[1].to_state == "Connected"


def test_client_advisory_immutable():
    advisory = ClientAdvisory(should_connect=True, should_wait=False)
    assert advisory.should_connect is True
    # Frozen dataclass — can't mutate
    try:
        advisory.should_connect = False  # type: ignore
        assert False, "Should have raised FrozenInstanceError"
    except AttributeError:
        pass
