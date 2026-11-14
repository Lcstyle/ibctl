"""Log retention (app.services.log_retention): logging.retention_days.

The daily log files of ibctl (live, paper, single mode) and the dashboard are
named by their day, ``<prefix>-YYYY-MM-DD.log``. With ``retention_days = N``
the dashboard deletes the files whose day is N or more days before today, so
N days are kept, today included. 0 keeps everything. Nothing else in the log
directory is ever touched.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from app.services import log_retention
from app.services.log_retention import LogRetentionMonitor, configured_retention_days, expired, prune

TODAY = date(2026, 11, 10)  # 90 days back: 2026-08-12


def make(log_dir: Path, *names: str) -> None:
    for name in names:
        (log_dir / name).write_text("x\n")


def names(paths) -> list[str]:
    return sorted(p.name for p in paths)


def test_ninety_days_keeps_today_and_the_89_days_before(tmp_path):
    make(tmp_path, "ibctl-live-2026-08-12.log", "ibctl-live-2026-08-13.log", "ibctl-live-2026-11-10.log")

    assert names(expired(tmp_path, TODAY, 90)) == ["ibctl-live-2026-08-12.log"]


def test_every_source_is_covered(tmp_path):
    old = ["dashboard-2026-04-09.log", "ibctl-2026-04-09.log", "ibctl-live-2026-04-09.log", "ibctl-paper-2026-04-09.log"]
    make(tmp_path, *old, "ibctl-paper-2026-11-01.log")

    assert names(expired(tmp_path, TODAY, 90)) == sorted(old)


def test_nothing_else_in_the_directory_is_touched(tmp_path):
    keep = [
        "uvicorn.stderr", "uvicorn.stderr.1", ".dashboard_crash.stamp", "notes-2020-01-01.log",
        "dashboard-2020-01-01.log.bak", "ibctl-live-2020-13-45.log", "ibctl-live-2020-01-01.txt",
    ]
    make(tmp_path, *keep)
    (tmp_path / "ibctl-live-2020-01-02.log").mkdir()  # a directory, not a log file

    assert expired(tmp_path, TODAY, 1) == []


def test_zero_keeps_everything(tmp_path):
    make(tmp_path, "ibctl-live-2020-01-01.log")

    assert expired(tmp_path, TODAY, 0) == []


def test_prune_deletes_and_reports(tmp_path):
    make(tmp_path, "dashboard-2026-01-01.log", "dashboard-2026-01-02.log", "dashboard-2026-11-10.log")

    result = prune(tmp_path, TODAY, 90)

    assert result.deleted == ["dashboard-2026-01-01.log", "dashboard-2026-01-02.log"]
    assert result.failed == []
    assert names(tmp_path.iterdir()) == ["dashboard-2026-11-10.log"]


def test_a_file_that_cannot_be_deleted_is_reported_and_the_rest_go(tmp_path, monkeypatch):
    make(tmp_path, "dashboard-2026-01-01.log", "dashboard-2026-01-02.log")
    real_unlink = Path.unlink

    def unlink(self, *a, **k):
        if self.name == "dashboard-2026-01-01.log":
            raise PermissionError("read-only")
        return real_unlink(self, *a, **k)

    monkeypatch.setattr(Path, "unlink", unlink)
    result = prune(tmp_path, TODAY, 90)

    assert result.deleted == ["dashboard-2026-01-02.log"]
    assert [name for name, _ in result.failed] == ["dashboard-2026-01-01.log"]


def test_a_missing_log_directory_is_nothing_to_do(tmp_path):
    assert prune(tmp_path / "absent", TODAY, 90).deleted == []


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / "ibctl.toml"
    monkeypatch.setenv("IBCTL_CONFIG", str(path))
    monkeypatch.delenv("IBCTL_LOG_RETENTION_DAYS", raising=False)
    return path


def test_the_setting_comes_from_the_config_file(config_file):
    config_file.write_text("[logging]\nretention_days = 90\n")

    assert configured_retention_days() == 90


def test_the_env_var_overrides_the_file(config_file, monkeypatch):
    config_file.write_text("[logging]\nretention_days = 90\n")
    monkeypatch.setenv("IBCTL_LOG_RETENTION_DAYS", "30")

    assert configured_retention_days() == 30


@pytest.mark.parametrize("toml", ["", "[logging]\nlevel = 'info'\n", "[logging]\nretention_days = -5\n"])
def test_unset_or_invalid_keeps_everything(config_file, toml):
    config_file.write_text(toml)

    assert configured_retention_days() == 0


def test_a_missing_config_file_keeps_everything(config_file):
    assert configured_retention_days() == 0


@pytest.mark.asyncio
async def test_the_monitor_prunes_with_the_configured_days(tmp_path):
    make(tmp_path, "ibctl-live-2026-01-01.log", "ibctl-live-2026-11-10.log")
    monitor = LogRetentionMonitor(str(tmp_path), keep_days=lambda: 90, today=lambda: TODAY)

    assert await monitor.check(None, None) == []
    assert names(tmp_path.iterdir()) == ["ibctl-live-2026-11-10.log"]


@pytest.mark.asyncio
async def test_the_monitor_does_nothing_at_zero(tmp_path):
    make(tmp_path, "ibctl-live-2026-01-01.log")
    monitor = LogRetentionMonitor(str(tmp_path), keep_days=lambda: 0, today=lambda: TODAY)

    await monitor.check(None, None)
    assert names(tmp_path.iterdir()) == ["ibctl-live-2026-01-01.log"]


def test_the_monitor_runs_a_few_times_a_day():
    assert log_retention.LogRetentionMonitor.interval_seconds <= 24 * 3600
