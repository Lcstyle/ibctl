"""Tests for IB System Status scraper — TCP-based connectivity checks."""

from __future__ import annotations

import socket
from unittest.mock import patch, MagicMock

import pytest

from app.services.ib_status_scraper import (
    IBStatusScraper,
    ScraperConfig,
    SystemStatus,
)


@pytest.fixture
def scraper():
    config = ScraperConfig(
        backend_hosts=["cdc1-hb1.ibllc.com", "cdc1-hb2.ibllc.com"],
        fallback_host="interactivebrokers.com",
    )
    return IBStatusScraper(config)


class TestCheckHost:
    """Test the _check_host static method (TCP socket connectivity)."""

    @patch("app.services.ib_status_scraper.socket.create_connection")
    def test_host_reachable(self, mock_conn):
        mock_conn.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)
        assert IBStatusScraper._check_host("example.com") is True

    @patch("app.services.ib_status_scraper.socket.create_connection")
    def test_host_unreachable(self, mock_conn):
        mock_conn.side_effect = socket.timeout("timed out")
        assert IBStatusScraper._check_host("unreachable.example") is False

    @patch("app.services.ib_status_scraper.socket.create_connection")
    def test_host_connection_refused_treated_as_reachable(self, mock_conn):
        # ECONNREFUSED means the host is up, port just not open
        mock_conn.side_effect = ConnectionRefusedError()
        assert IBStatusScraper._check_host("example.com") is True

    @patch("app.services.ib_status_scraper.socket.create_connection")
    def test_host_os_error(self, mock_conn):
        mock_conn.side_effect = OSError("network unreachable")
        assert IBStatusScraper._check_host("example.com") is False

    @patch("app.services.ib_status_scraper.socket.create_connection")
    def test_host_dns_error(self, mock_conn):
        mock_conn.side_effect = socket.gaierror("name or service not known")
        assert IBStatusScraper._check_host("bad-host.example") is False


class TestCheckBackends:
    """Test backend connectivity via TCP."""

    @patch.object(IBStatusScraper, "_check_host")
    def test_both_reachable(self, mock_check, scraper):
        mock_check.return_value = True
        ok, hosts = scraper.check_backends()
        assert ok is True
        assert len(hosts) == 2

    @patch.object(IBStatusScraper, "_check_host")
    def test_one_reachable(self, mock_check, scraper):
        mock_check.side_effect = [False, True]
        ok, hosts = scraper.check_backends()
        assert ok is True
        assert hosts == ["cdc1-hb2.ibllc.com"]

    @patch.object(IBStatusScraper, "_check_host")
    def test_none_reachable(self, mock_check, scraper):
        mock_check.return_value = False
        ok, hosts = scraper.check_backends()
        assert ok is False
        assert hosts == []

    def test_empty_backend_hosts(self):
        config = ScraperConfig(backend_hosts=[])
        s = IBStatusScraper(config)
        ok, hosts = s.check_backends()
        assert ok is False
        assert hosts == []


class TestCheckInternet:
    """Test internet connectivity — backends first, then CDN fallback."""

    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        # Zero out the per-host retry delay so tests don't spend real seconds
        # sleeping. The fix has a 200ms delay between retry attempts by default.
        monkeypatch.setattr("app.services.ib_status_scraper.time.sleep", lambda _: None)

    @patch.object(IBStatusScraper, "_check_host")
    def test_backends_reachable(self, mock_check, scraper):
        # Backends respond — no need to check CDN
        mock_check.return_value = True
        assert scraper.check_internet() is True

    @patch.object(IBStatusScraper, "_check_host")
    def test_backends_down_cdn_up(self, mock_check, scraper):
        # First host fails all retries, second host + CDN unused because second
        # succeeds first attempt. With probe_retries=2 default: host1 gets 3
        # attempts (all False), host2 gets 1 attempt (True) → 4 calls total.
        mock_check.side_effect = [False, False, False, True]
        assert scraper.check_internet() is True

    @patch.object(IBStatusScraper, "_check_host")
    def test_everything_down(self, mock_check, scraper):
        mock_check.return_value = False
        assert scraper.check_internet() is False

    @patch.object(IBStatusScraper, "_check_host")
    def test_first_attempt_wins_fast_path(self, mock_check, scraper):
        # Happy path: first host's first attempt succeeds → no retries triggered.
        # Guards against a regression where retry loop always exhausts.
        mock_check.return_value = True
        scraper.check_internet()
        assert mock_check.call_count == 1

    @patch.object(IBStatusScraper, "_check_host")
    def test_transient_glitch_recovers_within_retries(self, mock_check, scraper):
        # Single sub-second DNS/AAAA/roam glitch on host1 → retry on host1
        # succeeds → returns True without touching host2 or CDN.
        # This is the exact "no_internet flap" pattern from the 04-15 → 07-09
        # audit history.
        mock_check.side_effect = [False, True]
        assert scraper.check_internet() is True
        assert mock_check.call_count == 2


class TestFetchStatusHysteresis:
    """Test the consecutive-failure hysteresis on internet probe promotion."""

    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        monkeypatch.setattr("app.services.ib_status_scraper.time.sleep", lambda _: None)

    @patch.object(IBStatusScraper, "check_internet", return_value=False)
    def test_single_probe_failure_does_not_flip_to_no_internet(self, mock_internet, scraper):
        """A single failed probe cycle must NOT promote status to NO_INTERNET.

        The exact flap pattern the fix addresses. Before hysteresis, this
        would return NO_INTERNET on the first check.
        """
        status = scraper.fetch_status()
        assert status.status != SystemStatus.NO_INTERNET

    @patch.object(IBStatusScraper, "check_internet", return_value=False)
    def test_two_consecutive_failures_still_deferred(self, mock_internet, scraper):
        """Two failed cycles < default threshold of 3 → still deferred."""
        scraper.fetch_status()
        status = scraper.fetch_status()
        assert status.status != SystemStatus.NO_INTERNET

    @patch.object(IBStatusScraper, "check_internet", return_value=False)
    def test_three_consecutive_failures_promotes_to_no_internet(self, mock_internet, scraper):
        """Threshold reached → promote to NO_INTERNET."""
        scraper.fetch_status()
        scraper.fetch_status()
        status = scraper.fetch_status()
        assert status.status == SystemStatus.NO_INTERNET
        assert "Internet connectivity check failed" in (status.fetch_error or "")

    def test_success_resets_counter(self, scraper):
        """A single successful cycle resets the counter — 2 fails, 1 pass, 2 fails MUST NOT promote."""
        with patch.object(IBStatusScraper, "check_internet", return_value=False):
            scraper.fetch_status()
            scraper.fetch_status()
        # Success interlude — need to also mock the HTTP path to complete cleanly
        with patch.object(IBStatusScraper, "check_internet", return_value=True), \
             patch.object(IBStatusScraper, "check_backends", return_value=(True, [])), \
             patch.object(IBStatusScraper, "_get_session") as mock_session:
            resp = MagicMock()
            resp.text = "<html><body>Status: OK</body></html>"
            resp.raise_for_status = MagicMock()
            mock_session.return_value.get.return_value = resp
            scraper.fetch_status()
        # Now two more fails — should NOT promote because counter was reset
        with patch.object(IBStatusScraper, "check_internet", return_value=False):
            scraper.fetch_status()
            status = scraper.fetch_status()
        assert status.status != SystemStatus.NO_INTERNET

    @patch.object(IBStatusScraper, "check_internet", return_value=False)
    def test_first_run_without_cache_returns_unknown_not_no_internet(self, mock_internet, scraper):
        """Cold scraper (no cached status yet) + probe failure below threshold
        → return UNKNOWN, not the stale IBSystemStatus() default construction.
        """
        status = scraper.fetch_status()
        assert status.status == SystemStatus.UNKNOWN
        assert status.fetch_error is not None
        assert "deferring promotion" in status.fetch_error


class TestFetchStatus:
    """Test fetch_status — the main entry point."""

    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        monkeypatch.setattr("app.services.ib_status_scraper.time.sleep", lambda _: None)

    @patch.object(IBStatusScraper, "check_internet", return_value=True)
    @patch.object(IBStatusScraper, "check_backends", return_value=(True, ["cdc1-hb1.ibllc.com"]))
    def test_fetch_error_returns_unknown_status(self, mock_backends, mock_internet, scraper):
        """When HTTP fetch fails after retries, return UNKNOWN status."""
        import requests
        with patch.object(scraper, "_get_session") as mock_session:
            mock_session.return_value.get.side_effect = requests.RequestException("Connection refused")
            status = scraper.fetch_status()
            assert status.status == SystemStatus.UNKNOWN
            assert status.fetch_error is not None
