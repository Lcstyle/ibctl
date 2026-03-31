"""Tests for IB System Status scraper — ping-based connectivity checks."""

from __future__ import annotations

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


class TestPing:
    """Test the _ping static method."""

    @patch("app.services.ib_status_scraper.subprocess.run")
    def test_ping_success(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert IBStatusScraper._ping("example.com") is True
        mock_run.assert_called_once_with(
            ["ping", "-c", "1", "-W", "3", "example.com"],
            capture_output=True, timeout=5,
        )

    @patch("app.services.ib_status_scraper.subprocess.run")
    def test_ping_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert IBStatusScraper._ping("unreachable.example") is False

    @patch("app.services.ib_status_scraper.subprocess.run")
    def test_ping_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=5)
        assert IBStatusScraper._ping("slow.example") is False

    @patch("app.services.ib_status_scraper.subprocess.run")
    def test_ping_no_binary(self, mock_run):
        mock_run.side_effect = FileNotFoundError("ping not found")
        assert IBStatusScraper._ping("example.com") is False


class TestCheckBackends:
    """Test backend connectivity via ping."""

    @patch.object(IBStatusScraper, "_ping")
    def test_both_reachable(self, mock_ping, scraper):
        mock_ping.return_value = True
        ok, hosts = scraper.check_backends()
        assert ok is True
        assert len(hosts) == 2

    @patch.object(IBStatusScraper, "_ping")
    def test_one_reachable(self, mock_ping, scraper):
        mock_ping.side_effect = [False, True]
        ok, hosts = scraper.check_backends()
        assert ok is True
        assert hosts == ["cdc1-hb2.ibllc.com"]

    @patch.object(IBStatusScraper, "_ping")
    def test_none_reachable(self, mock_ping, scraper):
        mock_ping.return_value = False
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

    @patch.object(IBStatusScraper, "_ping")
    def test_backends_reachable(self, mock_ping, scraper):
        # Backends respond — no need to check CDN
        mock_ping.return_value = True
        assert scraper.check_internet() is True

    @patch.object(IBStatusScraper, "_ping")
    def test_backends_down_cdn_up(self, mock_ping, scraper):
        # Backends fail, CDN responds — internet is up
        call_count = [0]
        def side_effect(host, timeout=3):
            call_count[0] += 1
            # First 2 calls are backends, 3rd is CDN fallback
            return call_count[0] > 2
        mock_ping.side_effect = side_effect
        assert scraper.check_internet() is True

    @patch.object(IBStatusScraper, "_ping")
    def test_everything_down(self, mock_ping, scraper):
        mock_ping.return_value = False
        assert scraper.check_internet() is False


class TestFetchStatus:
    """Test fetch_status — the main entry point."""

    @patch.object(IBStatusScraper, "check_internet", return_value=False)
    def test_no_internet(self, mock_internet, scraper):
        status = scraper.fetch_status()
        assert status.status == SystemStatus.NO_INTERNET

    @patch.object(IBStatusScraper, "check_internet", return_value=True)
    @patch.object(IBStatusScraper, "check_backends", return_value=(False, []))
    @patch("app.services.ib_status_scraper.requests.Session")
    def test_backends_down_still_scrapes(self, mock_session_cls, mock_backends, mock_internet, scraper):
        """When backends are down but internet is up, scraper proceeds to fetch the page."""
        mock_response = MagicMock()
        mock_response.text = "<html><body>All systems operational</body></html>"
        mock_response.raise_for_status = MagicMock()
        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        scraper._session = mock_session

        status = scraper.fetch_status()
        # Should NOT be OUTAGE — scraper checked the page
        assert status.status != SystemStatus.OUTAGE
        assert status.status != SystemStatus.NO_INTERNET
        # The session.get was called (page was scraped)
        mock_session.get.assert_called_once()

    @patch.object(IBStatusScraper, "check_internet", return_value=True)
    @patch.object(IBStatusScraper, "check_backends", return_value=(True, ["cdc1-hb1.ibllc.com"]))
    @patch("app.services.ib_status_scraper.requests.Session")
    def test_all_good_scrapes_page(self, mock_session_cls, mock_backends, mock_internet, scraper):
        """Normal path: everything reachable, scrapes and parses."""
        mock_response = MagicMock()
        mock_response.text = "<html><body>All systems operational</body></html>"
        mock_response.raise_for_status = MagicMock()
        mock_session = MagicMock()
        mock_session.get.return_value = mock_response
        scraper._session = mock_session

        status = scraper.fetch_status()
        assert status.status == SystemStatus.AVAILABLE
        mock_session.get.assert_called_once()
