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

    @patch.object(IBStatusScraper, "_check_host")
    def test_backends_reachable(self, mock_check, scraper):
        # Backends respond — no need to check CDN
        mock_check.return_value = True
        assert scraper.check_internet() is True

    @patch.object(IBStatusScraper, "_check_host")
    def test_backends_down_cdn_up(self, mock_check, scraper):
        # Backends fail, CDN responds — internet is up
        call_count = [0]
        def side_effect(host, port=443, timeout=3):
            call_count[0] += 1
            # First 2 calls are backends, 3rd is CDN fallback
            return call_count[0] > 2
        mock_check.side_effect = side_effect
        assert scraper.check_internet() is True

    @patch.object(IBStatusScraper, "_check_host")
    def test_everything_down(self, mock_check, scraper):
        mock_check.return_value = False
        assert scraper.check_internet() is False


class TestFetchStatus:
    """Test fetch_status — the main entry point."""

    @patch.object(IBStatusScraper, "check_internet", return_value=False)
    def test_no_internet(self, mock_internet, scraper):
        status = scraper.fetch_status()
        assert status.status == SystemStatus.NO_INTERNET

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
