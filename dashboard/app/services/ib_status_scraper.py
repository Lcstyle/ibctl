"""IB System Status page scraper.

Parses the IB system status page
for maintenance windows, outages, and alerts. Determines overall availability.

The dashboard runs this scraper and pushes results to ibctl via IBSTATUS command.
ibctl's state machine uses it to enter WaitingForIB during maintenance.

Configurable detection rules allow tuning what triggers a lockout.
"""

from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, time
from enum import Enum
from typing import ClassVar
from zoneinfo import ZoneInfo

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("dashboard.services.ib_status")


class SystemStatus(Enum):
    AVAILABLE = "available"
    MAINTENANCE = "maintenance"
    OUTAGE = "outage"
    SCHEDULED_MAINTENANCE = "scheduled"
    NO_INTERNET = "no_internet"
    UNKNOWN = "unknown"


class AlertSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    SCHEDULED = "scheduled"


@dataclass(frozen=True)
class SystemAlert:
    severity: AlertSeverity
    message: str
    message_id: str = ""

    # Exchange names that indicate exchange-specific (non-blocking) outages
    EXCHANGE_KEYWORDS: ClassVar[list[str]] = [
        "CME", "CBOE", "CBOT", "COMEX", "NYMEX", "NYSE", "NASDAQ", "ISE",
        "ICE", "EUREX", "LSE", "TSE", "ASX", "SGX", "HKEX",
    ]

    def is_blocking(self) -> bool:
        """Is this a system-wide outage (not exchange-specific)?"""
        if self._is_exchange_specific():
            return False
        return self.severity in (AlertSeverity.CRITICAL, AlertSeverity.WARNING)

    def _is_exchange_specific(self) -> bool:
        msg_upper = self.message.upper()
        for exchange in self.EXCHANGE_KEYWORDS:
            if f"TO {exchange} TRADERS" in msg_upper:
                return True
            if f"{exchange} IS CURRENTLY UNAVAILABLE" in msg_upper:
                return True
        if "TECHNICAL PROBLEMS AT THE EXCHANGE" in msg_upper:
            return True
        return False


@dataclass(frozen=True)
class ResetWindow:
    region: str  # NA, EU, APAC
    start_time: time
    end_time: time
    timezone: str  # IANA timezone name
    is_weekend: bool = False
    description: str = ""


@dataclass
class IBSystemStatus:
    status: SystemStatus = SystemStatus.UNKNOWN
    alerts: list[SystemAlert] = field(default_factory=list)
    daily_resets: list[ResetWindow] = field(default_factory=list)
    weekend_resets: list[ResetWindow] = field(default_factory=list)
    last_updated: datetime | None = None
    fetch_error: str | None = None

    def has_blocking_alerts(self) -> bool:
        return any(a.is_blocking() for a in self.alerts)

    def is_in_reset_window(self, region: str = "NA") -> tuple[bool, ResetWindow | None]:
        """Check if current time is within a maintenance reset window."""
        now = datetime.now(ZoneInfo("UTC"))
        for window in self.daily_resets + self.weekend_resets:
            if window.region.upper() != region.upper():
                continue
            if window.is_weekend and now.weekday() < 5:
                continue
            try:
                tz = ZoneInfo(window.timezone)
                local_now = now.astimezone(tz).time()
                if window.start_time <= window.end_time:
                    if window.start_time <= local_now <= window.end_time:
                        return True, window
                else:
                    # Crosses midnight
                    if local_now >= window.start_time or local_now <= window.end_time:
                        return True, window
            except Exception:
                continue
        return False, None


class ScraperConfig:
    """Configurable detection rules for the IB status page scraper.

    All settings can be overridden via environment variables or ibctl.toml.
    """

    def __init__(
        self,
        url: str = "https://www.interactivebrokers.com/en/software/systemStatus.php",
        timeout: int = 10,
        max_retries: int = 2,
        blocking_keywords: list[str] | None = None,
        ignore_exchanges: list[str] | None = None,
        region: str = "NA",
        backend_hosts: list[str] | None = None,
        backend_port: int = 443,
        fallback_host: str = "interactivebrokers.com",
        fallback_port: int = 443,
    ):
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.blocking_keywords = blocking_keywords or [
            "maintenance", "unavailable", "unable", "outage", "disruption",
        ]
        self.ignore_exchanges = ignore_exchanges or list(SystemAlert.EXCHANGE_KEYWORDS)
        self.region = region
        self.backend_hosts = backend_hosts or ["cdc1-hb1.ibllc.com", "cdc1-hb2.ibllc.com"]
        self.backend_port = backend_port
        self.fallback_host = fallback_host
        self.fallback_port = fallback_port


class IBStatusScraper:
    """Scrapes and parses the IB system status page."""

    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def __init__(self, config: ScraperConfig | None = None):
        self.config = config or ScraperConfig()
        self._session: requests.Session | None = None
        self._last_status: IBSystemStatus | None = None

    def _get_session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": self.USER_AGENT})
        return self._session

    def check_backends(self) -> tuple[bool, list[str]]:
        """Check connectivity to IB backend servers (configurable via ScraperConfig).

        Returns (any_reachable, list_of_reachable_hosts).
        """
        reachable = []
        for host in self.config.backend_hosts:
            try:
                socket.create_connection((host, self.config.backend_port), timeout=5)
                reachable.append(host)
            except (socket.timeout, OSError):
                continue
        return len(reachable) > 0, reachable

    def check_internet(self) -> bool:
        """Check basic internet connectivity (IB backends first, then CDN fallback)."""
        backends_ok, _ = self.check_backends()
        if backends_ok:
            return True
        # Both backends unreachable — try the status page host as fallback
        try:
            socket.create_connection((self.config.fallback_host, self.config.fallback_port), timeout=5)
            return True
        except (socket.timeout, OSError):
            return False

    def fetch_status(self) -> IBSystemStatus:
        """Fetch and parse the IB system status page."""
        # Check internet first
        if not self.check_internet():
            return IBSystemStatus(
                status=SystemStatus.NO_INTERNET,
                fetch_error="Internet connectivity check failed — IB backends and CDN unreachable",
            )

        # Check IB backends separately — website could be up while trading infra is down
        backends_ok, reachable = self.check_backends()
        if not backends_ok:
            return IBSystemStatus(
                status=SystemStatus.OUTAGE,
                fetch_error="IB trading backends unreachable (cdc1-hb1/hb2.ibllc.com) — website CDN is up but trading infra may be down",
                alerts=[SystemAlert(
                    severity=AlertSeverity.CRITICAL,
                    message="IB backend servers unreachable — trading infrastructure may be down",
                )],
            )

        session = self._get_session()
        delay = 1.0

        for attempt in range(self.config.max_retries + 1):
            try:
                resp = session.get(self.config.url, timeout=self.config.timeout)
                resp.raise_for_status()
                return self._parse_response(resp.text)
            except requests.RequestException as e:
                logger.debug("Scrape attempt %d failed: %s", attempt + 1, e)
                if attempt < self.config.max_retries:
                    import time as time_mod
                    time_mod.sleep(delay)
                    delay *= 2

        # All retries failed
        if self._last_status:
            self._last_status.fetch_error = "Using cached status (scrape failed)"
            return self._last_status

        return IBSystemStatus(
            status=SystemStatus.UNKNOWN,
            fetch_error="Failed to fetch IB status page after retries",
        )

    def _parse_response(self, html: str) -> IBSystemStatus:
        """Parse the HTML response into structured status."""
        soup = BeautifulSoup(html, "html.parser")
        status = IBSystemStatus()

        try:
            status.alerts = self._parse_alerts(soup)
        except Exception as e:
            logger.debug("Failed to parse alerts: %s", e)

        try:
            status.daily_resets = self._parse_resets(soup, weekend=False)
        except Exception as e:
            logger.debug("Failed to parse daily resets: %s", e)

        try:
            status.weekend_resets = self._parse_resets(soup, weekend=True)
        except Exception as e:
            logger.debug("Failed to parse weekend resets: %s", e)

        status.last_updated = datetime.now(ZoneInfo("UTC"))
        status.status = self._determine_status(status)
        self._last_status = status
        return status

    def _parse_alerts(self, soup: BeautifulSoup) -> list[SystemAlert]:
        """Extract alerts from the status page."""
        alerts = []
        # Look for alert/status divs
        for div in soup.find_all("div", class_=re.compile(r"alert|status|message", re.I)):
            text = div.get_text(strip=True)
            if len(text) < 10:
                continue
            severity = self._classify_severity(text)
            alerts.append(SystemAlert(severity=severity, message=text))

        # Also check table rows
        for table in soup.find_all("table"):
            for row in table.find_all("tr"):
                cells = row.find_all("td")
                if len(cells) >= 1:
                    text = cells[0].get_text(strip=True)
                    if any(kw in text.lower() for kw in self.config.blocking_keywords):
                        severity = self._classify_severity(text)
                        alerts.append(SystemAlert(severity=severity, message=text))

        return alerts

    def _classify_severity(self, message: str) -> AlertSeverity:
        lower = message.lower()
        if "scheduled" in lower:
            return AlertSeverity.SCHEDULED
        if any(kw in lower for kw in ["unavailable", "outage", "disruption", "unable"]):
            return AlertSeverity.CRITICAL
        if any(kw in lower for kw in ["maintenance", "reset"]):
            return AlertSeverity.WARNING
        return AlertSeverity.INFO

    def _parse_resets(self, soup: BeautifulSoup, weekend: bool = False) -> list[ResetWindow]:
        """Parse maintenance reset windows from tables."""
        windows = []
        region_tz = {
            "NA": "America/New_York",
            "EU": "Europe/Zurich",
            "APAC": "Asia/Hong_Kong",
        }

        for table in soup.find_all("table"):
            header_text = ""
            header = table.find("thead") or table.find("tr")
            if header:
                header_text = header.get_text(strip=True).lower()

            for region, tz in region_tz.items():
                if region.lower() in header_text or region.lower() in table.get_text(strip=True).lower():
                    # Extract time patterns HH:MM-HH:MM
                    text = table.get_text()
                    for match in re.finditer(r"(\d{1,2}:\d{2})\s*[-–]\s*(\d{1,2}:\d{2})", text):
                        try:
                            start = self._parse_time(match.group(1))
                            end = self._parse_time(match.group(2))
                            if start and end:
                                windows.append(ResetWindow(
                                    region=region,
                                    start_time=start,
                                    end_time=end,
                                    timezone=tz,
                                    is_weekend=weekend,
                                ))
                        except Exception:
                            continue

        return windows

    @staticmethod
    def _parse_time(time_str: str) -> time | None:
        match = re.match(r"(\d{1,2}):(\d{2})", time_str)
        if match:
            return time(int(match.group(1)), int(match.group(2)))
        return None

    def _determine_status(self, status: IBSystemStatus) -> SystemStatus:
        """Determine overall system status from alerts and reset windows."""
        if status.has_blocking_alerts():
            return SystemStatus.OUTAGE

        in_reset, _ = status.is_in_reset_window(self.config.region)
        if in_reset:
            return SystemStatus.MAINTENANCE

        return SystemStatus.AVAILABLE
