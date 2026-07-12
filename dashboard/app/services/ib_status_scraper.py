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
import time
from dataclasses import dataclass, field
from datetime import datetime
from datetime import time as dt_time
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

    # Exchange/venue names that indicate venue-specific (non-blocking) outages.
    # These alerts affect a single exchange or crypto venue, not IB's core systems.
    EXCHANGE_KEYWORDS: ClassVar[list[str]] = [
        # Major futures/options exchanges
        "CME", "CBOE", "CBOT", "COMEX", "NYMEX", "NYSE", "NASDAQ", "ISE",
        "ICE", "EUREX", "LSE", "TSE", "ASX", "SGX", "HKEX",
        # Crypto venues
        "PAXOS", "COINBASE",
        # Other venues
        "ARCA", "BATS", "IEX", "MEMX", "MIAX", "PEARL", "AMEX",
        "TSX", "VENTURE", "IDEAL", "IBKRATS",
    ]

    # Phrases in alert text that indicate the alert is NOT about an outage
    BENIGN_PHRASES: ClassVar[list[str]] = [
        "IS AVAILABLE",
        "SYSTEMS ARE AVAILABLE",
        "OPERATING NORMALLY",
        "HAS BEEN RESOLVED",
        "IS NOW AVAILABLE",
    ]

    def is_blocking(self) -> bool:
        """Is this a system-wide outage (not exchange-specific, not benign)?"""
        if self._is_exchange_specific():
            return False
        if self._is_benign():
            return False
        return self.severity in (AlertSeverity.CRITICAL, AlertSeverity.WARNING)

    def _is_exchange_specific(self) -> bool:
        msg_upper = self.message.upper()
        for exchange in self.EXCHANGE_KEYWORDS:
            if f"TO {exchange} TRADERS" in msg_upper:
                return True
            if f"{exchange} IS CURRENTLY UNAVAILABLE" in msg_upper:
                return True
            if f"{exchange} IS UNAVAILABLE" in msg_upper:
                return True
        if "TECHNICAL PROBLEMS AT THE EXCHANGE" in msg_upper:
            return True
        # "at the exch" pattern (IB truncates "exchange" in some alerts)
        if "AT THE EXCH" in msg_upper:
            return True
        return False

    def _is_benign(self) -> bool:
        """Return True if this alert indicates a healthy/resolved state."""
        msg_upper = self.message.upper()
        return any(phrase in msg_upper for phrase in self.BENIGN_PHRASES)


@dataclass(frozen=True)
class ResetWindow:
    region: str  # NA, EU, APAC
    start_time: dt_time
    end_time: dt_time
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
        fallback_host: str = "interactivebrokers.com",
        probe_retries: int = 2,
        probe_retry_delay: float = 0.2,
        promote_after_consecutive_failures: int = 3,
    ):
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.blocking_keywords = blocking_keywords or [
            "maintenance", "unavailable", "unable", "outage", "disruption",
        ]
        self.ignore_exchanges = ignore_exchanges or list(SystemAlert.EXCHANGE_KEYWORDS)
        self.region = region
        self.backend_hosts = ["cdc1-hb1.ibllc.com", "cdc1-hb2.ibllc.com"] if backend_hosts is None else backend_hosts
        self.fallback_host = fallback_host
        # Per-host retry inside a single check_internet() call. Absorbs
        # sub-second DNS/AAAA/roam glitches without flipping status.
        self.probe_retries = probe_retries
        self.probe_retry_delay = probe_retry_delay
        # Consecutive-failure hysteresis on fetch_status(). Nine flap events
        # between 2026-04-15 and 2026-07-09 traced to single-cycle probe
        # failures; requiring N consecutive cycles removes the false positives
        # while keeping detection latency <= N * check_interval.
        self.promote_after_consecutive_failures = promote_after_consecutive_failures


class IBStatusScraper:
    """Scrapes and parses the IB system status page."""

    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def __init__(self, config: ScraperConfig | None = None):
        self.config = config or ScraperConfig()
        self._session: requests.Session | None = None
        self._last_status: IBSystemStatus | None = None
        # Tracks how many consecutive fetch_status() cycles have seen an
        # internet-probe failure. Reset to 0 on any successful probe. Only
        # promote status to NO_INTERNET when this crosses the config threshold.
        self._consecutive_internet_failures: int = 0

    def _get_session(self) -> requests.Session:
        if self._session is None:
            self._session = requests.Session()
            self._session.headers.update({"User-Agent": self.USER_AGENT})
        return self._session

    @staticmethod
    def _check_host(host: str, port: int = 443, timeout: int = 3) -> bool:
        """Check host reachability via TCP socket.

        Works in environments where ICMP ping is blocked (e.g. Kubernetes).
        ConnectionRefusedError is treated as reachable — the host responds,
        the port just isn't open (expected for IB backend servers).
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            logger.debug("TCP probe to %s:%d was refused; treating host as reachable", host, port)
            return True  # Host is up, port closed — routing works
        except socket.gaierror as e:
            logger.debug("TCP probe DNS resolution failed for %s:%d: %s", host, port, e)
        except socket.timeout:
            logger.debug("TCP probe to %s:%d timed out", host, port)
        except OSError as e:
            logger.debug("TCP probe to %s:%d failed: %s", host, port, e)
            return False
        return False

    def check_backends(self) -> tuple[bool, list[str]]:
        """Check connectivity to IB backend servers via TCP.

        Uses TCP socket on port 443; treats ECONNREFUSED as reachable since
        IB backend hosts don't expose public TCP ports. Works in Kubernetes
        where ICMP is typically blocked by CNI or NetworkPolicy.

        Returns (any_reachable, list_of_reachable_hosts).
        """
        reachable = []
        for host in self.config.backend_hosts:
            if self._check_host(host):
                reachable.append(host)
        return len(reachable) > 0, reachable

    def check_internet(self) -> bool:
        """Check basic internet connectivity with per-host retry.

        Tries each backend host + CDN fallback in order. Each host gets
        `probe_retries + 1` total attempts with `probe_retry_delay` seconds
        between them. First successful probe returns True; only after ALL
        hosts have exhausted their retries do we return False.

        Rationale: a single-shot 3s TCP probe is fragile against transient
        DNS/AAAA/roam glitches. Nine "no_internet -> available" flap events
        between 2026-04 and 2026-07 traced to sub-10s probe failures during
        routine network cycling. Per-host retry absorbs the transient class
        without slowing the happy path (first host / first attempt wins in
        the common case, one _check_host call total).
        """
        for host in self.config.backend_hosts + [self.config.fallback_host]:
            for attempt in range(self.config.probe_retries + 1):
                if self._check_host(host, 443):
                    return True
                if attempt < self.config.probe_retries:
                    time.sleep(self.config.probe_retry_delay)
        return False

    def fetch_status(self) -> IBSystemStatus:
        """Fetch and parse the IB system status page."""
        # Hysteresis gate: only promote to NO_INTERNET after N consecutive
        # failed probe cycles. A single failed cycle returns the cached
        # status (or UNKNOWN if none) to avoid audit-log flap.
        if not self.check_internet():
            self._consecutive_internet_failures += 1
            threshold = self.config.promote_after_consecutive_failures
            if self._consecutive_internet_failures < threshold:
                logger.info(
                    "Internet probe failed (%d/%d consecutive) — deferring promotion",
                    self._consecutive_internet_failures, threshold,
                )
                if self._last_status is not None:
                    return self._last_status
                return IBSystemStatus(
                    status=SystemStatus.UNKNOWN,
                    fetch_error=(
                        f"Internet probe failed ({self._consecutive_internet_failures}/"
                        f"{threshold} consecutive) — deferring promotion; no cached status yet"
                    ),
                )
            logger.warning(
                "Internet probe failed %d consecutive cycles — promoting to NO_INTERNET",
                self._consecutive_internet_failures,
            )
            return IBSystemStatus(
                status=SystemStatus.NO_INTERNET,
                fetch_error="Internet connectivity check failed — backends and CDN unreachable",
            )
        if self._consecutive_internet_failures > 0:
            logger.info(
                "Internet probe recovered after %d consecutive failures",
                self._consecutive_internet_failures,
            )
        self._consecutive_internet_failures = 0

        # Backend TCP probe is informational — if backends are down but CDN is up,
        # we still scrape the status page (it's the authoritative source)
        backends_ok, reachable = self.check_backends()
        if not backends_ok and self.config.backend_hosts:
            logger.warning(
                "IB backend servers not responding to TCP probe: %s",
                self.config.backend_hosts,
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
                    time.sleep(delay)
                    delay *= 2

        # All retries failed
        logger.error("IB status scrape failed after %d retries", self.config.max_retries + 1)
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

        if status.alerts:
            blocking = [a for a in status.alerts if a.is_blocking()]
            exchange = [a for a in status.alerts if a._is_exchange_specific()]
            benign = [a for a in status.alerts if a._is_benign()]
            logger.info(
                "IB status: %s (%d alerts: %d blocking, %d exchange-specific, %d benign)",
                status.status.value, len(status.alerts),
                len(blocking), len(exchange), len(benign),
            )
            for a in blocking:
                logger.warning("Blocking alert: [%s] %s", a.severity.value, a.message[:150])
            for a in exchange:
                logger.debug("Exchange alert (non-blocking): %s", a.message[:150])
        else:
            logger.debug("IB status: %s (no alerts)", status.status.value)

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
        # Check benign phrases first — "is available" should not escalate
        if any(p.lower() in lower for p in SystemAlert.BENIGN_PHRASES):
            return AlertSeverity.INFO
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
    def _parse_time(time_str: str) -> dt_time | None:
        match = re.match(r"(\d{1,2}):(\d{2})", time_str)
        if match:
            return dt_time(int(match.group(1)), int(match.group(2)))
        return None

    def _determine_status(self, status: IBSystemStatus) -> SystemStatus:
        """Determine overall system status from alerts and reset windows."""
        if status.has_blocking_alerts():
            return SystemStatus.OUTAGE

        in_reset, _ = status.is_in_reset_window(self.config.region)
        if in_reset:
            return SystemStatus.MAINTENANCE

        return SystemStatus.AVAILABLE
