"""Notification monitor plugins — registered with MonitorManager."""

from app.services.monitors.ib_maintenance import IBMaintenanceMonitor
from app.services.monitors.login_failed import LoginFailedMonitor
from app.services.monitors.no_clients import NoClientsMonitor
from app.services.monitors.relogin_failed import ReloginFailedMonitor
from app.services.monitors.session_lost import SessionLostMonitor
from app.services.monitors.warm_restart import WarmRestartMonitor

__all__ = [
    "LoginFailedMonitor",
    "NoClientsMonitor",
    "SessionLostMonitor",
    "ReloginFailedMonitor",
    "WarmRestartMonitor",
    "IBMaintenanceMonitor",
]
