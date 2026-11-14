"""Notification monitor plugins — registered with MonitorManager."""

from app.services.monitors.auth_relaunch import AuthRelaunchMonitor
from app.services.monitors.cold_restart_pending import ColdRestartPendingMonitor
from app.services.monitors.false_connected import FalseConnectedMonitor
from app.services.monitors.hitl_2fa import Hitl2faEntryMonitor
from app.services.monitors.ib_maintenance import IBMaintenanceMonitor
from app.services.monitors.login_failed import LoginFailedMonitor
from app.services.monitors.no_clients import NoClientsMonitor
from app.services.monitors.reconnect_giveup import ReconnectGiveUpMonitor
from app.services.monitors.relogin_failed import ReloginFailedMonitor
from app.services.monitors.session_conflict_loop import SessionConflictLoopMonitor
from app.services.monitors.session_lost import SessionLostMonitor
from app.services.monitors.twofa_push_waiting import TwoFaPushWaitingMonitor
from app.services.monitors.warm_restart import WarmRestartMonitor

__all__ = [
    "AuthRelaunchMonitor",
    "ColdRestartPendingMonitor",
    "FalseConnectedMonitor",
    "Hitl2faEntryMonitor",
    "LoginFailedMonitor",
    "NoClientsMonitor",
    "ReconnectGiveUpMonitor",
    "SessionConflictLoopMonitor",
    "SessionLostMonitor",
    "TwoFaPushWaitingMonitor",
    "ReloginFailedMonitor",
    "WarmRestartMonitor",
    "IBMaintenanceMonitor",
]
