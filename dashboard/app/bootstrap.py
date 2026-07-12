"""Crash-capture bootstrap — must be imported as the FIRST module in main.py.

Installs four hooks BEFORE any other dashboard code runs so that no failure
mode after this point can die silently:

  1. setup_dashboard_logging()  — ensures the JSONL file handler is live
     before any other module imports. Without this the excepthook below
     would fall back to root's default StreamHandler (stderr) — which is
     exactly the path that lost the 2026-06-20 traceback.
  2. sys.excepthook              — catches uncaught exceptions on the main
     thread, logs them at CRITICAL with full traceback to the JSONL file,
     calls logging.shutdown() to flush, then chains to the default
     excepthook so docker stderr behaviour is preserved.
  3. threading.excepthook        — same idea for crashes in background
     threads (these never reach sys.excepthook).
  4. SIGTERM/SIGINT handlers     — log signal receipt. A signal record
     followed by a startup record = killed externally and respawned. A
     crash record without a preceding signal = code bug. A startup record
     with no preceding shutdown record = uncatchable death (SIGKILL/OOM/
     SIGSEGV). The differential is the diagnostic.

This file has zero imports from the rest of the dashboard package so it
cannot itself fail on a bad import.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading

from app.services.market_day_logging import setup_dashboard_logging

# In production IBCTL_LOG_DIR is always set; we keep the production default
# as a safety net. In tests / dev shells the env var is typically unset
# AND the default path may not be writable — fall back to stderr-only
# logging rather than crashing on import, which would break pytest.
_LOG_DIR = os.environ.get("IBCTL_LOG_DIR", "/opt/ibctl/persist/logs")
_LOG_LEVEL = os.environ.get("IBCTL_LOG_LEVEL", "INFO")
try:
    os.makedirs(_LOG_DIR, exist_ok=True)
    setup_dashboard_logging(log_dir=_LOG_DIR, log_level=_LOG_LEVEL)
except OSError:
    # No durable log sink available — excepthook will still chain to the
    # default sys.__excepthook__ (stderr), so we don't lose tracebacks on
    # the developer terminal. Production deployments have IBCTL_LOG_DIR
    # set to a bind-mounted persistent path and never hit this branch.
    pass

_crash_log = logging.getLogger("dashboard.crash")
_signal_log = logging.getLogger("dashboard.signal")


def _excepthook(exc_type, exc, tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc, tb)
        return
    _crash_log.critical(
        "uncaught_exception",
        exc_info=(exc_type, exc, tb),
        extra={"event": "process.crash", "pid": os.getpid()},
    )
    logging.shutdown()
    sys.__excepthook__(exc_type, exc, tb)


def _thread_excepthook(args):
    if issubclass(args.exc_type, SystemExit):
        return
    _crash_log.critical(
        "uncaught_thread_exception",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        extra={
            "event": "thread.crash",
            "thread": args.thread.name if args.thread else "unknown",
            "pid": os.getpid(),
        },
    )


def _signal_handler(signum, _frame):
    try:
        name = signal.Signals(signum).name
    except ValueError:
        name = str(signum)
    _signal_log.warning(
        "signal_received",
        extra={"event": "process.signal", "signal": name, "pid": os.getpid()},
    )
    signal.signal(signum, signal.SIG_DFL)
    os.kill(os.getpid(), signum)


sys.excepthook = _excepthook
threading.excepthook = _thread_excepthook
for _sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(_sig, _signal_handler)
