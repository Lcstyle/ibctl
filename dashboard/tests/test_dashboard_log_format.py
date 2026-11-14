"""The dashboard's log file lines (market_day_logging.JsonLineFormatter).

One JSON object per line, the shape ibctl writes:
``{"ts":"2026-11-10T22:25:03.123Z","level":"INFO","target":"x","msg":"..."}``.
The message (and any traceback) is JSON-escaped, so a quote or a newline can
never break a line, and the time is the UTC instant, which the logs page shows
in local time. Separators stay compact: the older /api/v1/logs filter matches
the substring ``"level":"ERROR"``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from app.services.log_pages import read_before
from app.services.market_day_logging import JsonLineFormatter

# 2026-11-10 22:25:03.123 UTC = 17:25:03 in New York
CREATED = datetime(2026, 11, 10, 22, 25, 3, 123000, tzinfo=timezone.utc).timestamp()


def record(msg: str, *args, level: int = logging.INFO, exc_info=None) -> logging.LogRecord:
    rec = logging.LogRecord("uvicorn.access", level, __file__, 1, msg, args, exc_info)
    rec.created = CREATED
    rec.msecs = 123.0
    return rec


def test_a_message_with_quotes_is_one_valid_json_line():
    line = JsonLineFormatter().format(record('%s - "%s" %d', "172.18.0.1:57064", "GET /api/v1/ib-status HTTP/1.1", 200))

    assert "\n" not in line
    assert json.loads(line) == {
        "ts": "2026-11-10T22:25:03.123Z",
        "level": "INFO",
        "target": "uvicorn.access",
        "msg": '172.18.0.1:57064 - "GET /api/v1/ib-status HTTP/1.1" 200',
    }


def test_the_line_keeps_ibctls_compact_shape():
    line = JsonLineFormatter().format(record("boom", level=logging.ERROR))

    assert line.startswith('{"ts":"2026-11-10T22:25:03.123Z","level":"ERROR","target":"uvicorn.access","msg":')
    assert '"level":"ERROR"' in line


def test_a_traceback_stays_inside_the_line():
    try:
        raise ValueError("bad \"value\"")
    except ValueError:
        import sys

        line = JsonLineFormatter().format(record("handler failed", level=logging.ERROR, exc_info=sys.exc_info()))

    assert "\n" not in line
    msg = json.loads(line)["msg"]
    assert msg.startswith("handler failed\nTraceback (most recent call last):")
    assert msg.rstrip().endswith('ValueError: bad "value"')


def test_text_is_written_as_utf8_not_escaped():
    line = JsonLineFormatter().format(record("prix ünï €"))

    assert "prix ünï €" in line


def test_the_file_handler_writes_each_record_once_in_this_format(tmp_path):
    from app.services.market_day_logging import MarketDayFileHandler, setup_dashboard_logging

    # setup_dashboard_logging also attaches its handler to uvicorn's loggers,
    # sets their levels and captures warnings: undo all of it afterwards.
    # Importing app.main (conftest does) may already have attached the real
    # file handler, wherever the default log directory is writable (as root,
    # which is how CI runs). setup_dashboard_logging would then do nothing, so
    # that handler is set aside for the test and put back after it.
    loggers = [logging.getLogger(n) for n in ("", "uvicorn", "uvicorn.error", "uvicorn.access", "py.warnings")]
    saved = [(lg, list(lg.handlers), lg.level) for lg in loggers]
    for lg, handlers, _ in saved:
        for h in handlers:
            if isinstance(h, MarketDayFileHandler):
                lg.removeHandler(h)
    try:
        setup_dashboard_logging(log_dir=str(tmp_path), log_level="INFO")
        root = logging.getLogger()
        [handler] = [h for h in root.handlers if h not in saved[0][1] and isinstance(h, MarketDayFileHandler)]
        logging.getLogger("uvicorn.access").warning('%s - "%s" %d', "10.0.0.1:1", "GET / HTTP/1.1", 200)
        handler.flush()
        [written] = tmp_path.glob("dashboard-*.log")
        [line] = [x for x in written.read_text(encoding="utf-8").splitlines() if "10.0.0.1:1" in x]
    finally:
        logging.captureWarnings(False)
        for lg, handlers, level in saved:
            for h in [h for h in lg.handlers if h not in handlers]:
                lg.removeHandler(h)
                h.close()
            lg.handlers[:] = handlers
            lg.setLevel(level)

    entry = json.loads(line)
    assert (entry["level"], entry["msg"]) == ("WARNING", '10.0.0.1:1 - "GET / HTTP/1.1" 200')
    assert entry["ts"].endswith("Z")


def test_the_logs_page_shows_the_line_in_local_time(tmp_path):
    path = tmp_path / "dashboard-2026-11-10.log"
    path.write_text(JsonLineFormatter().format(record('GET "/logs"')) + "\n", encoding="utf-8")

    [line] = read_before(path, None, limit=10, tz="America/New_York").lines

    assert (line.ts, line.level, line.msg) == ("2026-11-10 17:25:03", "INFO", 'GET "/logs"')
