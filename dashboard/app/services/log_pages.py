"""Read a log file a page at a time, by byte offset.

The logs page scrolls back through a whole day's file and follows its tail
without holding the file anywhere. Each request reads at most about
``budget`` bytes, in ``chunk``-sized reads: backwards from a cursor for older
lines (``read_before``), or forwards from one for newer lines (``read_after``).

A page covers the bytes ``[start, end)`` of the file: the next older page ends
at ``start`` and the next newer one starts at ``end``. Cursors sit on line
boundaries (0, or just after a newline); one that doesn't is moved to the
nearest boundary that skips the line it points into. A line still being
written (no newline yet) is left for a later read. With a level filter a page
may hold fewer than ``limit`` lines, or none, but its cursors always move, so
paging on always reaches the start or the end of the file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from zoneinfo import ZoneInfo

CHUNK = 64 * 1024
BUDGET = 1024 * 1024
DISPLAY_TZ = "America/New_York"
_UTC = ZoneInfo("UTC")


@dataclass(frozen=True)
class LogLine:
    off: int  # byte offset of the line's first byte
    ts: str  # display time, in the display zone ("" when the line has none)
    level: str
    msg: str


@dataclass(frozen=True)
class LogPage:
    start: int
    end: int
    size: int
    at_start: bool  # start is the beginning of the file
    at_end: bool  # no complete line follows end
    lines: list[LogLine] = field(default_factory=list)  # oldest first
    reset: bool = False  # the cursor is past the end: the file was replaced


def read_before(
    path: Path,
    before: int | None,
    limit: int,
    level: str | None = None,
    *,
    tz: str = DISPLAY_TZ,
    chunk: int = CHUNK,
    budget: int = BUDGET,
) -> LogPage:
    """Up to ``limit`` lines ending at ``before`` (the newest lines when None)."""
    zone, want = ZoneInfo(tz), _level(level)
    with open(path, "rb") as f:
        size = f.seek(0, 2)
        last = _align_down(f, size, chunk)
        end = last if before is None else _align_down(f, min(before, size), chunk)
        newest_first: list[LogLine] = []
        start = pos = end
        buf = b""  # the unread-into-lines bytes [pos, start)
        scanned = 0
        while pos > 0 and len(newest_first) < limit and (scanned < budget or start == end):
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            scanned += step
            newline = buf.find(b"\n")
            if pos > 0 and newline < 0:
                continue  # no complete line yet
            cut = 0 if pos == 0 else newline + 1
            raws = buf[cut:].split(b"\n")[:-1]  # complete lines, each ended by a newline
            offsets = _offsets(pos + cut, raws)
            for raw, off in zip(reversed(raws), reversed(offsets)):
                start = off
                line = _match(raw, off, zone, want)
                if line is not None:
                    newest_first.append(line)
                    if len(newest_first) == limit:
                        break
            buf = buf[: start - pos]
    return LogPage(start, end, size, start == 0, end >= last, newest_first[::-1])


def read_after(
    path: Path,
    after: int,
    limit: int,
    level: str | None = None,
    *,
    tz: str = DISPLAY_TZ,
    chunk: int = CHUNK,
    budget: int = BUDGET,
) -> LogPage:
    """Up to ``limit`` complete lines starting at ``after``."""
    zone, want = ZoneInfo(tz), _level(level)
    with open(path, "rb") as f:
        size = f.seek(0, 2)
        if after > size:
            return LogPage(0, 0, size, False, False, reset=True)
        last = _align_down(f, size, chunk)
        start = _align_up(f, after, size, chunk)
        lines: list[LogLine] = []
        end = pos = start
        buf = b""  # the bytes [end, pos)
        scanned = 0
        while pos < size and len(lines) < limit and (scanned < budget or end == start):
            f.seek(pos)
            data = f.read(min(chunk, size - pos))
            pos += len(data)
            scanned += len(data)
            buf += data
            newline = buf.rfind(b"\n")
            if newline < 0:
                continue
            base = end
            for raw in buf[: newline + 1].split(b"\n")[:-1]:
                off, end = end, end + len(raw) + 1
                line = _match(raw, off, zone, want)
                if line is not None:
                    lines.append(line)
                    if len(lines) == limit:
                        break
            buf = buf[end - base :]
    return LogPage(start, end, size, start == 0, end >= last, lines)


def _offsets(first: int, raws: list[bytes]) -> list[int]:
    out, off = [], first
    for raw in raws:
        out.append(off)
        off += len(raw) + 1
    return out


def _match(raw: bytes, off: int, zone: ZoneInfo, want: str | None) -> LogLine | None:
    text = raw.decode("utf-8", errors="replace").rstrip("\r")
    if not text.strip():
        return None
    try:
        entry = json.loads(text)
    except ValueError:
        entry = None
    if not isinstance(entry, dict):
        # Not a structured line (a panic, a stray print): shown as written,
        # and only when no level filter is set.
        return None if want else LogLine(off, "", "INFO", text)
    line = LogLine(off, _display_time(entry.get("ts"), zone), _level(str(entry.get("level", "INFO"))) or "INFO",
                   str(entry.get("msg", text)))
    return line if want is None or line.level == want else None


def _level(level: str | None) -> str | None:
    if not level:
        return None
    level = level.upper()
    return "WARNING" if level == "WARN" else level  # Rust writes WARN, Python WARNING


def _display_time(ts: object, zone: ZoneInfo) -> str:
    """The line's UTC instant as wall time in the display zone (display layer only)."""
    if not ts:
        return ""
    try:
        parsed = datetime.fromisoformat(str(ts))
    except ValueError:
        return str(ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_UTC)  # ibctl and the dashboard write UTC
    return parsed.astimezone(zone).strftime("%Y-%m-%d %H:%M:%S")


def _align_down(f: BinaryIO, pos: int, chunk: int) -> int:
    """The last line boundary at or before ``pos``."""
    while pos > 0:
        step = min(chunk, pos)
        f.seek(pos - step)
        data = f.read(step)
        newline = data.rfind(b"\n")
        if newline >= 0:
            return pos - step + newline + 1
        pos -= step
    return 0


def _align_up(f: BinaryIO, pos: int, size: int, chunk: int) -> int:
    """The first line boundary at or after ``pos``; ``size`` when the line it
    points into has no newline yet."""
    if pos == 0:
        return 0
    f.seek(pos - 1)
    if f.read(1) == b"\n":
        return pos
    while pos < size:
        f.seek(pos)
        data = f.read(min(chunk, size - pos))
        newline = data.find(b"\n")
        if newline >= 0:
            return pos + newline + 1
        pos += len(data)
    return size
