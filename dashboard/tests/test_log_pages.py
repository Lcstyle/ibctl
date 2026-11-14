"""Paging a log file by byte offset (app.services.log_pages).

The logs page scrolls back through a whole day's file and follows its tail
without ever holding the file: each request reads a bounded number of bytes
backwards from a cursor (older lines) or forwards from one (newer lines), and
says where the next request in either direction starts.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.services.log_pages import read_after, read_before


def write_log(path: Path, n: int, levels: tuple[str, ...] = ("INFO",), tail: bytes = b"") -> list[bytes]:
    lines = [
        json.dumps(
            {"ts": f"2026-11-10T15:{i // 60 % 60:02d}:{i % 60:02d}.000Z", "level": levels[i % len(levels)],
             "msg": f"line {i} ünïcødé"},
            ensure_ascii=False,
        ).encode()
        for i in range(n)
    ]
    path.write_bytes(b"".join(line + b"\n" for line in lines) + tail)
    return lines


def msgs(page) -> list[str]:
    return [line.msg for line in page.lines]


def every(n: int) -> list[str]:
    return [f"line {i} ünïcødé" for i in range(n)]


def test_the_tail_page_is_the_newest_lines_oldest_first(tmp_path):
    path = tmp_path / "x.log"
    raw = write_log(path, 50)
    data = path.read_bytes()

    page = read_before(path, None, limit=10)

    assert msgs(page) == every(50)[40:]
    assert page.end == len(data) and page.at_end
    assert not page.at_start
    assert page.start == data.index(raw[40])
    for line, want in zip(page.lines, raw[40:]):
        assert data[line.off:].startswith(want + b"\n")


def test_paging_back_from_the_tail_visits_every_line_once(tmp_path):
    path = tmp_path / "x.log"
    write_log(path, 101)

    seen: list[str] = []
    page = read_before(path, None, limit=7, chunk=37)  # chunks split lines and characters
    seen[:0] = msgs(page)
    while not page.at_start:
        before = page.start
        page = read_before(path, before, limit=7, chunk=37)
        assert page.end == before
        seen[:0] = msgs(page)

    assert seen == every(101)


def test_paging_forward_from_the_start_visits_every_line_once(tmp_path):
    path = tmp_path / "x.log"
    write_log(path, 101)

    page = read_after(path, 0, limit=7, chunk=37)
    assert page.at_start
    seen = msgs(page)
    while not page.at_end:
        after = page.end
        page = read_after(path, after, limit=7, chunk=37)
        assert page.start == after
        seen += msgs(page)

    assert seen == every(101)


def test_a_line_still_being_written_waits_for_its_newline(tmp_path):
    path = tmp_path / "x.log"
    write_log(path, 3, tail=b'{"ts":"2026-11-10T16:00:00.000Z","level":"INFO","msg":"half')
    complete = path.read_bytes().rindex(b"\n") + 1

    tail = read_before(path, None, limit=10)
    assert msgs(tail) == every(3)
    assert tail.end == complete and tail.at_end

    nothing = read_after(path, tail.end, limit=10)
    assert nothing.lines == [] and nothing.end == complete and nothing.at_end

    with path.open("ab") as f:
        f.write(b' done"}\n')
    newer = read_after(path, tail.end, limit=10)
    assert msgs(newer) == ["half done"]
    assert newer.at_end


def test_the_level_filter_treats_warn_as_warning_and_keeps_paging(tmp_path):
    path = tmp_path / "x.log"
    write_log(path, 40, levels=("INFO", "WARN", "ERROR", "WARNING"))
    want = [m for i, m in enumerate(every(40)) if i % 4 in (1, 3)]

    page = read_before(path, None, limit=3, level="WARNING", chunk=50)
    assert {line.level for line in page.lines} == {"WARNING"}
    seen = msgs(page)
    while not page.at_start:
        page = read_before(path, page.start, limit=3, level="WARNING", chunk=50)
        seen[:0] = msgs(page)

    assert seen == want


def test_each_read_is_bounded_but_always_moves_the_cursor(tmp_path):
    path = tmp_path / "x.log"
    write_log(path, 500)
    size = path.stat().st_size

    page = read_before(path, None, limit=10, level="ERROR", chunk=64, budget=1000)
    assert page.lines == []
    assert 0 < page.start < size - 900  # ~budget bytes covered, no further
    assert not page.at_start

    steps, before = 0, page.start
    while not page.at_start:
        page = read_before(path, before, limit=10, level="ERROR", chunk=64, budget=1000)
        assert page.start < before
        before, steps = page.start, steps + 1
    assert steps < size // 900 + 2


def test_a_line_longer_than_the_budget_is_still_returned(tmp_path):
    path = tmp_path / "x.log"
    long = json.dumps({"ts": "2026-11-10T15:00:00.000Z", "level": "INFO", "msg": "x" * 5000})
    path.write_text(long + "\n")

    back = read_before(path, None, limit=5, chunk=64, budget=100)
    assert msgs(back) == ["x" * 5000] and back.at_start

    fwd = read_after(path, 0, limit=5, chunk=64, budget=100)
    assert msgs(fwd) == ["x" * 5000] and fwd.at_end


def test_a_file_that_shrank_tells_the_viewer_to_start_over(tmp_path):
    path = tmp_path / "x.log"
    write_log(path, 5)

    page = read_after(path, path.stat().st_size + 100, limit=10)

    assert page.reset
    assert page.lines == []


def test_a_cursor_inside_a_line_moves_to_a_line_boundary(tmp_path):
    path = tmp_path / "x.log"
    raw = write_log(path, 10)
    data = path.read_bytes()
    inside_line_5 = data.index(raw[5]) + 3

    fwd = read_after(path, inside_line_5, limit=2)
    assert msgs(fwd) == every(10)[6:8]

    back = read_before(path, inside_line_5, limit=2)
    assert msgs(back) == every(10)[3:5]


def test_lines_that_are_not_json_are_shown_as_written(tmp_path):
    path = tmp_path / "x.log"
    path.write_text('thread main panicked at src/x.rs:1\n{"ts":"2026-11-10T15:00:00Z","level":"ERROR","msg":"m"}\n')

    page = read_before(path, None, limit=10)
    assert [(line.level, line.msg) for line in page.lines] == [
        ("INFO", "thread main panicked at src/x.rs:1"),
        ("ERROR", "m"),
    ]
    assert [line.level for line in read_before(path, None, limit=10, level="INFO").lines] == []


def test_timestamps_are_shown_in_the_display_zone(tmp_path):
    path = tmp_path / "x.log"
    path.write_text('{"ts":"2026-11-10T15:00:00.123Z","level":"INFO","msg":"m"}\n')

    page = read_before(path, None, limit=1, tz="America/New_York")

    assert page.lines[0].ts == "2026-11-10 10:00:00"


def test_an_empty_file_is_one_empty_page(tmp_path):
    path = tmp_path / "x.log"
    path.write_bytes(b"")

    for page in (read_before(path, None, limit=10), read_after(path, 0, limit=10)):
        assert page.lines == []
        assert (page.start, page.end, page.at_start, page.at_end) == (0, 0, True, True)
