"""static/logwindow.js: the logs page's window onto a source's daily files, run under node.

Positions are (day, offset) pairs, so the window runs across files: past the
start of a day's file it continues with the previous day's (the page says
which day that is), and past the end with the next day's from its first byte.
The page keeps at most ``max`` lines: taking an older page drops lines from the
bottom and moves the newer cursor back to the first one dropped, so scrolling
down fetches them again; a newer page does the same at the top. Auto-scroll
turns off when the reader scrolls up and back on at the newest line.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

LOGWINDOW_JS = Path(__file__).resolve().parents[1] / "app" / "static" / "logwindow.js"
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

D9, D10, D11 = "2026-11-09", "2026-11-10", "2026-11-11"


def run(expr: str):
    """Evaluate ``expr`` with the module bound to ``W``; return it as JSON."""
    out = subprocess.run(
        [NODE, "-e", f"const W = require(process.argv[1]); console.log(JSON.stringify({expr}))", str(LOGWINDOW_JS)],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(out.stdout)


def page(date, offs, start, end, at_start=False, at_end=False, prev=None, nxt=None) -> str:
    return json.dumps({
        "date": date, "start": start, "end": end, "at_start": at_start, "at_end": at_end,
        "prev_date": prev, "next_date": nxt,
        "lines": [{"off": o, "ts": "", "level": "INFO", "msg": str(o)} for o in offs],
    })


TAIL = page(D10, [100, 110, 120], 100, 130, at_end=True, prev=D9)


def test_the_first_page_is_the_tail_of_a_day():
    win = run(f"W.fromPage({TAIL})")

    assert win["rows"] == [{"date": D10, "off": o} for o in (100, 110, 120)]
    assert win["start"] == {"date": D10, "off": 100} and win["end"] == {"date": D10, "off": 130}
    assert run(f"[W.atStart(W.fromPage({TAIL})), W.atEnd(W.fromPage({TAIL}))]") == [False, True]


def test_older_pages_come_from_the_same_file_until_its_start():
    assert run(f"W.olderRequest(W.fromPage({TAIL}))") == {"date": D10, "before": 100}


def test_at_the_start_of_a_file_the_previous_days_file_is_next():
    win = f"W.older(W.fromPage({TAIL}), {page(D10, [0, 50], 0, 100, at_start=True, prev=D9)}, 100).win"

    assert run(f"W.olderRequest({win})") == {"date": D9}
    assert run(f"W.atStart({win})") is False


def test_the_previous_days_tail_goes_on_top_and_the_cursor_moves_into_it():
    win = (f"W.older(W.older(W.fromPage({TAIL}), {page(D10, [0], 0, 100, at_start=True, prev=D9)}, 100).win,"
           f" {page(D9, [700, 800], 700, 900, at_end=True, prev=None)}, 100).win")
    got = run(win)

    assert [(r["date"], r["off"]) for r in got["rows"]] == [(D9, 700), (D9, 800), (D10, 0), (D10, 100), (D10, 110), (D10, 120)]
    assert got["start"] == {"date": D9, "off": 700}
    assert run(f"W.olderRequest({win})") == {"date": D9, "before": 700}


def test_the_first_day_is_the_beginning():
    win = f"W.fromPage({page(D9, [0], 0, 10, at_start=True, at_end=True, prev=None, nxt=D10)})"

    assert run(f"W.atStart({win})") is True
    assert run(f"W.olderRequest({win})") is None


def test_older_overflow_leaves_from_the_bottom_and_the_cursor_follows():
    got = run(f"W.older(W.fromPage({TAIL}), {page(D10, [70, 80, 90], 70, 100, prev=D9)}, 4)")

    assert [r["off"] for r in got["win"]["rows"]] == [70, 80, 90, 100]
    assert got["dropBottom"] == 2
    assert got["win"]["end"] == {"date": D10, "off": 110}
    assert run(f"W.atEnd(W.older(W.fromPage({TAIL}), {page(D10, [70, 80, 90], 70, 100, prev=D9)}, 4).win)") is False


def test_newer_pages_continue_in_the_same_file_then_the_next_days():
    mid = f"W.fromPage({page(D9, [500], 500, 600, prev=None, nxt=D10)})"
    assert run(f"W.newerRequest({mid})") == {"date": D9, "after": 600}

    end_of_day = f"W.newer({mid}, {page(D9, [600], 600, 700, at_end=True, nxt=D10)}, 100).win"
    assert run(f"W.newerRequest({end_of_day})") == {"date": D10, "after": 0}
    assert run(f"W.atEnd({end_of_day})") is False


def test_the_next_days_lines_go_below_and_the_end_moves_into_its_file():
    win = (f"W.newer(W.fromPage({page(D9, [600], 600, 700, at_end=True, nxt=D10)}),"
           f" {page(D10, [0, 40], 0, 80, at_start=True, at_end=True, prev=D9)}, 100).win")
    got = run(win)

    assert [(r["date"], r["off"]) for r in got["rows"]] == [(D9, 600), (D10, 0), (D10, 40)]
    assert got["end"] == {"date": D10, "off": 80}
    assert run(f"W.atEnd({win})") is True


def test_following_the_newest_file_keeps_reading_where_it_ended():
    assert run(f"W.newerRequest(W.fromPage({TAIL}))") == {"date": D10, "after": 130}


def test_a_new_days_file_appearing_moves_the_tail_into_it():
    rolled = f"W.newer(W.fromPage({TAIL}), {page(D10, [], 130, 130, at_end=True, prev=D9, nxt=D11)}, 100).win"

    assert run(f"W.newerRequest({rolled})") == {"date": D11, "after": 0}


def test_newer_overflow_leaves_from_the_top_and_the_cursor_follows():
    got = run(f"W.newer(W.fromPage({page(D9, [0, 10, 20], 0, 30, at_start=True, at_end=True, nxt=D10)}),"
              f" {page(D10, [0, 10], 0, 20, at_start=True, prev=D9)}, 3)")

    assert [(r["date"], r["off"]) for r in got["win"]["rows"]] == [(D9, 20), (D10, 0), (D10, 10)]
    assert got["dropTop"] == 2
    assert got["win"]["start"] == {"date": D9, "off": 20}
    # the dropped lines are fetched again from the same file
    assert run(f"W.olderRequest(W.newer(W.fromPage({page(D9, [0, 10, 20], 0, 30, at_start=True, at_end=True, nxt=D10)}),"
               f" {page(D10, [0, 10], 0, 20, at_start=True, prev=D9)}, 3).win)") == {"date": D9, "before": 20}


def test_a_page_with_no_matching_lines_still_moves_the_cursor():
    got = run(f"W.older(W.fromPage({TAIL}), {page(D10, [], 0, 100, at_start=True, prev=D9)}, 10)")

    assert got["dropBottom"] == 0
    assert got["win"]["start"] == {"date": D10, "off": 0}
    assert run(f"W.olderRequest(W.older(W.fromPage({TAIL}), {page(D10, [], 0, 100, at_start=True, prev=D9)}, 10).win)") == {"date": D9}


@pytest.mark.parametrize(
    "following, moved_up, at_bottom, at_end, expected",
    [
        (True, True, False, True, False),  # scrolling back turns it off
        (False, False, True, True, True),  # back down at the newest line: on again
        (False, False, True, False, False),  # bottom of what's loaded, newer lines still to fetch
        (False, False, False, True, False),  # moving down but not there yet
        (True, False, False, True, True),  # new lines arriving don't turn it off
    ],
)
def test_auto_scroll_follows_the_reader(following, moved_up, at_bottom, at_end, expected):
    got = run(f"W.follows({json.dumps(following)}, {json.dumps(moved_up)}, {json.dumps(at_bottom)}, {json.dumps(at_end)})")

    assert got is expected


def test_the_marker_between_two_days_names_both_days_and_files():
    label = run("W.transitionLabel('ibctl-live', '2026-11-08', '2026-11-10')")

    assert label == (
        "▲ end of Sunday, Nov 8, 2026 · ibctl-live-2026-11-08.log\n"
        "▼ start of Tuesday, Nov 10, 2026 · ibctl-live-2026-11-10.log"
    )
