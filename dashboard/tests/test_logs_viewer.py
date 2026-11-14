"""The logs page: GET /api/v1/logs/page and the viewer that pages through it.

The viewer scrolls back to the beginning of a day's file and follows its tail
a page at a time (app.services.log_pages does the reading). It is plain
JavaScript with no htmx attributes, so the dashboard's htmx refreshes (SSE
``ibctl-refresh`` and the refresh-rate rewriting, both of which select
``[hx-trigger]``) can never reload it.
"""

from __future__ import annotations

import json

import pytest
from bs4 import BeautifulSoup

from tests.test_ui_redesign import _make_client

DAY = "2026-11-10"


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.logs.LOG_DIR", str(tmp_path))
    monkeypatch.setattr("app.api.logs.get_market_day_date", lambda: DAY)
    lines = [
        json.dumps({"ts": f"2026-11-10T15:00:{i:02d}Z", "level": "WARN" if i % 5 == 0 else "INFO", "msg": f"m{i}"})
        for i in range(30)
    ]
    (tmp_path / f"ibctl-live-{DAY}.log").write_text("\n".join(lines) + "\n")
    return tmp_path


async def _get(path: str, **params):
    _, client = await _make_client()
    async with client:
        return await client.get(path, params=params)


@pytest.mark.asyncio
async def test_with_no_cursor_the_page_is_the_tail_of_todays_file(log_dir):
    r = await _get("/api/v1/logs/page", source="ibctl-live", limit=5)

    assert r.status_code == 200
    page = r.json()
    assert (page["date"], page["current_date"], page["exists"]) == (DAY, DAY, True)
    assert [line["msg"] for line in page["lines"]] == ["m25", "m26", "m27", "m28", "m29"]
    assert set(page["lines"][0]) == {"off", "ts", "level", "msg"}
    assert page["at_end"] and not page["at_start"] and not page["reset"]


@pytest.mark.asyncio
async def test_before_and_after_page_older_and_newer(log_dir):
    tail = (await _get("/api/v1/logs/page", source="ibctl-live", limit=5)).json()

    older = (await _get("/api/v1/logs/page", source="ibctl-live", date=DAY, before=tail["start"], limit=5)).json()
    assert [line["msg"] for line in older["lines"]] == ["m20", "m21", "m22", "m23", "m24"]
    assert older["end"] == tail["start"]

    newer = (await _get("/api/v1/logs/page", source="ibctl-live", date=DAY, after=older["end"], limit=2)).json()
    assert [line["msg"] for line in newer["lines"]] == ["m25", "m26"]


@pytest.mark.asyncio
async def test_the_level_filter_applies(log_dir):
    page = (await _get("/api/v1/logs/page", source="ibctl-live", level="WARNING", limit=100)).json()

    assert [line["msg"] for line in page["lines"]] == ["m0", "m5", "m10", "m15", "m20", "m25"]
    assert page["at_start"] and page["at_end"]


@pytest.mark.asyncio
async def test_a_missing_file_is_an_empty_page(log_dir):
    page = (await _get("/api/v1/logs/page", source="ibctl-paper")).json()

    assert page["exists"] is False
    assert page["lines"] == [] and page["at_start"] and page["at_end"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params",
    [
        {"source": "nope"},
        {"source": "ibctl-live", "date": "../../etc/passwd"},
        {"source": "ibctl-live", "before": 10, "after": 5},
        {"source": "ibctl-live", "before": -1},
    ],
)
async def test_bad_requests_are_refused(log_dir, params):
    r = await _get("/api/v1/logs/page", **params)

    assert r.status_code in (400, 422)


@pytest.mark.asyncio
async def test_the_page_size_is_capped(log_dir, monkeypatch):
    seen = {}

    def fake_read_before(path, before, limit, level=None, **kw):
        seen["limit"] = limit
        from app.services.log_pages import LogPage

        return LogPage(0, 0, 0, True, True)

    monkeypatch.setattr("app.api.logs.read_before", fake_read_before)
    await _get("/api/v1/logs/page", source="ibctl-live", limit=10**6)

    assert seen["limit"] == 1000


@pytest.mark.asyncio
async def test_the_logs_page_is_full_width_and_out_of_htmxs_reach(log_dir):
    r = await _get("/logs")
    soup = BeautifulSoup(r.text, "html.parser")

    assert "main-wide" in soup.find("main")["class"]
    viewer = soup.find(id="log-content")
    for el in [viewer, *viewer.find_all(True)]:
        assert not [a for a in el.attrs if a.startswith("hx-")], el
    assert soup.find("script", src=lambda s: s and "/static/logwindow.js" in s)
    assert "/partials/logs" not in r.text


@pytest.mark.asyncio
async def test_the_old_partial_is_gone(log_dir):
    r = await _get("/partials/logs", source="ibctl-live")

    assert r.status_code == 404


@pytest.fixture
def three_days(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.logs.LOG_DIR", str(tmp_path))
    monkeypatch.setattr("app.api.logs.get_market_day_date", lambda: DAY)
    for day in ("2026-11-06", "2026-11-08", DAY):
        (tmp_path / f"ibctl-live-{day}.log").write_text(json.dumps({"ts": f"{day}T15:00:00Z", "level": "INFO", "msg": day}) + "\n")
    (tmp_path / "ibctl-live-2026-11-07.log.bak").write_text("not a day file\n")
    return tmp_path


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "date, prev, nxt",
    [
        ("2026-11-08", "2026-11-06", DAY),
        (DAY, "2026-11-08", None),
        ("2026-11-06", None, "2026-11-08"),
        ("2026-11-09", "2026-11-08", DAY),  # a day with no file still knows its neighbours
    ],
)
async def test_a_page_names_the_neighbouring_days_that_have_files(three_days, date, prev, nxt):
    page = (await _get("/api/v1/logs/page", source="ibctl-live", date=date)).json()

    assert (page["prev_date"], page["next_date"]) == (prev, nxt)


@pytest.mark.asyncio
async def test_todays_page_without_a_date_names_yesterday(three_days):
    page = (await _get("/api/v1/logs/page", source="ibctl-live")).json()

    assert page["date"] == DAY and page["prev_date"] == "2026-11-08"


@pytest.mark.asyncio
async def test_the_single_mode_source_does_not_pick_up_live_or_paper_files(three_days):
    dates = (await _get("/api/v1/logs/dates", source="ibctl")).json()["dates"]
    page = (await _get("/api/v1/logs/page", source="ibctl")).json()

    assert dates == []
    assert (page["prev_date"], page["next_date"]) == (None, None)


@pytest.mark.asyncio
async def test_the_date_list_is_newest_first_and_only_day_files(three_days):
    dates = (await _get("/api/v1/logs/dates", source="ibctl-live")).json()["dates"]

    assert dates == [DAY, "2026-11-08", "2026-11-06"]
