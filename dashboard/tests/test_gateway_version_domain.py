"""Gateway version tracking — the domain: versions, IB's 2172 notice, IB's
release files. Inputs are real strings captured from IB."""

from __future__ import annotations

from datetime import date

import httpx
import pytest

from app.services.gateway_version.desupport import DesupportNotice, parse_2172
from app.services.gateway_version.releases import ChannelRelease, fetch_release, parse_version_file
from app.services.gateway_version.versions import GatewayVersion

REAL_2172 = (
    "The version of the application you are running, 1047.1, needs to be upgraded, "
    "as it will be desupported on 20261215. The minimum supported version at that "
    "time will be 1050.1. "
)


class TestGatewayVersion:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("10.50.1f", GatewayVersion(10, 50, 1, "f")),
            ("10.47.1b", GatewayVersion(10, 47, 1, "b")),
            ("10.50.1", GatewayVersion(10, 50, 1)),
            ("1047.1", GatewayVersion(10, 47, 1)),
            ("1050.1", GatewayVersion(10, 50, 1)),
        ],
    )
    def test_both_spellings_parse(self, text, expected):
        assert GatewayVersion.parse(text) == expected

    def test_it_prints_in_the_image_spelling(self):
        assert str(GatewayVersion.parse("1050.1")) == "10.50.1"
        assert str(GatewayVersion.parse("10.50.1f")) == "10.50.1f"

    def test_the_build_letter_counts_only_after_the_number(self):
        minimum = GatewayVersion.parse("1050.1")
        assert GatewayVersion.parse("10.50.1f") >= minimum, "any 10.50.1 build meets a 10.50.1 minimum"
        assert GatewayVersion.parse("10.47.1b") < minimum
        assert GatewayVersion.parse("10.51.1a") > GatewayVersion.parse("10.50.1f")
        assert GatewayVersion.parse("10.50.1f") > GatewayVersion.parse("10.50.1e")

    @pytest.mark.parametrize("text", ["", "latest", "10.50", "10.50.1ff", "v10.50.1f", "99"])
    def test_anything_else_is_refused(self, text):
        with pytest.raises(ValueError):
            GatewayVersion.parse(text)


class TestParse2172:
    def test_the_real_message(self):
        assert parse_2172(REAL_2172) == DesupportNotice(
            running=GatewayVersion(10, 47, 1),
            cutoff=date(2026, 12, 15),
            minimum=GatewayVersion(10, 50, 1),
        )

    def test_a_different_message_is_refused_not_guessed(self):
        with pytest.raises(ValueError):
            parse_2172("Market data farm connection is OK:usfarm")

    def test_an_impossible_date_is_refused(self):
        with pytest.raises(ValueError):
            parse_2172(REAL_2172.replace("20261215", "20261345"))

    def test_days_left_counts_calendar_days(self):
        notice = parse_2172(REAL_2172)
        assert notice.days_left(today=date(2026, 11, 9)) == 36
        assert notice.days_left(today=date(2026, 12, 15)) == 0
        assert notice.days_left(today=date(2026, 12, 20)) == -5

    def test_it_is_met_by_a_version_at_the_minimum(self):
        notice = parse_2172(REAL_2172)
        assert notice.met_by(GatewayVersion.parse("10.50.1f"))
        assert not notice.met_by(GatewayVersion.parse("10.47.1b"))


# IB serves each channel's current build as JSONP.
STABLE_FILE = 'ibgatewaystable_callback({"buildVersion":"10.50.1f","buildDateTime":"20261005 16:18:53"});'


class TestReleaseFiles:
    def test_the_jsonp_file_parses(self):
        assert parse_version_file("stable", STABLE_FILE) == ChannelRelease(
            channel="stable", version=GatewayVersion(10, 50, 1, "f"), released_on=date(2026, 10, 5)
        )

    @pytest.mark.parametrize("body", ["", "<html>maintenance</html>", 'cb({"buildVersion":"x"})'])
    def test_a_file_that_does_not_parse_is_an_error(self, body):
        with pytest.raises(ValueError):
            parse_version_file("stable", body)

    async def test_it_fetches_the_channel_from_ibs_own_url(self):
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(200, text=STABLE_FILE)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            release = await fetch_release(client, "stable")

        assert release.version == GatewayVersion(10, 50, 1, "f")
        assert seen == ["https://download2.interactivebrokers.com/installers/ibgateway/stable-standalone/version.json"]

    async def test_an_http_error_is_an_error(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
            with pytest.raises(httpx.HTTPStatusError):
                await fetch_release(client, "latest")

    async def test_only_known_channels_are_fetched(self):
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as client:
            with pytest.raises(ValueError):
                await fetch_release(client, "nightly")
