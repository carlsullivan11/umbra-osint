"""Overpass rate limiting, from the cron that reported it.

    rf sync ok cameras_upserted=206 fails=4
    fail Rogers, AR: overpass 504
    fail Berkeley, CA: overpass 429
    fail Alameda, CA: overpass 429
    fail San Mateo, CA: overpass 429

Overpass does not limit requests per second. It grants **slots** per client IP
— `/api/status` says "Rate limit: 2" and either "2 slots available now." or
"Slot available after: <iso>, in N seconds." 429 means the slots are gone; 504
means the server is busy. Both are transient and both mean come back shortly.

The old code did neither. It fired fourteen regions back to back with a 1.1s
pause tuned for Nominatim's policy, and dropped any region that came back 429
or 504 — permanently, for that run, with no record that the region had not
been looked at.
"""
from __future__ import annotations

import pytest

from umbra.lake.rf import RfLake, _overpass_fetch, _slot_wait_seconds, sync_regions

STATUS_FREE = """Connected as: 2960225024
Current time: 2026-08-30T15:52:59Z
Rate limit: 2
2 slots available now.
"""

STATUS_EXHAUSTED = """Connected as: 2960225024
Current time: 2026-08-30T15:52:59Z
Rate limit: 2
Slot available after: 2026-08-30T15:53:46Z, in 47 seconds.
Slot available after: 2026-08-30T15:54:30Z, in 91 seconds.
"""


class Resp:
    def __init__(self, status=200, payload=None, text="", headers=None):
        self.status_code = status
        self._payload = payload
        self.text = text
        self.headers = headers or {}

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class FakeHttp:
    """Scripted Overpass. Records what was asked and how long we slept."""

    def __init__(self, post_results, status_text=STATUS_FREE):
        self.post_results = list(post_results)
        self.status_text = status_text
        self.posts: list[str] = []
        self.status_calls = 0

    def get(self, url, **kw):
        self.status_calls += 1
        return Resp(200, text=self.status_text)

    def post(self, url, **kw):
        self.posts.append(url)
        return self.post_results.pop(0) if self.post_results else Resp(500)


class TestSlotParsing:
    def test_free_slots_mean_no_wait(self):
        http = FakeHttp([], STATUS_FREE)
        assert _slot_wait_seconds(http, "s", {}, 10) == 0.0

    def test_exhausted_waits_for_the_soonest_slot(self):
        http = FakeHttp([], STATUS_EXHAUSTED)
        assert _slot_wait_seconds(http, "s", {}, 10) == 47.0

    def test_unreadable_status_does_not_block_the_query(self):
        """A status page we cannot parse must not become an outage — the
        request itself will say 429 if we were wrong, and that is handled."""

        class Broken:
            def get(self, *a, **k):
                raise RuntimeError("nope")

        assert _slot_wait_seconds(Broken(), "s", {}, 10) == 0.0


class TestRetry:
    def test_a_429_is_retried_not_dropped(self):
        # This is Berkeley, Alameda and San Mateo from the cron report.
        http = FakeHttp([Resp(429), Resp(200, {"elements": []})])
        slept: list[float] = []
        payload, reason = _overpass_fetch(
            http, "q", headers={}, timeout=30, sleep=slept.append
        )
        assert reason is None
        assert payload == {"elements": []}
        assert len(http.posts) == 2, "should have tried again"
        assert slept, "should have waited before retrying"

    def test_a_504_is_retried(self):
        # This is Rogers, AR.
        http = FakeHttp([Resp(504), Resp(200, {"elements": []})])
        payload, reason = _overpass_fetch(http, "q", headers={}, timeout=30, sleep=lambda s: None)
        assert reason is None and payload is not None

    def test_retry_after_header_is_honoured(self):
        http = FakeHttp([Resp(429, headers={"Retry-After": "5"}), Resp(200, {"elements": []})])
        slept: list[float] = []
        _overpass_fetch(http, "q", headers={}, timeout=30, sleep=slept.append)
        assert any(abs(s - 6.0) < 0.01 for s in slept), slept

    def test_falls_over_to_the_mirror_only_after_the_primary_refuses(self):
        # Politeness: exhaust the main instance before spending someone
        # else's capacity.
        http = FakeHttp([Resp(429), Resp(429), Resp(429), Resp(200, {"elements": []})])
        payload, reason = _overpass_fetch(http, "q", headers={}, timeout=30, sleep=lambda s: None)
        assert reason is None
        assert "overpass-api.de" in http.posts[0]
        assert "kumi.systems" in http.posts[-1]

    def test_a_400_is_not_retried(self):
        """A malformed query fails the same way every time; hammering a public
        service with it is rude and pointless."""
        http = FakeHttp([Resp(400)])
        payload, reason = _overpass_fetch(http, "q", headers={}, timeout=30, sleep=lambda s: None)
        assert payload is None
        assert "400" in reason
        assert len(http.posts) == 1

    def test_gives_up_with_a_reason_a_human_can_act_on(self):
        http = FakeHttp([Resp(429)] * 12)
        payload, reason = _overpass_fetch(http, "q", headers={}, timeout=30, sleep=lambda s: None)
        assert payload is None
        assert "429" in reason and "overpass" in reason.lower()


class TestUncheckedIsNotEmpty:
    """The failure that mattered: a 429'd region left no trace in the lake."""

    @pytest.fixture
    def lake(self, tmp_path):
        lk = RfLake(tmp_path / "rf.sqlite")
        yield lk
        lk.close() if hasattr(lk, "close") else None

    def test_a_failed_region_is_recorded_as_failed(self, lake):
        lake.mark_region("Berkeley, CA", "failed", "HTTP 429 from overpass-api.de")
        st = lake.region_status("Berkeley, CA")
        assert st["status"] == "failed"
        assert "429" in st["detail"]

    def test_a_checked_empty_region_is_distinguishable_from_a_failed_one(self, lake):
        lake.mark_region("Albany, CA", "ok", None, cameras=0)
        lake.mark_region("Berkeley, CA", "failed", "HTTP 429")
        assert lake.region_status("Albany, CA")["status"] == "ok"
        assert lake.region_status("Berkeley, CA")["status"] == "failed"
        # Both have zero cameras in the lake. Only one of them is an answer.
        assert [r["region"] for r in lake.stale_regions()] == ["Berkeley, CA"]

    def test_a_region_never_attempted_says_none_rather_than_ok(self, lake):
        assert lake.region_status("Nowhere, ZZ") is None

    def test_sync_records_every_region_it_touches(self, lake, monkeypatch):
        import umbra.lake.rf as rf

        monkeypatch.setattr(rf.time, "sleep", lambda s: None)

        class Http:
            def get(self, url, **kw):
                if "nominatim" in url:
                    return Resp(200, [{"lat": "37.8", "lon": "-122.2"}])
                return Resp(200, text=STATUS_FREE)

            def __init__(self):
                self.n = 0

            def post(self, url, **kw):
                self.n += 1
                # First city succeeds, second is rate limited to exhaustion.
                if self.n == 1:
                    return Resp(200, {"elements": []})
                return Resp(429)

        out = sync_regions(Http(), lake=lake, regions=["Oakland, CA", "Berkeley, CA"],
                           sleep=lambda s: None)
        assert out["checked"] == 1
        assert len(out["fails"]) == 1
        assert lake.region_status("Oakland, CA")["status"] == "ok"
        assert lake.region_status("Berkeley, CA")["status"] == "failed"

    def test_a_capped_region_says_so(self, lake, monkeypatch):
        """`out body N` truncates server-side. A region returning exactly N
        probably has more, and silently keeping N would be a lie of omission."""
        import umbra.lake.rf as rf

        monkeypatch.setattr(rf.time, "sleep", lambda s: None)
        elements = [
            {"id": i, "lat": 37.8 + i / 1000, "lon": -122.2, "tags": {}} for i in range(3)
        ]

        class Http:
            def get(self, url, **kw):
                if "nominatim" in url:
                    return Resp(200, [{"lat": "37.8", "lon": "-122.2"}])
                return Resp(200, text=STATUS_FREE)

            def post(self, url, **kw):
                return Resp(200, {"elements": elements})

        out = sync_regions(Http(), lake=lake, regions=["Oakland, CA"], max_per_region=3,
                           sleep=lambda s: None)
        assert out["capped"] == ["Oakland, CA"]
        assert lake.region_status("Oakland, CA")["capped"] == 1
