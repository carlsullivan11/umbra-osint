"""Coverage should count portals a collector can read, not packs someone wrote.

`/people/coverage` reports "L2 deep 75". Probing all 288 distinct portal URLs
showed that is not the same number as what is reachable — roughly a quarter
cannot be crawled, and the largest slice of that is the site's own choice.

Four outcomes, kept apart for the same reason `closed` and `filtered` stay apart
in the port scanner: they call for different actions, and merging them sends
someone to fix a link that is working exactly as intended.
"""
from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.people.portal_health import PortalHealth, check_all, classify, probe  # noqa: E402


class TestClassification:
    @pytest.mark.parametrize("code", [200, 301, 302, 399])
    def test_success_is_fetchable(self, code):
        assert classify(code, None)[0] == "fetchable"

    @pytest.mark.parametrize("code", [401, 403, 406, 429])
    def test_a_site_refusing_bots_is_link_only_not_broken(self, code):
        """The county tracker's rule is literally "store the link". A 403 means
        the link still works for a person — recording it as broken would push
        someone to "fix" a URL the county is deliberately protecting."""
        status, detail = classify(code, None)
        assert status == "link_only"
        assert "still works for a person" in detail

    @pytest.mark.parametrize("code", [404, 410])
    def test_a_missing_page_needs_a_new_url(self, code):
        status, detail = classify(code, None)
        assert status == "broken"
        assert "needs updating" in detail

    def test_our_own_guard_blocking_is_about_us_not_them(self):
        """BlockedAddress is Umbra's SSRF guard refusing the target, usually
        because DNS returned nothing. Filing that under "needs a new URL" sends
        someone to fix a portal that is fine."""
        status, detail = classify(None, "BlockedAddress")
        assert status == "blocked_by_guard"
        assert "Not evidence the portal is broken" in detail

    def test_a_transport_error_is_broken(self):
        assert classify(None, "ConnectError")[0] == "broken"

    def test_the_four_statuses_are_distinct(self):
        seen = {
            classify(200, None)[0],
            classify(403, None)[0],
            classify(None, "BlockedAddress")[0],
            classify(404, None)[0],
        }
        assert len(seen) == 4


class TestRecording:
    @pytest.fixture
    def health(self, tmp_path):
        h = PortalHealth(tmp_path / "ph.sqlite")
        yield h
        h.close()

    def test_never_checked_is_not_all_healthy(self, tmp_path):
        """Zero rows means nobody looked. Reporting that as clean coverage is
        the failure this whole module exists to prevent."""
        st = PortalHealth(tmp_path / "missing.sqlite").summary()
        assert st["checked"] is False
        assert st["total"] == 0

    def test_counts_by_status(self, health):
        health.record("us-ar", "assessor", "A", "https://a.example", 200, None)
        health.record("us-ar", "clerk", "B", "https://b.example", 403, None)
        health.record("us-ca", "courts", "C", "https://c.example", 404, None)
        health.record("us-al", "courts", "D", "https://d.example", None, "BlockedAddress")
        st = health.summary()
        assert (st["fetchable"], st["link_only"], st["broken"], st["blocked_by_guard"]) == (1, 1, 1, 1)
        assert st["checked"] is True

    def test_rechecking_updates_rather_than_duplicates(self, health):
        health.record("us-ar", "assessor", "A", "https://a.example", 404, None)
        health.record("us-ar", "assessor", "A", "https://a.example", 200, None)
        st = health.summary()
        assert st["total"] == 1
        assert st["fetchable"] == 1 and st["broken"] == 0

    def test_broken_lists_only_what_needs_a_human(self, health):
        health.record("us-ar", "a", "ok", "https://ok.example", 200, None)
        health.record("us-ar", "b", "blocked", "https://b.example", 403, None)
        health.record("us-ar", "c", "gone", "https://gone.example", 404, None)
        rows = health.broken()
        assert [r["name"] for r in rows] == ["gone"]


class TestProbe:
    class Resp:
        def __init__(self, code):
            self.status_code = code

    class Http:
        def __init__(self, head_code, get_code=None):
            self._head, self._get = head_code, get_code
            self.calls = []

        def head(self, url, **kw):
            self.calls.append(("HEAD", url))
            return TestProbe.Resp(self._head)

        def get(self, url, **kw):
            self.calls.append(("GET", url))
            return TestProbe.Resp(self._get)

    def test_head_is_tried_first(self):
        http = self.Http(200)
        assert probe(http, "https://x.example") == (200, None)
        assert [c[0] for c in http.calls] == ["HEAD"]

    @pytest.mark.parametrize("code", [403, 405, 501])
    def test_hosts_that_refuse_head_are_retried_with_get(self, code):
        """Some portals only answer GET. Recording the HEAD refusal would
        mislabel a perfectly fetchable page."""
        http = self.Http(code, 200)
        assert probe(http, "https://x.example") == (200, None)
        assert [c[0] for c in http.calls] == ["HEAD", "GET"]

    def test_an_exception_is_a_result_not_a_crash(self):
        class Boom:
            def head(self, *a, **k):
                raise RuntimeError("nope")

        assert probe(Boom(), "https://x.example") == (None, "RuntimeError")


class TestCheckAll:
    def test_duplicate_urls_are_probed_once(self):
        """Portals repeat across regions; probing the same URL five times is
        rude to the host and slows the sweep for no gain."""
        class Http:
            def __init__(self):
                self.n = 0

            def head(self, url, **kw):
                self.n += 1
                return TestProbe.Resp(200)

        import tempfile

        health = PortalHealth(tempfile.mktemp(suffix=".sqlite"))
        http = Http()
        rows = [("us-ar", "a", "A", "https://same.example")] * 4
        out = check_all(health, http, rows)
        health.close()
        assert http.n == 1
        assert out["checked"] == 1
