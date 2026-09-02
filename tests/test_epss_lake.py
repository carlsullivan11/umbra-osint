"""EPSS lake — a prediction that never gets to sound like an observation.

KEV says a vulnerability *is* being exploited. EPSS says a model thinks it
*might be*. The whole value of pairing them is lost if the second one renders
like the first, so most of what is asserted here is about wording and about
refusing to answer when the lake does not know.
"""
from __future__ import annotations

import gzip
import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.lake.epss import (  # noqa: E402
    EpssLake,
    band,
    parse_header,
    parse_rows,
    sync,
)

# Shaped exactly like the real feed, header line included.
FEED = """#model_version:v2026.06.15,score_date:2026-08-31T12:00:22Z
cve,epss,percentile
CVE-2021-44228,0.94400,0.99990
CVE-1999-0001,0.03351,0.87829
CVE-2024-00001,0.00042,0.05000
"""


@pytest.fixture
def lake(tmp_path):
    lk = EpssLake(tmp_path / "epss.sqlite")
    yield lk
    lk.close()


@pytest.fixture
def loaded(lake):
    header, rows = parse_rows(FEED.splitlines())
    lake.replace_all(header, rows)
    return lake


class TestParsing:
    def test_header_provenance_is_kept(self):
        h = parse_header("#model_version:v2026.06.15,score_date:2026-08-31T12:00:22Z")
        assert h["model_version"] == "v2026.06.15"
        assert h["score_date"] == "2026-08-31T12:00:22Z"

    def test_rows_parse(self):
        header, rows = parse_rows(FEED.splitlines())
        assert header["model_version"] == "v2026.06.15"
        assert len(rows) == 3
        assert ("CVE-2021-44228", 0.944, 0.9999) == pytest.approx(rows[0], rel=1e-3)

    def test_junk_rows_are_dropped_not_guessed(self):
        bad = FEED + "not-a-cve,0.5,0.5\nCVE-2020-1,notanumber,0.5\n"
        _, rows = parse_rows(bad.splitlines())
        assert len(rows) == 3

    def test_case_is_normalised(self):
        _, rows = parse_rows(["cve,epss,percentile", "cve-2021-44228,0.9,0.9"])
        assert rows[0][0] == "CVE-2021-44228"


class TestBands:
    @pytest.mark.parametrize("score,expected", [
        (0.944, "high"), (0.51, "high"), (0.2, "elevated"),
        (0.05, "low"), (0.0004, "very low"), (0.0, "very low"),
    ])
    def test_band_labels(self, score, expected):
        assert band(score)[0] == expected

    def test_every_band_says_modelled(self):
        """Wording is the guardrail. 'is exploited' belongs to KEV alone."""
        for score in (0.9, 0.2, 0.05, 0.0):
            label, meaning = band(score)
            assert "modelled" in meaning
            assert " is exploited" not in meaning


class TestLookup:
    def test_a_scored_cve_comes_back_with_its_provenance(self, loaded):
        s = loaded.score("CVE-2021-44228")
        assert s["score"] == pytest.approx(0.944)
        assert s["band"] == "high"
        # A number with no model version and no date is not usable evidence.
        assert s["model_version"] == "v2026.06.15"
        assert s["score_date"] == "2026-08-31T12:00:22Z"
        assert "FIRST" in s["source"]

    def test_lookup_is_case_insensitive(self, loaded):
        assert loaded.score("cve-2021-44228") is not None

    def test_an_unscored_cve_returns_none_not_zero(self, loaded):
        """The core honesty rule. A CVE published after the last sync has no row;
        answering 0.0 would be a confident claim about something nobody has
        modelled."""
        assert loaded.score("CVE-2030-99999") is None

    def test_an_absent_lake_returns_none(self, lake):
        assert lake.score("CVE-2021-44228") is None
        assert lake.row_count() == 0

    def test_top_ranks_by_score(self, loaded):
        ranked = loaded.top(["CVE-1999-0001", "CVE-2021-44228", "CVE-2024-00001"])
        assert [r["cve"] for r in ranked] == [
            "CVE-2021-44228", "CVE-1999-0001", "CVE-2024-00001",
        ]

    def test_top_drops_unscored_rather_than_ranking_them_last(self, loaded):
        ranked = loaded.top(["CVE-2030-99999", "CVE-2021-44228"])
        assert [r["cve"] for r in ranked] == ["CVE-2021-44228"]


class TestSync:
    class Resp:
        def __init__(self, content, status=200):
            self.content = content
            self.status_code = status

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    class Http:
        def __init__(self, resp):
            self._resp = resp
            self.calls = []

        def get(self, url, **kw):
            self.calls.append((url, kw))
            return self._resp

    def test_sync_loads_and_records_provenance(self, lake):
        http = self.Http(self.Resp(gzip.compress(FEED.encode())))
        out = sync(lake, http)
        assert out["rows"] == 3
        assert out["model_version"] == "v2026.06.15"
        assert lake.row_count() == 3
        assert lake.status()["score_date"] == "2026-08-31T12:00:22Z"

    def test_sync_replaces_rather_than_appends(self, lake):
        http = self.Http(self.Resp(gzip.compress(FEED.encode())))
        sync(lake, http)
        sync(lake, http)
        assert lake.row_count() == 3, "a re-sync must not duplicate the corpus"

    def test_a_withdrawn_cve_disappears_on_resync(self, lake):
        sync(lake, self.Http(self.Resp(gzip.compress(FEED.encode()))))
        assert lake.score("CVE-1999-0001") is not None
        shorter = "#model_version:v2\ncve,epss,percentile\nCVE-2021-44228,0.9,0.99\n"
        sync(lake, self.Http(self.Resp(gzip.compress(shorter.encode()))))
        assert lake.score("CVE-1999-0001") is None

    def test_an_empty_feed_refuses_to_wipe_the_lake(self, lake):
        """A bad fetch that parses to nothing must not silently empty a working
        lake — that turns every CVE into 'unscored' at once."""
        sync(lake, self.Http(self.Resp(gzip.compress(FEED.encode()))))
        empty = self.Http(self.Resp(gzip.compress(b"#model_version:v2\ncve,epss,percentile\n")))
        with pytest.raises(ValueError, match="zero rows"):
            sync(lake, empty)
        assert lake.row_count() == 3, "the previous corpus must survive a bad sync"

    def test_an_http_error_propagates(self, lake):
        with pytest.raises(RuntimeError):
            sync(lake, self.Http(self.Resp(b"", status=503)))
