"""Domain reputation must read the URLhaus corpus Umbra already owns.

Found during the feature review: a live check of cloudflare.com reported
"2 source(s) checked — openphish, spamhaus_dbl". URLhaus was absent, because
the collector went straight to urlhaus-api.abuse.ch, which has needed a free
Auth-Key since 2024, and recorded "urlhaus: skipped (no UMBRA_ABUSECH_AUTH_KEY)".

Meanwhile `umbra abuse sync` had 54,911 rows of URLhaus in the local lake on a
6h timer, which malware_infra reads with no key at all. The answer was on disk
and the verdict said it had not been checked.
"""
from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.collectors.reputation import DomainReputationCollector  # noqa: E402
from umbra.core.models import CollectorResult  # noqa: E402


class FakeLake:
    def __init__(self, synced=True, urls=None):
        self._synced = synced
        self._urls = urls or []
        self.closed = False

    def abuse_feed_synced_at(self, feed):
        return "2026-08-31T00:00:00+00:00" if self._synced else None

    def abuse_urls_for_host(self, host, limit=200):
        return self._urls

    def close(self):
        self.closed = True


@pytest.fixture
def collector(monkeypatch):
    c = DomainReputationCollector()
    return c


def _patch_lake(monkeypatch, lake):
    import umbra.lake.store as store_mod

    monkeypatch.setattr(store_mod.LakeStore, "from_settings", classmethod(lambda cls, s: lake))


class Ctx:
    settings = None


def test_a_listed_host_is_found_without_any_api_key(collector, monkeypatch):
    lake = FakeLake(urls=[{"url_status": "online"}, {"url_status": "offline"}])
    _patch_lake(monkeypatch, lake)
    result = CollectorResult()
    hit = collector._urlhaus_from_lake("evil.example", Ctx(), result)
    assert hit is not None
    assert hit.listed is True
    assert hit.source == "urlhaus"
    assert hit.weight >= 0.9, "an online malware URL is decisive"
    assert "1 online" in hit.detail


def test_historical_only_is_weaker_but_still_listed(collector, monkeypatch):
    _patch_lake(monkeypatch, FakeLake(urls=[{"url_status": "offline"}]))
    hit = collector._urlhaus_from_lake("old.example", Ctx(), CollectorResult())
    assert hit.listed is True
    assert 0.5 < hit.weight < 0.9


def test_a_clean_host_is_reported_as_checked_and_not_listed(collector, monkeypatch):
    _patch_lake(monkeypatch, FakeLake(urls=[]))
    hit = collector._urlhaus_from_lake("cloudflare.com", Ctx(), CollectorResult())
    assert hit is not None, "a synced lake with no rows for the host IS an answer"
    assert hit.listed is False
    assert hit.weight == 0.0


def test_an_unsynced_lake_returns_no_hit_rather_than_a_clean_one(collector, monkeypatch):
    """The whole point. A lake that has never synced knows nothing about every
    host equally — reporting that as "not listed" is the failure this codebase
    exists to avoid."""
    _patch_lake(monkeypatch, FakeLake(synced=False))
    result = CollectorResult()
    hit = collector._urlhaus_from_lake("anything.example", Ctx(), result)
    assert hit is None
    assert any("never synced" in n for n in result.notes)
    assert any("unknown rather than clean" in n for n in result.notes)


def test_the_lake_handle_is_closed(collector, monkeypatch):
    lake = FakeLake(urls=[])
    _patch_lake(monkeypatch, lake)
    collector._urlhaus_from_lake("x.example", Ctx(), CollectorResult())
    assert lake.closed, "a leaked sqlite handle per domain check adds up"


def test_an_unreadable_lake_says_so_and_does_not_raise(collector, monkeypatch):
    import umbra.lake.store as store_mod

    def boom(cls, s):
        raise RuntimeError("disk gone")

    monkeypatch.setattr(store_mod.LakeStore, "from_settings", classmethod(boom))
    result = CollectorResult()
    assert collector._urlhaus_from_lake("x.example", Ctx(), result) is None
    assert any("unreadable" in n for n in result.notes)
