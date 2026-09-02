"""Lake freshness belongs in `umbra doctor`, not in every run's notes.

Before this, the only place a cold lake surfaced was the run output itself,
once per affected entity — "GeoIP lake not loaded" four times on a three-seed
run, "abuse lake never synced" six. That is a chore being reported as though it
were a finding, and repeating it did not make it more actionable.

It is also the check that would have caught the nine-day deploy outage as a
chore rather than an outage: the people lake being empty is a thing to notice
in doctor, not a reason for a test to fail on the build box.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from umbra.cli.onboarding import _age_days, _lake_check, lake_checks
from umbra.core.config import Settings


def _iso(days_ago: float) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(days=days_ago)).isoformat()


class TestOneLake:
    def test_empty_lake_names_the_command_that_fills_it(self):
        c = _lake_check("geoip", 0, None)
        assert not c.ok
        assert c.optional  # Umbra works without it; this is not a failure
        assert "umbra geoip sync" in c.detail

    def test_fresh_lake_reports_rows_and_age(self):
        c = _lake_check("abuse.ch", 12345, _iso(2))
        assert c.ok
        assert "12,345 rows" in c.detail
        assert "2d ago" in c.detail

    def test_stale_lake_is_flagged_with_its_threshold(self):
        # Blocklists move in hours. A month-old copy is materially wrong, and
        # saying "1,000 rows" without saying when would imply it is current.
        c = _lake_check("abuse.ch", 1000, _iso(30))
        assert not c.ok
        assert "stale past 7d" in c.detail
        assert "umbra abuse sync" in c.detail

    def test_ct_is_allowed_to_be_older_than_a_blocklist(self):
        # The CT corpus is tail-forward and always incomplete by design.
        assert _lake_check("certificate transparency", 2100, _iso(16)).ok
        assert not _lake_check("abuse.ch", 2100, _iso(16)).ok

    def test_today_reads_as_today(self):
        assert "today" in _lake_check("geoip", 5, _iso(0.1)).detail

    def test_unknown_timestamp_says_so_rather_than_guessing(self):
        # "unchecked is not clean" applies to freshness too: a lake whose sync
        # time cannot be read must not render as fresh.
        c = _lake_check("people", 10001, None)
        assert "last sync unknown" in c.detail


class TestAgeParsing:
    @pytest.mark.parametrize("stamp", [None, "", "not a date", 12345])
    def test_unreadable_stamps_return_none_rather_than_raising(self, stamp):
        assert _age_days(stamp) is None

    def test_handles_a_z_suffix_and_a_naive_stamp(self):
        assert _age_days(_iso(3).replace("+00:00", "Z")) == pytest.approx(3, abs=0.1)
        naive = (datetime.now(tz=timezone.utc) - timedelta(days=3)).replace(tzinfo=None)
        assert _age_days(naive.isoformat()) == pytest.approx(3, abs=0.1)


class TestAllLakes:
    def test_never_raises_on_a_bare_data_dir(self, tmp_path):
        # doctor is what you run when things are broken; it must not be the
        # thing that breaks.
        checks = lake_checks(Settings(data_dir=tmp_path))
        assert checks
        names = {c.name for c in checks}
        assert {"abuse.ch lake", "geoip lake", "people lake"} <= names

    def test_a_cold_lake_is_optional_not_a_failure(self, tmp_path):
        for c in lake_checks(Settings(data_dir=tmp_path)):
            assert c.optional, f"{c.name} must not fail an install that simply has no lakes"


class TestWikiCorpusFreshness:
    """A corpus eleven days behind upstream looked perfectly healthy.

    `umbra doctor` reported "wiki corpus: 3681 pages" and nothing else. The KEV
    entries added since simply were not there — measuring CVE coverage against
    that stale copy produced a 16-entry gap that did not exist upstream. Size
    without age is the same omission as a lake reporting rows with no sync time.
    """

    def test_a_fresh_corpus_passes_and_counts_cves(self, tmp_path):
        from umbra.cli.onboarding import doctor_checks
        from umbra.core.config import Settings

        corpus = tmp_path / "wiki"
        (corpus / "cve").mkdir(parents=True)
        for i in range(3):
            (corpus / "cve" / f"CVE-2021-4422{i}.md").write_text("# page\n")
        (corpus / "index.md").write_text("# index\n")

        import umbra.cli.onboarding as ob

        original = ob._wiki_corpus_dir
        ob._wiki_corpus_dir = lambda: corpus
        try:
            check = next(c for c in doctor_checks(Settings(data_dir=tmp_path))
                         if c.name == "wiki corpus")
        finally:
            ob._wiki_corpus_dir = original

        assert check.ok
        assert "4 pages" in check.detail
        assert "3 CVE" in check.detail
        assert "today" in check.detail

    def test_a_stale_corpus_is_flagged_with_the_remedy(self, tmp_path, monkeypatch):
        import os
        import time

        from umbra.cli.onboarding import doctor_checks
        from umbra.core.config import Settings

        corpus = tmp_path / "wiki"
        corpus.mkdir()
        page = corpus / "old.md"
        page.write_text("# old\n")
        old = time.time() - 30 * 86400
        os.utime(page, (old, old))

        import umbra.cli.onboarding as ob

        original = ob._wiki_corpus_dir
        ob._wiki_corpus_dir = lambda: corpus
        try:
            check = next(c for c in doctor_checks(Settings(data_dir=tmp_path))
                         if c.name == "wiki corpus")
        finally:
            ob._wiki_corpus_dir = original

        assert not check.ok
        assert "stale past 14d" in check.detail
        assert "umbra wiki update" in check.detail
        # Still optional: Umbra runs without a corpus at all.
        assert check.optional
