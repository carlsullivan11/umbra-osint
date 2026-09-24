"""Per-collector scorecard, from data the orchestrator already writes.

Prod motivated this: run wall-clock is p50 1.9s / p95 59.2s — a 31x tail with
no attribution anywhere in the product. Aggregating `runs.stats` answered it in
one query: `rdap_ip` averages 6.58s per run against 276s total, while every
other collector sits under 1s. That was invisible before and it is the single
most useful number about how Umbra spends its time.

Two things this must not get wrong, both of which would make the numbers a lie:

1. `collector_seconds[name]` is a **sum over every entity a collector saw in
   that run**, not one call. So the honest unit is seconds *per run*. Dividing
   by anything else and calling it latency would invent a measurement.

2. Timing arrived with the per-collector timeout budget (U5), so most historical
   runs do not carry it — 60 of 672 on prod. A report that silently averages
   over the 60 and presents it as "how Umbra behaves" is the same class of
   error as a blocklist reporting `unknown` as `clean`.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from umbra.analytics.collectors import collector_scorecard
from umbra.core.config import Settings
from umbra.core.models import utcnow
from umbra.db.repository import Repository
from umbra.db.schema import Evidence, get_session, init_db


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    return Repository(get_session(), settings.raw_dir)


def _run(repo, *, seconds=None, notes=None, days_ago=0.0, status="ok", case_id=None):
    case_id = case_id or repo.create_case("acme", "own_asset").id
    run = repo.create_run(case_id, depth=1, max_entities=10,
                          collectors=list((seconds or {}).keys()))
    run.started_at = utcnow() - timedelta(days=days_ago)
    run.finished_at = run.started_at + timedelta(seconds=5)
    run.status = status
    stats = dict(run.stats or {})
    if seconds is not None:
        stats["collector_seconds"] = seconds
    if notes:
        stats["notes"] = notes
    run.stats = stats
    repo.session.commit()
    return run


def _evidence(repo, run, collector, confidence=0.8, n=1):
    for i in range(n):
        repo.session.add(Evidence(
            id=f"{run.id[:8]}{collector[:6]}{i}"[:32], case_id=run.case_id,
            run_id=run.id, collector=collector, source_name=collector,
            summary="s", confidence=confidence))
    repo.session.commit()


# --- the headline number ---------------------------------------------------

def test_a_slow_collector_is_named(repo):
    """The whole point: 31x tail, one culprit, previously unattributable."""
    _run(repo, seconds={"rdap_ip": 6.5, "ip_geo": 0.1})
    card = collector_scorecard(repo.session)
    assert card.rows[0].collector == "rdap_ip"
    assert card.rows[0].total_seconds == pytest.approx(6.5)


def test_collectors_rank_by_total_time_not_by_average(repo):
    """A 0.2s collector on every run costs more than a 5s one used once."""
    for _ in range(40):
        _run(repo, seconds={"chatty": 0.2})
    _run(repo, seconds={"rare": 5.0})
    card = collector_scorecard(repo.session)
    assert card.rows[0].collector == "chatty"
    assert card.rows[0].total_seconds == pytest.approx(8.0)


def test_time_share_is_reported(repo):
    _run(repo, seconds={"slow": 7.5, "fast": 2.5})
    by = {r.collector: r for r in collector_scorecard(repo.session).rows}
    assert by["slow"].share_of_seconds == pytest.approx(0.75)


# --- the unit must not be misrepresented -----------------------------------

def test_the_average_is_per_run_not_per_call(repo):
    """collector_seconds sums every entity a collector saw in that run. One run
    covering 10 entities in 8s is 8s per run — calling it 0.8s per call would
    invent a measurement the orchestrator never took."""
    _run(repo, seconds={"rdap_ip": 8.0})
    row = collector_scorecard(repo.session).rows[0]
    assert row.runs == 1
    assert row.mean_seconds_per_run == pytest.approx(8.0)
    assert not hasattr(row, "mean_seconds_per_call")


# --- coverage: unmeasured is not fast --------------------------------------

def test_coverage_is_reported_when_older_runs_carry_no_timing(repo):
    """Timing arrived with U5. 60 of 672 prod runs have it."""
    for _ in range(3):
        _run(repo, seconds={"dns_resolve": 0.4})
    for _ in range(7):
        _run(repo, seconds=None)
    card = collector_scorecard(repo.session)
    assert card.runs_total == 10
    assert card.runs_with_timing == 3


def test_partial_coverage_is_stated_in_words(repo):
    """A number nobody can qualify gets used as if it were complete."""
    _run(repo, seconds={"dns_resolve": 0.4})
    _run(repo, seconds=None)
    assert "1 of 2" in collector_scorecard(repo.session).coverage_note


def test_full_coverage_says_so_rather_than_staying_silent(repo):
    _run(repo, seconds={"dns_resolve": 0.4})
    note = collector_scorecard(repo.session).coverage_note
    assert "2 of" not in note
    assert note


def test_no_runs_at_all_is_empty_not_a_zero_row(repo):
    """An install that has never run must not render a table of zeroes."""
    card = collector_scorecard(repo.session)
    assert card.rows == []
    assert card.runs_total == 0
    assert "no runs" in card.coverage_note.lower()


# --- yield: time is only half the question ---------------------------------

def test_evidence_yield_per_run_is_computed(repo):
    run = _run(repo, seconds={"dns_resolve": 0.4})
    _evidence(repo, run, "dns_resolve", n=3)
    row = collector_scorecard(repo.session).rows[0]
    assert row.evidence == 3
    assert row.evidence_per_run == pytest.approx(3.0)


def test_a_collector_that_costs_time_and_returns_nothing_is_visible(repo):
    """The interesting row: expensive and empty."""
    _run(repo, seconds={"expensive_dud": 9.0})
    row = collector_scorecard(repo.session).rows[0]
    assert row.evidence == 0
    assert row.evidence_per_run == 0.0


def test_mean_confidence_of_produced_evidence_is_reported(repo):
    """Prod: ip_reputation averages 0.51, asn_cymru 0.90. Same second spent,
    very different value."""
    run = _run(repo, seconds={"weak": 1.0})
    _evidence(repo, run, "weak", confidence=0.5, n=2)
    row = collector_scorecard(repo.session).rows[0]
    assert row.mean_confidence == pytest.approx(0.5)


def test_confidence_is_none_when_nothing_was_produced(repo):
    """Not 0.0 — that reads as "produced worthless evidence"."""
    _run(repo, seconds={"dud": 1.0})
    assert collector_scorecard(repo.session).rows[0].mean_confidence is None


# --- failures, attributed --------------------------------------------------

def test_timeouts_are_counted_per_collector(repo):
    _run(repo, seconds={"rdap_ip": 20.0}, notes=[
        "rdap_ip timed out after its 20s budget on ip:1.2.3.4 — not checked, "
        "so this is unknown rather than clean"])
    assert collector_scorecard(repo.session).rows[0].timeouts == 1


def test_errors_are_counted_per_collector(repo):
    _run(repo, seconds={"crtsh": 1.0}, notes=["crtsh on domain:example.com: boom"])
    assert collector_scorecard(repo.session).rows[0].errors == 1


def test_an_unrelated_note_is_not_charged_to_a_collector(repo):
    """Run notes carry advisories too — "IP geolocation is approximate" names
    no collector and must not be counted as anyone's failure."""
    _run(repo, seconds={"ip_geo": 1.0}, notes=[
        "IP geolocation is approximate. CGNAT, VPN and hosting anycast often "
        "place the IP far from the end user."])
    row = collector_scorecard(repo.session).rows[0]
    assert row.errors == 0 and row.timeouts == 0


def test_a_note_naming_a_collector_that_never_ran_does_not_invent_a_row(repo):
    _run(repo, seconds={"dns_resolve": 0.4}, notes=["ghost on x: boom"])
    assert {r.collector for r in collector_scorecard(repo.session).rows} == {"dns_resolve"}


# --- windowing -------------------------------------------------------------

def test_the_window_excludes_older_runs(repo):
    _run(repo, seconds={"recent": 1.0}, days_ago=1)
    _run(repo, seconds={"ancient": 9.0}, days_ago=90)
    names = {r.collector for r in collector_scorecard(repo.session, days=30).rows}
    assert names == {"recent"}


def test_the_window_is_reported_so_a_total_can_be_interpreted(repo):
    _run(repo, seconds={"a": 1.0})
    assert collector_scorecard(repo.session, days=7).days == 7
