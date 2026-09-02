"""Stage S1 / Phase B4 — collector and job timeouts.

Acceptance: a hung collector cannot block the worker forever. A slow collector
costs one collector slot, not the run; a run that exceeds its wall clock stops
cleanly; and neither takes the worker process down.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

from umbra.collectors.base import BaseCollector, CollectorRegistry
from umbra.core.config import Settings
from umbra.core.models import CollectorResult, EntityIn, EntityType, EvidenceIn
from umbra.core.orchestrator import Orchestrator
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db


class SlowCollector(BaseCollector):
    """Simulates a hung upstream (unresponsive DNS/HTTP with no timeout)."""

    name = "slow_test"
    inputs = {EntityType.DOMAIN}
    description = "test-only: sleeps past the collector timeout"

    def __init__(self, seconds: float = 5.0):
        self.seconds = seconds

    def collect(self, entity, ctx) -> CollectorResult:  # pragma: no cover - timing
        time.sleep(self.seconds)
        return CollectorResult(notes=["slow collector finished (should not be reached)"])


class FastCollector(BaseCollector):
    name = "fast_test"
    inputs = {EntityType.DOMAIN}
    description = "test-only: returns immediately"

    def collect(self, entity, ctx) -> CollectorResult:
        return CollectorResult(
            entities=[EntityIn(type=EntityType.IP, value="192.0.2.7", confidence=0.6)],
            evidence=[EvidenceIn(collector=self.name, source_name="test",
                                 summary="fast ok", entity_key=entity.norm_key)],
            notes=["fast collector ran"],
        )


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    r = Repository(get_session(), settings.raw_dir)
    return r


def _seeded_case(repo: Repository) -> str:
    case = repo.create_case("timeouts", "training_lab", "t")
    repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value="example.com", confidence=0.95))
    repo.session.commit()
    return case.id


def _registry(*collectors) -> CollectorRegistry:
    reg = CollectorRegistry()
    for c in collectors:
        reg.register(c)
    return reg


# --- per-collector timeout ------------------------------------------------

def test_slow_collector_times_out_and_is_recorded(repo, tmp_path):
    """A hung collector must be abandoned, counted as an error, and NOT stop
    the run — this is the core B4 acceptance."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=0.3)
    case_id = _seeded_case(repo)
    orch = Orchestrator(repo, settings=settings, registry=_registry(SlowCollector(seconds=5)))

    started = time.monotonic()
    stats = orch.run(case_id, depth=0, collectors=["slow_test"])
    elapsed = time.monotonic() - started

    assert elapsed < 4.0, "run must not wait for the hung collector"
    assert stats["errors"] >= 1
    # "timed out" or "timeout" — the contract is that the note says so, not
    # which spelling. The message now also names the budget it exceeded, since
    # a global number the operator cannot find in the code is not actionable.
    assert any(
        "timed out" in n.lower() or "timeout" in n.lower() for n in stats["notes"]
    ), stats["notes"]


def test_run_continues_after_a_collector_times_out(repo, tmp_path):
    """One slow collector must not deprive the case of the others' results."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=0.3)
    case_id = _seeded_case(repo)
    orch = Orchestrator(
        repo, settings=settings, registry=_registry(SlowCollector(seconds=5), FastCollector())
    )

    stats = orch.run(case_id, depth=0, collectors=["slow_test", "fast_test"])

    assert stats["collector_runs"] >= 1, "the fast collector must still have run"
    assert any("fast collector ran" in n for n in stats["notes"]), stats["notes"]
    values = {e.value for e in repo.list_entities(case_id)}
    assert "192.0.2.7" in values, "results from the healthy collector must persist"


def test_fast_collector_is_unaffected_by_the_timeout(repo, tmp_path):
    settings = Settings(data_dir=tmp_path, collector_timeout_s=0.3)
    case_id = _seeded_case(repo)
    orch = Orchestrator(repo, settings=settings, registry=_registry(FastCollector()))
    stats = orch.run(case_id, depth=0, collectors=["fast_test"])
    assert stats["errors"] == 0
    assert stats["collector_runs"] == 1


# --- job wall-clock budget ------------------------------------------------

def test_run_stops_at_wall_clock_budget(repo, tmp_path):
    """Many individually-tolerable collectors must still not run forever."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=2.0, job_max_seconds=0.5)
    case_id = _seeded_case(repo)
    orch = Orchestrator(
        repo, settings=settings, registry=_registry(SlowCollector(seconds=1.0))
    )

    started = time.monotonic()
    stats = orch.run(case_id, depth=0, collectors=["slow_test"])
    elapsed = time.monotonic() - started

    assert elapsed < 5.0
    assert any("budget" in n.lower() or "wall" in n.lower() for n in stats["notes"]), stats["notes"]


def test_zero_timeout_disables_the_limit(repo, tmp_path):
    """0 must mean 'no limit', so operators can opt out deliberately."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=0)
    case_id = _seeded_case(repo)
    orch = Orchestrator(repo, settings=settings, registry=_registry(FastCollector()))
    stats = orch.run(case_id, depth=0, collectors=["fast_test"])
    assert stats["errors"] == 0


# --- defaults -------------------------------------------------------------

def test_timeout_settings_have_sane_defaults():
    s = Settings()
    assert s.collector_timeout_s > 0, "a hung collector must be bounded by default"
    assert s.job_max_seconds > s.collector_timeout_s


# --- per-collector budgets (U5) -------------------------------------------

def test_every_collector_declares_its_own_budget():
    """One global timeout is wrong in both directions.

    45s for a DNS lookup means a dead resolver holds the run open fifteen times
    longer than it needs to. 45s for a git clone truncates real work — which is
    exactly what happened to `github_commits` in a live run.
    """
    from umbra.collectors.base import default_registry

    missing = [c.name for c in default_registry().list() if not getattr(c, "timeout_s", None)]
    assert not missing, f"collectors with no declared budget: {missing}"


def test_budgets_are_proportionate_to_the_work():
    """A sanity band, not a spec. Anything outside it is likely a typo."""
    from umbra.collectors.base import default_registry

    for col in default_registry().list():
        assert 5 <= col.timeout_s <= 180, f"{col.name} budget {col.timeout_s}s looks wrong"

    by_name = {c.name: c.timeout_s for c in default_registry().list()}
    # Local lake reads must be tighter than network scrapes.
    assert by_name["ct_lake"] < by_name["crtsh"]
    assert by_name["dns_resolve"] < by_name["github_commits"]


def test_a_collectors_own_budget_beats_the_global_default(repo, tmp_path):
    """The declared number is the one that applies."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=30.0)
    case_id = _seeded_case(repo)

    slow = SlowCollector(seconds=5)
    slow.timeout_s = 0.3  # far tighter than the global 30s

    started = time.monotonic()
    stats = Orchestrator(repo, settings=settings, registry=_registry(slow)).run(
        case_id, depth=0, collectors=["slow_test"])
    elapsed = time.monotonic() - started

    assert elapsed < 4.0, "the collector's own 0.3s budget should have applied, not 30s"
    assert any("0.3s budget" in n for n in stats["notes"]), stats["notes"]


def test_the_note_names_the_budget_it_exceeded(repo, tmp_path):
    """A note citing a number the operator cannot find in the code is not
    actionable — it has to be the collector's own declared budget."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=60.0)
    case_id = _seeded_case(repo)
    slow = SlowCollector(seconds=5)
    slow.timeout_s = 0.4

    stats = Orchestrator(repo, settings=settings, registry=_registry(slow)).run(
        case_id, depth=0, collectors=["slow_test"])

    note = next(n for n in stats["notes"] if "slow_test" in n)
    assert "0.4s" in note
    assert "60" not in note, "the note quoted the global default, not the real bound"
    # unchecked is not clean, even for a timeout
    assert "unknown rather than clean" in note


def test_collector_durations_are_recorded(repo, tmp_path):
    """Slow sources were folklore. Recorded so the next budget comes from
    evidence rather than a guess."""
    settings = Settings(data_dir=tmp_path, collector_timeout_s=5.0)
    case_id = _seeded_case(repo)
    slow = SlowCollector(seconds=0.5)
    slow.timeout_s = 5.0

    stats = Orchestrator(repo, settings=settings, registry=_registry(slow)).run(
        case_id, depth=0, collectors=["slow_test"])

    seconds = stats.get("collector_seconds") or {}
    assert "slow_test" in seconds
    assert seconds["slow_test"] >= 0.4


def test_a_timeout_is_a_coverage_gap_not_a_run_cap():
    """Different buckets because the reader reaction differs: a source that
    timed out means this run's coverage is incomplete; a run cap means the run
    stopped early. `budget` alone used to match both."""
    from umbra.core.notes import NoteKind, classify

    assert classify(
        "slow_test timed out after its 30s budget on domain:x — not checked"
    ) == NoteKind.SOURCE_FAILED
    assert classify(
        "job wall-clock budget reached (120s); stopping early"
    ) == NoteKind.LIMIT
