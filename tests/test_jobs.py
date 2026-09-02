"""Phase B1 — durable job model + repository.

The contract that matters: a job survives an API restart, exactly one worker
can claim it, and a crashed worker's job can be recovered rather than lost.

Backed by SQLite here (per PHASES.md#B1); the claim is written to be correct on
both SQLite and Postgres — see `Repository.claim_job`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.core.config import Settings
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    session = get_session()
    r = Repository(session, settings.raw_dir)
    r._case = r.create_case("jobs", "training_lab", "t")  # type: ignore[attr-defined]
    session.commit()
    return r


def _case(repo: Repository) -> str:
    return repo._case.id  # type: ignore[attr-defined]


# --- enqueue --------------------------------------------------------------

def test_enqueue_starts_queued(repo):
    job = repo.enqueue_job(_case(repo), collectors=["dns_resolve"], depth=1, max_entities=40)
    assert job.status == "queued"
    assert job.case_id == _case(repo)
    assert job.collectors == ["dns_resolve"]
    assert job.depth == 1 and job.max_entities == 40
    assert job.started_at is None and job.finished_at is None


def test_enqueued_job_is_visible_for_the_case(repo):
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    jobs = repo.list_jobs(_case(repo))
    assert len(jobs) == 1 and jobs[0].status == "queued"


# --- claim ----------------------------------------------------------------

def test_claim_returns_the_queued_job_and_marks_it_running(repo):
    repo.enqueue_job(_case(repo), collectors=["dns_resolve"], depth=1, max_entities=10)
    job = repo.claim_job(worker_id="w1")
    assert job is not None
    assert job.status == "running"
    assert job.worker_id == "w1"
    assert job.started_at is not None


def test_claim_is_exclusive(repo):
    """Two workers must never run the same job."""
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    first = repo.claim_job(worker_id="w1")
    second = repo.claim_job(worker_id="w2")
    assert first is not None
    assert second is None, "a running job must not be claimable again"


def test_claim_returns_none_when_queue_empty(repo):
    assert repo.claim_job(worker_id="w1") is None


def test_claim_is_fifo(repo):
    a = repo.enqueue_job(_case(repo), collectors=["a"], depth=1, max_entities=10)
    b = repo.enqueue_job(_case(repo), collectors=["b"], depth=1, max_entities=10)
    assert repo.claim_job(worker_id="w1").id == a.id
    assert repo.claim_job(worker_id="w2").id == b.id


# --- finish / fail --------------------------------------------------------

def test_finish_records_stats_and_timestamp(repo):
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    job = repo.claim_job(worker_id="w1")
    repo.finish_job(job, "ok", stats={"processed": 3})
    assert job.status == "ok"
    assert job.stats == {"processed": 3}
    assert job.finished_at is not None
    assert job.error is None


def test_fail_records_error(repo):
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    job = repo.claim_job(worker_id="w1")
    repo.finish_job(job, "failed", stats={}, error="collector exploded")
    assert job.status == "failed"
    assert job.error == "collector exploded"
    assert job.finished_at is not None


def test_finished_job_is_not_reclaimed(repo):
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    job = repo.claim_job(worker_id="w1")
    repo.finish_job(job, "ok", stats={})
    assert repo.claim_job(worker_id="w2") is None


# --- durability / recovery ------------------------------------------------

def test_job_survives_a_new_session(repo, tmp_path):
    """The point of durability: the queue lives in the DB, not in process
    memory, so an API restart cannot lose queued work."""
    job = repo.enqueue_job(_case(repo), collectors=["dns_resolve"], depth=1, max_entities=10)
    repo.session.commit()

    fresh = Repository(get_session(), Settings(data_dir=tmp_path).raw_dir)
    again = fresh.get_job(job.id)
    assert again is not None and again.status == "queued"


def test_stale_running_jobs_can_be_requeued(repo):
    """A worker killed mid-job leaves the row 'running' forever. Recovery must
    be possible or that case is stuck permanently."""
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    job = repo.claim_job(worker_id="dead-worker")
    assert job.status == "running"

    n = repo.requeue_stale_jobs(older_than_s=0)
    assert n == 1
    assert repo.get_job(job.id).status == "queued"
    assert repo.claim_job(worker_id="w2") is not None


def test_requeue_leaves_fresh_running_jobs_alone(repo):
    repo.enqueue_job(_case(repo), collectors=[], depth=1, max_entities=10)
    repo.claim_job(worker_id="w1")
    assert repo.requeue_stale_jobs(older_than_s=3600) == 0
