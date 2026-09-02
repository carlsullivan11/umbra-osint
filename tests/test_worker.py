"""Phase B2 — worker process that drains the job queue.

The worker must be boring and unkillable: one bad job must never take down the
process, and a shutdown signal must not abandon work silently.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.core.config import Settings
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.worker.main import WorkerLoop


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    r = Repository(get_session(), settings.raw_dir)
    r._case = r.create_case("worker", "training_lab", "t")  # type: ignore[attr-defined]
    r.session.commit()
    return r


def _case(repo) -> str:
    return repo._case.id  # type: ignore[attr-defined]


def test_processes_a_queued_job(repo):
    job = repo.enqueue_job(_case(repo), ["dns_resolve"], 1, 10)
    seen = []

    loop = WorkerLoop(repo, worker_id="w1", runner=lambda j: seen.append(j.id) or {"processed": 1})
    assert loop.tick() is True          # claimed and ran something
    assert seen == [job.id]

    done = repo.get_job(job.id)
    assert done.status == "ok"
    assert done.stats == {"processed": 1}
    assert done.finished_at is not None


def test_tick_is_false_when_queue_empty(repo):
    loop = WorkerLoop(repo, worker_id="w1", runner=lambda j: {})
    assert loop.tick() is False


def test_failing_job_is_marked_failed_not_crashing_the_worker(repo):
    """One poisonous job must not kill the process — that is the whole point
    of a worker separate from the API."""
    job = repo.enqueue_job(_case(repo), ["boom"], 1, 10)

    def explode(j):
        raise RuntimeError("collector exploded")

    loop = WorkerLoop(repo, worker_id="w1", runner=explode)
    assert loop.tick() is True          # handled, did not raise

    done = repo.get_job(job.id)
    assert done.status == "failed"
    assert "exploded" in (done.error or "")
    assert done.finished_at is not None


def test_worker_continues_after_a_failure(repo):
    bad = repo.enqueue_job(_case(repo), ["boom"], 1, 10)
    good = repo.enqueue_job(_case(repo), ["ok"], 1, 10)

    def runner(j):
        if j.id == bad.id:
            raise RuntimeError("nope")
        return {"processed": 2}

    loop = WorkerLoop(repo, worker_id="w1", runner=runner)
    loop.tick()
    loop.tick()

    assert repo.get_job(bad.id).status == "failed"
    assert repo.get_job(good.id).status == "ok"


def test_stop_requested_ends_the_run_loop(repo):
    """SIGTERM path: the loop must exit cleanly rather than be killed mid-job."""
    loop = WorkerLoop(repo, worker_id="w1", runner=lambda j: {})
    loop.request_stop()
    assert loop.should_stop is True
    # run() must return promptly instead of blocking forever
    loop.run(idle_sleep_s=0)


def test_run_drains_queue_then_stops(repo):
    for _ in range(3):
        repo.enqueue_job(_case(repo), [], 1, 10)
    processed = []

    loop = WorkerLoop(repo, worker_id="w1", runner=lambda j: processed.append(j.id) or {})
    loop.run(idle_sleep_s=0, max_idle_ticks=1)   # stop once the queue runs dry

    assert len(processed) == 3
    assert all(repo.get_job(j).status == "ok" for j in processed)


# --- S1 / B4: worker-level job timeout ------------------------------------

def test_worker_marks_overrunning_job_failed_and_survives(repo, monkeypatch):
    """A job that blows its wall clock must be marked failed with a useful
    message, and the worker must stay alive to take the next one."""
    import time as _t

    slow = repo.enqueue_job(_case(repo), ["slow"], 1, 10)
    nxt = repo.enqueue_job(_case(repo), ["fast"], 1, 10)

    def runner(j):
        if j.id == slow.id:
            _t.sleep(1.0)
            return {}
        return {"processed": 1}

    loop = WorkerLoop(repo, worker_id="w1", runner=runner, job_timeout_s=0.2)
    assert loop.tick() is True

    done = repo.get_job(slow.id)
    assert done.status == "failed"
    assert "timeout" in (done.error or "").lower(), done.error

    # worker still healthy and processes the next job
    assert loop.tick() is True
    assert repo.get_job(nxt.id).status == "ok"


def test_job_timeout_zero_disables_the_limit(repo):
    job = repo.enqueue_job(_case(repo), [], 1, 10)
    loop = WorkerLoop(repo, worker_id="w1", runner=lambda j: {"ok": 1}, job_timeout_s=0)
    assert loop.tick() is True
    assert repo.get_job(job.id).status == "ok"
