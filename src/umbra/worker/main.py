"""Worker process: claim jobs from the DB queue and run collectors (B2).

Runs as its own container so collectors never share fate with the HTTP server
(`docs/ENGINEERING.md` § Architecture constraints). The API only enqueues; this
process does the slow work.

Design rules, each of which is a test:
- **One bad job must not kill the worker.** Any exception from the runner marks
  that job `failed` and the loop continues. A poisonous target should cost one
  job, not the whole pipeline.
- **Shutdown is cooperative.** SIGTERM/SIGINT set a flag; the loop finishes the
  job in hand and exits, rather than being killed mid-run and leaving a row
  stuck `running`.
- **Stale jobs are rescued on startup**, so a previous hard kill self-heals.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Callable

from umbra.core.config import get_settings
from umbra.core.orchestrator import Orchestrator
from umbra.db.repository import Repository
from umbra.db.schema import Job, get_session, init_db
from umbra.export.profile import export_graphml, write_profile

logger = logging.getLogger("umbra.worker")

JobRunner = Callable[[Job], dict]


def run_job_with_orchestrator(repo: Repository, job: Job) -> dict:
    """Default runner: the same Orchestrator the CLI and web UI use."""
    settings = get_settings()
    orch = Orchestrator(repo)
    stats = orch.run(
        job.case_id,
        depth=job.depth,
        collectors=list(job.collectors) or None,
        max_entities=job.max_entities,
    )
    try:
        prof = settings.exports_dir / f"{job.case_id}_profile.md"
        write_profile(repo, job.case_id, prof, seed_value=job.seed_value)
        export_graphml(repo, job.case_id, settings.exports_dir / f"{job.case_id}.graphml")
    except Exception as exc:  # noqa: BLE001 - export failure must not fail the run
        logger.warning("export failed for case %s: %s", job.case_id, exc)
        stats = dict(stats or {})
        stats["export_warning"] = str(exc)[:200]
    return stats


class WorkerLoop:
    """Claim → run → finish, with failure isolation and cooperative shutdown."""

    def __init__(
        self,
        repo: Repository,
        worker_id: str,
        runner: JobRunner | None = None,
        job_timeout_s: float | None = None,
    ):
        self.repo = repo
        self.worker_id = worker_id
        self.runner = runner or (lambda job: run_job_with_orchestrator(self.repo, job))
        self.should_stop = False
        # Belt-and-braces with the orchestrator's own budget (B4): even if a
        # runner ignores it, no single job may occupy the worker forever.
        # 0/None disables the bound.
        self.job_timeout_s = (
            job_timeout_s if job_timeout_s is not None
            else float(os.environ.get("UMBRA_JOB_TIMEOUT_S", "3600"))
        )

    def request_stop(self, *_args) -> None:
        logger.info("stop requested; finishing current job then exiting")
        self.should_stop = True

    def tick(self) -> bool:
        """Process at most one job. Returns True if a job was handled."""
        job = self.repo.claim_job(self.worker_id)
        if job is None:
            return False

        logger.info("job %s claimed (case=%s collectors=%s depth=%s)",
                    job.id, job.case_id, job.collectors, job.depth)
        try:
            stats = self._run_with_timeout(job) or {}
            self.repo.finish_job(job, "ok", stats=stats)
            logger.info("job %s ok: %s", job.id, stats)
            self._check_run_quality(job, stats)
        except FuturesTimeout:
            msg = f"job timeout after {self.job_timeout_s:.0f}s"
            logger.error("job %s %s", job.id, msg)
            self.repo.finish_job(job, "failed", stats={}, error=msg)
            # Timeouts and crashes triage differently: a timeout usually points
            # at a budget or a slow upstream, a crash usually at a bug.
            self._emit_job_event(job, "job_timeout", msg, collectors=job.collectors)
        except Exception as exc:  # noqa: BLE001 - isolate the job, keep the worker
            logger.exception("job %s failed", job.id)
            self.repo.finish_job(job, "failed", stats={}, error=f"{type(exc).__name__}: {exc}"[:2000])
            self._emit_job_event(job, "job_failed", f"{type(exc).__name__}: {exc}",
                                 collectors=job.collectors)
        return True

    def _check_run_quality(self, job: Job, stats: dict) -> None:
        """Unattended runs are the ones nobody watches finish (E2)."""
        from umbra.ops.quality import check_run_quality

        check_run_quality(stats, case_id=job.case_id, collectors=job.collectors,
                          job_id=job.id, source="worker")

    def _emit_job_event(self, job: Job, kind: str, message: str,
                        collectors=None) -> None:
        """Record a job failure as an ops event (E1).

        Fingerprinted on kind + collector set + error type, never on the job or
        case id — otherwise one broken collector produces a new event per run
        and the dedupe is worthless.
        """
        from umbra.ops.events import emit

        cols = ",".join(sorted(collectors or [])) or "all"
        error_type = message.split(":", 1)[0][:60]
        emit(
            severity="S2",
            kind=kind,
            title=f"{kind} [{cols}]: {message}"[:500],
            detail={
                "case_id": job.case_id,
                "job_id": job.id,
                "worker_id": self.worker_id,
                "collectors": list(collectors or []),
                "error": message[:2000],
            },
            fingerprint_key=f"{cols}|{error_type}",
            source="worker",
        )

    def _run_with_timeout(self, job: Job) -> dict:
        """Execute the job, abandoning it if it exceeds the wall clock.

        The pool is not awaited on timeout — waiting for a stuck job is exactly
        what this prevents. Threads are daemons, so an abandoned one cannot keep
        the process alive; the job row is marked failed and the loop moves on.
        """
        if not self.job_timeout_s or self.job_timeout_s <= 0:
            return self.runner(job)

        pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"job-{job.id}")
        try:
            return pool.submit(self.runner, job).result(timeout=self.job_timeout_s)
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def run(self, idle_sleep_s: float = 2.0, max_idle_ticks: int | None = None) -> None:
        """Drain the queue until stopped.

        `max_idle_ticks` exists for tests and one-shot draining: stop after that
        many consecutive empty polls instead of running forever.
        """
        idle = 0
        while not self.should_stop:
            worked = self.tick()
            if worked:
                idle = 0
                continue
            idle += 1
            if max_idle_ticks is not None and idle >= max_idle_ticks:
                return
            if idle_sleep_s:
                time.sleep(idle_sleep_s)


def main() -> None:  # pragma: no cover - process entrypoint
    logging.basicConfig(
        level=os.environ.get("UMBRA_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s worker %(message)s",
    )
    settings = get_settings()
    init_db(settings)
    repo = Repository(get_session(), settings.raw_dir)

    worker_id = os.environ.get("UMBRA_WORKER_ID") or f"worker-{os.getpid()}"
    poll_s = float(os.environ.get("UMBRA_WORKER_POLL_S", "2"))
    stale_s = float(os.environ.get("UMBRA_WORKER_STALE_S", "1800"))

    # Self-heal: a previous hard kill can leave rows stuck 'running'.
    try:
        rescued = repo.requeue_stale_jobs(older_than_s=stale_s)
        if rescued:
            logger.warning("requeued %s stale job(s) from a previous run", rescued)
        # The job sweep above was not enough on its own: production had runs
        # stuck at "running" for 120 hours whose jobs had all completed `ok`.
        # The job was rescued; the run row was never closed, and the case page
        # kept telling its owner the work was still going.
        reaped = repo.reap_orphaned_runs()
        if reaped:
            logger.warning("closed %s run(s) abandoned by a previous worker", reaped)
    except Exception:  # noqa: BLE001
        logger.exception("stale-job sweep failed (continuing)")

    loop = WorkerLoop(repo, worker_id=worker_id)
    signal.signal(signal.SIGTERM, loop.request_stop)
    signal.signal(signal.SIGINT, loop.request_stop)

    logger.info("umbra worker %s started (poll=%ss)", worker_id, poll_s)
    loop.run(idle_sleep_s=poll_s)
    logger.info("umbra worker %s stopped cleanly", worker_id)


if __name__ == "__main__":  # pragma: no cover
    main()
