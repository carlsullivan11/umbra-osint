"""The run-quality heuristic, shared by every path that runs collectors (E2).

It lives here rather than in the orchestrator so that the *caller* supplies the
context it has — a worker job id, or a CLI invocation — and so a single run can
never emit twice.

Deliberately not in `Orchestrator.run()`: the orchestrator is also used by
playbooks and the exposure monitor, where "found nothing" has different meaning,
and burying an emit inside it makes the signal impossible to reason about from
the call sites.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def check_run_quality(
    stats: dict,
    case_id: str,
    collectors=None,
    job_id: str | None = None,
    source: str = "worker",
) -> None:
    """Emit `run_empty` (S3) when a run succeeded and discovered nothing.

    Silent when no collector ran — that means the plan excluded them all, which
    is a planning outcome rather than a data-quality one, and flagging it buries
    the real signals.
    """
    try:
        collector_runs = int(stats.get("collector_runs") or 0)
        added = int(stats.get("entities_added") or 0)
        if collector_runs <= 0 or added > 0:
            return

        from umbra.ops.events import emit

        cols = ",".join(sorted(collectors or [])) or "all"
        detail = {
            "case_id": case_id,
            "collectors": list(collectors or []),
            "collector_runs": collector_runs,
            "errors": int(stats.get("errors") or 0),
            "processed": int(stats.get("processed") or 0),
            "notes": list(stats.get("notes") or [])[:10],
        }
        if job_id:
            detail["job_id"] = job_id
        emit(
            severity="S3",
            kind="run_empty",
            title=f"run added no entities [{cols}]",
            detail=detail,
            # Keyed on the collector set, not the case: the pattern worth seeing
            # is "this collector set always comes back empty".
            fingerprint_key=f"run_empty|{cols}",
            source=source,
        )
    except Exception:  # noqa: BLE001 - a quality signal must not fail a run
        logger.exception("run quality check failed for case %s", case_id)
