"""Per-collector scorecard: where a run's time goes, and what it buys.

Prod measurement that motivated this (2026-09-02): run wall-clock is p50 1.9s
against p95 59.2s. A 31x tail, and nothing in the product could say which
collector caused it. The data was already being written — `Orchestrator` has
accumulated `stats["collector_seconds"]` since the per-collector timeout budget
landed — it had simply never been read back. Aggregating it named the culprit
immediately: `rdap_ip` at 6.58s mean per run and 276s total, against every other
collector under 1s.

Two properties this module exists to preserve, because getting either wrong
turns a useful number into a confident lie:

**The unit is seconds per run, not per call.** `collector_seconds[name]` is a
sum over every entity that collector saw during the run. A run that fanned out
to ten IPs records one figure covering ten lookups. Dividing by an invented call
count would manufacture a latency the orchestrator never measured, so the field
is named `mean_seconds_per_run` and there is deliberately no per-call sibling.

**Unmeasured is not fast.** Timing arrived with U5, so historical runs carry
none — 60 of 672 on prod at the time of writing. Averaging the 60 and presenting
it as how Umbra behaves is the same error as a blocklist reporting `unknown` as
`clean`, which the rest of the codebase goes out of its way not to make. Every
report therefore carries `runs_total`, `runs_with_timing` and a `coverage_note`
that says so in words.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, select

from umbra.core.models import utcnow
from umbra.db.schema import Evidence, Run

DEFAULT_WINDOW_DAYS = 30

# The orchestrator writes both of these; matching its exact phrasing keeps the
# parse honest. A note that names no collector — "IP geolocation is
# approximate…" — matches neither and is charged to nobody.
_TIMEOUT_NOTE = re.compile(r"^(?P<name>[a-z0-9_]+) timed out after its ")
_ERROR_NOTE = re.compile(r"^(?P<name>[a-z0-9_]+) on [a-z0-9_]+:\S+: ")


@dataclass
class CollectorRow:
    collector: str
    runs: int = 0
    total_seconds: float = 0.0
    evidence: int = 0
    timeouts: int = 0
    errors: int = 0
    #: Mean confidence of the evidence this collector produced, or None when it
    #: produced none. Not 0.0 — that reads as "produced worthless evidence"
    #: rather than "produced nothing".
    mean_confidence: float | None = None
    #: Share of all measured collector time in the window, 0.0–1.0.
    share_of_seconds: float = 0.0

    @property
    def mean_seconds_per_run(self) -> float:
        """Seconds this collector cost in an average run it took part in.

        Per *run*, not per call — see the module docstring. A run that fanned
        out to ten entities contributes one figure covering all ten.
        """
        return (self.total_seconds / self.runs) if self.runs else 0.0

    @property
    def evidence_per_run(self) -> float:
        """Yield. The interesting row is high seconds with this near zero."""
        return (self.evidence / self.runs) if self.runs else 0.0


@dataclass
class Scorecard:
    days: int
    runs_total: int
    runs_with_timing: int
    rows: list[CollectorRow] = field(default_factory=list)

    @property
    def measured_seconds(self) -> float:
        return sum(r.total_seconds for r in self.rows)

    @property
    def coverage_note(self) -> str:
        """Always says what the numbers are drawn from.

        A partial aggregate presented without its denominator gets read as the
        whole picture; that is the failure this string exists to prevent.
        """
        if not self.runs_total:
            return f"no runs in the last {self.days} days — nothing to measure"
        if self.runs_with_timing == 0:
            return (
                f"{self.runs_total} run(s) in the last {self.days} days, none "
                "carrying per-collector timing — timing is recorded from the "
                "per-collector budget onwards, so older runs have none"
            )
        if self.runs_with_timing < self.runs_total:
            return (
                f"measured across {self.runs_with_timing} of {self.runs_total} "
                f"run(s) in the last {self.days} days; the rest predate "
                "per-collector timing and are not counted as fast"
            )
        return (
            f"measured across all {self.runs_total} run(s) in the last "
            f"{self.days} days"
        )


def _attribute_note(note: str, rows: dict[str, CollectorRow]) -> None:
    """Charge a run note to the collector it names, if it names one.

    Only collectors already seen in `collector_seconds` can be charged. A note
    naming something that never ran in this window would otherwise conjure a
    row with zero seconds and one error, which reads as a collector that is
    purely broken rather than one that is absent.
    """
    for pattern, attr in ((_TIMEOUT_NOTE, "timeouts"), (_ERROR_NOTE, "errors")):
        m = pattern.match(note)
        if m:
            row = rows.get(m.group("name"))
            if row is not None:
                setattr(row, attr, getattr(row, attr) + 1)
            return


def collector_scorecard(session, days: int = DEFAULT_WINDOW_DAYS) -> Scorecard:
    """Aggregate `runs.stats` and `evidence` into one row per collector.

    Never raises on malformed stats: a run whose JSON is not the shape expected
    is skipped rather than allowed to take the whole report down. The report is
    what an operator opens when something is already wrong.
    """
    since = utcnow() - timedelta(days=days)
    runs = session.execute(
        select(Run).where(Run.started_at >= since)
    ).scalars().all()

    rows: dict[str, CollectorRow] = {}
    runs_with_timing = 0
    for run in runs:
        stats = run.stats if isinstance(run.stats, dict) else {}
        seconds = stats.get("collector_seconds")
        if not isinstance(seconds, dict) or not seconds:
            continue
        runs_with_timing += 1
        for name, secs in seconds.items():
            try:
                value = float(secs)
            except (TypeError, ValueError):
                continue
            row = rows.setdefault(str(name), CollectorRow(collector=str(name)))
            row.runs += 1
            row.total_seconds += value
        for note in stats.get("notes") or []:
            if isinstance(note, str):
                _attribute_note(note, rows)

    if rows:
        run_ids = [r.id for r in runs]
        counts = session.execute(
            select(Evidence.collector, func.count(Evidence.id),
                   func.avg(Evidence.confidence))
            .where(Evidence.run_id.in_(run_ids))
            .group_by(Evidence.collector)
        ).all()
        for name, n, avg_conf in counts:
            row = rows.get(str(name))
            if row is None:
                # Evidence from a collector with no timing in this window. It
                # belongs to the window but not to the time budget, so it gets
                # a row with zero seconds rather than being dropped.
                row = rows.setdefault(str(name), CollectorRow(collector=str(name)))
            row.evidence = int(n or 0)
            row.mean_confidence = round(float(avg_conf), 3) if avg_conf is not None else None

    total = sum(r.total_seconds for r in rows.values())
    for row in rows.values():
        row.share_of_seconds = (row.total_seconds / total) if total else 0.0
        row.total_seconds = round(row.total_seconds, 2)

    ordered = sorted(
        rows.values(), key=lambda r: (-r.total_seconds, -r.evidence, r.collector)
    )
    return Scorecard(days=days, runs_total=len(runs),
                     runs_with_timing=runs_with_timing, rows=ordered)
