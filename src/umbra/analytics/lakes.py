"""Lake health over time — what `umbra doctor` structurally cannot tell you.

`doctor` reports each lake's row count and age as of now. That catches a lake
nobody is syncing. It cannot catch the more dangerous failure: a sync that ran,
returned HTTP 200, and quietly brought back less than it should have.

That failure is on the record. A Tor node fetch from dan.me.uk was rate-limited
and returned **12KB where 2.4MB was expected, at HTTP 200**. Every per-request
check passed. Nothing about that response, examined alone, was wrong. The only
signal was the row count set against the previous day's.

Hence a series rather than a state. A lake that shrank did not update; it lost
something, and an operator needs to hear about it before Umbra starts answering
"not listed" out of a corpus that no longer contains the answer — which it will
do with total confidence, because absence is indistinguishable from clean once
the rows are gone.

Staleness is judged per lake, from `EXPECTED_CADENCE_DAYS`. One global
threshold is wrong in both directions: abuse.ch moves in hours and DB-IP
publishes monthly, so twenty days is an incident for the first and unremarkable
for the second.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import select

from umbra.core.models import utcnow
from umbra.db.schema import LakeSnapshot

#: How long each corpus may go between syncs before a "not listed" answer from
#: it stops being trustworthy. Mirrors the thresholds `umbra doctor` reports
#: against; the reasoning for each number lives there.
EXPECTED_CADENCE_DAYS = {
    "abuse.ch": 7,
    "certificate transparency": 30,
    "geoip": 45,
    "epss": 7,
    "public suffix": 60,
    "people": 90,
    "tor": 3,
    "wiki": 7,
    # The FAA refreshes daily; a month-old copy still answers most
    # registrations correctly, but ownership changes are the point.
    "faa registry": 30,
}

#: The command that warms each lake, so a stale row can say what to do about it
#: instead of only that something is wrong.
REMEDY = {
    "abuse.ch": "umbra abuse sync",
    "certificate transparency": "umbra ct ingest",
    "geoip": "umbra geoip sync",
    "epss": "umbra epss sync",
    "public suffix": "umbra psl sync",
    "people": "umbra people seed",
    "tor": "umbra tor sync",
    "wiki": "umbra wiki update",
    "faa registry": "umbra faa sync",
}

DEFAULT_CADENCE_DAYS = 30


@dataclass
class LakeReading:
    """One lake as it looks right now, before any comparison.

    `rows=None` with an `error` is materially different from `rows=0`: the
    first means we could not look, the second means we looked and it is empty.
    Collapsing them would later render an unreadable lake as one that lost
    everything it had.
    """

    lake: str
    rows: int | None
    synced_at: datetime | None
    error: str | None = None

    @property
    def readable(self) -> bool:
        return self.error is None and self.rows is not None


@dataclass
class LakeRow:
    lake: str
    rows: int
    synced_at: datetime | None
    observed_at: datetime
    previous_rows: int | None = None
    stale: bool = False
    age_days: float | None = None
    cadence_days: int = DEFAULT_CADENCE_DAYS

    @property
    def delta(self) -> int | None:
        """Change since the previous snapshot, or None when there isn't one.

        None rather than 0: "did not change" and "nothing to compare against"
        are different claims, and printing the second as the first is how a
        first-ever snapshot comes to look like a stable corpus.
        """
        if self.previous_rows is None:
            return None
        return self.rows - self.previous_rows

    @property
    def shrank(self) -> bool:
        d = self.delta
        return d is not None and d < 0

    @property
    def healthy(self) -> bool:
        return not self.shrank and not self.stale

    @property
    def note(self) -> str:
        if self.shrank:
            return (
                f"shrank by {abs(self.delta):,} to {self.rows:,} rows — a sync "
                f"that returns fewer rows than it replaced has usually failed "
                f"while reporting success; check the source before trusting a "
                f"'not listed' answer from this lake"
            )
        if self.stale:
            cmd = REMEDY.get(self.lake)
            tail = f" — run `{cmd}`" if cmd else ""
            age = f"{self.age_days:.0f}d" if self.age_days is not None else "unknown age"
            return (
                f"last synced {age} ago, past its {self.cadence_days}d "
                f"cadence{tail}"
            )
        if self.previous_rows is None:
            return f"{self.rows:,} rows — no previous snapshot to compare against yet"
        if self.delta == 0:
            return f"{self.rows:,} rows, unchanged since the previous snapshot"
        return f"{self.rows:,} rows, +{self.delta:,} since the previous snapshot"


@dataclass
class LakeHealth:
    rows: list[LakeRow] = field(default_factory=list)

    @property
    def by_name(self) -> dict[str, LakeRow]:
        return {r.lake: r for r in self.rows}

    @property
    def anomalies(self) -> list[LakeRow]:
        """Lakes that shrank or went stale — the rows worth waking up for."""
        return [r for r in self.rows if not r.healthy]

    @property
    def note(self) -> str:
        if not self.rows:
            return (
                "no snapshots recorded yet — run `umbra analytics lakes --record` "
                "(or let the timer do it) and there will be a series to compare"
            )
        bad = self.anomalies
        if not bad:
            return f"{len(self.rows)} lake(s), all fresh and none shrinking"
        return f"{len(self.rows)} lake(s), {len(bad)} needing attention"


def _age_days(stamp: datetime | None) -> float | None:
    if stamp is None:
        return None
    when = stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    return (utcnow() - when).total_seconds() / 86400.0


def record_snapshot(session, readings: list[LakeReading]) -> int:
    """Append one snapshot row per readable lake. Returns how many were written.

    An unreadable lake is skipped rather than stored as zero — see LakeReading.
    """
    written = 0
    for reading in readings:
        if not reading.readable:
            continue
        session.add(LakeSnapshot(
            id=uuid4().hex[:32],
            ts=utcnow(),
            lake=reading.lake,
            rows=int(reading.rows or 0),
            synced_at=reading.synced_at,
        ))
        written += 1
    if written:
        session.commit()
    return written


def lake_health(session, days: int = 90) -> LakeHealth:
    """Latest reading per lake, compared against the one before it."""
    since = utcnow() - timedelta(days=days)
    snaps = session.execute(
        select(LakeSnapshot)
        .where(LakeSnapshot.ts >= since)
        .order_by(LakeSnapshot.lake, LakeSnapshot.ts.desc())
    ).scalars().all()

    seen: dict[str, list[LakeSnapshot]] = {}
    for snap in snaps:
        seen.setdefault(snap.lake, []).append(snap)

    rows: list[LakeRow] = []
    for lake, series in seen.items():
        latest = series[0]
        previous = series[1] if len(series) > 1 else None
        cadence = EXPECTED_CADENCE_DAYS.get(lake, DEFAULT_CADENCE_DAYS)
        age = _age_days(latest.synced_at)
        rows.append(LakeRow(
            lake=lake,
            rows=int(latest.rows or 0),
            synced_at=latest.synced_at,
            observed_at=latest.ts,
            previous_rows=int(previous.rows) if previous is not None else None,
            # An unknown sync time is not treated as stale: the lake may simply
            # not record one, and inventing an incident from a missing field
            # trains an operator to ignore the report.
            stale=(age is not None and age > cadence),
            age_days=age,
            cadence_days=cadence,
        ))

    rows.sort(key=lambda r: (r.healthy, r.lake))
    return LakeHealth(rows=rows)
