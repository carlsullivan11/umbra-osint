"""FTC Do Not Call complaints — an owned index of a public feed.

The one source on a phone page that is neither Umbra's own community nor a
commercial data broker: consumer-reported calls, published by the US government,
and **explicitly unverified by the FTC**. Independent of our reporters, so it
corroborates instead of echoing, and honest about its own limits by
construction.

**The API is the trap; the daily CSV is the source.** Measured against both from
production: `api.ftc.gov/v0/dnc-complaints` cannot be filtered by number (every
unknown parameter is silently ignored), caps a page at 50, ignores `page`, and
walks ~19M records from the *oldest* end with `offset` — 384,000 requests to
index, and no way to answer "complaints about this number". Its records are also
misaligned about 2% of the time: a date in the phone column, a company name in
the city column.

The FTC publishes `DNC_Complaint_Numbers_<date>.csv` daily instead: ~11,000
complaints with ~9,900 distinct numbers per file, a 26-day rolling window, clean
columns, and **no API key at all**. Same trade as abuse.ch and CISA KEV — the
bulk download is the real source and the API is the thing that looks convenient.

Rows are keyed by a content hash, since the CSV carries no row id. A complaint
re-read from an overlapping file lands on the same key, so re-ingesting a day
costs nothing.
"""
from __future__ import annotations

import csv
import hashlib
import io
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, select

from umbra.core.models import utcnow
from umbra.db.schema import FtcComplaint
from umbra.phone.normalize import phone_facts

logger = logging.getLogger(__name__)

INDEX_URL = "https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data"
FILE_BASE = "https://www.ftc.gov/sites/default/files/"
SOURCE_NAME = "FTC Do Not Call consumer complaints"
SOURCE_URL = "https://www.ftc.gov/policy-notices/open-government/data-sets/do-not-call-data"

_FILE_RE = re.compile(r"DNC_Complaint_Numbers_(\d{4}-\d{2}-\d{2})[^\"\']*\.csv")

# One day is ~1.2 MB / 11k rows. Anything an order of magnitude past that means
# the file shape changed rather than that complaints spiked.
MAX_FILE_BYTES = 64 * 1024 * 1024

_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y")


@dataclass
class Complaint:
    id: str
    source_day: str
    e164: str
    complaint_date: datetime | None
    subject: str
    is_robocall: bool
    state: str | None
    area_code: str | None


def _parse_date(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _e164(value: Any) -> str | None:
    """A US/CA number, or None. This is the field the shifted rows corrupt."""
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 10:
        digits = "1" + digits
    if len(digits) != 11 or not digits.startswith("1"):
        return None
    facts = phone_facts("+" + digits)
    # `possible` is not enough here: the shifted rows produce digit strings that
    # are the right length by accident.
    return facts["e164"] if facts.get("valid") else None


def parse(text: str, source_day: str = "") -> list[Complaint]:
    """Complaints from one daily CSV. Bad rows are dropped, never guessed."""
    if not text or not text.strip():
        return []
    reader = csv.DictReader(io.StringIO(text))
    out: list[Complaint] = []
    for record in reader:
        if not record:
            continue
        e164 = _e164(record.get("Company_Phone_Number"))
        if not e164:
            continue  # blank, or a row whose columns do not line up
        when = _parse_date(record.get("Violation_Date")) or _parse_date(
            record.get("Created_Date"))
        if when is None:
            continue  # a complaint with no usable date cannot be aged or ranked
        subject = str(record.get("Subject") or "").strip()[:160]
        state = str(record.get("Consumer_State") or "").strip()[:40] or None
        area = str(record.get("Consumer_Area_Code") or "").strip()[:8] or None
        robocall = str(record.get("Recorded_Message_Or_Robocall") or "").upper() == "Y"
        # The CSV has no row id, so the row's own content is the key. The same
        # complaint re-read from an overlapping file lands on the same row.
        digest = hashlib.sha256(
            "|".join([e164, str(record.get("Created_Date") or ""),
                      str(record.get("Violation_Date") or ""),
                      str(record.get("Consumer_City") or ""), state or "",
                      area or "", subject]).encode("utf-8", "replace")
        ).hexdigest()[:32]
        out.append(Complaint(
            id=digest, source_day=source_day, e164=e164, complaint_date=when,
            subject=subject, is_robocall=robocall, state=state, area_code=area))
    return out


def ingest(session, rows: list[Complaint]) -> int:
    """Store complaints not seen before. Returns how many were new."""
    if not rows:
        return 0
    ids = [r.id for r in rows]
    known = {
        i for i in session.execute(
            select(FtcComplaint.id).where(FtcComplaint.id.in_(ids))
        ).scalars()
    }
    added = 0
    for row in rows:
        if row.id in known:
            continue
        session.add(FtcComplaint(
            id=row.id, source_day=row.source_day, e164=row.e164,
            complaint_date=row.complaint_date, subject=row.subject,
            is_robocall=row.is_robocall, state=row.state,
            area_code=row.area_code, ingested_at=utcnow()))
        known.add(row.id)
        added += 1
    if added:
        session.commit()
    return added


def available_days(index_html: str) -> list[str]:
    """Dates the FTC currently publishes, newest first (a ~26-day window)."""
    return sorted({m.group(1) for m in _FILE_RE.finditer(index_html or "")},
                  reverse=True)


def file_url(index_html: str, day: str) -> str | None:
    """The exact filename for a day — some carry an `_0` suffix."""
    for match in _FILE_RE.finditer(index_html or ""):
        if match.group(1) == day:
            return FILE_BASE + match.group(0)
    return None


def ingested_days(session) -> set[str]:
    return set(session.execute(
        select(FtcComplaint.source_day).distinct()).scalars())


def sync(session, http, days: int = 7) -> dict[str, int]:
    """Download the newest daily files not already ingested. Never raises."""
    stats = {"days": 0, "fetched": 0, "stored": 0, "errors": 0, "skipped": 0}
    try:
        resp = http.get(INDEX_URL)
        resp.raise_for_status()
        index_html = resp.text
    except Exception as exc:  # noqa: BLE001 - a government site being down is not a crash
        logger.warning("ftc index unavailable: %s", exc)
        stats["errors"] += 1
        return stats

    have = ingested_days(session)
    for day in available_days(index_html)[:max(1, days)]:
        if day in have:
            stats["skipped"] += 1
            continue
        url = file_url(index_html, day)
        if not url:
            continue
        try:
            page = http.get(url)
            page.raise_for_status()
            body = page.text
            if len(body.encode("utf-8", "ignore")) > MAX_FILE_BYTES:
                raise ValueError(f"{day} file is implausibly large")
            rows = parse(body, source_day=day)
        except Exception as exc:  # noqa: BLE001 - one bad day is not the run
            logger.warning("ftc %s failed: %s", day, exc)
            stats["errors"] += 1
            continue
        stats["days"] += 1
        stats["fetched"] += len(rows)
        stats["stored"] += ingest(session, rows)
    return stats


def summary(session, e164: str) -> dict[str, Any]:
    """What the FTC index knows about one number.

    `checked` is the load-bearing field: an empty index is not "the FTC has no
    complaints about this number", it is "we have not looked yet" — the same
    unchecked-is-not-clean rule the collectors follow.
    """
    total_indexed = session.execute(
        select(func.count()).select_from(FtcComplaint)
    ).scalar_one() or 0
    checked = total_indexed > 0

    rows = session.execute(
        select(FtcComplaint).where(FtcComplaint.e164 == (e164 or "").strip())
    ).scalars().all()

    subjects: dict[str, int] = {}
    robocalls = 0
    for row in rows:
        if row.subject:
            subjects[row.subject] = subjects.get(row.subject, 0) + 1
        if row.is_robocall:
            robocalls += 1
    dates = [r.complaint_date for r in rows if r.complaint_date]

    if not checked:
        note = ("The FTC complaint index has not been loaded on this instance, "
                "so this number has not been checked against it.")
    elif not rows:
        note = ("No FTC Do Not Call complaints for this number in the indexed "
                "window. The FTC does not verify complaints, and an absence "
                "here is not evidence the number is legitimate.")
    else:
        # Plain text: this string is rendered into HTML, where markdown
        # asterisks show up as asterisks.
        note = (f"{len(rows)} consumer complaint(s) to the FTC. These are "
                f"consumer reports and are not verified by the FTC — they are "
                f"a signal, not a finding.")

    return {
        "checked": checked,
        "complaints": len(rows),
        "robocalls": robocalls,
        "first": min(dates) if dates else None,
        "last": max(dates) if dates else None,
        "subjects": [{"subject": s, "count": n}
                     for s, n in sorted(subjects.items(), key=lambda kv: -kv[1])[:5]],
        "note": note,
        "source": SOURCE_NAME,
        "source_url": SOURCE_URL,
        "indexed_total": total_indexed,
    }
