"""Reads and writes for community phone reputation.

Separate from `umbra.db.repository` on purpose. That class is the case graph —
evidence an operator collected under an authorization basis. This is a pile of
strangers' allegations, and the two must not be able to leak into one another.

Every rule in the write path exists because of a specific way this goes wrong:
one person deciding a number's reputation (one report per reporter, and one
reporter is never a verdict), sockpuppets voting it down (one changeable vote per
principal, counted apart from reports), the note field becoming a doxxing box
(short, no contact details, no links), somebody reporting in anger (retract,
without asking anyone), and a number being brigaded with nobody able to stop it
(operator hide, shipped with the write path rather than after it).

Counters are recomputed from rows rather than incremented. A counter that drifts
from its rows is a number the page states as fact and cannot back up.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import exists, func, select

from umbra.core.models import utcnow
from umbra.db.schema import (
    PhoneModerationEvent,
    PhoneNumber,
    PhoneReport,
    PhoneVote,
)
from umbra.phone.normalize import phone_facts
from umbra.phone.verdict import CATEGORIES, compute_verdict

logger = logging.getLogger(__name__)

# Numbers that must never get a reputation page. Emergency lines are not spam
# report targets, and a page implying otherwise is liability with no upside.
# Short codes are shared marketing infrastructure rather than a line somebody
# answers, so a "verdict" about one is meaningless.
_EMERGENCY = {
    "911", "999", "112", "000", "111", "119", "110", "115", "118", "122",
    "+1911", "+44999", "+112",
}
_SHORT_CODE_MAX_DIGITS = 6

# A lookup is not a report. Rows nobody ever reported are pruned so the table
# does not become a log of every number typed into the search box.
UNREPORTED_RETENTION_DAYS = 30


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value or "")


def is_refused(raw: str, e164: str | None) -> bool:
    """True for numbers Umbra will not host a reputation page about."""
    text = (raw or "").strip().replace(" ", "").replace("-", "")
    if text in _EMERGENCY or (e164 or "") in _EMERGENCY:
        return True
    if _digits(text) in {_digits(e) for e in _EMERGENCY}:
        return True
    # A bare short code never parses to a full national number.
    if not (e164 or "").startswith("+") and len(_digits(text)) <= _SHORT_CODE_MAX_DIGITS:
        return True
    return False


def get_or_create(session, raw: str, *, default_region: str = "US") -> PhoneNumber | None:
    """The row for a number, creating it on first sight. None if not usable."""
    facts = phone_facts(raw, default_region=default_region)
    e164 = facts.get("e164")
    if not e164 or not facts.get("possible"):
        return None
    if is_refused(raw, e164):
        return None

    row = session.execute(
        select(PhoneNumber).where(PhoneNumber.e164 == e164)
    ).scalar_one_or_none()
    if row is not None:
        return row

    row = PhoneNumber(id=uuid4().hex[:24], e164=e164)
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def public_view(session, phone_id: str) -> dict[str, Any] | None:
    """Everything the result page renders, or None if there is nothing to show."""
    row = session.get(PhoneNumber, (phone_id or "").strip())
    if row is None or row.hidden:
        return None

    counts: dict[str, int] = {}
    operator_reports = 0
    for report in session.execute(
        select(PhoneReport).where(
            PhoneReport.phone_id == row.id,
            PhoneReport.retracted.is_(False),
            PhoneReport.hidden.is_(False),
        )
    ).scalars():
        counts[report.category] = counts.get(report.category, 0) + 1
        if report.source == "operator":
            operator_reports += 1

    reporters = sum(counts.values())
    verdict = compute_verdict(counts, agree=row.agree_count or 0,
                              disagree=row.disagree_count or 0, reporters=reporters)
    active = bool(row.active) if row.active is not None else True

    if not active and reporters:
        # Do not carry a live accusation about a number nobody has mentioned in
        # months — numbers get reassigned.
        verdict = dict(verdict)
        verdict["label"] = "Previously reported"
        verdict["note"] = (
            f"This number was reported {reporters} time(s), but has not been "
            f"reported again since "
            f"{row.last_report_at.strftime('%Y-%m-%d') if row.last_report_at else 'then'}. "
            f"It is no longer on the active list. Numbers get reassigned, so an "
            f"old report says little about whoever answers today."
        )
    elif operator_reports and reporters == operator_reports:
        verdict = dict(verdict)
        verdict["note"] = (
            "Reported by the operator of this site from a personal call log — "
            "one source, not a community consensus. " + verdict["note"]
        )

    # Deliberately a separate layer rather than an input to the verdict above.
    # The FTC feed is consumer reports to a government programme; folding its
    # counts into Umbra's community verdict would blur which body of people said
    # what, and both are unverified in different ways.
    from umbra.phone import ftc as ftc_index

    return {
        "id": row.id,
        # Offline numbering-plan facts are the only thing on this page Umbra
        # states as fact rather than relays as an allegation.
        "facts": phone_facts(row.e164),
        "ftc": ftc_index.summary(session, row.e164),
        "verdict": verdict,
        "reports": reporters,
        "operator_reports": operator_reports,
        "active": active,
        "delisted_at": row.delisted_at,
        "first_report_at": row.first_report_at,
        "last_report_at": row.last_report_at,
    }


# --- who is writing -------------------------------------------------------
#
# Reports are keyed by an HMAC of the anonymous owner cookie: enough to enforce
# one report per person and to ban an abuser, not enough to identify anybody.
# The raw cookie and the IP never reach this table.

_EPHEMERAL_SECRET = secrets.token_urlsafe(32)


def reporter_key(owner_id: str) -> str:
    secret = (os.environ.get("UMBRA_SESSION_SECRET", "").strip()
              or _EPHEMERAL_SECRET).encode("utf-8")
    payload = f"{owner_id}|phone-rep|v1".encode("utf-8")
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()[:48]


# --- the note field, which is the dangerous one ---------------------------
#
# A note is for what the caller *did* — "claimed to be from my bank and asked
# for a code". It is not a place to publish somebody's contact details, address
# or identity, and it is the one free-text field on a public page about a real
# phone line. Anything that looks like it is heading that way is refused with an
# explanation rather than silently stripped, so the reporter can rewrite it.

NOTE_MAX = 280

_NOTE_BANS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+"), "an email address"),
    (re.compile(r"https?://|www\.", re.I), "a link"),
    (re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"), "something shaped like an SSN"),
    (re.compile(r"(?:\b\d{4}[-\s]?){3}\b\d{4}\b"), "something shaped like a card number"),
    (re.compile(r"\b\d{1,5}\s+\w+(\s+\w+)?\s+"
                r"(street|st|road|rd|avenue|ave|lane|ln|drive|dr|boulevard|blvd)\b",
                re.I), "a street address"),
)


def check_note(note: str | None) -> tuple[str | None, str | None]:
    """(clean_note, refusal_reason). Either may be None."""
    text = " ".join((note or "").split())
    if not text:
        return None, None
    for pattern, what in _NOTE_BANS:
        if pattern.search(text):
            return None, (
                f"Notes cannot contain {what}. Describe what the caller did, "
                f"not who you think they are."
            )
    return text[:NOTE_MAX], None


# --- writes ---------------------------------------------------------------

def _recount(session, row: PhoneNumber) -> None:
    """Rebuild the denormalised counters from the rows they summarise."""
    reports = session.execute(
        select(PhoneReport).where(
            PhoneReport.phone_id == row.id,
            PhoneReport.retracted.is_(False),
            PhoneReport.hidden.is_(False),
        )
    ).scalars().all()
    votes = session.execute(
        select(PhoneVote).where(PhoneVote.phone_id == row.id)
    ).scalars().all()

    row.report_count = len(reports)
    row.agree_count = sum(1 for v in votes if v.value == 1)
    row.disagree_count = sum(1 for v in votes if v.value == -1)
    # Aggregated in SQL rather than Python: SQLite hands back naive datetimes
    # for rows read from disk while a row added in this session still carries
    # the timezone-aware default, and min() over the mix raises.
    stamps = session.execute(
        select(func.min(PhoneReport.created_at), func.max(PhoneReport.created_at))
        .where(PhoneReport.phone_id == row.id,
               PhoneReport.retracted.is_(False),
               PhoneReport.hidden.is_(False))
    ).one()
    row.first_report_at, row.last_report_at = stamps[0], stamps[1]
    row.updated_at = utcnow()


def add_report(session, phone_id: str, key: str, category: str,
               note: str | None = None, frequency: str | None = None,
               source: str = "community") -> PhoneReport | None:
    """Create or update this reporter's single report. None if refused.

    `source="operator"` marks a report Umbra itself filed — a seeded call log,
    say. It is still one voice and still cannot reach a verdict alone; the point
    of the flag is that the page can say where it came from instead of implying
    a crowd.
    """
    if category not in CATEGORIES:
        return None  # never store a category outside the fixed enum
    row = session.get(PhoneNumber, phone_id)
    if row is None or row.hidden:
        return None
    clean_note, refusal = check_note(note)
    if refusal:
        # Refuse the whole write: a report stored without the note the reporter
        # meant to attach is not the report they made.
        return None

    existing = session.execute(
        select(PhoneReport).where(PhoneReport.phone_id == phone_id,
                                  PhoneReport.reporter_key == key)
    ).scalar_one_or_none()
    if existing is None:
        existing = PhoneReport(id=uuid4().hex[:24], phone_id=phone_id,
                               reporter_key=key, category=category,
                               source=source, note=clean_note,
                               frequency=frequency)
        session.add(existing)
    else:
        # Changing your mind is not a second voice.
        existing.category = category
        existing.source = source
        existing.note = clean_note
        existing.frequency = frequency
        existing.retracted = False
        existing.updated_at = utcnow()
    # A number being reported again is a number that is calling people again.
    # Votes deliberately do not do this: one agree click should not resurrect a
    # listing everyone else has forgotten about.
    row.active = True
    session.flush()
    _recount(session, row)
    session.commit()
    session.refresh(existing)
    return existing


def retract(session, phone_id: str, key: str) -> bool:
    """Withdraw this reporter's own report. Never anybody else's."""
    report = session.execute(
        select(PhoneReport).where(PhoneReport.phone_id == phone_id,
                                  PhoneReport.reporter_key == key,
                                  PhoneReport.retracted.is_(False))
    ).scalar_one_or_none()
    if report is None:
        return False
    report.retracted = True
    report.updated_at = utcnow()
    session.flush()  # _recount re-queries; the change has to be visible to it
    row = session.get(PhoneNumber, phone_id)
    if row is not None:
        _recount(session, row)
    session.commit()
    return True


def cast_vote(session, phone_id: str, key: str, value: int | None) -> bool:
    """Agree (+1) or disagree (-1) with a number's reports. One per principal."""
    if value not in (1, -1):
        return False
    row = session.get(PhoneNumber, phone_id)
    if row is None or row.hidden:
        return False
    vote = session.execute(
        select(PhoneVote).where(PhoneVote.phone_id == phone_id,
                                PhoneVote.voter_key == key)
    ).scalar_one_or_none()
    if vote is None:
        session.add(PhoneVote(id=uuid4().hex[:24], phone_id=phone_id,
                              voter_key=key, value=value))
    else:
        vote.value = value
        vote.updated_at = utcnow()
    session.flush()
    _recount(session, row)
    session.commit()
    return True


# --- moderation, shipped with the write path rather than after it ---------

def _record_moderation(session, action: str, actor: str, reason: str | None,
                       phone_id: str | None = None, report_id: str | None = None) -> None:
    session.add(PhoneModerationEvent(
        id=uuid4().hex[:24], phone_id=phone_id, report_id=report_id,
        actor=actor or "operator", action=action, reason=reason))


def hide_phone(session, phone_id: str, *, actor: str, reason: str | None = None) -> bool:
    """Take a number's page down. Survives later reports."""
    row = session.get(PhoneNumber, phone_id)
    if row is None:
        return False
    row.hidden = True
    row.updated_at = utcnow()
    _record_moderation(session, "hide_phone", actor, reason, phone_id=phone_id)
    session.commit()
    return True


def hide_report(session, report_id: str, *, actor: str, reason: str | None = None) -> bool:
    """Remove one report from the count without touching the rest."""
    report = session.get(PhoneReport, report_id)
    if report is None:
        return False
    report.hidden = True
    report.updated_at = utcnow()
    session.flush()
    row = session.get(PhoneNumber, report.phone_id)
    if row is not None:
        _recount(session, row)
    _record_moderation(session, "hide_report", actor, reason,
                       phone_id=report.phone_id, report_id=report_id)
    session.commit()
    return True


def list_recent_reports(session, limit: int = 100) -> list[dict[str, Any]]:
    """The moderation queue: newest first, with the number they are about."""
    rows = session.execute(
        select(PhoneReport, PhoneNumber)
        .join(PhoneNumber, PhoneNumber.id == PhoneReport.phone_id)
        .order_by(PhoneReport.created_at.desc())
        .limit(limit)
    ).all()
    return [
        {"id": r.id, "phone_id": r.phone_id, "e164": p.e164,
         "category": r.category, "note": r.note, "created_at": r.created_at,
         "retracted": r.retracted, "hidden": r.hidden, "phone_hidden": p.hidden}
        for r, p in rows
    ]


# --- a listing is a claim about now ---------------------------------------
#
# Spam numbers are recycled, reassigned and abandoned. A number reported heavily
# in March and silent since is not evidence about whoever answers it today, so a
# quiet listing drops off the active list rather than carrying a live accusation
# forever. The reports stay: "it was on the list once" has to remain answerable
# for the operator and for whoever the number belongs to.

LISTING_ACTIVE_DAYS = 180


def expire_stale_listings(session, days: int = LISTING_ACTIVE_DAYS) -> int:
    """Delist numbers with reports but no recent activity. Zero disables it."""
    if not days or days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    stale = session.execute(
        select(PhoneNumber).where(
            PhoneNumber.active.is_(True),
            PhoneNumber.report_count > 0,
            PhoneNumber.last_report_at.is_not(None),
            PhoneNumber.last_report_at < cutoff,
        )
    ).scalars().all()
    for row in stale:
        row.active = False
        row.delisted_at = utcnow()
        row.updated_at = utcnow()
        _record_moderation(
            session, "delist", "retention", 
            f"no report in {days} days; listing is stale and numbers get reassigned",
            phone_id=row.id)
    if stale:
        session.commit()
    return len(stale)


def active_listings(session, limit: int = 1000) -> list[dict[str, Any]]:
    """Numbers currently on the active list. Not a public endpoint: a dump of
    the whole spam database is a scraping and harassment target."""
    rows = session.execute(
        select(PhoneNumber).where(
            PhoneNumber.active.is_(True),
            PhoneNumber.hidden.is_(False),
            PhoneNumber.report_count > 0,
        ).order_by(PhoneNumber.last_report_at.desc()).limit(limit)
    ).scalars().all()
    return [
        {"id": r.id, "e164": r.e164, "reports": r.report_count,
         "last_report_at": r.last_report_at}
        for r in rows
    ]


def purge_unreported(session, days: int = UNREPORTED_RETENTION_DAYS) -> int:
    """Delete rows created by a lookup that nobody ever reported.

    Zero disables the sweep, matching `case_retention_days`. A number with
    reports is never touched: those rows exist because somebody wrote something,
    not because somebody searched. That means any report row, retracted or
    hidden included, and any vote. `report_count` only counts live reports, so
    it cannot be the test: a number whose one report was retracted reads zero
    while its report still holds the foreign key, and deleting it would fail
    the whole sweep.
    """
    if not days or days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    stale = session.execute(
        select(PhoneNumber).where(
            PhoneNumber.created_at < cutoff,
            PhoneNumber.report_count == 0,
            ~exists().where(PhoneReport.phone_id == PhoneNumber.id),
            ~exists().where(PhoneVote.phone_id == PhoneNumber.id),
        )
    ).scalars().all()
    for row in stale:
        session.delete(row)
    if stale:
        session.commit()
    return len(stale)
