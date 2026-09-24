"""Animal-abuse registry — official findings, cited, with a way back out.

A registry that names people as animal abusers is only defensible when every
row is something an authority already decided and published. So this lake holds
exactly one kind of row, a **finding**: a conviction, a plea, a listing on a
government registry, or a civil order, each carrying the source it came from.
The invariants below are enforced here, in the storage layer, rather than left
to whichever page or command reads the table later.

**A charge is not a finding.** Arrests, citations and pending charges are
allegations, and people are acquitted of them. Import rows with those
dispositions are counted and skipped, never stored as entries. Allegations have
exactly one home — the report queue — and nothing reads that queue into a
public answer.

**Reports are leads, never entries.** Rescues, shelters and agencies can file a
report about a person. A report is not shown anywhere. A reviewer turns it into
a registry entry only by finding the official record behind it and adding that
record as a finding with its citation; the report is then linked to the entry.
A report nobody can back with a record stays a report, or is rejected.

**The source decides how long a row lives.** Government registries delist
people when their listing period ends. A registry import is therefore a
*snapshot*: a row missing from the latest import is marked removed, and a
removed row is not published. A source may also carry `retention_years`, after
which a finding stops being published even if the source still lists it.

**A dispute hides the row while it is open.** Wrong person, expunged,
overturned on appeal — the cost of showing a disputed row for another week is
borne by someone who may be innocent, and the cost of hiding it is borne by
nobody. An upheld dispute suppresses the row permanently, and a re-import of the
same source does not bring it back.

**No street addresses, no dates of birth, no photos.** City, county and state
only. Some sources publish more; the source link is where someone confirms an
identity, and copying the rest here would turn a registry into a locator.

**Every moderation step is audited** — who, what, when — in `event`. Report
narratives are not copied into the audit trail.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from umbra.people.names import MatchStrength, compare_names, canonical, name_keys, query_keys

#: Dispositions that are findings by an authority. The only ones stored.
FINDING_DISPOSITIONS = frozenset({
    "convicted",
    "pleaded_guilty",
    "pleaded_no_contest",
    "registry_listed",
    "civil_order",
})

#: Dispositions that are allegations or reversals. Recognised so an import can
#: say *why* a row was skipped, rather than calling it malformed.
NON_FINDING_DISPOSITIONS = frozenset({
    "charged", "arrested", "cited", "pending", "dismissed", "acquitted",
    "vacated", "overturned", "expunged", "sealed",
})

SOURCE_KINDS = frozenset({"government_registry", "court", "manual"})

#: The source every reviewer-added finding lives under.
MANUAL_SOURCE = "manual"

REPORT_STATUSES = ("pending", "linked", "rejected")
DISPUTE_STATUSES = ("open", "upheld", "rejected")

_URL_RE = re.compile(r"^https?://[^\s/]+\.[^\s]+$", re.I)
_STATE_RE = re.compile(r"^[A-Z]{2}$")
_SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS source (
  source_id       TEXT PRIMARY KEY,
  name            TEXT NOT NULL,
  kind            TEXT NOT NULL,
  jurisdiction    TEXT,
  url             TEXT NOT NULL,
  terms_note      TEXT,
  retention_years INTEGER,
  last_imported_at TEXT,
  last_rows       INTEGER
);
CREATE TABLE IF NOT EXISTS entry (
  entry_id        TEXT PRIMARY KEY,
  source_id       TEXT NOT NULL REFERENCES source(source_id),
  record_id       TEXT,
  name_raw        TEXT NOT NULL,
  name_canonical  TEXT NOT NULL,
  city            TEXT,
  county          TEXT,
  state           TEXT,
  offense         TEXT NOT NULL,
  statute         TEXT,
  disposition     TEXT NOT NULL,
  finding_date    TEXT,
  expires_at      TEXT,
  source_url      TEXT NOT NULL,
  citation        TEXT,
  first_seen_at   TEXT NOT NULL,
  last_seen_at    TEXT NOT NULL,
  removed_at      TEXT,
  suppressed_at   TEXT,
  suppressed_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_entry_source ON entry(source_id);
CREATE INDEX IF NOT EXISTS idx_entry_state ON entry(state);
CREATE INDEX IF NOT EXISTS idx_entry_canonical ON entry(name_canonical);
CREATE TABLE IF NOT EXISTS entry_name_key (
  key       TEXT NOT NULL,
  entry_id  TEXT NOT NULL REFERENCES entry(entry_id),
  PRIMARY KEY (key, entry_id)
);
CREATE TABLE IF NOT EXISTS report (
  report_id        TEXT PRIMARY KEY,
  submitted_at     TEXT NOT NULL,
  submitter_org    TEXT NOT NULL,
  submitter_contact TEXT,
  subject_name     TEXT NOT NULL,
  subject_canonical TEXT NOT NULL,
  city             TEXT,
  county           TEXT,
  state            TEXT,
  narrative        TEXT NOT NULL,
  reference_url    TEXT,
  status           TEXT NOT NULL DEFAULT 'pending',
  linked_entry_id  TEXT REFERENCES entry(entry_id),
  reviewed_by      TEXT,
  reviewed_at      TEXT,
  review_note      TEXT
);
CREATE INDEX IF NOT EXISTS idx_report_status ON report(status);
CREATE TABLE IF NOT EXISTS dispute (
  dispute_id  TEXT PRIMARY KEY,
  entry_id    TEXT NOT NULL REFERENCES entry(entry_id),
  opened_at   TEXT NOT NULL,
  basis       TEXT NOT NULL,
  contact     TEXT,
  status      TEXT NOT NULL DEFAULT 'open',
  resolved_at TEXT,
  resolved_by TEXT,
  note        TEXT
);
CREATE INDEX IF NOT EXISTS idx_dispute_entry ON dispute(entry_id, status);
CREATE TABLE IF NOT EXISTS event (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  at      TEXT NOT NULL,
  actor   TEXT NOT NULL,
  action  TEXT NOT NULL,
  target  TEXT NOT NULL,
  detail  TEXT
);
"""

#: The one definition of "may be shown". Every read that answers a search or a
#: browse goes through it, so the rules above cannot drift apart per caller.
_PUBLISHABLE = """
  e.removed_at IS NULL
  AND e.suppressed_at IS NULL
  AND (e.expires_at IS NULL OR e.expires_at > :today)
  AND NOT EXISTS (
    SELECT 1 FROM dispute d WHERE d.entry_id = e.entry_id AND d.status = 'open'
  )
"""


class RegistryError(ValueError):
    """A write the registry refuses, with the reason in the message."""


@dataclass(frozen=True, slots=True)
class ImportResult:
    rows: int
    stored: int
    skipped_not_a_finding: int
    skipped_invalid: int
    delisted: int
    relisted: int

    def as_dict(self) -> dict[str, int]:
        return {
            "rows": self.rows,
            "stored": self.stored,
            "skipped_not_a_finding": self.skipped_not_a_finding,
            "skipped_invalid": self.skipped_invalid,
            "delisted": self.delisted,
            "relisted": self.relisted,
        }


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(value: Any, limit: int = 240) -> str | None:
    if value is None:
        return None
    text = " ".join(str(value).split())
    return text[:limit] or None


def _state(value: Any) -> str | None:
    text = (_clean(value, 8) or "").upper()
    return text if _STATE_RE.match(text) else None


def _iso_date(value: Any) -> str | None:
    """YYYY-MM-DD, or MM/DD/YYYY as US registries tend to publish it."""
    text = (_clean(value, 32) or "")
    if not text:
        return None
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
        try:
            return datetime.strptime(text, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def _disposition(value: Any) -> str:
    return (_clean(value, 40) or "").lower().replace(" ", "_").replace("-", "_")


def _expiry(finding_date: str | None, retention_years: int | None) -> str | None:
    if not finding_date or not retention_years:
        return None
    d = date.fromisoformat(finding_date)
    try:
        return d.replace(year=d.year + retention_years).isoformat()
    except ValueError:  # 29 February into a non-leap year
        return d.replace(year=d.year + retention_years, day=28).isoformat()


def _entry_id(source_id: str, record_id: str | None, name_canonical: str,
              offense: str, finding_date: str | None) -> str:
    if record_id:
        return f"{source_id}:{record_id}"
    digest = hashlib.sha1(
        "|".join([source_id, name_canonical, offense.lower(), finding_date or ""]).encode()
    ).hexdigest()[:16]
    return f"{source_id}:h{digest}"


def default_path(data_dir: Path | str | None = None) -> Path:
    env = os.environ.get("UMBRA_ANIMAL_REGISTRY_DB", "").strip()
    if env:
        return Path(env).expanduser()
    if data_dir is None:
        try:
            from umbra.core.config import get_settings

            data_dir = get_settings().data_dir
        except Exception:  # noqa: BLE001
            data_dir = Path.home() / "umbra" / "data"
    return Path(data_dir) / "lake" / "animal_registry.sqlite"


class AnimalRegistryLake:
    """SQLite store for registry findings, reports, disputes and their audit."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @classmethod
    def from_settings(cls, settings) -> "AnimalRegistryLake":
        return cls(default_path(getattr(settings, "data_dir", None)))

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    # --- audit ------------------------------------------------------------

    def _audit(self, actor: str, action: str, target: str, detail: str | None = None) -> None:
        self._conn.execute(
            "INSERT INTO event (at, actor, action, target, detail) VALUES (?,?,?,?,?)",
            (_now(), actor or "unknown", action, target, detail),
        )

    def events(self, *, target: str | None = None, limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM event"
        args: list[Any] = []
        if target:
            sql += " WHERE target = ?"
            args.append(target)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(max(1, int(limit)))
        return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    # --- sources ----------------------------------------------------------

    def add_source(self, source_id: str, *, name: str, kind: str, url: str,
                   jurisdiction: str | None = None, terms_note: str | None = None,
                   retention_years: int | None = None, actor: str = "cli") -> dict:
        """Register (or update) a source. Findings can only be filed under one.

        `terms_note` records what the source's access terms say about
        republication. Some jurisdictions give registry access to shelters and
        pet sellers only, and republishing those lists is not something the
        data being "official" makes lawful.
        """
        source_id = (source_id or "").strip().lower()
        if not _SOURCE_ID_RE.match(source_id):
            raise RegistryError("source id must be 2-64 chars of a-z, 0-9, '_' or '-'")
        if kind not in SOURCE_KINDS:
            raise RegistryError(f"kind must be one of {sorted(SOURCE_KINDS)}")
        if not _URL_RE.match(url or ""):
            raise RegistryError("a source needs an http(s) URL people can check")
        if not _clean(name):
            raise RegistryError("a source needs a name")
        if retention_years is not None and retention_years < 1:
            raise RegistryError("retention_years must be a positive number of years")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO source (source_id, name, kind, jurisdiction, url,
                                    terms_note, retention_years)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET
                  name = excluded.name, kind = excluded.kind,
                  jurisdiction = excluded.jurisdiction, url = excluded.url,
                  terms_note = excluded.terms_note,
                  retention_years = excluded.retention_years
                """,
                (source_id, _clean(name), kind, _clean(jurisdiction), url,
                 _clean(terms_note, 1000), retention_years),
            )
            self._recompute_expiry(source_id)
            self._audit(actor, "source.upsert", source_id, kind)
            self._conn.commit()
        return self.source(source_id) or {}

    def source(self, source_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM source WHERE source_id = ?", (source_id,)).fetchone()
        return dict(row) if row else None

    def sources(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM source ORDER BY source_id").fetchall()]

    def _ensure_manual_source(self) -> None:
        if self.source(MANUAL_SOURCE) is None:
            self._conn.execute(
                "INSERT INTO source (source_id, name, kind, url) VALUES (?,?,?,?)",
                (MANUAL_SOURCE, "Reviewer-added findings (each cites its own record)",
                 "manual", "https://umbra-osint.com"),
            )

    def _recompute_expiry(self, source_id: str) -> None:
        src = self.source(source_id)
        years = src["retention_years"] if src else None
        rows = self._conn.execute(
            "SELECT entry_id, finding_date FROM entry WHERE source_id = ?",
            (source_id,)).fetchall()
        for r in rows:
            self._conn.execute(
                "UPDATE entry SET expires_at = ? WHERE entry_id = ?",
                (_expiry(r["finding_date"], years), r["entry_id"]))

    # --- findings ---------------------------------------------------------

    def _validate_row(self, row: dict[str, Any], *, default_url: str) -> dict[str, Any] | str:
        """A cleaned finding, or the reason it cannot be one."""
        name_raw = _clean(row.get("name"), 160)
        name_canonical = canonical(name_raw)
        if not name_raw or len(name_canonical.split()) < 2:
            return "invalid"  # a registry row needs at least first + last name
        disposition = _disposition(row.get("disposition"))
        if not disposition:
            return "invalid"
        if disposition not in FINDING_DISPOSITIONS:
            # Named allegations and reversals, and anything unrecognised, are
            # all "not a finding": an unknown word is not evidence of one.
            return "not_a_finding"
        offense = _clean(row.get("offense"), 240)
        if not offense:
            return "invalid"
        source_url = _clean(row.get("source_url"), 1000) or default_url
        if not _URL_RE.match(source_url or ""):
            return "invalid"
        return {
            "record_id": _clean(row.get("record_id"), 120),
            "name_raw": name_raw,
            "name_canonical": name_canonical,
            "city": _clean(row.get("city"), 80),
            "county": _clean(row.get("county"), 80),
            "state": _state(row.get("state")),
            "offense": offense,
            "statute": _clean(row.get("statute"), 120),
            "disposition": disposition,
            "finding_date": _iso_date(row.get("finding_date")),
            "source_url": source_url,
            "citation": _clean(row.get("citation"), 400),
        }

    def _upsert_entry(self, source_id: str, clean: dict[str, Any], seen_at: str,
                      retention_years: int | None) -> tuple[str, bool]:
        """Store one finding. Returns (entry_id, was_relisted).

        `suppressed_at` is never touched here: an upheld dispute outlives every
        later import of the same source.
        """
        eid = _entry_id(source_id, clean["record_id"], clean["name_canonical"],
                        clean["offense"], clean["finding_date"])
        prior = self._conn.execute(
            "SELECT removed_at FROM entry WHERE entry_id = ?", (eid,)).fetchone()
        self._conn.execute(
            """
            INSERT INTO entry (entry_id, source_id, record_id, name_raw, name_canonical,
              city, county, state, offense, statute, disposition, finding_date,
              expires_at, source_url, citation, first_seen_at, last_seen_at)
            VALUES (:eid, :source_id, :record_id, :name_raw, :name_canonical,
              :city, :county, :state, :offense, :statute, :disposition, :finding_date,
              :expires_at, :source_url, :citation, :seen, :seen)
            ON CONFLICT(entry_id) DO UPDATE SET
              name_raw = excluded.name_raw, name_canonical = excluded.name_canonical,
              city = excluded.city, county = excluded.county, state = excluded.state,
              offense = excluded.offense, statute = excluded.statute,
              disposition = excluded.disposition, finding_date = excluded.finding_date,
              expires_at = excluded.expires_at, source_url = excluded.source_url,
              citation = excluded.citation, last_seen_at = excluded.last_seen_at,
              removed_at = NULL
            """,
            {**clean, "eid": eid, "source_id": source_id, "seen": seen_at,
             "expires_at": _expiry(clean["finding_date"], retention_years)},
        )
        self._conn.execute("DELETE FROM entry_name_key WHERE entry_id = ?", (eid,))
        self._conn.executemany(
            "INSERT OR IGNORE INTO entry_name_key (key, entry_id) VALUES (?,?)",
            [(k, eid) for k in name_keys(clean["name_raw"])],
        )
        return eid, bool(prior and prior["removed_at"])

    def import_rows(self, source_id: str, rows: Iterable[dict[str, Any]], *,
                    snapshot: bool = True, actor: str = "cli") -> ImportResult:
        """Fold a source's rows in.

        With `snapshot` (the default for a registry) the rows are the source's
        whole current list, so anything previously imported from it and absent
        now is marked removed — that is how a delisting reaches this lake.
        Pass `snapshot=False` for a partial export that is only additions.
        """
        src = self.source(source_id)
        if src is None:
            raise RegistryError(f"unknown source {source_id!r}; add it first")
        if src["kind"] == "manual":
            raise RegistryError("manual findings are added one at a time with add_finding")
        seen_at = _now()
        total = stored = not_finding = invalid = relisted = 0
        seen_ids: set[str] = set()
        with self._lock:
            for row in rows:
                total += 1
                clean = self._validate_row(row, default_url=src["url"])
                if clean == "not_a_finding":
                    not_finding += 1
                    continue
                if isinstance(clean, str):
                    invalid += 1
                    continue
                eid, was_relisted = self._upsert_entry(
                    source_id, clean, seen_at, src["retention_years"])
                seen_ids.add(eid)
                stored += 1
                relisted += int(was_relisted)

            delisted = 0
            if snapshot:
                if stored == 0 and total > 0:
                    # A file that parsed to nothing is a broken export, not a
                    # source that delisted everyone. Wiping the registry on it
                    # would be the tor-lake failure in a far worse place.
                    self._conn.rollback()
                    raise RegistryError(
                        "no row in this import was a valid finding; refusing to "
                        "treat it as a snapshot that delists every entry")
                cur = self._conn.execute(
                    "SELECT entry_id FROM entry WHERE source_id = ? AND removed_at IS NULL",
                    (source_id,))
                gone = [r["entry_id"] for r in cur.fetchall() if r["entry_id"] not in seen_ids]
                self._conn.executemany(
                    "UPDATE entry SET removed_at = ? WHERE entry_id = ?",
                    [(seen_at, eid) for eid in gone])
                delisted = len(gone)

            self._conn.execute(
                "UPDATE source SET last_imported_at = ?, last_rows = ? WHERE source_id = ?",
                (seen_at, stored, source_id))
            result = ImportResult(total, stored, not_finding, invalid, delisted, relisted)
            self._audit(actor, "source.import", source_id,
                        " ".join(f"{k}={v}" for k, v in result.as_dict().items()))
            self._conn.commit()
        return result

    def add_finding(self, *, name: str, offense: str, disposition: str,
                    source_url: str, citation: str, state: str | None = None,
                    county: str | None = None, city: str | None = None,
                    statute: str | None = None, finding_date: str | None = None,
                    record_id: str | None = None, actor: str = "cli") -> dict:
        """A reviewer-added finding, citing the court or agency record behind it.

        This is how a vetted report becomes an entry: not by trusting the
        report, but by finding the record it points at.
        """
        if not _clean(citation):
            raise RegistryError("a manual finding needs a citation (docket, case number, order)")
        if not _URL_RE.match(source_url or ""):
            raise RegistryError("a manual finding needs the http(s) URL of its record")
        clean = self._validate_row({
            "name": name, "offense": offense, "disposition": disposition,
            "source_url": source_url, "citation": citation, "state": state,
            "county": county, "city": city, "statute": statute,
            "finding_date": finding_date, "record_id": record_id,
        }, default_url="")
        if clean == "not_a_finding":
            raise RegistryError(
                f"{_disposition(disposition)!r} is not a finding; only "
                f"{sorted(FINDING_DISPOSITIONS)} can be registry entries")
        if isinstance(clean, str):
            raise RegistryError("a finding needs a first and last name, an offense and a disposition")
        with self._lock:
            self._ensure_manual_source()
            eid, _ = self._upsert_entry(MANUAL_SOURCE, clean, _now(), None)
            self._audit(actor, "finding.add", eid, clean["citation"])
            self._conn.commit()
        return self.entry(eid) or {}

    def entry(self, entry_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT e.*, s.name AS source_name, s.kind AS source_kind "
            "FROM entry e JOIN source s USING (source_id) WHERE e.entry_id = ?",
            (entry_id,)).fetchone()
        if not row:
            return None
        out = dict(row)
        out["publishable"] = self._is_publishable(entry_id)
        out["open_disputes"] = int(self._conn.execute(
            "SELECT COUNT(*) FROM dispute WHERE entry_id = ? AND status = 'open'",
            (entry_id,)).fetchone()[0])
        return out

    def _is_publishable(self, entry_id: str) -> bool:
        return self._conn.execute(
            f"SELECT 1 FROM entry e WHERE e.entry_id = :eid AND {_PUBLISHABLE}",
            {"eid": entry_id, "today": date.today().isoformat()},
        ).fetchone() is not None

    # --- reads ------------------------------------------------------------

    def search(self, name: str, *, state: str | None = None,
               limit: int = 25) -> list[dict]:
        """Publishable findings whose name matches, strongest first.

        Each hit carries `match` — how the searched name compares to the name
        on the record. A name match is a candidate, never an identification.
        """
        keys = query_keys(name)
        if not keys:
            return []
        st = _state(state) if state else None
        placeholders = ",".join("?" for _ in keys)
        sql = (
            "SELECT DISTINCT e.*, s.name AS source_name FROM entry_name_key k "
            "JOIN entry e ON e.entry_id = k.entry_id "
            "JOIN source s ON s.source_id = e.source_id "
            f"WHERE k.key IN ({placeholders}) AND "
            + _PUBLISHABLE.replace(":today", "?")
        )
        args: list[Any] = [k for k, _ in keys] + [date.today().isoformat()]
        if st:
            sql += " AND e.state = ?"
            args.append(st)
        rows = self._conn.execute(sql, args).fetchall()
        order = {MatchStrength.EXACT: 0, MatchStrength.PARTIAL: 1,
                 MatchStrength.WEAK: 2, MatchStrength.SURNAME: 3}
        hits: list[dict] = []
        for r in rows:
            strength = compare_names(name, r["name_raw"])
            if strength is None:
                continue
            hit = dict(r)
            hit["match"] = strength.value
            hits.append(hit)
        hits.sort(key=lambda h: (order[MatchStrength(h["match"])], h["name_canonical"],
                                 h["finding_date"] or ""))
        return hits[: max(1, int(limit))]

    def browse(self, *, state: str | None = None, limit: int = 50,
               offset: int = 0) -> list[dict]:
        """The publishable registry as a list — what a public page may show."""
        sql = ("SELECT e.*, s.name AS source_name FROM entry e "
               "JOIN source s ON s.source_id = e.source_id WHERE " + _PUBLISHABLE)
        args: dict[str, Any] = {"today": date.today().isoformat(),
                                "limit": max(1, int(limit)), "offset": max(0, int(offset))}
        st = _state(state) if state else None
        if st:
            sql += " AND e.state = :state"
            args["state"] = st
        sql += " ORDER BY e.name_canonical, e.finding_date LIMIT :limit OFFSET :offset"
        return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def status(self) -> dict:
        today = date.today().isoformat()
        q = self._conn.execute
        total = int(q("SELECT COUNT(*) FROM entry").fetchone()[0])
        publishable = int(q(f"SELECT COUNT(*) FROM entry e WHERE {_PUBLISHABLE}",
                            {"today": today}).fetchone()[0])
        return {
            "path": str(self.path),
            "available": publishable > 0,
            "entries": total,
            "publishable": publishable,
            "removed": int(q("SELECT COUNT(*) FROM entry WHERE removed_at IS NOT NULL").fetchone()[0]),
            "suppressed": int(q("SELECT COUNT(*) FROM entry WHERE suppressed_at IS NOT NULL").fetchone()[0]),
            "reports_pending": int(q("SELECT COUNT(*) FROM report WHERE status='pending'").fetchone()[0]),
            "disputes_open": int(q("SELECT COUNT(*) FROM dispute WHERE status='open'").fetchone()[0]),
            "sources": len(self.sources()),
        }

    # --- reports ----------------------------------------------------------

    def submit_report(self, *, submitter_org: str, subject_name: str, narrative: str,
                      state: str | None = None, county: str | None = None,
                      city: str | None = None, reference_url: str | None = None,
                      submitter_contact: str | None = None, actor: str = "cli") -> dict:
        """File a report from a rescue, shelter or agency. It is never published."""
        org = _clean(submitter_org, 160)
        if not org:
            raise RegistryError("a report must name the submitting organisation")
        subject = _clean(subject_name, 160)
        if not subject or len(canonical(subject).split()) < 2:
            raise RegistryError("a report needs the subject's first and last name")
        text = (narrative or "").strip()
        if not text:
            raise RegistryError("a report needs a narrative a reviewer can act on")
        if reference_url and not _URL_RE.match(reference_url):
            raise RegistryError("reference_url must be an http(s) URL")
        rid = f"r_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO report (report_id, submitted_at, submitter_org, submitter_contact,
                  subject_name, subject_canonical, city, county, state, narrative, reference_url)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """,
                (rid, _now(), org, _clean(submitter_contact, 200), subject, canonical(subject),
                 _clean(city, 80), _clean(county, 80), _state(state), text[:5000],
                 reference_url),
            )
            self._audit(actor, "report.submit", rid, org)
            self._conn.commit()
        return self.report(rid) or {}

    def report(self, report_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM report WHERE report_id = ?", (report_id,)).fetchone()
        return dict(row) if row else None

    def reports(self, *, status: str | None = "pending", limit: int = 100) -> list[dict]:
        sql = "SELECT * FROM report"
        args: list[Any] = []
        if status:
            if status not in REPORT_STATUSES:
                raise RegistryError(f"status must be one of {REPORT_STATUSES}")
            sql += " WHERE status = ?"
            args.append(status)
        sql += " ORDER BY submitted_at LIMIT ?"
        args.append(max(1, int(limit)))
        return [dict(r) for r in self._conn.execute(sql, args).fetchall()]

    def _pending_report(self, report_id: str) -> dict:
        rep = self.report(report_id)
        if rep is None:
            raise RegistryError(f"no report {report_id!r}")
        if rep["status"] != "pending":
            raise RegistryError(f"report {report_id} is already {rep['status']}")
        return rep

    def link_report(self, report_id: str, entry_id: str, *, reviewer: str,
                    note: str | None = None) -> dict:
        """Close a report against the official finding that backs it."""
        if not _clean(reviewer):
            raise RegistryError("linking a report needs a named reviewer")
        with self._lock:
            self._pending_report(report_id)
            if self.entry(entry_id) is None:
                raise RegistryError(f"no entry {entry_id!r}; add the finding first")
            self._conn.execute(
                "UPDATE report SET status='linked', linked_entry_id=?, reviewed_by=?, "
                "reviewed_at=?, review_note=? WHERE report_id=?",
                (entry_id, reviewer, _now(), _clean(note, 1000), report_id))
            self._audit(reviewer, "report.link", report_id, entry_id)
            self._conn.commit()
        return self.report(report_id) or {}

    def reject_report(self, report_id: str, *, reviewer: str, note: str) -> dict:
        if not _clean(reviewer):
            raise RegistryError("rejecting a report needs a named reviewer")
        if not _clean(note):
            raise RegistryError("say why the report was rejected")
        with self._lock:
            self._pending_report(report_id)
            self._conn.execute(
                "UPDATE report SET status='rejected', reviewed_by=?, reviewed_at=?, "
                "review_note=? WHERE report_id=?",
                (reviewer, _now(), _clean(note, 1000), report_id))
            self._audit(reviewer, "report.reject", report_id)
            self._conn.commit()
        return self.report(report_id) or {}

    # --- disputes ---------------------------------------------------------

    def open_dispute(self, entry_id: str, *, basis: str, contact: str | None = None,
                     actor: str = "cli") -> dict:
        """Hide an entry pending review. Anyone may open one; no proof is needed
        to pause publication, only to end it."""
        if self.entry(entry_id) is None:
            raise RegistryError(f"no entry {entry_id!r}")
        text = _clean(basis, 1000)
        if not text:
            raise RegistryError("a dispute needs a basis (wrong person, expunged, overturned …)")
        did = f"d_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._conn.execute(
                "INSERT INTO dispute (dispute_id, entry_id, opened_at, basis, contact) "
                "VALUES (?,?,?,?,?)",
                (did, entry_id, _now(), text, _clean(contact, 200)))
            self._audit(actor, "dispute.open", entry_id, did)
            self._conn.commit()
        return self.dispute(did) or {}

    def dispute(self, dispute_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM dispute WHERE dispute_id = ?", (dispute_id,)).fetchone()
        return dict(row) if row else None

    def disputes(self, *, status: str | None = "open") -> list[dict]:
        sql = "SELECT * FROM dispute"
        args: list[Any] = []
        if status:
            if status not in DISPUTE_STATUSES:
                raise RegistryError(f"status must be one of {DISPUTE_STATUSES}")
            sql += " WHERE status = ?"
            args.append(status)
        return [dict(r) for r in self._conn.execute(sql + " ORDER BY opened_at", args).fetchall()]

    def resolve_dispute(self, dispute_id: str, *, upheld: bool, reviewer: str,
                        note: str) -> dict:
        """Upheld: the entry is suppressed for good. Rejected: it is shown again
        (unless another dispute on it is still open)."""
        if not _clean(reviewer):
            raise RegistryError("resolving a dispute needs a named reviewer")
        if not _clean(note):
            raise RegistryError("record why the dispute was resolved this way")
        with self._lock:
            d = self.dispute(dispute_id)
            if d is None:
                raise RegistryError(f"no dispute {dispute_id!r}")
            if d["status"] != "open":
                raise RegistryError(f"dispute {dispute_id} is already {d['status']}")
            now = _now()
            self._conn.execute(
                "UPDATE dispute SET status=?, resolved_at=?, resolved_by=?, note=? "
                "WHERE dispute_id=?",
                ("upheld" if upheld else "rejected", now, reviewer, _clean(note, 1000),
                 dispute_id))
            if upheld:
                self._conn.execute(
                    "UPDATE entry SET suppressed_at=?, suppressed_reason=? WHERE entry_id=?",
                    (now, f"dispute {dispute_id} upheld: {_clean(note, 200)}", d["entry_id"]))
            self._audit(reviewer, "dispute.upheld" if upheld else "dispute.rejected",
                        d["entry_id"], dispute_id)
            self._conn.commit()
        return self.dispute(dispute_id) or {}


def read_csv_rows(path: Path | str) -> list[dict[str, str]]:
    """Rows from a CSV export, header names lower-cased and trimmed.

    Expected columns: name, offense, disposition; optional record_id, statute,
    finding_date, city, county, state, source_url, citation. Anything a given
    source names differently is mapped before import, not guessed at here.
    """
    import csv

    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        return [
            {(k or "").strip().lower(): (v or "") for k, v in row.items()}
            for row in reader
        ]


def default_lake() -> AnimalRegistryLake:
    return AnimalRegistryLake()
