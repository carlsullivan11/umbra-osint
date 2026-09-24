"""FEC individual contributions — the bulk source of living people.

Wikidata tops out near 454k deceased US humans. Millions means living people,
and the largest lawful bulk source that carries an occupation is FEC campaign
finance: name, city, state, ZIP, employer, occupation and date, published by
the FEC as public record for precisely this purpose.

Format confirmed against the real `indiv24.zip` (3.95 GB, ZIP64): 21
pipe-delimited columns, no header, and `NAME` in **"LAST, FIRST"** form — which
`people.names.canonical` already un-reverses, so the source drops straight in.

Three constraints shape this module:

**Memory.** The member expands past 30 GB and the host has 8 GB. Nothing reads
the member; lines are streamed. Aggregation happens in SQLite via UPSERT rather
than in a Python dict, because ~10M contributors held in memory is several GB
on its own.

**Aggregated, not transactional.** 70M contribution rows are a donations
database. Umbra wants a person index, so rows collapse to one record per
(name, state, ZIP) carrying counts, totals and a date range.

**A separate table.** These are not merged into `people`, which holds deceased
notables with obituaries and kinship. Millions of living donors in that table
would destroy what a row there means. A name+ZIP agreement is also not an
identification — two people with one name in one ZIP are indistinguishable
here, and nothing in this module pretends otherwise.
"""
from __future__ import annotations

import io
import logging
import os
import sqlite3
import threading
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

DATA_MEMBER = "itcont.txt"
BULK_URL = "https://www.fec.gov/files/bulk-downloads/{cycle}/indiv{yy}.zip"

#: FEC ENTITY_TP for a natural person. Committees, corporations and party
#: organisations use other codes and are not people.
ENTITY_INDIVIDUAL = "IND"

# Column positions in itcont.txt, from the FEC's published layout and verified
# against the live file. Named rather than inlined because a shifted index is
# silent — it produces plausible values from the wrong field.
_COL_ENTITY = 6
_COL_NAME = 7
_COL_CITY = 8
_COL_STATE = 9
_COL_ZIP = 10
_COL_EMPLOYER = 11
_COL_OCCUPATION = 12
_COL_DATE = 13
_COL_AMOUNT = 14
_MIN_COLS = 15

#: Separator for the collected employer/occupation lists. Pipe is the field
#: delimiter of the source file, so it cannot appear inside a value.
LIST_SEP = " | "

_BATCH = 20_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS contributor (
  key TEXT PRIMARY KEY,
  name_raw TEXT NOT NULL,
  name_canonical TEXT NOT NULL,
  city TEXT,
  state TEXT,
  zip5 TEXT,
  employers TEXT,
  occupations TEXT,
  contributions INTEGER NOT NULL DEFAULT 0,
  total_amount INTEGER NOT NULL DEFAULT 0,
  first_seen TEXT,
  last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_contributor_name ON contributor(name_canonical);
CREATE INDEX IF NOT EXISTS idx_contributor_state ON contributor(state);
-- Which source files have been folded in, so a re-import of the same cycle
-- does not double every total. Keyed on the member CRC, which changes when the
-- FEC republishes and does not when the file is merely copied.
CREATE TABLE IF NOT EXISTS imported (
  crc TEXT PRIMARY KEY,
  filename TEXT,
  rows INTEGER,
  imported_at TEXT
);
"""


@dataclass(frozen=True, slots=True)
class FecRecord:
    name_raw: str
    name_canonical: str
    city: str | None
    state: str | None
    zip5: str | None
    employer: str | None
    occupation: str | None
    date: str | None
    amount: int


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _iso_date(raw: str | None) -> str | None:
    """FEC ships MMDDYYYY."""
    text = (raw or "").strip()
    if len(text) != 8 or not text.isdigit():
        return None
    mm, dd, yyyy = text[:2], text[2:4], text[4:]
    if not ("01" <= mm <= "12") or not ("01" <= dd <= "31"):
        return None
    return f"{yyyy}-{mm}-{dd}"


def parse_line(line: str) -> FecRecord | None:
    """One itcont row -> a contributor, or None when it is not a usable person.

    Never raises: a 70M-row file will contain malformed rows, and one of them
    must not end the import.
    """
    if not line:
        return None
    parts = line.rstrip("\n").split("|")
    if len(parts) < _MIN_COLS:
        return None
    if (parts[_COL_ENTITY] or "").strip().upper() != ENTITY_INDIVIDUAL:
        return None

    name_raw = (parts[_COL_NAME] or "").strip()
    if not name_raw:
        return None

    from umbra.people.names import canonical

    name_canonical = canonical(name_raw)
    if not name_canonical:
        return None

    # ZIP+4 is shipped; five digits is the identity-useful part and the +4 is
    # close enough to a street address to be worth not storing.
    zip_raw = (parts[_COL_ZIP] or "").strip()
    zip5 = zip_raw[:5] if len(zip_raw) >= 5 and zip_raw[:5].isdigit() else None

    try:
        amount = int(float((parts[_COL_AMOUNT] or "0").strip() or 0))
    except ValueError:
        amount = 0

    return FecRecord(
        name_raw=name_raw,
        name_canonical=name_canonical,
        city=_clean(parts[_COL_CITY]),
        state=(_clean(parts[_COL_STATE]) or "")[:2].upper() or None,
        zip5=zip5,
        # "NOT EMPLOYED" is what the filer declared. Nulling it would lose a
        # fact and make the field look unasked rather than answered.
        employer=_clean(parts[_COL_EMPLOYER]),
        occupation=_clean(parts[_COL_OCCUPATION]),
        date=_iso_date(parts[_COL_DATE]),
        amount=amount,
    )


def contributor_key(rec: FecRecord | None) -> str | None:
    """Identity key: canonical name + state + ZIP5.

    Deliberately coarse and deliberately not clever. Two people with the same
    name in one ZIP collapse into one row, and one person who moved becomes
    two. Neither is resolvable from this file, and inventing a link between
    them would be an identification the source does not support.
    """
    if rec is None:
        return None
    return "|".join([rec.name_canonical, rec.state or "", rec.zip5 or ""])


def default_fec_path() -> Path:
    env = os.environ.get("UMBRA_FEC_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "fec.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "fec.sqlite"


class FecLake:
    """SQLite index of FEC individual contributors."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_fec_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            # WAL lets the growth timer's writer and a concurrent web lookup
            # (a reader) run without blocking each other; busy_timeout=5000
            # (ms) gives a writer a bounded wait for a lock instead of an
            # immediate "database is locked" — same values as nppes/uls.
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    @property
    def available(self) -> bool:
        try:
            return self.count() > 0
        except sqlite3.Error:
            return False

    def count(self) -> int:
        return int(self._conn.execute(
            "SELECT COUNT(*) FROM contributor").fetchone()[0])

    def status(self) -> dict:
        try:
            rows = self._conn.execute(
                "SELECT filename, rows, imported_at FROM imported "
                "ORDER BY imported_at DESC").fetchall()
            n = self.count()
        except sqlite3.Error:
            return {"path": str(self.path), "available": False, "contributors": 0}
        return {
            "path": str(self.path),
            "available": n > 0,
            "contributors": n,
            "files": [dict(r) for r in rows],
            "imported_at": rows[0]["imported_at"] if rows else None,
        }

    # --- import -----------------------------------------------------------

    def import_zip(self, zip_path: Path, *, progress_every: int = 1_000_000) -> dict:
        """Fold one bulk file into the index.

        Streams the member — the real file expands past 30 GB and the host has
        8 GB, so nothing here materialises it. Aggregation is done by SQLite
        with an UPSERT rather than in a Python dict, because ~10M contributors
        held in memory is several GB before any values are attached.
        """
        zip_path = Path(zip_path)
        if not zip_path.is_file():
            raise FileNotFoundError(zip_path)

        with zipfile.ZipFile(zip_path) as zf:
            member = None
            for info in zf.infolist():
                if info.filename.rsplit("/", 1)[-1].lower() == DATA_MEMBER:
                    member = info
                    break
            if member is None:
                raise ValueError(
                    f"{zip_path.name} has no {DATA_MEMBER} — not an FEC "
                    "individual-contributions archive"
                )

            crc = f"{member.CRC:08x}"
            already = self._conn.execute(
                "SELECT rows FROM imported WHERE crc = ?", (crc,)).fetchone()
            if already:
                logger.info("fec: %s already imported (crc %s)", zip_path.name, crc)
                return {
                    "rows": int(already[0] or 0),
                    "contributors": self.count(),
                    "skipped_non_individual": 0,
                    "already_imported": True,
                }

            rows = kept = skipped = 0
            pending = 0
            with zf.open(member) as raw:
                stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                                          newline="")
                with self._lock:
                    for line in stream:
                        rows += 1
                        rec = parse_line(line)
                        if rec is None:
                            skipped += 1
                            continue
                        self._upsert(rec)
                        kept += 1
                        pending += 1
                        if pending >= _BATCH:
                            self._conn.commit()
                            pending = 0
                        if progress_every and rows % progress_every == 0:
                            logger.info("fec: %s rows, %s contributors so far",
                                        f"{rows:,}", f"{self.count():,}")
                    self._conn.execute(
                        "INSERT OR REPLACE INTO imported (crc, filename, rows, "
                        "imported_at) VALUES (?,?,?,?)",
                        (crc, zip_path.name, rows,
                         datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                    )
                    self._conn.commit()

        return {
            "rows": rows,
            "kept": kept,
            "contributors": self.count(),
            "skipped_non_individual": skipped,
            "already_imported": False,
        }

    def _upsert(self, rec: FecRecord) -> None:
        """Fold one contribution into its contributor row.

        The list columns append only when the value is not already present, so
        a donor with one employer across 40 contributions keeps one entry
        rather than forty.
        """
        key = contributor_key(rec)
        self._conn.execute(
            """
            INSERT INTO contributor (
              key, name_raw, name_canonical, city, state, zip5,
              employers, occupations, contributions, total_amount,
              first_seen, last_seen
            ) VALUES (?,?,?,?,?,?,?,?,1,?,?,?)
            ON CONFLICT(key) DO UPDATE SET
              contributions = contributions + 1,
              total_amount  = total_amount + excluded.total_amount,
              first_seen    = MIN(COALESCE(first_seen, excluded.first_seen),
                                  COALESCE(excluded.first_seen, first_seen)),
              last_seen     = MAX(COALESCE(last_seen, excluded.last_seen),
                                  COALESCE(excluded.last_seen, last_seen)),
              employers     = CASE
                WHEN excluded.employers IS NULL OR excluded.employers = '' THEN employers
                WHEN employers IS NULL OR employers = '' THEN excluded.employers
                WHEN instr(employers, excluded.employers) > 0 THEN employers
                ELSE employers || ? || excluded.employers END,
              occupations   = CASE
                WHEN excluded.occupations IS NULL OR excluded.occupations = '' THEN occupations
                WHEN occupations IS NULL OR occupations = '' THEN excluded.occupations
                WHEN instr(occupations, excluded.occupations) > 0 THEN occupations
                ELSE occupations || ? || excluded.occupations END
            """,
            (
                key, rec.name_raw, rec.name_canonical, rec.city, rec.state,
                rec.zip5, rec.employer, rec.occupation, rec.amount,
                rec.date, rec.date, LIST_SEP, LIST_SEP,
            ),
        )

    # --- lookup -----------------------------------------------------------

    def lookup(self, name: str, *, limit: int = 25) -> list[dict]:
        """Contributors whose canonical name matches. Never raises.

        A hit is a name that appears in campaign finance filings — not proof
        that the person searched for is the person who filed.
        """
        from umbra.people.names import canonical

        norm = canonical(name)
        if not norm:
            return []
        try:
            rows = self._conn.execute(
                "SELECT * FROM contributor WHERE name_canonical = ? "
                "ORDER BY contributions DESC LIMIT ?",
                (norm, max(1, int(limit))),
            ).fetchall()
        except sqlite3.Error:
            return []
        return [dict(r) for r in rows]


def default_lake() -> FecLake:
    return FecLake()
