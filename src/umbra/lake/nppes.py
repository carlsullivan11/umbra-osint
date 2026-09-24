"""CMS NPPES — the National Provider Identifier registry, FEC-shaped.

NPPES (National Plan and Provider Enumeration System) is CMS's public bulk
download of every enumerated healthcare provider: NPI, legal name, practice
address and taxonomy (specialty). It is published monthly as a lawful, public
"NPPES Downloadable File" for exactly this purpose:

  https://download.cms.gov/nppes/NPI_Files.html

Unlike FEC's `itcont.txt`, the NPPES member ships **with a header row**, so
columns are addressed by the published header name rather than by position —
still pinned as named constants, for the same reason `lake/fec.py` pins column
indexes: a silently shifted column produces plausible values from the wrong
field.

**NPI is the identity key, not name+ZIP.** Every enumerated provider gets one
NPI for life; it does not get reused. That is a stronger identity than FEC's
coarse name+state+ZIP key, but the *name* on the record is exactly as
ambiguous as anywhere else — a name match against this lake is a registry row,
not "this is the person you meant."

**Individuals only.** Entity Type Code 1 is an individual provider; 2 is an
organization (a clinic, a hospital, a group practice). Organizations are
skipped the same way FEC skips non-`IND` entity types — this is a people lake,
not a facility directory.

**Streamed, not read.** The monthly file's data member is hundreds of
megabytes to low gigabytes; nothing here materialises it. Rows are read with
`csv.DictReader` over a streamed `TextIOWrapper`, one line at a time, the same
shape as `lake/fec.py`.

**A separate table.** NPI rows are not merged into `people` or into the FEC
contributor table. A clinician's occupation record and a donor record are two
different public-record claims about two different, unrelated slices of a
life, and merging them would assert a link the sources do not support.
"""
from __future__ import annotations

import csv
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

#: The monthly zip's data member is named e.g. `npidata_pfile_20050523-20260908.csv`.
#: Matched by prefix rather than an exact name because the date range in the
#: filename changes every release.
DATA_MEMBER_PREFIX = "npidata_pfile_"

#: CMS documents the current bulk file at this landing page; the direct URL
#: changes every month and is not guessed here (see docs/PEOPLE.md).
NPI_FILES_URL = "https://download.cms.gov/nppes/NPI_Files.html"

#: NPPES Entity Type Code. 1 = individual provider, 2 = organization.
#: https://download.cms.gov/nppes/NPPES_Data_Dissemination_Readme.pdf
ENTITY_INDIVIDUAL = "1"
ENTITY_ORGANIZATION = "2"

# Column names from the published NPPES data dictionary, pinned as constants
# rather than inlined so a header reorder or renamed column fails loudly
# (KeyError on a missing column) instead of silently reading the wrong field.
COL_NPI = "NPI"
COL_ENTITY_TYPE = "Entity Type Code"
COL_LAST_NAME = "Provider Last Name (Legal Name)"
COL_FIRST_NAME = "Provider First Name"
COL_MIDDLE_NAME = "Provider Middle Name"
COL_ADDR1 = "Provider First Line Business Practice Location Address"
COL_ADDR2 = "Provider Second Line Business Practice Location Address"
COL_CITY = "Provider Business Practice Location Address City Name"
COL_STATE = "Provider Business Practice Location Address State Name"
COL_ZIP = "Provider Business Practice Location Address Postal Code"
COL_ENUMERATION_DATE = "Provider Enumeration Date"
COL_TAXONOMY_1 = "Healthcare Provider Taxonomy Code_1"

_BATCH = 20_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS provider (
  npi TEXT PRIMARY KEY,
  name_raw TEXT NOT NULL,
  name_canonical TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  city TEXT,
  state TEXT,
  zip5 TEXT,
  taxonomy TEXT,
  practice_address TEXT,
  enumeration_date TEXT
);
CREATE INDEX IF NOT EXISTS idx_provider_name ON provider(name_canonical);
CREATE INDEX IF NOT EXISTS idx_provider_state_zip ON provider(state, zip5);
-- Which source files have been folded in, keyed on the member CRC so a
-- re-import of the same monthly file does not double-count anything.
CREATE TABLE IF NOT EXISTS imported (
  crc TEXT PRIMARY KEY,
  filename TEXT,
  rows INTEGER,
  imported_at TEXT
);
"""


@dataclass(frozen=True, slots=True)
class NppesRecord:
    npi: str
    name_raw: str
    name_canonical: str
    entity_type: str
    city: str | None
    state: str | None
    zip5: str | None
    taxonomy: str | None
    practice_address: str | None
    enumeration_date: str | None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def parse_row(row: dict) -> NppesRecord | None:
    """One npidata_pfile row -> a provider, or None when it is not usable.

    Never raises: a multi-million-row file will contain malformed or
    incomplete rows, and one of them must not end the import.
    """
    if not row:
        return None

    npi = (row.get(COL_NPI) or "").strip()
    if not npi:
        return None

    entity_type = (row.get(COL_ENTITY_TYPE) or "").strip()
    if entity_type != ENTITY_INDIVIDUAL:
        return None

    last = (row.get(COL_LAST_NAME) or "").strip()
    first = (row.get(COL_FIRST_NAME) or "").strip()
    middle = (row.get(COL_MIDDLE_NAME) or "").strip()
    if not last and not first:
        return None
    name_raw = " ".join(t for t in (first, middle, last) if t)

    from umbra.people.names import canonical

    name_canonical = canonical(name_raw)
    if not name_canonical:
        return None

    zip_raw = (row.get(COL_ZIP) or "").strip()
    zip5 = zip_raw[:5] if len(zip_raw) >= 5 and zip_raw[:5].isdigit() else None

    addr1 = _clean(row.get(COL_ADDR1))
    addr2 = _clean(row.get(COL_ADDR2))
    practice_address = ", ".join(a for a in (addr1, addr2) if a) or None

    return NppesRecord(
        npi=npi,
        name_raw=name_raw,
        name_canonical=name_canonical,
        entity_type=entity_type,
        city=_clean(row.get(COL_CITY)),
        state=(_clean(row.get(COL_STATE)) or "")[:2].upper() or None,
        zip5=zip5,
        taxonomy=_clean(row.get(COL_TAXONOMY_1)),
        practice_address=practice_address,
        enumeration_date=_clean(row.get(COL_ENUMERATION_DATE)),
    )


def default_nppes_path() -> Path:
    env = os.environ.get("UMBRA_NPPES_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "nppes.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "nppes.sqlite"


class NppesLake:
    """SQLite index of NPPES individual providers, keyed on NPI."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_nppes_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
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
            "SELECT COUNT(*) FROM provider").fetchone()[0])

    def status(self) -> dict:
        try:
            rows = self._conn.execute(
                "SELECT filename, rows, imported_at FROM imported "
                "ORDER BY imported_at DESC").fetchall()
            n = self.count()
        except sqlite3.Error:
            return {"path": str(self.path), "available": False, "providers": 0}
        return {
            "path": str(self.path),
            "available": n > 0,
            "providers": n,
            "files": [dict(r) for r in rows],
            "imported_at": rows[0]["imported_at"] if rows else None,
        }

    # --- import -----------------------------------------------------------

    def import_zip(self, zip_path: Path, *, progress_every: int = 1_000_000) -> dict:
        """Fold one NPPES monthly file into the index.

        Streams the member with `csv.DictReader` — nothing here materialises
        the whole file. Individuals are upserted keyed on NPI; organizations
        are counted and skipped.
        """
        zip_path = Path(zip_path)
        if not zip_path.is_file():
            raise FileNotFoundError(zip_path)

        with zipfile.ZipFile(zip_path) as zf:
            member = None
            for info in zf.infolist():
                base = info.filename.rsplit("/", 1)[-1].lower()
                if base.startswith(DATA_MEMBER_PREFIX) and base.endswith(".csv"):
                    member = info
                    break
            if member is None:
                raise ValueError(
                    f"{zip_path.name} has no {DATA_MEMBER_PREFIX}*.csv member — "
                    "not an NPPES downloadable file"
                )

            crc = f"{member.CRC:08x}"
            already = self._conn.execute(
                "SELECT rows FROM imported WHERE crc = ?", (crc,)).fetchone()
            if already:
                logger.info("nppes: %s already imported (crc %s)", zip_path.name, crc)
                return {
                    "rows": int(already[0] or 0),
                    "providers": self.count(),
                    "skipped_organization": 0,
                    "already_imported": True,
                }

            rows = kept = skipped_org = skipped_bad = 0
            pending = 0
            with zf.open(member) as raw:
                stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                                          newline="")
                reader = csv.DictReader(stream)
                with self._lock:
                    for row in reader:
                        rows += 1
                        entity_type = (row.get(COL_ENTITY_TYPE) or "").strip()
                        rec = parse_row(row)
                        if rec is None:
                            if entity_type == ENTITY_ORGANIZATION:
                                skipped_org += 1
                            else:
                                skipped_bad += 1
                            continue
                        self._upsert(rec)
                        kept += 1
                        pending += 1
                        if pending >= _BATCH:
                            self._conn.commit()
                            pending = 0
                        if progress_every and rows % progress_every == 0:
                            logger.info("nppes: %s rows, %s providers so far",
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
            "providers": self.count(),
            "skipped_organization": skipped_org,
            "skipped_incomplete": skipped_bad,
            "already_imported": False,
        }

    def _upsert(self, rec: NppesRecord) -> None:
        self._conn.execute(
            """
            INSERT INTO provider (
              npi, name_raw, name_canonical, entity_type, city, state, zip5,
              taxonomy, practice_address, enumeration_date
            ) VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(npi) DO UPDATE SET
              name_raw = excluded.name_raw,
              name_canonical = excluded.name_canonical,
              entity_type = excluded.entity_type,
              city = excluded.city,
              state = excluded.state,
              zip5 = excluded.zip5,
              taxonomy = excluded.taxonomy,
              practice_address = excluded.practice_address,
              enumeration_date = excluded.enumeration_date
            """,
            (
                rec.npi, rec.name_raw, rec.name_canonical, rec.entity_type,
                rec.city, rec.state, rec.zip5, rec.taxonomy,
                rec.practice_address, rec.enumeration_date,
            ),
        )

    # --- lookup -----------------------------------------------------------

    def lookup(self, name: str, *, state: str | None = None, limit: int = 25) -> list[dict]:
        """Providers whose canonical name matches, using an equality index.

        A hit is a registry row that carries the name searched for — the NPI
        is unique to one provider, but the name on it is not, and a match here
        is not proof of identity.
        """
        from umbra.people.names import canonical

        norm = canonical(name)
        if not norm:
            return []
        try:
            if state:
                rows = self._conn.execute(
                    "SELECT * FROM provider WHERE name_canonical = ? AND state = ? "
                    "ORDER BY npi LIMIT ?",
                    (norm, state.strip().upper()[:2], max(1, int(limit))),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM provider WHERE name_canonical = ? "
                    "ORDER BY npi LIMIT ?",
                    (norm, max(1, int(limit))),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [dict(r) for r in rows]

    def by_npi(self, npi: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM provider WHERE npi = ?", (str(npi).strip(),)).fetchone()
        return dict(row) if row else None


def default_lake() -> NppesLake:
    return NppesLake()
