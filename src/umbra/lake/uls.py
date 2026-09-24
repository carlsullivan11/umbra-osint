"""FCC ULS — Universal Licensing System bulk license extract, FAA-shaped.

ULS is the FCC's public database of radio licensees: amateur, land mobile,
GMRS, microwave, and dozens of other radio services. Each licensed callsign is
a name + address + service on file with a federal regulator — the same class
of high-fidelity asset/license fact as an FAA N-number registration
(`lake/faa.py`, `docs/FAA.md`), and unrelated to it: an N-number is an
aircraft, a callsign is a radio license, and the two lakes are never joined.

**Bulk files, not the web UI.** The FCC publishes per-radio-service database
dumps as pipe-delimited `.dat` files inside zip archives, refreshed daily and
weekly:

  https://www.fcc.gov/uls/transactions/daily-weekly
  https://www.fcc.gov/wireless/data/public-access-files-database-downloads

There is one zip per radio service (`l_amat.zip` for amateur, `l_market.zip`
for market-based services, and so on) rather than a single "complete ULS"
archive, and the exact per-service URL is not guessed here — same reasoning as
`lake/nppes.py` documenting a landing page instead of a direct link: it moves,
and a wrong guess is a silent 404 or, worse, a WAF page saved with a `.zip`
extension. Fetch the file for the radio service you want from the index page
above and import it with `--zip PATH`. If the FCC restructures that index,
`--download` (unimplemented, same as NPPES) fails loudly rather than guessing.

**Two record types, joined by Unique System Identifier, never by callsign
alone.** `HD.dat` (one row per license) carries the callsign, license status
and radio service code. `EN.dat` (one or more rows per license) carries the
licensee's name and address. Both are keyed on `Unique System Identifier`
(USI) — documented at
<https://www.fcc.gov/sites/default/files/public_access_database_definitions_v2.pdf>
— which is why import loads `EN.dat` into a keyed side table first, then
streams `HD.dat` and joins each header to its entity **in SQLite**, not in a
Python dict: nothing here holds the whole corpus in memory at once, the same
reasoning as `lake/faa.py` joining `MASTER.txt` to `ACFTREF.txt` in the
database rather than in a hash map.

**Person vs organization, from the record shape.** An `EN` row for the
licensee (`Entity Type Code` `L`) carries *either* an `Entity Name` (a
business, club, or trust) *or* a `First Name`/`Last Name` pair (a person) —
never both. That is the entity-type signal the source actually gives; rows
that are clearly companies (an `Entity Name` with no personal name) are
skipped, the same as FAA's organisation registrants are not turned into
`PERSON` nodes. A license whose `EN` row is missing or unparsable is skipped
outright rather than stored with a blank name.

**A callsign is not a person.** A licensee name on file with the FCC is a
public record, not an identification — the same caveat `lake/nppes.py` and
`lake/fec.py` carry. This table is never merged into `people`.

**Streamed, not read.** Both `.dat` members can be large; each is iterated
line-by-line through `io.TextIOWrapper`, the same shape as `lake/fec.py` and
`lake/nppes.py`. Nothing here materialises a whole zip member into memory at
once.
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

#: FCC's daily/weekly transaction index. There is no single "complete ULS"
#: zip — one archive per radio service — so the direct URL is not guessed;
#: see the module docstring.
ULS_INDEX_URL = "https://www.fcc.gov/uls/transactions/daily-weekly"
DATABASE_DEFINITIONS_URL = (
    "https://www.fcc.gov/sites/default/files/public_access_database_definitions_v2.pdf"
)

HD_MEMBER = "HD.dat"
EN_MEMBER = "EN.dat"

#: `EN` rows exist for licensees, contacts, attorneys and more per USI; only
#: the licensee row (`L`) is the license's name of record.
ENTITY_TYPE_LICENSEE = "L"

# Field positions from the FCC's published database definitions, pinned as
# named constants rather than inlined — same reasoning as `lake/fec.py`
# pinning column indexes: a silently shifted column produces a plausible
# value from the wrong field. Both `.dat` files are pipe-delimited with no
# header row.
IDX_HD_USI = 1
IDX_HD_CALLSIGN = 4
IDX_HD_STATUS = 5
IDX_HD_RADIO_SERVICE = 6

IDX_EN_USI = 1
IDX_EN_CALLSIGN = 4
IDX_EN_ENTITY_TYPE = 5
IDX_EN_ENTITY_NAME = 7
IDX_EN_FIRST_NAME = 8
IDX_EN_MI = 9
IDX_EN_LAST_NAME = 10
IDX_EN_SUFFIX = 11
IDX_EN_STREET = 15
IDX_EN_CITY = 16
IDX_EN_STATE = 17
IDX_EN_ZIP = 18

_BATCH = 20_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
-- EN.dat licensee entities, keyed on Unique System Identifier. A staging
-- table joined against HD.dat during import, not a public lookup surface.
CREATE TABLE IF NOT EXISTS entity (
  usi TEXT PRIMARY KEY,
  name_raw TEXT NOT NULL,
  name_canonical TEXT NOT NULL,
  street TEXT,
  city TEXT,
  state TEXT,
  zip TEXT
);
CREATE TABLE IF NOT EXISTS license (
  fcc_uls_id TEXT PRIMARY KEY,
  callsign TEXT,
  name_raw TEXT NOT NULL,
  name_canonical TEXT NOT NULL,
  city TEXT,
  state TEXT,
  zip TEXT,
  radio_service TEXT,
  status TEXT,
  source TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_license_name ON license(name_canonical);
CREATE INDEX IF NOT EXISTS idx_license_callsign ON license(callsign);
-- Which source files have been folded in, keyed on the member CRC so a
-- re-import of the same zip does not double-count anything.
CREATE TABLE IF NOT EXISTS imported (
  crc TEXT PRIMARY KEY,
  filename TEXT,
  rows INTEGER,
  imported_at TEXT
);
"""


@dataclass(frozen=True, slots=True)
class UlsEntity:
    usi: str
    name_raw: str
    name_canonical: str
    street: str | None
    city: str | None
    state: str | None
    zip: str | None


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _field(parts: list[str], idx: int) -> str | None:
    if idx >= len(parts):
        return None
    return _clean(parts[idx])


def parse_hd_row(line: str) -> tuple[str, str | None, str | None, str | None] | None:
    """One `HD.dat` line -> `(usi, callsign, status, radio_service)`, or None.

    Never raises: a multi-million-row file will contain short or malformed
    lines, and one of them must not end the import.
    """
    if not line:
        return None
    parts = line.rstrip("\n").rstrip("\r").split("|")
    usi = _field(parts, IDX_HD_USI)
    if not usi:
        return None
    return (
        usi,
        _field(parts, IDX_HD_CALLSIGN),
        _field(parts, IDX_HD_STATUS),
        _field(parts, IDX_HD_RADIO_SERVICE),
    )


def parse_en_row(line: str) -> UlsEntity | None:
    """One `EN.dat` line -> a licensee entity, or None when it is not usable.

    Skips non-licensee entity rows (contacts, attorneys) and rows that are
    clearly a company: an `Entity Name` with no personal name populated.
    """
    if not line:
        return None
    parts = line.rstrip("\n").rstrip("\r").split("|")
    usi = _field(parts, IDX_EN_USI)
    if not usi:
        return None
    entity_type = _field(parts, IDX_EN_ENTITY_TYPE)
    if entity_type != ENTITY_TYPE_LICENSEE:
        return None

    first = _field(parts, IDX_EN_FIRST_NAME)
    mi = _field(parts, IDX_EN_MI)
    last = _field(parts, IDX_EN_LAST_NAME)
    suffix = _field(parts, IDX_EN_SUFFIX)

    if not first and not last:
        # No personal name on file — either a company/club/trust (Entity
        # Name populated) or an unusable row. Either way, not a person.
        return None
    name_raw = " ".join(t for t in (first, mi, last, suffix) if t)
    if not name_raw:
        return None

    from umbra.people.names import canonical

    name_canonical = canonical(name_raw)
    if not name_canonical:
        return None

    return UlsEntity(
        usi=usi,
        name_raw=name_raw,
        name_canonical=name_canonical,
        street=_field(parts, IDX_EN_STREET),
        city=_field(parts, IDX_EN_CITY),
        state=(_field(parts, IDX_EN_STATE) or "")[:2].upper() or None,
        zip=(_field(parts, IDX_EN_ZIP) or "")[:5] or None,
    )


def default_uls_path() -> Path:
    env = os.environ.get("UMBRA_ULS_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "uls.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "uls.sqlite"


def _find_member(zf: zipfile.ZipFile, name: str) -> str | None:
    target = name.lower()
    for member in zf.namelist():
        if member.rsplit("/", 1)[-1].lower() == target:
            return member
    return None


class UlsLake:
    """SQLite index of FCC ULS licenses, keyed on Unique System Identifier."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_uls_path()
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
            "SELECT COUNT(*) FROM license").fetchone()[0])

    def status(self) -> dict:
        try:
            rows = self._conn.execute(
                "SELECT filename, rows, imported_at FROM imported "
                "ORDER BY imported_at DESC").fetchall()
            n = self.count()
        except sqlite3.Error:
            return {"path": str(self.path), "available": False, "licenses": 0}
        return {
            "path": str(self.path),
            "available": n > 0,
            "licenses": n,
            "files": [dict(r) for r in rows],
            "imported_at": rows[0]["imported_at"] if rows else None,
            "source": ULS_INDEX_URL,
        }

    # --- import -----------------------------------------------------------

    def import_zip(self, zip_path: Path, *, progress_every: int = 1_000_000) -> dict:
        """Fold one per-radio-service ULS zip into the index.

        `EN.dat` is streamed into the `entity` staging table first; `HD.dat`
        is then streamed and joined to it by USI in SQLite. Nothing here
        materialises either member — both are read line-by-line through
        `io.TextIOWrapper`.
        """
        zip_path = Path(zip_path)
        if not zip_path.is_file():
            raise FileNotFoundError(zip_path)

        with zipfile.ZipFile(zip_path) as zf:
            hd_member = _find_member(zf, HD_MEMBER)
            en_member = _find_member(zf, EN_MEMBER)
            if hd_member is None or en_member is None:
                raise ValueError(
                    f"{zip_path.name} has no {HD_MEMBER}/{EN_MEMBER} pair — "
                    "not a ULS per-radio-service bulk archive"
                )

            hd_info = zf.getinfo(hd_member)
            en_info = zf.getinfo(en_member)
            # Both members' CRCs, not just HD.dat's: a re-published file with
            # the same license headers but amended addresses must not be
            # treated as an unchanged re-import.
            crc = f"{hd_info.CRC:08x}{en_info.CRC:08x}"
            already = self._conn.execute(
                "SELECT rows FROM imported WHERE crc = ?", (crc,)).fetchone()
            if already:
                logger.info("uls: %s already imported (crc %s)", zip_path.name, crc)
                return {
                    "rows": int(already[0] or 0),
                    "licenses": self.count(),
                    "skipped_company": 0,
                    "already_imported": True,
                }

            with self._lock:
                self._conn.execute("DELETE FROM entity")
                self._conn.commit()
                entities = self._load_entities(zf, en_member)
                hd_rows, kept, skipped_company = self._load_headers(zf, hd_member)
                self._conn.execute("DELETE FROM entity")
                self._conn.execute(
                    "INSERT OR REPLACE INTO imported (crc, filename, rows, "
                    "imported_at) VALUES (?,?,?,?)",
                    (crc, zip_path.name, hd_rows,
                     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                )
                self._conn.commit()

        return {
            "rows": hd_rows,
            "entities": entities,
            "kept": kept,
            "licenses": self.count(),
            "skipped_company": skipped_company,
            "already_imported": False,
        }

    def _load_entities(self, zf: zipfile.ZipFile, member: str) -> int:
        n = 0
        pending = 0
        with zf.open(member) as raw:
            stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                                       newline="")
            for line in stream:
                rec = parse_en_row(line)
                if rec is None:
                    continue
                self._conn.execute(
                    "INSERT OR REPLACE INTO entity (usi, name_raw, "
                    "name_canonical, street, city, state, zip) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (rec.usi, rec.name_raw, rec.name_canonical, rec.street,
                     rec.city, rec.state, rec.zip),
                )
                n += 1
                pending += 1
                if pending >= _BATCH:
                    self._conn.commit()
                    pending = 0
        self._conn.commit()
        return n

    def _load_headers(self, zf: zipfile.ZipFile, member: str) -> tuple[int, int, int]:
        rows = kept = skipped_company = 0
        pending = 0
        with zf.open(member) as raw:
            stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                                       newline="")
            for line in stream:
                parsed = parse_hd_row(line)
                if parsed is None:
                    continue
                rows += 1
                usi, callsign, status, radio_service = parsed
                ent = self._conn.execute(
                    "SELECT name_raw, name_canonical, city, state, zip "
                    "FROM entity WHERE usi = ?", (usi,)).fetchone()
                if ent is None:
                    # No licensee entity row for this USI — either it is a
                    # company (skipped while loading EN.dat) or the entity
                    # row is missing outright. Either way, not a person.
                    skipped_company += 1
                    continue
                self._conn.execute(
                    """
                    INSERT INTO license (
                      fcc_uls_id, callsign, name_raw, name_canonical, city,
                      state, zip, radio_service, status, source
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(fcc_uls_id) DO UPDATE SET
                      callsign = excluded.callsign,
                      name_raw = excluded.name_raw,
                      name_canonical = excluded.name_canonical,
                      city = excluded.city,
                      state = excluded.state,
                      zip = excluded.zip,
                      radio_service = excluded.radio_service,
                      status = excluded.status,
                      source = excluded.source
                    """,
                    (usi, callsign, ent["name_raw"], ent["name_canonical"],
                     ent["city"], ent["state"], ent["zip"], radio_service,
                     status, "fcc_uls_bulk"),
                )
                kept += 1
                pending += 1
                if pending >= _BATCH:
                    self._conn.commit()
                    pending = 0
        self._conn.commit()
        return rows, kept, skipped_company

    # --- lookup -----------------------------------------------------------

    def lookup(self, name: str, *, state: str | None = None, limit: int = 25) -> list[dict]:
        """Licenses whose canonical name matches, using an equality index.

        A hit is a callsign on file with the FCC that carries the name
        searched for — not an identification.
        """
        from umbra.people.names import canonical

        norm = canonical(name)
        if not norm:
            return []
        try:
            if state:
                rows = self._conn.execute(
                    "SELECT * FROM license WHERE name_canonical = ? AND state = ? "
                    "ORDER BY fcc_uls_id LIMIT ?",
                    (norm, state.strip().upper()[:2], max(1, int(limit))),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM license WHERE name_canonical = ? "
                    "ORDER BY fcc_uls_id LIMIT ?",
                    (norm, max(1, int(limit))),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [dict(r) for r in rows]

    def by_callsign(self, callsign: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM license WHERE callsign = ?",
            (str(callsign).strip().upper(),)).fetchone()
        return dict(row) if row else None


def default_lake() -> UlsLake:
    return UlsLake()
