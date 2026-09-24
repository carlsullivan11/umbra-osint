"""Owned FAA aircraft-registration lake — N-number → registrant of record.

Same pattern as `umbra.lake.geoip` and the OUI table: ingest a primary source
once, then answer offline forever. Fill with::

    umbra faa sync            # download + import
    umbra faa import-zip PATH # air-gapped

Source: the FAA Releasable Aircraft Database,
<https://registry.faa.gov/database/ReleasableAircraft.zip> — refreshed daily at
23:30 US Central. This reads the published archive; it does **not** scrape
registry.faa.gov, and there is no live flight data anywhere in this module.

**Registrant is not operator and not pilot.** The MASTER file records who holds
the certificate of registration. It does not say who was flying, who leases the
airframe, or who was aboard. A trust, an LLC, or a management company is an
extremely common registrant for an aircraft flown by someone else entirely, so
treating the name as "the owner" — let alone as a person of interest — reads a
fact the file does not contain.

**A miss is unchecked, never "not registered".** Beyond the ordinary reasons a
lake can be stale, the FAA operates a PII-withholding programme under
49 U.S.C. § 44114(b): a private owner may request their name and address be
withheld from public dissemination. An absent registrant can therefore be a
live registration whose owner opted out, which is exactly why absence here
cannot be reported as absence of registration.

Three properties of the published file drive the parsing, all confirmed against
the real archive rather than assumed:

- the N-NUMBER column **omits the leading N** (`100` means N100)
- every field is space-padded to a fixed width (`NAME` is 50 columns)
- the header line carries a UTF-8 BOM, a leading space on ``" KIT MODEL"``, and
  a trailing comma producing an empty final column

so columns are matched by *normalised* header name, never by position.
"""
from __future__ import annotations

import csv
import io
import logging
import os
import re
import sqlite3
import threading
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

RELEASABLE_ZIP_URL = "https://registry.faa.gov/database/ReleasableAircraft.zip"
DOCUMENTATION_URL = "https://registry.faa.gov/database/ardata.pdf"
SOURCE_PAGE = (
    "https://www.faa.gov/licenses_certificates/aircraft_certification/"
    "aircraft_registry/releasable_aircraft_download"
)

MASTER_MEMBER = "MASTER.txt"
ACFTREF_MEMBER = "ACFTREF.txt"

# N + 1–5 alphanumerics. Deliberately not stricter: the FAA's own composition
# rules (no I or O, limits on trailing letters) describe what it will *issue*,
# and a lake that rejects anything outside them would refuse rows the file
# actually contains.
_N_NUMBER_RE = re.compile(r"^N[A-Z0-9]{1,5}$")

#: MASTER.txt `TYPE REGISTRANT`. Codes 3/5/7/8 are organisations; 1 is a named
#: individual, 4 and 9 are co-ownership, which is people as often as not.
_REGISTRANT_TYPES = {
    "1": ("Individual", False),
    "2": ("Partnership", False),
    "3": ("Corporation", True),
    "4": ("Co-owned", False),
    "5": ("Government", True),
    "7": ("LLC", True),
    "8": ("Non-citizen corporation", True),
    "9": ("Non-citizen co-owned", False),
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS aircraft (
  n_number TEXT PRIMARY KEY,
  serial TEXT,
  mfr_mdl_code TEXT,
  year_mfr TEXT,
  type_registrant TEXT,
  name TEXT,
  city TEXT,
  state TEXT,
  country TEXT,
  status_code TEXT,
  cert_issue_date TEXT,
  expiration_date TEXT,
  mode_s_hex TEXT,
  unique_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_aircraft_code ON aircraft(mfr_mdl_code);
CREATE TABLE IF NOT EXISTS model (
  code TEXT PRIMARY KEY,
  mfr TEXT,
  model TEXT,
  type_acft TEXT,
  type_eng TEXT,
  engines INTEGER,
  seats INTEGER,
  weight TEXT
);
"""


def normalize_n_number(raw: str | None) -> str | None:
    """Canonical `N…` form, or None when it is not an N-number.

    Accepts what people type (`n-737-kl`) and what the FAA file stores
    (`737KL`, with the N omitted). Returning the same canonical string for both
    is the whole reason lookups hit.
    """
    if not raw:
        return None
    text = re.sub(r"[\s\-]", "", str(raw)).upper()
    if not text or not text.isalnum():
        return None
    if text.startswith("N"):
        candidate = text
    elif text[0].isdigit():
        # The MASTER.txt form, with the N stripped. Only a leading *digit*
        # earns the prefix: every US registration is N followed by a digit, so
        # prepending to anything alphanumeric would turn "ZZ123" — or any
        # stray token — into the plausible-looking N-number NZZ123.
        candidate = f"N{text}"
    else:
        return None
    # A bare "N" is a prefix, not a registration.
    if len(candidate) < 2:
        return None
    return candidate if _N_NUMBER_RE.match(candidate) else None


@dataclass(frozen=True, slots=True)
class AircraftHit:
    n_number: str
    registrant_name: str | None
    registrant_type: str | None
    registrant_is_org: bool
    city: str | None
    state: str | None
    country: str | None
    year_manufactured: int | None
    status_code: str | None
    cert_issue_date: str | None
    expiration_date: str | None
    mode_s_hex: str | None
    serial: str | None
    manufacturer: str | None
    model: str | None
    aircraft_type: str | None
    engines: int | None
    seats: int | None
    weight_class: str | None

    def airframe_label(self) -> str:
        parts = [p for p in (self.manufacturer, self.model) if p]
        return " ".join(parts) if parts else "unknown airframe"

    def as_dict(self) -> dict:
        return asdict(self)


def default_faa_path() -> Path:
    env = os.environ.get("UMBRA_FAA_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "faa.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "faa.sqlite"


def _clean(value: str | None) -> str | None:
    """Strip fixed-width padding. Empty becomes None, never ''."""
    if value is None:
        return None
    text = value.strip()
    return text or None


def _norm_header(name: str) -> str:
    """Header cell → comparable key.

    Handles the three things wrong with the real header line at once: the BOM
    on the first cell, the leading space on ``" KIT MODEL"``, and case.
    """
    return name.replace("﻿", "").strip().upper()


def _int_or_none(value: str | None) -> int | None:
    text = _clean(value)
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _rows(member: io.TextIOBase) -> tuple[dict[str, int], csv.reader]:
    reader = csv.reader(member)
    try:
        header = next(reader)
    except StopIteration:
        return {}, reader
    return {_norm_header(h): i for i, h in enumerate(header)}, reader


def _get(row: list[str], idx: dict[str, int], key: str) -> str | None:
    i = idx.get(key)
    if i is None or i >= len(row):
        return None
    return _clean(row[i])


class FaaLake:
    """SQLite-backed N-number → registration lake."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_faa_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    # --- plumbing ---------------------------------------------------------

    @property
    def available(self) -> bool:
        if not self.path.is_file():
            return False
        try:
            return self.count("aircraft") > 0
        except Exception:  # noqa: BLE001
            return False

    def connect(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        with self._lock:
            if self._conn is not None:
                return self._conn
            self.path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.executescript(SCHEMA)
            self._conn = conn
            return conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def count(self, table: str) -> int:
        if not self.path.is_file():
            return 0
        if table not in {"aircraft", "model"}:
            raise ValueError(table)
        return int(self.connect().execute(f"SELECT COUNT(*) n FROM {table}").fetchone()["n"])

    def get_meta(self, key: str) -> str | None:
        if not self.path.is_file():
            return None
        row = self.connect().execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def status(self) -> dict:
        return {
            "path": str(self.path),
            "available": self.available,
            "aircraft": self.count("aircraft"),
            "models": self.count("model"),
            "edition": self.get_meta("edition"),
            "imported_at": self.get_meta("imported_at"),
            "source": self.get_meta("source") or RELEASABLE_ZIP_URL,
        }

    # --- import -----------------------------------------------------------

    def import_zip(self, zip_path: Path, *, edition: str | None = None) -> dict:
        """Replace the lake from a ReleasableAircraft.zip.

        Built into a temporary database and swapped into place, like the geoip
        lake: a half-written corpus that still answers lookups is worse than
        one that reports itself empty, because it answers *wrongly* with
        exactly the same confidence.
        """
        zip_path = Path(zip_path)
        if not zip_path.is_file():
            raise FileNotFoundError(zip_path)

        with zipfile.ZipFile(zip_path) as zf:
            names = {n.rsplit("/", 1)[-1].upper(): n for n in zf.namelist()}
            if MASTER_MEMBER.upper() not in names:
                raise ValueError(
                    f"{zip_path.name} has no {MASTER_MEMBER} — this is not a "
                    "ReleasableAircraft archive, and importing the rest would "
                    "leave a lake with airframes and no registrations"
                )

            tmp = self.path.with_suffix(self.path.suffix + ".importing")
            tmp.parent.mkdir(parents=True, exist_ok=True)
            tmp.unlink(missing_ok=True)
            conn = sqlite3.connect(str(tmp))
            conn.executescript(SCHEMA)
            try:
                n_models = 0
                if ACFTREF_MEMBER.upper() in names:
                    n_models = self._load_models(zf, names[ACFTREF_MEMBER.upper()], conn)
                n_aircraft = self._load_master(zf, names[MASTER_MEMBER.upper()], conn)

                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                for k, v in {
                    "source": RELEASABLE_ZIP_URL,
                    "edition": edition or zip_path.name,
                    "imported_at": now,
                    "aircraft": str(n_aircraft),
                    "models": str(n_models),
                }.items():
                    conn.execute(
                        "INSERT INTO meta(key, value) VALUES(?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (k, v),
                    )
                conn.commit()
            finally:
                conn.close()

        self.close()
        os.replace(tmp, self.path)
        return {"aircraft": n_aircraft, "models": n_models, "path": str(self.path)}

    def _load_models(self, zf: zipfile.ZipFile, member: str, conn: sqlite3.Connection) -> int:
        n = 0
        batch: list[tuple] = []
        with zf.open(member) as raw:
            stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
            idx, reader = _rows(stream)
            for row in reader:
                code = _get(row, idx, "CODE")
                if not code:
                    continue
                batch.append((
                    code,
                    _get(row, idx, "MFR"),
                    _get(row, idx, "MODEL"),
                    _get(row, idx, "TYPE-ACFT"),
                    _get(row, idx, "TYPE-ENG"),
                    _int_or_none(_get(row, idx, "NO-ENG")),
                    _int_or_none(_get(row, idx, "NO-SEATS")),
                    _get(row, idx, "AC-WEIGHT"),
                ))
                n += 1
                if len(batch) >= 5000:
                    conn.executemany(
                        "INSERT OR REPLACE INTO model(code, mfr, model, type_acft, "
                        "type_eng, engines, seats, weight) VALUES (?,?,?,?,?,?,?,?)", batch)
                    batch = []
        if batch:
            conn.executemany(
                "INSERT OR REPLACE INTO model(code, mfr, model, type_acft, type_eng, "
                "engines, seats, weight) VALUES (?,?,?,?,?,?,?,?)", batch)
        return n

    def _load_master(self, zf: zipfile.ZipFile, member: str, conn: sqlite3.Connection) -> int:
        n = 0
        batch: list[tuple] = []
        with zf.open(member) as raw:
            stream = io.TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
            idx, reader = _rows(stream)
            for row in reader:
                # The column omits the leading N; normalize puts it back so the
                # stored key is the form a user types.
                n_number = normalize_n_number(_get(row, idx, "N-NUMBER"))
                if not n_number:
                    continue
                batch.append((
                    n_number,
                    _get(row, idx, "SERIAL NUMBER"),
                    _get(row, idx, "MFR MDL CODE"),
                    _get(row, idx, "YEAR MFR"),
                    _get(row, idx, "TYPE REGISTRANT"),
                    _get(row, idx, "NAME"),
                    _get(row, idx, "CITY"),
                    _get(row, idx, "STATE"),
                    _get(row, idx, "COUNTRY"),
                    _get(row, idx, "STATUS CODE"),
                    _get(row, idx, "CERT ISSUE DATE"),
                    _get(row, idx, "EXPIRATION DATE"),
                    _get(row, idx, "MODE S CODE HEX"),
                    _get(row, idx, "UNIQUE ID"),
                ))
                n += 1
                if len(batch) >= 5000:
                    conn.executemany(
                        "INSERT OR REPLACE INTO aircraft(n_number, serial, mfr_mdl_code, "
                        "year_mfr, type_registrant, name, city, state, country, status_code, "
                        "cert_issue_date, expiration_date, mode_s_hex, unique_id) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)
                    batch = []
        if batch:
            conn.executemany(
                "INSERT OR REPLACE INTO aircraft(n_number, serial, mfr_mdl_code, year_mfr, "
                "type_registrant, name, city, state, country, status_code, cert_issue_date, "
                "expiration_date, mode_s_hex, unique_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                batch)
        return n

    # --- lookup -----------------------------------------------------------

    def lookup(self, raw: str) -> AircraftHit | None:
        """One N-number against the local lake. No network, never raises."""
        n_number = normalize_n_number(raw)
        if not n_number or not self.path.is_file():
            return None
        try:
            conn = self.connect()
            row = conn.execute(
                "SELECT * FROM aircraft WHERE n_number = ?", (n_number,)
            ).fetchone()
        except sqlite3.Error:
            logger.warning("faa lake unreadable at %s", self.path, exc_info=True)
            return None
        if row is None:
            return None

        model_row = None
        if row["mfr_mdl_code"]:
            try:
                model_row = conn.execute(
                    "SELECT * FROM model WHERE code = ?", (row["mfr_mdl_code"],)
                ).fetchone()
            except sqlite3.Error:
                model_row = None

        type_name, is_org = _REGISTRANT_TYPES.get(row["type_registrant"] or "", (None, False))
        return AircraftHit(
            n_number=row["n_number"],
            registrant_name=row["name"],
            registrant_type=type_name,
            registrant_is_org=is_org,
            city=row["city"],
            state=row["state"],
            country=row["country"],
            year_manufactured=_int_or_none(row["year_mfr"]),
            status_code=row["status_code"],
            cert_issue_date=row["cert_issue_date"],
            expiration_date=row["expiration_date"],
            mode_s_hex=row["mode_s_hex"],
            serial=row["serial"],
            manufacturer=model_row["mfr"] if model_row else None,
            model=model_row["model"] if model_row else None,
            aircraft_type=model_row["type_acft"] if model_row else None,
            engines=model_row["engines"] if model_row else None,
            seats=model_row["seats"] if model_row else None,
            weight_class=model_row["weight"] if model_row else None,
        )


def default_lake() -> FaaLake:
    return FaaLake()
