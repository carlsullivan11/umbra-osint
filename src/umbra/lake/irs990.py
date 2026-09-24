"""IRS Form 990 officers/directors — a lawful bulk name <-> org graph.

Every tax-exempt organization's Form 990 lists its officers, directors,
trustees and key employees by name and title (Part VII, Section A). The IRS
publishes the e-filed originals as public XML, indexed per filing year:

  https://www.irs.gov/charities-non-profits/form-990-series-downloads
  https://apps.irs.gov/pub/epostcard/990/xml/{year}/index_{year}.csv
  https://apps.irs.gov/pub/epostcard/990/xml/{year}/{OBJECT_ID}_public.xml

This is the *official bulk download* page, confirmed live: `index_2023.csv`
has the header `RETURN_ID,FILING_TYPE,EIN,TAX_PERIOD,SUB_DATE,TAXPAYER_NAME,
RETURN_TYPE,DLN,OBJECT_ID`, and `OBJECT_ID` is the key that resolves to one
filing's XML at the second URL. This is a different surface than the Tax
Exempt Organization Search *SPA* (`apps.irs.gov/app/eos/`) that issue #9
explicitly rules out — that is a search UI over the same underlying data, not
a bulk-download endpoint, and is not touched here.

The IRS also ships whole-year bulk zips (`{year}_TEOS_XML_{MM}A.zip`, one to
several GB each) on the same downloads page. Those are *not* used here: the
per-filing index+object approach gives a natural, persistable cursor
(`--max-files` per call, resumed from `meta`) without ever holding a
multi-GB archive or its member list in memory. Each filing XML is small (KB
to a few MB) and is parsed with `ElementTree.iterparse`, clearing each element
once consumed, so even a pathological filing cannot pin the whole tree.

**Officer/director fields, from the IRS's own MeF schema** (`IRS990.xsd`,
`ReturnHeader990x.xsd` — not guessed; these are the documented element names
used by every public 990 parser, e.g. `jsfenfen/990-xml-reader`,
Charity Navigator's 990 Decoder):

  Form990PartVIISectionAGrp/PersonNm   -- officer/director/trustee name
  Form990PartVIISectionAGrp/TitleTxt   -- title, as filed ("Trustee" is a
                                           filed role, not an identity claim)
  ReturnHeader/Filer/EIN               -- the organization's EIN
  ReturnHeader/Filer/BusinessName/BusinessNameLine1Txt -- org name
  ReturnHeader/Filer/USAddress/CityNm, StateAbbreviationCd
  ReturnHeader/TaxYr

**Not a people-finder.** A name on a 990 is an org-officer candidate: it
identifies a role at one organization in one tax year, nothing more. Rows are
never merged into `people`, FEC, or NPPES — same discipline as those lakes.

**Identity key.** (ein, name_canonical, title) — two officers who share a
surname at two different organizations get two different rows, and two
officers with the same title at the same org (rare, but the schema allows a
repeated title, e.g. "Board Member") are still told apart by name.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

#: Official IRS bulk-download index and per-filing XML, confirmed live
#: against the 2023 index (see module docstring). The `{year}` and
#: `{object_id}` fields come from the index row itself.
INDEX_URL_TEMPLATE = "https://apps.irs.gov/pub/epostcard/990/xml/{year}/index_{year}.csv"
XML_URL_TEMPLATE = "https://apps.irs.gov/pub/epostcard/990/xml/{year}/{object_id}_public.xml"

#: Index CSV columns, from the live header (see module docstring). Named
#: rather than positional since csv.DictReader keys on the header row.
COL_OBJECT_ID = "OBJECT_ID"
COL_EIN = "EIN"
COL_TAXPAYER_NAME = "TAXPAYER_NAME"
COL_TAX_PERIOD = "TAX_PERIOD"
COL_RETURN_TYPE = "RETURN_TYPE"

_TAG_RE = re.compile(r"^\{[^}]+\}")


def _local(tag: str) -> str:
    """Strip the XML namespace so element matching does not depend on the
    schema version's namespace URI, which changes across filing years."""
    return _TAG_RE.sub("", tag)


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS officer (
  key TEXT PRIMARY KEY,
  ein TEXT NOT NULL,
  org_name TEXT,
  name_raw TEXT NOT NULL,
  name_canonical TEXT NOT NULL,
  title TEXT,
  city TEXT,
  state TEXT,
  tax_year TEXT,
  source_url TEXT NOT NULL,
  imported_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_officer_name ON officer(name_canonical);
CREATE INDEX IF NOT EXISTS idx_officer_ein ON officer(ein);
-- Which filings (OBJECT_ID) have been folded in, so re-running the same
-- --year does not re-fetch or double-count a filing already indexed.
CREATE TABLE IF NOT EXISTS imported (
  object_id TEXT PRIMARY KEY,
  year TEXT,
  officers INTEGER,
  imported_at TEXT
);
"""


@dataclass(frozen=True, slots=True)
class OfficerRecord:
    ein: str
    org_name: str | None
    name_raw: str
    name_canonical: str
    title: str | None
    city: str | None
    state: str | None
    tax_year: str | None
    source_url: str


def officer_key(rec: OfficerRecord) -> str:
    return "|".join([rec.ein, rec.name_canonical, rec.title or ""])


def _clean(text: str | None) -> str | None:
    if text is None:
        return None
    text = text.strip()
    return text or None


def parse_filing_xml(data: bytes, source_url: str) -> list[OfficerRecord]:
    """One filing's XML -> its officer/director/trustee rows.

    Streamed with `iterparse` and each element cleared once read, rather than
    held as a whole tree: a single filing is small, but the point of a spike
    is to not need to revisit this once a pathological filing shows up.
    Never raises: a malformed filing must not end a bounded --year run.
    """
    from umbra.people.names import canonical

    ein = org_name = city = state = tax_year = None
    officers: list[OfficerRecord] = []
    pending_person: str | None = None
    pending_title: str | None = None
    in_group = False

    try:
        for event, elem in ET.iterparse(io.BytesIO(data), events=("start", "end")):
            tag = _local(elem.tag)
            if event == "start":
                if tag == "Form990PartVIISectionAGrp":
                    in_group = True
                    pending_person = pending_title = None
                continue

            # event == "end"
            if tag == "EIN" and ein is None:
                ein = _clean(elem.text)
            elif tag == "BusinessNameLine1Txt" and org_name is None:
                org_name = _clean(elem.text)
            elif tag == "TaxYr" and tax_year is None:
                tax_year = _clean(elem.text)
            elif tag == "CityNm" and city is None:
                city = _clean(elem.text)
            elif tag == "StateAbbreviationCd" and state is None:
                state = _clean(elem.text)
            elif in_group and tag == "PersonNm":
                pending_person = _clean(elem.text)
            elif in_group and tag == "TitleTxt":
                pending_title = _clean(elem.text)
            elif tag == "Form990PartVIISectionAGrp":
                in_group = False
                if pending_person:
                    name_canonical = canonical(pending_person)
                    if name_canonical:
                        officers.append(OfficerRecord(
                            ein=ein or "",
                            org_name=org_name,
                            name_raw=pending_person,
                            name_canonical=name_canonical,
                            title=pending_title,
                            city=city,
                            state=state,
                            tax_year=tax_year,
                            source_url=source_url,
                        ))
                pending_person = pending_title = None
            elem.clear()
    except ET.ParseError:
        logger.warning("irs990: could not parse %s", source_url)
        return []

    return officers


def default_irs990_path() -> Path:
    env = os.environ.get("UMBRA_IRS990_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "irs990.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "irs990.sqlite"


class Irs990Lake:
    """SQLite index of IRS Form 990 officers/directors/trustees."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_irs990_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
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
        return int(self._conn.execute("SELECT COUNT(*) FROM officer").fetchone()[0])

    def status(self) -> dict:
        try:
            n = self.count()
            years = [r[0] for r in self._conn.execute(
                "SELECT DISTINCT tax_year FROM officer WHERE tax_year IS NOT NULL "
                "ORDER BY tax_year").fetchall()]
            files = int(self._conn.execute(
                "SELECT COUNT(*) FROM imported").fetchone()[0])
            cursors = {r[0]: r[1] for r in self._conn.execute(
                "SELECT key, value FROM meta WHERE key LIKE 'cursor:%'").fetchall()}
            newest = self._conn.execute(
                "SELECT imported_at FROM imported ORDER BY imported_at DESC "
                "LIMIT 1").fetchone()
        except sqlite3.Error:
            return {"path": str(self.path), "available": False, "officers": 0}
        return {
            "path": str(self.path),
            "available": n > 0,
            "officers": n,
            "years": years,
            "files_imported": files,
            "cursors": cursors,
            "imported_at": newest[0] if newest else None,
        }

    def lookup(self, name: str, *, limit: int = 25) -> list[dict]:
        """Officer/director rows whose name matches. Never raises.

        Identity key is (ein, name_canonical, title): the same name at two
        EINs is two rows, never folded into one "officer".
        """
        from umbra.people.names import canonical

        norm = canonical(name)
        if not norm:
            return []
        try:
            rows = self._conn.execute(
                "SELECT * FROM officer WHERE name_canonical = ? "
                "ORDER BY ein, title LIMIT ?",
                (norm, max(1, int(limit))),
            ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    # --- import -------------------------------------------------------

    def import_filing_xml(self, data: bytes, source_url: str, *, year: str | None = None,
                           object_id: str | None = None) -> int:
        """Fold one filing's officers into the index. Returns rows kept.

        The unit tests exercise this directly with fixture bytes — no live
        IRS fetch is needed to prove the parsing and identity-key logic.
        """
        officers = parse_filing_xml(data, source_url)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            for rec in officers:
                self._upsert(rec, now)
            if object_id:
                self._conn.execute(
                    "INSERT OR REPLACE INTO imported (object_id, year, officers, "
                    "imported_at) VALUES (?,?,?,?)",
                    (object_id, year, len(officers), now),
                )
            self._conn.commit()
        return len(officers)

    def _upsert(self, rec: OfficerRecord, imported_at: str) -> None:
        self._conn.execute(
            """
            INSERT INTO officer (
              key, ein, org_name, name_raw, name_canonical, title, city,
              state, tax_year, source_url, imported_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(key) DO UPDATE SET
              org_name = excluded.org_name,
              city = excluded.city,
              state = excluded.state,
              tax_year = excluded.tax_year,
              source_url = excluded.source_url,
              imported_at = excluded.imported_at
            """,
            (
                officer_key(rec), rec.ein, rec.org_name, rec.name_raw,
                rec.name_canonical, rec.title, rec.city, rec.state,
                rec.tax_year, rec.source_url, imported_at,
            ),
        )

    def import_year(self, year: int, *, max_files: int = 25) -> dict:
        """Fetch the official index for one filing year and fold in up to
        `max_files` new filings, resuming from a persisted row cursor.

        Streams: the index CSV for one year is at most tens of MB (rows are
        one line each), and each filing is fetched and parsed one at a time —
        nothing here ever holds a whole year's XML corpus in memory. Calling
        this repeatedly with the same --year advances the cursor rather than
        re-reading already-imported filings.
        """
        import csv

        from umbra.core.config import get_settings
        from umbra.core.http_guard import GuardedClient, check_url

        settings = get_settings()
        cursor_key = f"cursor:{year}"
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (cursor_key,)).fetchone()
        start = int(row[0]) if row else 0

        index_url = INDEX_URL_TEMPLATE.format(year=year)
        processed = kept = skipped_dup = 0
        cursor = start

        with GuardedClient(timeout=120.0, headers={"User-Agent": settings.user_agent}) as http:
            check_url(index_url)
            resp = http.get(index_url, follow_redirects=True)
            resp.raise_for_status()
            reader = csv.DictReader(io.StringIO(resp.text))
            for i, row_dict in enumerate(reader):
                if i < start:
                    continue
                if processed >= max_files:
                    break
                cursor = i + 1
                processed += 1
                object_id = (row_dict.get(COL_OBJECT_ID) or "").strip()
                if not object_id:
                    continue
                with self._lock:
                    already = self._conn.execute(
                        "SELECT 1 FROM imported WHERE object_id = ?",
                        (object_id,)).fetchone()
                if already:
                    skipped_dup += 1
                    continue
                xml_url = XML_URL_TEMPLATE.format(year=year, object_id=object_id)
                check_url(xml_url)
                xresp = http.get(xml_url, follow_redirects=True)
                if xresp.status_code != 200:
                    logger.warning("irs990: %s -> HTTP %s", xml_url, xresp.status_code)
                    continue
                kept += self.import_filing_xml(
                    xresp.content, xml_url, year=str(year), object_id=object_id)

            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    (cursor_key, str(cursor)))
                self._conn.commit()

        return {
            "year": year,
            "files_processed": processed,
            "officers_kept": kept,
            "already_imported": skipped_dup,
            "cursor": cursor,
            "officers_total": self.count(),
        }


def default_lake() -> Irs990Lake:
    return Irs990Lake()
