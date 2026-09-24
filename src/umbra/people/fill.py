"""Keep the bulk people lakes filled — a bounded, resumable run for a timer.

`/people` already searches every lake (Wikidata people, FEC contributors,
NPPES clinicians, FCC ULS licensees, IRS 990 officers, parcels). What it was
short of was rows: the four bulk lakes filled only when someone downloaded a
file by hand, so most of them sat at whatever the last manual import left.
Only the Wikidata harvest ran on a timer, at 400 people a night.

One `run_fill()` does at most one unit of work per source and is safe to call
on a schedule:

**FEC** — one *closed* election cycle per run, newest first, never the cycle
in progress. The FEC lake aggregates contributions with an UPSERT keyed on the
member CRC, and the current cycle's file is republished weekly with a new CRC;
importing it on a timer would add every contribution again each week. A closed
cycle is imported once, identified by filename, and never re-fetched.

**NPPES** — the current monthly full file. Its URL changes every month and is
*read* from the CMS index page, never constructed: a link that does not match
the documented monthly name is a failure, not a guess. Providers upsert on NPI,
so the monthly refresh replaces rather than duplicates.

**ULS** — the complete weekly file for each configured radio service (default:
amateur, the service licensed to individuals). Licenses upsert on the FCC's
unique system identifier. Refreshed at most every `ULS_REFRESH_DAYS`.

**IRS 990** — advances the per-year cursor for the latest filing years by a
bounded number of filings.

Every download goes through `guarded_download`, which re-checks the egress
guard on each redirect hop (a plain `httpx` stream with `follow_redirects=True`
does not), refuses to start when the disk is short, and deletes the archive
once it is imported. A source that fails is reported and the others still run.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urljoin

import httpx

from umbra.core.http_guard import check_url

logger = logging.getLogger(__name__)

SOURCES = ("fec", "nppes", "uls", "990")

#: Oldest FEC cycle a fill will reach back to. Older donor addresses are mostly
#: stale, and each cycle is a ~4 GB download.
FEC_OLDEST_CYCLE = int(os.environ.get("UMBRA_FILL_FEC_OLDEST", "2012"))

#: The monthly full-replacement file, e.g.
#: `NPPES_Data_Dissemination_September_2026.zip` (CMS sometimes appends `_V2`).
#: Weekly incrementals and deactivation files have other names and are ignored.
NPPES_MONTHLY_RE = re.compile(
    r"NPPES_Data_Dissemination_(January|February|March|April|May|June|July|"
    r"August|September|October|November|December)_(\d{4})(?:_V\d+)?\.zip$",
    re.I,
)
_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+\.zip)["']""", re.I)

ULS_COMPLETE_URL = "https://data.fcc.gov/download/pub/uls/complete/{service}.zip"
#: `l_amat` is the amateur service: licensed to individuals by name, which is
#: what a people lake is for. Other services are mostly companies.
ULS_DEFAULT_SERVICES = ("l_amat",)
ULS_REFRESH_DAYS = 28

IRS990_FILES_PER_YEAR = int(os.environ.get("UMBRA_FILL_990_FILES", "200"))

#: Minimum free space to start a download, on top of the file's own size. The
#: FEC member expands past 30 GB, but it is streamed; what grows is the lake.
MIN_FREE_GB = float(os.environ.get("UMBRA_FILL_MIN_FREE_GB", "15"))

_CHUNK = 1024 * 512


class FillError(RuntimeError):
    """One source could not do its unit of work; the reason is the message."""


@dataclass
class SourceOutcome:
    source: str
    status: str  # imported | skipped | failed
    detail: str = ""
    stats: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"source": self.source, "status": self.status,
                "detail": self.detail, "stats": self.stats}


# --- downloads ---------------------------------------------------------------

def free_gb(path: Path) -> float:
    path.mkdir(parents=True, exist_ok=True)
    return shutil.disk_usage(path).free / 1e9


def guarded_download(http: httpx.Client, url: str, dest: Path, *,
                     max_redirects: int = 5, min_free_gb: float = MIN_FREE_GB,
                     disk_free: Callable[[Path], float] = free_gb) -> Path:
    """Stream `url` to `dest`, validating every hop against the egress guard.

    `httpx.Client.stream` goes through `send`, not `request`, so
    `GuardedClient`'s per-hop check never sees a redirect there. This follows
    redirects itself and calls `check_url` before each connection.
    """
    current = url
    for _ in range(max_redirects + 1):
        check_url(current)
        with http.stream("GET", current, follow_redirects=False) as resp:
            if resp.is_redirect and resp.headers.get("location"):
                current = urljoin(current, resp.headers["location"])
                continue
            resp.raise_for_status()
            size = int(resp.headers.get("content-length") or 0) / 1e9
            have = disk_free(dest.parent)
            if have < size + min_free_gb:
                raise FillError(
                    f"not enough disk for {dest.name}: {have:.1f} GB free, need "
                    f"{size:.1f} GB + {min_free_gb:.0f} GB headroom")
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("wb") as out:
                for chunk in resp.iter_bytes(chunk_size=_CHUNK):
                    out.write(chunk)
            return dest
    raise FillError(f"too many redirects fetching {url}")


def _fetch_text(http: httpx.Client, url: str, *, max_redirects: int = 5) -> str:
    current = url
    for _ in range(max_redirects + 1):
        check_url(current)
        resp = http.get(current, follow_redirects=False)
        if resp.is_redirect and resp.headers.get("location"):
            current = urljoin(current, resp.headers["location"])
            continue
        resp.raise_for_status()
        return resp.text
    raise FillError(f"too many redirects fetching {url}")


# --- source selection ----------------------------------------------------------

def current_fec_cycle(today: date | None = None) -> int:
    """The two-year cycle still open: an even year, this one or next."""
    year = (today or date.today()).year
    return year if year % 2 == 0 else year + 1


def closed_fec_cycles(today: date | None = None,
                      oldest: int = FEC_OLDEST_CYCLE) -> list[int]:
    """Closed cycles, newest first."""
    return list(range(current_fec_cycle(today) - 2, oldest - 1, -2))


def fec_filename(cycle: int) -> str:
    return f"indiv{str(cycle)[2:]}.zip"


def next_fec_cycle(imported_files: Iterable[str], today: date | None = None,
                   oldest: int = FEC_OLDEST_CYCLE) -> int | None:
    have = {f.lower() for f in imported_files}
    for cycle in closed_fec_cycles(today, oldest):
        if fec_filename(cycle) not in have:
            return cycle
    return None


def pick_nppes_monthly(index_html: str, base_url: str) -> str:
    """The newest monthly full-file link on the CMS index page.

    Raises when there is none: the page's layout changing is a reason to stop
    and look, not to build a URL from a pattern.
    """
    months = {m: i for i, m in enumerate(
        ("january", "february", "march", "april", "may", "june", "july",
         "august", "september", "october", "november", "december"), start=1)}
    best: tuple[tuple[int, int, str], str] | None = None
    for href in _HREF_RE.findall(index_html or ""):
        name = href.rsplit("/", 1)[-1]
        m = NPPES_MONTHLY_RE.search(name)
        if not m:
            continue
        key = (int(m.group(2)), months[m.group(1).lower()], name.lower())
        if best is None or key > best[0]:
            best = (key, urljoin(base_url, href))
    if best is None:
        raise FillError(
            "no monthly NPPES_Data_Dissemination_<Month>_<Year>.zip link on the "
            "CMS index page — the page may have changed; not guessing a URL")
    return best[1]


def _stale(imported_at: str | None, days: int, now: datetime | None = None) -> bool:
    if not imported_at:
        return True
    try:
        when = datetime.strptime(imported_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return (now or datetime.now(timezone.utc)) - when >= timedelta(days=days)


# --- the run ---------------------------------------------------------------------

def _fill_fec(http, work: Path, lake_factory, today) -> SourceOutcome:
    from umbra.lake.fec import BULK_URL

    lake = lake_factory()
    try:
        files = [f["filename"] for f in lake.status().get("files", [])]
        cycle = next_fec_cycle(files, today)
        if cycle is None:
            return SourceOutcome("fec", "skipped", "every closed cycle is imported")
        dest = work / fec_filename(cycle)
        guarded_download(http, BULK_URL.format(cycle=cycle, yy=str(cycle)[2:]), dest)
        try:
            stats = lake.import_zip(dest)
        finally:
            dest.unlink(missing_ok=True)
        return SourceOutcome("fec", "imported", f"cycle {cycle}", stats)
    finally:
        lake.close()


def _fill_nppes(http, work: Path, lake_factory) -> SourceOutcome:
    from umbra.lake.nppes import NPI_FILES_URL

    url = pick_nppes_monthly(_fetch_text(http, NPI_FILES_URL), NPI_FILES_URL)
    name = url.rsplit("/", 1)[-1]
    lake = lake_factory()
    try:
        # The lake records the archive name it imported, so a month already
        # done is skipped before 1 GB is fetched only to be CRC-deduplicated.
        if name.lower() in {f["filename"].lower() for f in lake.status().get("files", [])}:
            return SourceOutcome("nppes", "skipped", f"{name} already imported")
        dest = work / name
        guarded_download(http, url, dest)
        try:
            stats = lake.import_zip(dest)
        finally:
            dest.unlink(missing_ok=True)
        return SourceOutcome("nppes", "imported", name, stats)
    finally:
        lake.close()


def _fill_uls(http, work: Path, lake_factory, services: Iterable[str]) -> SourceOutcome:
    lake = lake_factory()
    try:
        # `files` is newest first; keep the first (newest) import per archive.
        last: dict[str, str] = {}
        for f in lake.status().get("files", []):
            last.setdefault(f["filename"], f["imported_at"])
        done: list[str] = []
        stats: dict[str, Any] = {}
        for service in services:
            fname = f"{service}.zip"
            if not _stale(last.get(fname), ULS_REFRESH_DAYS):
                continue
            dest = work / fname
            guarded_download(http, ULS_COMPLETE_URL.format(service=service), dest)
            try:
                stats[service] = lake.import_zip(dest)
            finally:
                dest.unlink(missing_ok=True)
            done.append(service)
        if not done:
            return SourceOutcome("uls", "skipped",
                                 f"refreshed within {ULS_REFRESH_DAYS} days")
        return SourceOutcome("uls", "imported", ", ".join(done), stats)
    finally:
        lake.close()


def _fill_990(lake_factory, today: date, files_per_year: int) -> SourceOutcome:
    lake = lake_factory()
    try:
        stats = {}
        for year in (today.year, today.year - 1):
            try:
                stats[year] = lake.import_year(year, max_files=files_per_year)
            except Exception as exc:  # noqa: BLE001 - a year not yet published
                stats[year] = {"error": str(exc)[:200]}
        kept = sum(s.get("officers_kept", 0) for s in stats.values())
        return SourceOutcome("990", "imported" if kept else "skipped",
                             f"{kept} officers kept", stats)
    finally:
        lake.close()


def run_fill(*, only: Iterable[str] | None = None, http: httpx.Client | None = None,
             work_dir: Path | None = None, today: date | None = None,
             lakes: dict[str, Callable[[], Any]] | None = None,
             uls_services: Iterable[str] = ULS_DEFAULT_SERVICES,
             files_per_year: int = IRS990_FILES_PER_YEAR) -> list[SourceOutcome]:
    """One bounded fill pass. Never raises; each source reports its outcome."""
    wanted = [s for s in SOURCES if not only or s in set(only)]
    today = today or date.today()

    if work_dir is None:
        from umbra.core.config import get_settings

        work_dir = Path(get_settings().data_dir) / "tmp" / "people-fill"
    work_dir.mkdir(parents=True, exist_ok=True)

    if lakes is None:
        from umbra.lake.fec import FecLake
        from umbra.lake.irs990 import Irs990Lake
        from umbra.lake.nppes import NppesLake
        from umbra.lake.uls import UlsLake

        lakes = {"fec": FecLake, "nppes": NppesLake, "uls": UlsLake, "990": Irs990Lake}

    own_http = http is None
    if own_http:
        from umbra.core.config import get_settings
        from umbra.core.http_guard import GuardedClient

        http = GuardedClient(timeout=httpx.Timeout(60.0, read=600.0),
                             headers={"User-Agent": get_settings().user_agent})
    out: list[SourceOutcome] = []
    try:
        for source in wanted:
            try:
                if source == "fec":
                    res = _fill_fec(http, work_dir, lakes["fec"], today)
                elif source == "nppes":
                    res = _fill_nppes(http, work_dir, lakes["nppes"])
                elif source == "uls":
                    res = _fill_uls(http, work_dir, lakes["uls"], uls_services)
                else:
                    res = _fill_990(lakes["990"], today, files_per_year)
            except Exception as exc:  # noqa: BLE001 - one source must not stop the rest
                logger.warning("people fill: %s failed", source, exc_info=True)
                res = SourceOutcome(source, "failed", f"{type(exc).__name__}: {exc}"[:300])
            out.append(res)
    finally:
        if own_http:
            http.close()
    return out
