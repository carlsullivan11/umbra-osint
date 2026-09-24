"""Bulk parcel ingest — own the roll instead of querying it one name at a time.

`umbra.records.parcels` asks a county layer about a single name. That is the
right shape for a live lookup and useless for building a corpus, which is why
`land_facts` sat at zero for the life of the project while 100 verified ArcGIS
layers went unread.

Probed against the real endpoints on 2026-09-06:

    Hillsborough County FL   367,316 parcels   maxRecordCount 2000   pagination yes
    Ramsey County MN          83,505 parcels   maxRecordCount 2000   pagination yes

184 requests owns a county's entire owner roll, and every ArcGIS FeatureServer
speaks the same dialect — the same insight that made `records.parcels` possible,
applied one level up. So this pages `resultOffset` and writes the result into a
lake Umbra owns.

**These are homes.** Every row is a real person's address and what their county
thinks it is worth. It is public record, published deliberately by the state,
and that is what makes reading it lawful — but lawful is not harmless, and a
name match is still not an identity. `SMITH, JAMES` is thousands of people.

**Coverage is per county and stated.** A name absent from this lake means the
county was never ingested, never that the person owns nothing. `coverage()` is
what lets a caller say which.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: ArcGIS ships the literal string "None" for an empty field. Stored naively it
#: becomes a street address nobody lives at.
_NULLISH = {"", "none", "null", "n/a", "na", "unknown", "<null>"}

DEFAULT_PAGE = 2000
DEFAULT_PAUSE_S = 0.3

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS parcel (
  key TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  owner_canonical TEXT NOT NULL,
  address TEXT,
  city TEXT,
  parcel_id TEXT,
  state TEXT,
  county TEXT,
  layer_url TEXT,
  fetched_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_parcel_owner ON parcel(owner_canonical);
CREATE INDEX IF NOT EXISTS idx_parcel_region ON parcel(state, county);
CREATE TABLE IF NOT EXISTS ingested (
  layer_url TEXT PRIMARY KEY,
  state TEXT,
  county TEXT,
  rows INTEGER,
  reported_total INTEGER,
  capped INTEGER DEFAULT 0,
  -- One layer covering a whole state. `records.coverage._covered_keys` has read
  -- this since it was written; the column did not exist, so `row.get()` always
  -- returned None and the statewide branch could never fire. Florida's cadastral
  -- layer is 67 counties in one FeatureServer and counted as zero.
  statewide INTEGER DEFAULT 0,
  ingested_at TEXT
);
"""


def order_for_sweep(sources: list[dict], ingested: dict | None) -> list[dict]:
    """Registry layers in the order a sweep should page them.

    `ParcelSourceLake.verified()` orders `state, county` and takes `LIMIT n`, so
    asking for three layers returned the same three every run — 195 sources
    verified, 10 ever ingested, and the lake frozen at 408,935 rows since a
    manual run on 2026-09-06. A nightly timer on that ordering would have
    re-paged Alaska every night.

    Priority, in order:

    1. **Never ingested.** A county nobody has collected is worth more than a
       county collected again, and that stays true whatever the caps are.
    2. **Capped before complete.** A layer cut off at 1.4% of 10.8 million rows
       has more to give than one that finished.
    3. **Oldest first.** Owner rolls change; the stalest copy is the one worth
       refreshing.

    With nothing ingested this is the identity, so a first sweep is exactly the
    registry's own order and a reader can predict what it does next.
    """
    state = ingested if isinstance(ingested, dict) else {}
    usable = [s for s in (sources or []) if isinstance(s, dict) and s.get("layer_url")]

    def key(index_and_source: tuple[int, dict]) -> tuple:
        index, source = index_and_source
        row = state.get(source["layer_url"])
        if not row:
            return (0, "", 0, index)
        # `capped` inverted so 1 (more to fetch) sorts ahead of 0.
        return (1, str(row.get("ingested_at") or ""),
                0 if row.get("capped") else 1, index)

    return [s for _i, s in sorted(enumerate(usable), key=key)]


@dataclass(frozen=True, slots=True)
class ParcelSource:
    """One county/state layer and the field names it happens to use."""

    layer_url: str
    state: str | None = None
    county: str | None = None
    owner_field: str = "OWNER"
    address_field: str | None = None
    parcel_field: str | None = None
    city_field: str | None = None
    page: int = DEFAULT_PAGE
    #: One layer covering a whole state — 67 counties, not one.
    statewide: bool = False

    def out_fields(self) -> str:
        # OBJECTID unconditionally. Every ArcGIS FeatureServer exposes one and
        # it is the only per-feature identity guaranteed to exist — without it,
        # a layer whose registry entry has no `parcel_field` has nothing to tell
        # two of one owner's parcels apart, and they collapse into one row.
        wanted = [f for f in ("OBJECTID", self.owner_field, self.address_field,
                              self.parcel_field, self.city_field) if f]
        return ",".join(dict.fromkeys(wanted)) or "*"


@dataclass(frozen=True, slots=True)
class ParcelRow:
    owner: str
    owner_canonical: str
    address: str | None
    city: str | None
    parcel_id: str | None
    state: str | None
    county: str | None
    layer_url: str
    #: ArcGIS per-feature id. The fallback identity when the layer publishes no
    #: parcel number of its own.
    object_id: str | None = None


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text.lower() in _NULLISH else text


def parse_features(features: Any, source: ParcelSource) -> list[ParcelRow]:
    """ArcGIS features -> parcel rows. Never raises; junk is dropped.

    A row with no owner is not a parcel record for our purposes — it is a
    geometry, and this lake is about who a county says holds the title.
    """
    from umbra.people.names import canonical

    out: list[ParcelRow] = []
    for feat in features or []:
        if not isinstance(feat, dict):
            continue
        attrs = feat.get("attributes")
        if not isinstance(attrs, dict):
            continue
        owner = _clean(attrs.get(source.owner_field))
        if not owner:
            continue
        norm = canonical(owner)
        if not norm:
            continue
        out.append(ParcelRow(
            owner=owner,
            owner_canonical=norm,
            address=_clean(attrs.get(source.address_field)) if source.address_field else None,
            city=_clean(attrs.get(source.city_field)) if source.city_field else None,
            parcel_id=_clean(attrs.get(source.parcel_field)) if source.parcel_field else None,
            object_id=_clean(attrs.get("OBJECTID") or attrs.get("objectid")
                             or attrs.get("OBJECTID_1")),
            state=source.state,
            county=source.county,
            layer_url=source.layer_url,
        ))
    return out


def row_key(r: ParcelRow) -> str:
    """Storage identity for one parcel row.

    Layer, then the best per-feature identity available, then the owner. The
    middle term is what broke: it was `parcel_id` alone, and the registry stores
    `parcel_field` as an empty string for layers that publish no parcel number.
    `parcel_id` was then NULL, the key collapsed to `layer|owner`, and every
    parcel a person owned in that county merged into one row — Fairbanks North
    Star Borough wrote 57,839 rows and stored 30,964 of them.

    `OBJECTID` is the fallback because every ArcGIS FeatureServer has one and it
    is stable per feature, so re-paging a layer still updates rather than
    duplicating. The layer's own parcel id stays preferred where it exists: it
    survives the layer being republished with fresh OBJECTIDs, which is the case
    the original key was written for.

    Owner stays in the key, so two owners on one parcel remain two rows.
    """
    identity = r.parcel_id or (f"oid:{r.object_id}" if r.object_id else "")
    return f"{r.layer_url}|{identity}|{r.owner_canonical}"


def default_parcel_path() -> Path:
    env = os.environ.get("UMBRA_PARCEL_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "parcels.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "parcels.sqlite"


class ParcelLake:
    """SQLite index of county parcel owners."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_parcel_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            # Added after the table shipped; ALTER is a no-op on a fresh file.
            try:
                self._conn.execute("ALTER TABLE ingested ADD COLUMN statewide INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass  # already present
            self._conn.commit()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM parcel").fetchone()[0])

    def status(self) -> dict:
        try:
            n = self.count()
            counties = int(self._conn.execute(
                "SELECT COUNT(*) FROM ingested").fetchone()[0])
            newest = self._conn.execute(
                "SELECT ingested_at FROM ingested ORDER BY ingested_at DESC "
                "LIMIT 1").fetchone()
        except sqlite3.Error:
            return {"path": str(self.path), "available": False,
                    "parcels": 0, "counties": 0}
        return {
            "path": str(self.path),
            "available": n > 0,
            "parcels": n,
            "counties": counties,
            "imported_at": newest[0] if newest else None,
        }

    def ingest_state(self) -> dict[str, dict]:
        """What has been paged already, keyed by layer URL.

        `coverage()` answers "which counties are in the lake" and deliberately
        does not carry the URL. The sweep needs the URL, because that is what
        joins the parcel lake to the source registry.
        """
        try:
            rows = self._conn.execute(
                "SELECT layer_url, rows, reported_total, capped, ingested_at "
                "FROM ingested").fetchall()
        except sqlite3.Error:
            return {}
        return {r["layer_url"]: dict(r) for r in rows if r["layer_url"]}

    def set_region(self, layer_url: str, state: str | None,
                   county: str | None, statewide: bool = False) -> int:
        """Attach a region to a layer and every row it produced.

        Rows were stored with NULL state and county when the registry did not
        know one, which left them in the lake and unsearchable by location. The
        region is derivable from the layer afterwards (`records.region`), so
        this backfills rather than requiring a re-page of the county server.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE ingested SET state=?, county=?, statewide=? WHERE layer_url=?",
                (state, county, 1 if statewide else 0, layer_url))
            cur = self._conn.execute(
                "UPDATE parcel SET state=?, county=? WHERE layer_url=?",
                (state, county, layer_url))
            self._conn.commit()
            return int(cur.rowcount or 0)

    def unresolved_layers(self) -> list[dict]:
        """Layers whose region is still unknown, worst first."""
        try:
            rows = self._conn.execute(
                "SELECT layer_url, COUNT(*) AS rows FROM parcel "
                "WHERE state IS NULL OR county IS NULL "
                "GROUP BY layer_url ORDER BY 2 DESC").fetchall()
        except sqlite3.Error:
            return []
        return [dict(r) for r in rows]

    def coverage(self) -> list[dict]:
        """Which counties are ingested, so absence can be explained."""
        try:
            rows = self._conn.execute(
                "SELECT state, county, rows, reported_total, capped, statewide, ingested_at "
                "FROM ingested ORDER BY state, county").fetchall()
        except sqlite3.Error:
            return []
        return [dict(r) for r in rows]

    # --- ingest -----------------------------------------------------------

    def ingest_source(
        self,
        source: ParcelSource,
        *,
        http=None,
        pause_s: float = DEFAULT_PAUSE_S,
        max_rows: int | None = None,
    ) -> dict:
        """Page a layer to completion and store its owners.

        `pause_s` is a courtesy: these are county servers, often a single box
        behind a municipal firewall, and 184 back-to-back requests is rude at
        best. A failed page keeps everything before it — a server that dies at
        page three must not cost pages one and two.
        """
        own_http = http is None
        if own_http:
            from umbra.core.http_guard import GuardedClient
            from umbra.core.config import get_settings

            http = GuardedClient(
                timeout=90.0,
                headers={"User-Agent": get_settings().user_agent},
            )

        query = f"{source.layer_url.rstrip('/')}/query"
        page = max(1, min(int(source.page or DEFAULT_PAGE), 5000))
        rows = 0
        offset = 0
        errors: list[str] = []
        reported_total: int | None = None
        capped = False

        try:
            try:
                resp = http.get(query, params={
                    "where": "1=1", "returnCountOnly": "true", "f": "json"})
                reported_total = int((resp.json() or {}).get("count") or 0) or None
            except Exception as exc:  # noqa: BLE001
                errors.append(f"count: {exc}")

            while True:
                if max_rows is not None and rows >= max_rows:
                    capped = True
                    break
                try:
                    resp = http.get(query, params={
                        "where": "1=1",
                        "outFields": source.out_fields(),
                        "returnGeometry": "false",
                        "resultOffset": str(offset),
                        "resultRecordCount": str(page),
                        "f": "json",
                    })
                    payload = resp.json() or {}
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"offset {offset}: {exc}")
                    break

                if payload.get("error"):
                    errors.append(f"offset {offset}: {payload['error']}")
                    break

                features = payload.get("features") or []
                if not features:
                    break

                parsed = parse_features(features, source)
                if max_rows is not None:
                    parsed = parsed[: max(0, max_rows - rows)]
                self._write(parsed)
                rows += len(parsed)
                offset += len(features)

                if len(features) < page:
                    break
                if pause_s:
                    time.sleep(pause_s)

            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO ingested (layer_url, state, county, "
                    "rows, reported_total, capped, statewide, ingested_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (source.layer_url, source.state, source.county, rows,
                     reported_total, 1 if capped else 0,
                     1 if getattr(source, "statewide", False) else 0,
                     datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")),
                )
                self._conn.commit()
        finally:
            if own_http:
                http.close()

        note = f"{rows:,} owner record(s) from {source.county or source.layer_url}"
        if capped and reported_total:
            # Never a silent cap: a partial county read as a whole one would
            # make an absent owner look like a person with no property.
            note += f" — capped, the layer reports {reported_total:,}"
        elif reported_total:
            note += f" of {reported_total:,} reported"
        if errors:
            note += f"; {len(errors)} page error(s)"

        return {
            "rows": rows,
            "reported_total": reported_total,
            "capped": capped,
            "errors": errors[:5],
            "error_count": len(errors),
            "note": note,
        }

    def _write(self, rows: list[ParcelRow]) -> None:
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT OR REPLACE INTO parcel (key, owner, owner_canonical, "
                "address, city, parcel_id, state, county, layer_url, fetched_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                [
                    (
                        row_key(r),
                        r.owner, r.owner_canonical, r.address, r.city,
                        r.parcel_id, r.state, r.county, r.layer_url,
                        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    )
                    for r in rows
                ],
            )
            self._conn.commit()

    # --- lookup -----------------------------------------------------------

    def lookup(self, name: str, *, state: str | None = None,
               limit: int = 25) -> list[dict]:
        """Parcels whose owner name matches. Never raises."""
        from umbra.people.names import canonical

        norm = canonical(name)
        if not norm:
            return []
        sql = "SELECT * FROM parcel WHERE owner_canonical = ?"
        args: list[Any] = [norm]
        if state:
            sql += " AND state = ?"
            args.append(state.strip().upper())
        sql += " LIMIT ?"
        args.append(max(1, int(limit)))
        try:
            return [dict(r) for r in self._conn.execute(sql, args).fetchall()]
        except sqlite3.Error:
            return []


def default_lake() -> ParcelLake:
    return ParcelLake()
