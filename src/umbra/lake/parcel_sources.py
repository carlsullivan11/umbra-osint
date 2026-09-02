"""Owned registry of verified county parcel layers.

`umbra.records.parcels` shipped with five hand-added statewide layers. Five
states is five states, and the honest note saying so was doing a lot of work.

The catalog behind ArcGIS Online lists ~10,000 public "parcels" feature
services. That number is not coverage — a first pass found roughly **30% of
candidates actually expose a queryable owner-name field**, and several fields
whose *name* looked right (`TaxPayerAddr1`, `OWNERLAB`) hold addresses and map
labels rather than owner names. A catalog entry is a claim. This table only
stores claims Umbra has tested itself:

    - the layer answered a real owner query
    - the values that came back look like names, not house numbers
    - the state and county came from the FCC census-area lookup, not a guess

That is why this is a lake table and not a constant in the source file. It is
evidence with a date on it, and `verified_at` is what lets a later run notice
that a county reorganised its GIS and the layer went away.

Geography is stored as `state`/`county_fips` **or left NULL**. A parcel row
attributed to the wrong state is worse than one attributed to nowhere, so an
unresolved extent stays unresolved rather than being approximated from a
bounding box.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS parcel_sources (
  layer_url     TEXT PRIMARY KEY,
  item_id       TEXT,
  title         TEXT,
  org           TEXT,
  owner_field   TEXT NOT NULL,
  address_field TEXT,
  city_field    TEXT,
  parcel_field  TEXT,
  value_field   TEXT,
  state         TEXT,
  county        TEXT,
  county_fips   TEXT,
  page          INTEGER NOT NULL DEFAULT 200,
  -- Sample owner values kept as the evidence this was verified, not guessed.
  sample        TEXT,
  status        TEXT NOT NULL,
  detail        TEXT,
  verified_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_parcel_src_state ON parcel_sources(state);
CREATE INDEX IF NOT EXISTS idx_parcel_src_status ON parcel_sources(status);
CREATE TABLE IF NOT EXISTS parcel_seen (
  item_id   TEXT PRIMARY KEY,
  seen_at   TEXT NOT NULL,
  outcome   TEXT NOT NULL
);
"""


def default_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "parcel_sources.sqlite"


class ParcelSourceLake:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @classmethod
    def from_settings(cls, settings) -> "ParcelSourceLake":
        return cls(default_path(getattr(settings, "data_dir", None)))

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(SCHEMA)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def available(self) -> bool:
        return self.path.is_file()

    # -- writes ------------------------------------------------------------

    def record(self, source: dict[str, Any]) -> None:
        conn = self.connect()
        cols = ("layer_url", "item_id", "title", "org", "owner_field",
                "address_field", "city_field", "parcel_field", "value_field",
                "state", "county", "county_fips", "page", "sample", "status",
                "detail")
        row = [source.get(c) for c in cols]
        # An explicit NULL beats a column DEFAULT in SQLite, so a rejected row
        # (which has no page size) has to be coerced rather than left absent.
        if row[cols.index("page")] is None:
            row[cols.index("page")] = 200
        if isinstance(row[cols.index("sample")], (list, tuple)):
            row[cols.index("sample")] = json.dumps(list(row[cols.index("sample")])[:5])
        row.append(datetime.now(tz=timezone.utc).isoformat())
        placeholders = ",".join("?" * (len(cols) + 1))
        updates = ",".join(f"{c}=excluded.{c}" for c in cols[1:]) + ",verified_at=excluded.verified_at"
        with self._lock, conn:
            conn.execute(
                f"INSERT INTO parcel_sources({','.join(cols)},verified_at) "
                f"VALUES({placeholders}) "
                f"ON CONFLICT(layer_url) DO UPDATE SET {updates}",
                row,
            )

    def mark_seen(self, item_id: str, outcome: str) -> None:
        """Remember a probed catalog item so the next run advances instead of
        re-probing the same 60 services forever."""
        conn = self.connect()
        with self._lock, conn:
            conn.execute(
                "INSERT INTO parcel_seen(item_id, seen_at, outcome) VALUES(?,?,?) "
                "ON CONFLICT(item_id) DO UPDATE SET seen_at=excluded.seen_at, "
                "outcome=excluded.outcome",
                (item_id, datetime.now(tz=timezone.utc).isoformat(), outcome),
            )

    def already_seen(self) -> set[str]:
        if not self.path.is_file():
            return set()
        return {r["item_id"] for r in
                self.connect().execute("SELECT item_id FROM parcel_seen")}

    # -- reads -------------------------------------------------------------

    def verified(self, state: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        sql = "SELECT * FROM parcel_sources WHERE status='verified'"
        args: list[Any] = []
        if state:
            sql += " AND state=?"
            args.append(state.upper())
        sql += " ORDER BY state, county LIMIT ?"
        args.append(limit)
        return [dict(r) for r in self.connect().execute(sql, args)]

    def states(self) -> list[str]:
        """States the registry can actually search — derived, never asserted."""
        if not self.path.is_file():
            return []
        rows = self.connect().execute(
            "SELECT DISTINCT state FROM parcel_sources "
            "WHERE status='verified' AND state IS NOT NULL ORDER BY state")
        return [r["state"] for r in rows]

    def status(self) -> dict[str, Any]:
        """Counts, and when the sweep last ran.

        Zero rows means *never synced*, which is not the same as "nothing to
        find" — the caller has to be able to tell those apart.
        """
        if not self.path.is_file():
            return {"synced": False, "verified": 0, "rejected": 0, "states": 0,
                    "counties": 0, "probed": 0, "verified_at": None}
        conn = self.connect()
        by_status = {r["status"]: r["n"] for r in conn.execute(
            "SELECT status, COUNT(*) n FROM parcel_sources GROUP BY status")}
        counties = conn.execute(
            "SELECT COUNT(DISTINCT county_fips) n FROM parcel_sources "
            "WHERE status='verified' AND county_fips IS NOT NULL").fetchone()["n"]
        newest = conn.execute(
            "SELECT MAX(verified_at) t FROM parcel_sources").fetchone()["t"]
        probed = conn.execute("SELECT COUNT(*) n FROM parcel_seen").fetchone()["n"]
        return {
            "synced": bool(by_status),
            "verified": by_status.get("verified", 0),
            "rejected": by_status.get("rejected", 0),
            "states": len(self.states()),
            "counties": counties,
            "probed": probed,
            "verified_at": newest,
        }
