"""Bounded RF lake — OSM cameras + WiGLE hits + operator surveys.

Path: ``$UMBRA_DATA_DIR/lake/rf.sqlite``

Not a WiGLE/OpenWifiMap mirror. Daily sync queries Nominatim + Overpass for
a small list of cities Umbra already cares about (NWA + Bay + SD).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_OVERPASS = "https://overpass-api.de/api/interpreter"
_OVERPASS_STATUS = "https://overpass-api.de/api/status"
_NOMINATIM = "https://nominatim.openstreetmap.org/search"

# Overpass does not rate-limit by requests-per-second. It grants **slots** per
# client IP — `/api/status` reports "Rate limit: 2" and either "2 slots
# available now." or "Slot available after: <iso>, in N seconds." Exceed them
# and you get 429; hit a busy server and you get 504. Both are transient and
# both mean "come back shortly", which is exactly what the old code did not do:
# it fired fourteen regions back to back with a 1.1s pause tuned for
# Nominatim's policy, then dropped any region that came back 429 or 504.
#
# A fallback endpoint, used only after the primary has refused. kumi.systems
# runs a high-capacity public instance for exactly this. Politeness order
# matters: we exhaust waiting on the main instance before spending someone
# else's capacity.
_OVERPASS_MIRRORS = [
    ("https://overpass-api.de/api/interpreter", "https://overpass-api.de/api/status"),
    ("https://overpass.kumi.systems/api/interpreter", "https://overpass.kumi.systems/api/status"),
]

#: Never wait longer than this for a slot before moving on — a daily cron may
#: not sit for ten minutes on one city.
_MAX_SLOT_WAIT_S = 180.0
_MAX_ATTEMPTS = 3

# County packs Carl actually uses — not the planet.
DEFAULT_REGIONS = [
    "Bentonville, AR",
    "Rogers, AR",
    "Fayetteville, AR",
    "Springdale, AR",
    "Oakland, CA",
    "Berkeley, CA",
    "Alameda, CA",
    "Albany, CA",
    "San Francisco, CA",
    "San Mateo, CA",
    "San Jose, CA",
    "San Diego, CA",
    "Pacifica, CA",
    "El Cerrito, CA",
]

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cameras (
  id TEXT PRIMARY KEY,
  osm_id INTEGER,
  lat REAL NOT NULL,
  lon REAL NOT NULL,
  label TEXT,
  region TEXT,
  tags_json TEXT,
  source TEXT NOT NULL DEFAULT 'osm_overpass',
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cam_region ON cameras(region);
CREATE INDEX IF NOT EXISTS idx_cam_latlon ON cameras(lat, lon);
CREATE TABLE IF NOT EXISTS region_sync (
  region TEXT PRIMARY KEY,
  status TEXT NOT NULL,          -- ok | failed
  detail TEXT,
  cameras INTEGER NOT NULL DEFAULT 0,
  capped INTEGER NOT NULL DEFAULT 0,
  checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS geocode (
  q TEXT PRIMARY KEY,
  lat REAL NOT NULL,
  lon REAL NOT NULL,
  fetched_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wigle_hits (
  id TEXT PRIMARY KEY,
  bssid TEXT NOT NULL,
  ssid TEXT,
  lat REAL,
  lon REAL,
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wigle_bssid ON wigle_hits(bssid);
CREATE TABLE IF NOT EXISTS survey_aps (
  id TEXT PRIMARY KEY,
  bssid TEXT,
  ssid TEXT,
  lat REAL,
  lon REAL,
  fetched_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return f"rf_{h}"


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def default_path(settings=None) -> Path:
    if settings is None:
        from umbra.core.config import get_settings

        settings = get_settings()
    root = Path(getattr(settings, "data_dir", Path.home() / "umbra" / "data"))
    p = root / "lake"
    p.mkdir(parents=True, exist_ok=True)
    return p / "rf.sqlite"


@dataclass
class RfLakeStatus:
    path: str
    cameras: int
    wigle_hits: int
    survey_aps: int
    last_sync: str | None
    synced: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "cameras": self.cameras,
            "wigle_hits": self.wigle_hits,
            "survey_aps": self.survey_aps,
            "last_sync": self.last_sync,
            "synced": self.synced,
        }


class RfLake:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    @classmethod
    def from_settings(cls, settings) -> "RfLake":
        return cls(default_path(settings))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def status(self) -> RfLakeStatus:
        with self._lock:
            cam = self._conn.execute("SELECT COUNT(*) FROM cameras").fetchone()[0]
            wig = self._conn.execute("SELECT COUNT(*) FROM wigle_hits").fetchone()[0]
            sur = self._conn.execute("SELECT COUNT(*) FROM survey_aps").fetchone()[0]
            last = self._conn.execute(
                "SELECT value FROM meta WHERE key='last_sync'"
            ).fetchone()
        return RfLakeStatus(
            path=str(self.path),
            cameras=cam,
            wigle_hits=wig,
            survey_aps=sur,
            last_sync=last[0] if last else None,
            synced=cam > 0 or wig > 0 or sur > 0,
        )

    def cameras_for_region(self, region: str, limit: int = 40) -> list[dict[str, Any]]:
        blob = f"%{(region or '').strip()}%"
        if blob == "%%":
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM cameras
                WHERE region LIKE ? OR label LIKE ?
                ORDER BY fetched_at DESC LIMIT ?
                """,
                (blob, blob, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def geocode_get(self, query: str) -> tuple[float, float] | None:
        q = (query or "").strip().lower()
        if len(q) < 3:
            return None
        with self._lock:
            row = self._conn.execute("SELECT lat, lon FROM geocode WHERE q = ?", (q,)).fetchone()
        if not row:
            return None
        return float(row[0]), float(row[1])

    def geocode_put(self, query: str, lat: float, lon: float) -> None:
        q = (query or "").strip().lower()
        if len(q) < 3:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO geocode (q, lat, lon, fetched_at) VALUES (?,?,?,?)
                ON CONFLICT(q) DO UPDATE SET lat=excluded.lat, lon=excluded.lon, fetched_at=excluded.fetched_at
                """,
                (q, lat, lon, _now()),
            )
            self._conn.commit()

    def cameras_near(self, lat: float, lon: float, *, km: float = 6.0, limit: int = 8) -> list[dict[str, Any]]:
        """Haversine join — string region match misses Cupertino vs San Jose cameras."""
        try:
            lat_f, lon_f = float(lat), float(lon)
        except (TypeError, ValueError):
            return []
        dlat = km / 111.0
        dlon = km / max(0.2, 111.0 * abs(math.cos(math.radians(lat_f))))
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM cameras
                WHERE lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?
                LIMIT 80
                """,
                (lat_f - dlat, lat_f + dlat, lon_f - dlon, lon_f + dlon),
            ).fetchall()
        scored: list[tuple[float, dict[str, Any]]] = []
        for r in rows:
            d = _haversine_km(lat_f, lon_f, float(r["lat"]), float(r["lon"]))
            if d <= km:
                rec = dict(r)
                rec["distance_km"] = round(d, 2)
                scored.append((d, rec))
        scored.sort(key=lambda x: x[0])
        return [rec for _, rec in scored[:limit]]

    def backfill_geocode_from_cameras(self) -> int:
        """Centroid of stored cameras per region — no extra Nominatim."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT region, AVG(lat), AVG(lon) FROM cameras WHERE region IS NOT NULL GROUP BY region"
            ).fetchall()
        n = 0
        for region, lat, lon in rows:
            if region and lat is not None:
                self.geocode_put(str(region), float(lat), float(lon))
                n += 1
        return n

    def wigle_for_bssid(self, bssid: str) -> dict[str, Any] | None:
        key = (bssid or "").replace("-", ":").upper()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM wigle_hits WHERE bssid = ? ORDER BY fetched_at DESC LIMIT 1",
                (key,),
            ).fetchone()
        return dict(row) if row else None

    def upsert_camera(
        self,
        *,
        osm_id: int | None,
        lat: float,
        lon: float,
        label: str | None,
        region: str,
        tags: dict | None = None,
    ) -> str:
        cid = _id("cam", str(osm_id or ""), f"{lat:.5f}", f"{lon:.5f}")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO cameras (id, osm_id, lat, lon, label, region, tags_json, source, fetched_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  label=COALESCE(excluded.label, cameras.label),
                  fetched_at=excluded.fetched_at
                """,
                (
                    cid,
                    osm_id,
                    lat,
                    lon,
                    label,
                    region,
                    json.dumps(tags or {})[:2000],
                    "osm_overpass",
                    _now(),
                ),
            )
            self._conn.commit()
        return cid

    def upsert_wigle(
        self,
        *,
        bssid: str,
        ssid: str | None = None,
        lat: float | None = None,
        lon: float | None = None,
    ) -> str:
        key = bssid.replace("-", ":").upper()
        wid = _id("wigle", key)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO wigle_hits (id, bssid, ssid, lat, lon, fetched_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  ssid=COALESCE(excluded.ssid, wigle_hits.ssid),
                  lat=COALESCE(excluded.lat, wigle_hits.lat),
                  lon=COALESCE(excluded.lon, wigle_hits.lon),
                  fetched_at=excluded.fetched_at
                """,
                (wid, key, ssid, lat, lon, _now()),
            )
            self._conn.commit()
        return wid

    def upsert_survey(self, *, bssid: str | None, ssid: str | None, lat: float | None, lon: float | None) -> str:
        sid = _id("survey", bssid or "", ssid or "", str(lat), str(lon))
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO survey_aps (id, bssid, ssid, lat, lon, fetched_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET fetched_at=excluded.fetched_at
                """,
                (sid, bssid, ssid, lat, lon, _now()),
            )
            self._conn.commit()
        return sid

    def mark_region(
        self,
        region: str,
        status: str,
        detail: str | None,
        *,
        cameras: int = 0,
        capped: bool = False,
    ) -> None:
        """Record that a region was checked, or that checking it failed.

        Without this the lake only holds what was *found*, so a region that
        429'd is indistinguishable from a region with nothing in it — the same
        "unchecked is not clean" trap the collectors are careful about.
        """
        with self._lock:
            self._conn.execute(
                "INSERT INTO region_sync(region,status,detail,cameras,capped,checked_at) "
                "VALUES(?,?,?,?,?,?) ON CONFLICT(region) DO UPDATE SET "
                "status=excluded.status, detail=excluded.detail, cameras=excluded.cameras, "
                "capped=excluded.capped, checked_at=excluded.checked_at",
                (region, status, detail, int(cameras), 1 if capped else 0, _now()),
            )
            self._conn.commit()

    def region_status(self, region: str) -> dict | None:
        """What we know about a region's last sync, or None if never attempted."""
        with self._lock:
            row = self._conn.execute(
                "SELECT region,status,detail,cameras,capped,checked_at FROM region_sync WHERE region=?",
                (region,),
            ).fetchone()
        return dict(row) if row else None

    def stale_regions(self) -> list[dict]:
        """Regions whose last attempt failed — the coverage gaps."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT region,status,detail,checked_at FROM region_sync "
                "WHERE status!='ok' ORDER BY region"
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_synced(self) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key,value) VALUES('last_sync',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (_now(),),
            )
            self._conn.commit()




# --- Overpass, politely -----------------------------------------------------

def _slot_wait_seconds(http, status_url: str, headers: dict, timeout: float) -> float:
    """Seconds until this client has an Overpass slot. 0 means now.

    `/api/status` is plain text:

        Rate limit: 2
        2 slots available now.

    or, when exhausted:

        Slot available after: 2026-08-30T15:55:00Z, in 47 seconds.

    Unreadable status is treated as "go ahead" — the request itself will say
    429 if we are wrong, and that path is handled. Refusing to query because we
    could not parse a status page would turn a cosmetic problem into an outage.
    """
    try:
        r = http.get(status_url, headers=headers, timeout=min(timeout, 10))
        if r.status_code >= 400:
            return 0.0
        text = r.text or ""
    except Exception:  # noqa: BLE001
        return 0.0

    if re.search(r"\bslots? available now", text, re.I):
        return 0.0
    waits = [int(m) for m in re.findall(r"in (\d+) seconds", text)]
    return float(min(waits)) if waits else 0.0


def _overpass_fetch(
    http, query: str, *, headers: dict, timeout: float, sleep=None
) -> tuple[dict | None, str | None]:
    """Run one Overpass query, waiting for a slot and retrying transients.

    Returns `(payload, None)` or `(None, reason)`. The reason is a sentence,
    because it ends up in the sync report and in the lake — a region that could
    not be checked must never be mistaken for a region with no cameras.
    """
    # Resolved at call time, not bound as a default: a default of `time.sleep`
    # captures the function object at import, so monkeypatching the module's
    # sleep in a test does nothing and the suite really waits out the backoff.
    sleep = sleep or time.sleep
    last = "no attempt made"
    for endpoint, status_url in _OVERPASS_MIRRORS:
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            wait = _slot_wait_seconds(http, status_url, headers, timeout)
            if wait > _MAX_SLOT_WAIT_S:
                last = f"no Overpass slot for {wait:.0f}s at {_host(endpoint)}"
                break  # try the mirror rather than sit here
            if wait:
                sleep(wait + 1.0)

            try:
                resp = http.post(
                    endpoint,
                    content=query.encode(),
                    headers={**headers, "Content-Type": "text/plain"},
                    timeout=timeout,
                )
            except Exception as exc:  # noqa: BLE001
                last = f"{type(exc).__name__} from {_host(endpoint)}"
                sleep(min(2 ** attempt, 30))
                continue

            if resp.status_code == 200:
                try:
                    return resp.json(), None
                except Exception:  # noqa: BLE001
                    last = f"{_host(endpoint)} returned 200 with a body that is not JSON"
                    break

            # 429 = slots exhausted, 504 = server busy, 502/503 = restarting.
            # All transient, all "come back shortly".
            if resp.status_code in (429, 502, 503, 504):
                retry_after = resp.headers.get("Retry-After")
                delay = None
                if retry_after and str(retry_after).strip().isdigit():
                    delay = float(retry_after)
                if delay is None:
                    slot = _slot_wait_seconds(http, status_url, headers, timeout)
                    delay = slot if slot else min(2 ** attempt, 30)
                last = f"HTTP {resp.status_code} from {_host(endpoint)}"
                if attempt < _MAX_ATTEMPTS and delay <= _MAX_SLOT_WAIT_S:
                    sleep(delay + 1.0)
                    continue
                break

            # Anything else is our problem (a 400 is a malformed query), and
            # retrying an identical request will not fix it.
            return None, f"HTTP {resp.status_code} from {_host(endpoint)}"

    return None, last


def _host(url: str) -> str:
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1) if m else url


def sync_regions(
    http,
    *,
    lake: RfLake,
    regions: list[str] | None = None,
    user_agent: str = "UmbraOSINT/0.2 (https://umbra-osint.com; security@umbra-osint.com)",
    timeout: float = 20,
    pause_s: float = 1.1,
    around_m: int = 4000,
    # 25 truncated seven of fourteen cities on the first honest run — the Bay
    # Area packs have well over that many mapped cameras each, and the lake had
    # been quietly storing a quarter of them. `out body N` is a server-side
    # limit on a 4km radius query, so a larger N costs Overpass very little.
    max_per_region: int = 200,
    sleep=None,
) -> dict[str, Any]:
    """Nominatim + Overpass for each city. Bounded. Stores cameras only.

    Every region ends in `region_sync` with `ok` or `failed`. That table is the
    difference between "we looked at Berkeley and there are no cameras" and "we
    never got to look at Berkeley" — before it existed, a 429 left the lake with
    no Berkeley rows, which reads identically to an answer.
    """
    sleep = sleep or time.sleep
    regions = regions or list(DEFAULT_REGIONS)
    headers = {"User-Agent": user_agent, "Accept": "application/json"}
    cameras = 0
    fails: list[str] = []
    checked = 0
    capped: list[str] = []

    for loc in regions:
        try:
            cached = lake.geocode_get(loc)
            if cached:
                lat, lon = cached
            else:
                geo = http.get(
                    _NOMINATIM,
                    params={"q": loc, "format": "json", "limit": 1},
                    headers=headers,
                    timeout=min(timeout, 15),
                )
                if geo.status_code >= 400:
                    reason = f"nominatim {geo.status_code}"
                    fails.append(f"{loc}: {reason}")
                    lake.mark_region(loc, "failed", reason)
                    sleep(pause_s)
                    continue
                hits = geo.json() or []
                if not hits:
                    fails.append(f"{loc}: no geocode")
                    lake.mark_region(loc, "failed", "no geocode result")
                    sleep(pause_s)
                    continue
                lat, lon = hits[0].get("lat"), hits[0].get("lon")
                lake.geocode_put(loc, float(lat), float(lon))

            query = (
                f"[out:json][timeout:60];"
                f'(node["man_made"="surveillance"](around:{around_m},{lat},{lon});'
                f'node["surveillance:type"="ALPR"](around:{around_m},{lat},{lon});'
                f'node["highway"="speed_camera"](around:{around_m},{lat},{lon}););'
                f"out body {max_per_region};"
            )
            # The server-side [timeout:] must exceed our HTTP timeout, or we
            # hang up on a query the server is still happily running — which is
            # its own way of manufacturing a 504.
            payload, reason = _overpass_fetch(
                http, query, headers=headers, timeout=max(timeout, 45), sleep=sleep
            )
            if payload is None:
                fails.append(f"{loc}: {reason}")
                lake.mark_region(loc, "failed", reason or "unknown")
                sleep(pause_s)
                continue

            found = 0
            for el in (payload or {}).get("elements") or []:
                elat, elon = el.get("lat"), el.get("lon")
                if elat is None or elon is None:
                    continue
                tags = el.get("tags") or {}
                label = tags.get("name") or tags.get("surveillance:type") or "surveillance camera"
                lake.upsert_camera(
                    osm_id=el.get("id"),
                    lat=float(elat),
                    lon=float(elon),
                    label=str(label)[:200],
                    region=loc,
                    tags=tags,
                )
                cameras += 1
                found += 1

            # `out body N` truncates server-side. Never a silent cap: a region
            # that came back exactly at the limit probably has more.
            hit_cap = found >= max_per_region
            if hit_cap:
                capped.append(loc)
            checked += 1
            lake.mark_region(loc, "ok", None, cameras=found, capped=hit_cap)
        except Exception as exc:  # noqa: BLE001
            fails.append(f"{loc}: {exc}")
            lake.mark_region(loc, "failed", f"{type(exc).__name__}: {exc}")
        sleep(pause_s)
    lake.mark_synced()
    return {
        "regions": len(regions),
        "checked": checked,
        "cameras_upserted": cameras,
        "fails": fails,
        "capped": capped,
        "path": str(lake.path),
    }
