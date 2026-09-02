"""Owned IP geolocation lake — free DB-IP City Lite (CC-BY-4.0).

Collectors never hit the network for lookups. Fill with::

    umbra geoip sync

Source: https://db-ip.com/db/download/ip-to-city-lite
License requires attribution when redistributing derived products.

Honesty: commercial geo DBs are approximate (CGNAT, VPN, mobile, anycast).
A miss or unsynced lake is *unchecked*, never \"no location\".
"""

from __future__ import annotations

import csv
import gzip
import ipaddress
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import date, datetime, timezone
from io import TextIOWrapper
from pathlib import Path
from typing import BinaryIO, Iterable, TextIO

logger = logging.getLogger(__name__)

# DB-IP free City Lite monthly files (CSV). Prefer previous month if current
# month is not published yet (usually drops early in the month).
_DBIP_CITY_CSV = "https://download.db-ip.com/free/dbip-city-lite-{ym}.csv.gz"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS geo_v4 (
  start INTEGER NOT NULL,
  end   INTEGER NOT NULL,
  country TEXT,
  region  TEXT,
  city    TEXT,
  lat     REAL,
  lon     REAL
);
CREATE INDEX IF NOT EXISTS idx_geo_v4_start ON geo_v4(start);
CREATE TABLE IF NOT EXISTS geo_v6 (
  start BLOB NOT NULL,
  end   BLOB NOT NULL,
  country TEXT,
  region  TEXT,
  city    TEXT,
  lat     REAL,
  lon     REAL
);
CREATE INDEX IF NOT EXISTS idx_geo_v6_start ON geo_v6(start);
"""


@dataclass(frozen=True, slots=True)
class GeoHit:
    country: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    network_start: str | None = None
    network_end: str | None = None
    source: str = "db-ip-city-lite"

    def location_label(self) -> str:
        """Human label for EntityType.LOCATION — city-first when present."""
        parts: list[str] = []
        if self.city:
            parts.append(self.city)
        if self.region and self.region != self.city:
            parts.append(self.region)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts) if parts else (self.country or "unknown")

    def as_dict(self) -> dict:
        return {
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "network_start": self.network_start,
            "network_end": self.network_end,
            "source": self.source,
            "location": self.location_label(),
        }


def default_geoip_path() -> Path:
    env = os.environ.get("UMBRA_GEOIP_DB", "").strip()
    if env:
        return Path(env).expanduser()
    try:
        from umbra.core.config import get_settings

        return get_settings().data_dir / "lake" / "geoip.sqlite"
    except Exception:  # noqa: BLE001
        return Path.home() / "umbra" / "data" / "lake" / "geoip.sqlite"


def candidate_dbip_urls(today: date | None = None) -> list[str]:
    """Newest-first monthly DB-IP City Lite CSV URLs."""
    d = today or date.today()
    urls: list[str] = []
    y, m = d.year, d.month
    for _ in range(3):
        ym = f"{y:04d}-{m:02d}"
        urls.append(_DBIP_CITY_CSV.format(ym=ym))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    return urls


def _ip_to_v4_int(ip: ipaddress.IPv4Address) -> int:
    return int(ip)


def _ip_to_v6_bytes(ip: ipaddress.IPv6Address) -> bytes:
    return ip.packed


def _parse_lat_lon(lat_s: str, lon_s: str) -> tuple[float | None, float | None]:
    try:
        lat = float(lat_s) if lat_s not in ("", None) else None
    except ValueError:
        lat = None
    try:
        lon = float(lon_s) if lon_s not in ("", None) else None
    except ValueError:
        lon = None
    return lat, lon


def _open_csv_stream(path: Path) -> TextIO:
    if str(path).endswith(".gz"):
        raw: BinaryIO = gzip.open(path, "rb")  # type: ignore[assignment]
        return TextIOWrapper(raw, encoding="utf-8", errors="replace", newline="")
    return path.open("r", encoding="utf-8", errors="replace", newline="")


def iter_dbip_city_rows(stream: TextIO) -> Iterable[tuple]:
    """Yield (version, start, end, country, region, city, lat, lon).

    DB-IP free City Lite CSV columns (no header)::
        ip_start, ip_end, continent, country, stateprov, city, latitude, longitude
    """
    reader = csv.reader(stream)
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 8:
            # some dumps omit continent differently — require at least 6 cols
            if len(row) < 6:
                continue
        try:
            start = ipaddress.ip_address(row[0].strip().strip('"'))
            end = ipaddress.ip_address(row[1].strip().strip('"'))
        except ValueError:
            continue
        # Handle both 8-col (with continent) and 7-col variants
        if len(row) >= 8:
            country = row[3].strip().strip('"') or None
            region = row[4].strip().strip('"') or None
            city = row[5].strip().strip('"') or None
            lat, lon = _parse_lat_lon(row[6].strip().strip('"'), row[7].strip().strip('"'))
        else:
            country = row[2].strip().strip('"') or None
            region = row[3].strip().strip('"') or None
            city = row[4].strip().strip('"') or None
            lat, lon = _parse_lat_lon(
                row[5].strip().strip('"') if len(row) > 5 else "",
                row[6].strip().strip('"') if len(row) > 6 else "",
            )
        if start.version != end.version:
            continue
        if isinstance(start, ipaddress.IPv4Address) and isinstance(end, ipaddress.IPv4Address):
            yield (4, _ip_to_v4_int(start), _ip_to_v4_int(end), country, region, city, lat, lon)
        elif isinstance(start, ipaddress.IPv6Address) and isinstance(end, ipaddress.IPv6Address):
            yield (
                6,
                _ip_to_v6_bytes(start),
                _ip_to_v6_bytes(end),
                country,
                region,
                city,
                lat,
                lon,
            )


class GeoIpStore:
    """SQLite-backed IP → city/country lake."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else default_geoip_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @property
    def available(self) -> bool:
        if not self.path.is_file():
            return False
        try:
            return self.row_count() > 0
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

    def get_meta(self, key: str) -> str | None:
        if not self.path.is_file():
            return None
        row = self.connect().execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        conn = self.connect()
        conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        conn.commit()

    def row_count(self) -> int:
        if not self.path.is_file():
            return 0
        conn = self.connect()
        v4 = conn.execute("SELECT COUNT(*) AS n FROM geo_v4").fetchone()["n"]
        v6 = conn.execute("SELECT COUNT(*) AS n FROM geo_v6").fetchone()["n"]
        return int(v4) + int(v6)

    def status(self) -> dict:
        return {
            "path": str(self.path),
            "available": self.available,
            "rows": self.row_count() if self.path.is_file() else 0,
            "source": self.get_meta("source"),
            "edition": self.get_meta("edition"),
            "imported_at": self.get_meta("imported_at"),
            "attribution": self.get_meta("attribution")
            or "IP Geolocation by DB-IP (https://db-ip.com) — CC-BY 4.0",
        }

    def import_csv_file(self, csv_path: Path, *, edition: str | None = None) -> dict:
        """Replace lake contents from a DB-IP City Lite CSV or .csv.gz."""
        csv_path = Path(csv_path)
        if not csv_path.is_file():
            raise FileNotFoundError(csv_path)

        # Build into a temp DB then replace — avoids half-imported lakes
        tmp = self.path.with_suffix(self.path.suffix + ".importing")
        if tmp.exists():
            tmp.unlink()
        tmp.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(tmp))
        conn.executescript(SCHEMA)

        n4 = n6 = 0
        batch_v4: list[tuple] = []
        batch_v6: list[tuple] = []
        BATCH = 5000

        def flush() -> None:
            nonlocal batch_v4, batch_v6
            if batch_v4:
                conn.executemany(
                    "INSERT INTO geo_v4(start, end, country, region, city, lat, lon) "
                    "VALUES (?,?,?,?,?,?,?)",
                    batch_v4,
                )
                batch_v4 = []
            if batch_v6:
                conn.executemany(
                    "INSERT INTO geo_v6(start, end, country, region, city, lat, lon) "
                    "VALUES (?,?,?,?,?,?,?)",
                    batch_v6,
                )
                batch_v6 = []

        with _open_csv_stream(csv_path) as fh:
            for ver, start, end, country, region, city, lat, lon in iter_dbip_city_rows(fh):
                if ver == 4:
                    batch_v4.append((start, end, country, region, city, lat, lon))
                    n4 += 1
                else:
                    batch_v6.append((start, end, country, region, city, lat, lon))
                    n6 += 1
                if len(batch_v4) + len(batch_v6) >= BATCH:
                    flush()
        flush()

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ed = edition or csv_path.name
        meta = {
            "source": "db-ip-city-lite",
            "edition": ed,
            "imported_at": now,
            "attribution": "IP Geolocation by DB-IP (https://db-ip.com) — CC-BY 4.0",
            "rows_v4": str(n4),
            "rows_v6": str(n6),
        }
        for k, v in meta.items():
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, v),
            )
        conn.commit()
        conn.close()

        # atomic replace
        self.close()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, self.path)
        return {"rows_v4": n4, "rows_v6": n6, "path": str(self.path), "edition": ed}

    def lookup(self, ip_str: str) -> GeoHit | None:
        """Return geo hit or None if not in lake / invalid / private."""
        try:
            ip = ipaddress.ip_address(ip_str.split("%")[0].strip())
        except ValueError:
            return None
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return None
        if not self.path.is_file():
            return None
        conn = self.connect()
        if isinstance(ip, ipaddress.IPv4Address):
            n = _ip_to_v4_int(ip)
            row = conn.execute(
                "SELECT start, end, country, region, city, lat, lon FROM geo_v4 "
                "WHERE start <= ? ORDER BY start DESC LIMIT 1",
                (n,),
            ).fetchone()
            if not row or int(row["end"]) < n:
                return None
            return GeoHit(
                country=row["country"],
                region=row["region"],
                city=row["city"],
                latitude=row["lat"],
                longitude=row["lon"],
                network_start=str(ipaddress.IPv4Address(int(row["start"]))),
                network_end=str(ipaddress.IPv4Address(int(row["end"]))),
            )
        packed = _ip_to_v6_bytes(ip)
        row = conn.execute(
            "SELECT start, end, country, region, city, lat, lon FROM geo_v6 "
            "WHERE start <= ? ORDER BY start DESC LIMIT 1",
            (packed,),
        ).fetchone()
        if not row or bytes(row["end"]) < packed:
            return None
        return GeoHit(
            country=row["country"],
            region=row["region"],
            city=row["city"],
            latitude=row["lat"],
            longitude=row["lon"],
            network_start=str(ipaddress.IPv6Address(bytes(row["start"]))),
            network_end=str(ipaddress.IPv6Address(bytes(row["end"]))),
        )


def default_store() -> GeoIpStore:
    return GeoIpStore()
