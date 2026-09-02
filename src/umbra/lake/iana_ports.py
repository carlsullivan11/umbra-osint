"""IANA service names — what a listening port is supposed to be.

This registry sat on the "worth importing" list for a while with no consumer,
because Umbra had nothing that observed a port: `tls_cert` hardcodes 443 and
the sentinel fingerprints scanners by User-Agent. Importing it then would have
been 1.1 MB of data nothing read.

`umbra scan ports` changes that. An open port is a number; `6379` means nothing
to most readers and `redis` means quite a lot — especially the ones that should
not be reachable from outside.

**The registry says what a port is assigned to, not what is running there.** An
open 6379 is *probably* Redis and might be anything; a listening service is free
to ignore the assignment entirely. So the name is rendered as an expectation and
never as a finding — same reason a reputation verdict names its sources.

Source: https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
(~1.1 MB, public domain, no key.)
"""
from __future__ import annotations

import csv
import io
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

IANA_URL = (
    "https://www.iana.org/assignments/service-names-port-numbers/"
    "service-names-port-numbers.csv"
)
ATTRIBUTION = "Service Name and Transport Protocol Port Number Registry (IANA)"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS services (
  port INTEGER NOT NULL,
  proto TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  PRIMARY KEY (port, proto)
);
"""

#: Ports whose exposure is worth flagging regardless of what IANA calls them.
#: Not a vulnerability list — a "this is almost never meant to face the
#: internet" list, which is a different and more defensible claim.
SENSITIVE = {
    3306: "database", 5432: "database", 1433: "database", 1521: "database",
    27017: "database", 6379: "cache/database", 11211: "cache",
    9200: "search cluster", 9300: "search cluster",
    2375: "container runtime (unauthenticated by default)",
    2376: "container runtime",
    3389: "remote desktop", 5900: "remote desktop", 23: "cleartext remote shell",
    445: "file sharing", 139: "file sharing", 135: "RPC endpoint mapper",
    161: "SNMP", 5985: "remote management", 5986: "remote management",
    15672: "message broker admin", 5672: "message broker",
}


def default_ports_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "iana_ports.sqlite"


def parse_csv(text: str) -> list[tuple[int, str, str, str]]:
    """(port, proto, name, description) rows worth keeping.

    The registry has 14,533 rows; ~2,800 are unnamed reservations and port
    ranges that answer nothing useful, so they are dropped rather than stored as
    empty names.
    """
    out: list[tuple[int, str, str, str]] = []
    for row in csv.DictReader(io.StringIO(text)):
        name = (row.get("Service Name") or "").strip()
        port_raw = (row.get("Port Number") or "").strip()
        proto = (row.get("Transport Protocol") or "").strip().lower()
        if not name or not proto or not port_raw.isdigit():
            continue
        out.append((int(port_raw), proto, name, (row.get("Description") or "").strip()))
    return out


class IanaPortsLake:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_ports_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @classmethod
    def from_settings(cls, settings) -> "IanaPortsLake":
        return cls(default_ports_path(getattr(settings, "data_dir", None)))

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

    def row_count(self) -> int:
        if not self.path.is_file():
            return 0
        return int(self.connect().execute("SELECT COUNT(*) AS n FROM services").fetchone()["n"])

    def service(self, port: int, proto: str = "tcp") -> str | None:
        """The assigned name, or None when unknown or the lake is absent.

        None rather than a guess: an unknown port is unknown, and inventing a
        name for it would be exactly the kind of confident wrong answer the rest
        of this codebase refuses to give.
        """
        if not self.path.is_file():
            return None
        row = self.connect().execute(
            "SELECT name FROM services WHERE port=? AND proto=?", (int(port), proto.lower())
        ).fetchone()
        return row["name"] if row else None

    def describe(self, port: int, proto: str = "tcp") -> dict[str, Any]:
        """Name, description and whether this is a port that should be exposed."""
        name = self.service(port, proto)
        return {
            "port": port,
            "proto": proto,
            "service": name,
            "sensitive": SENSITIVE.get(int(port)),
            # Stated every time, because the registry cannot see what is really
            # listening — only what the number was assigned to.
            "caveat": "IANA assignment, not an observation of the running service",
        }

    def replace_all(self, rows: list[tuple[int, str, str, str]]) -> int:
        conn = self.connect()
        with self._lock, conn:
            conn.execute("DELETE FROM services")
            conn.executemany(
                "INSERT OR REPLACE INTO services(port, proto, name, description) "
                "VALUES(?,?,?,?)", rows,
            )
            conn.execute(
                "INSERT INTO meta(key,value) VALUES('imported_at',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (datetime.now(tz=timezone.utc).isoformat(),),
            )
        return len(rows)

    def status(self) -> dict[str, Any]:
        stamp = None
        if self.path.is_file():
            row = self.connect().execute(
                "SELECT value FROM meta WHERE key='imported_at'").fetchone()
            stamp = row["value"] if row else None
        return {
            "path": str(self.path),
            "available": self.available,
            "rows": self.row_count(),
            "imported_at": stamp,
            "attribution": ATTRIBUTION,
        }


def sync(lake: IanaPortsLake, http, *, url: str = IANA_URL, timeout: float = 120.0) -> dict:
    resp = http.get(url, timeout=timeout, follow_redirects=True)
    resp.raise_for_status()
    rows = parse_csv(resp.text)
    if len(rows) < 1000:
        raise ValueError(
            f"IANA registry from {url} parsed to only {len(rows)} rows — "
            "refusing to replace the existing lake"
        )
    return {"rows": lake.replace_all(rows), "url": url}
