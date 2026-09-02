"""Which record portals can actually be fetched, and which only a human can open.

`/people/coverage` reports **L2 deep 75** — seventy-five counties with a portal
pack shipped. That counts what is *listed*, and a check of all 288 distinct
portal URLs found that is not the same as what is *reachable*:

    37  block automation (403)   — valid for a person, never for a collector
    25  persistently unreachable — dead, geo-blocked, or TLS-broken
    11  dead URL (404/410)
     6  transient (recovered on retry)
   209  fetchable

So roughly a quarter of the portals cannot be crawled, and the largest slice of
that is the site's own choice rather than anything broken. A pack of links a
collector can never follow is still useful — the county tracker's rule is
literally *"store the link"* — but counting it as coverage overstates what an
investigation will actually return.

Three outcomes, kept apart for the same reason `closed` and `filtered` are kept
apart in the port scanner:

    fetchable          a collector can read it
    link_only          the site refuses automation; a person can still click it
    blocked_by_guard   our own egress guard refused it — about us, not them
    broken             404, or nothing answers at all

`link_only` is not a failure. Recording it as one would push someone to "fix"
URLs that are working exactly as the county intends.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS portal_health (
  url TEXT PRIMARY KEY,
  region TEXT NOT NULL,
  kind TEXT,
  name TEXT,
  status TEXT NOT NULL,        -- fetchable | link_only | broken
  http_code INTEGER,
  detail TEXT,
  checked_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_portal_region ON portal_health(region);
CREATE INDEX IF NOT EXISTS idx_portal_status ON portal_health(status);
"""

#: A site answering 401/403 to a bot is not broken. It has decided, and the
#: pack entry remains a perfectly good link for a person.
_REFUSES_AUTOMATION = {401, 403, 406, 429}


def classify(http_code: int | None, error: str | None) -> tuple[str, str]:
    """(status, human detail) for one probe result."""
    if error == "BlockedAddress":
        # Our own SSRF guard refused the target — usually because DNS returned
        # nothing and the guard fails closed. That is a fact about our egress
        # path, not about the portal, and filing it under "needs a new URL"
        # would send someone to fix a link that is fine.
        return "blocked_by_guard", (
            "Umbra's egress guard refused this target — DNS returned nothing, or "
            "it resolved somewhere the guard will not follow. Not evidence the "
            "portal is broken."
        )
    if error:
        return "broken", f"{error} — no response"
    if http_code is None:
        return "broken", "no response"
    if 200 <= http_code < 400:
        return "fetchable", f"HTTP {http_code}"
    if http_code in _REFUSES_AUTOMATION:
        return "link_only", (
            f"HTTP {http_code} — the site refuses automated requests. The link "
            f"still works for a person; a collector will never read it."
        )
    if http_code in (404, 410):
        return "broken", f"HTTP {http_code} — the page is gone; the pack entry needs updating"
    if http_code >= 500:
        return "broken", f"HTTP {http_code} — server error"
    return "broken", f"HTTP {http_code}"


def default_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "portal_health.sqlite"


class PortalHealth:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @classmethod
    def from_settings(cls, settings) -> "PortalHealth":
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

    def record(self, region: str, kind: str, name: str, url: str,
               http_code: int | None, error: str | None) -> str:
        status, detail = classify(http_code, error)
        conn = self.connect()
        with self._lock, conn:
            conn.execute(
                "INSERT INTO portal_health(url, region, kind, name, status, http_code, "
                "detail, checked_at) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(url) DO UPDATE SET region=excluded.region, kind=excluded.kind, "
                "name=excluded.name, status=excluded.status, http_code=excluded.http_code, "
                "detail=excluded.detail, checked_at=excluded.checked_at",
                (url, region, kind, name, status, http_code, detail,
                 datetime.now(tz=timezone.utc).isoformat()),
            )
        return status

    def summary(self) -> dict[str, Any]:
        """Counts by status, plus when the check last ran.

        Zero rows means *never checked*, which is not the same as "all healthy"
        — the caller has to be able to tell those apart.
        """
        if not self.path.is_file():
            return {"checked": False, "fetchable": 0, "link_only": 0,
                    "blocked_by_guard": 0, "broken": 0, "total": 0,
                    "checked_at": None}
        conn = self.connect()
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM portal_health GROUP BY status").fetchall()
        counts = {r["status"]: r["n"] for r in rows}
        newest = conn.execute("SELECT MAX(checked_at) AS t FROM portal_health").fetchone()["t"]
        total = sum(counts.values())
        return {
            "checked": total > 0,
            "fetchable": counts.get("fetchable", 0),
            "link_only": counts.get("link_only", 0),
            "blocked_by_guard": counts.get("blocked_by_guard", 0),
            "broken": counts.get("broken", 0),
            "total": total,
            "checked_at": newest,
        }

    def broken(self, limit: int = 50) -> list[dict[str, Any]]:
        """The entries that actually need a human to update a URL."""
        if not self.path.is_file():
            return []
        rows = self.connect().execute(
            "SELECT region, name, url, http_code, detail FROM portal_health "
            "WHERE status='broken' ORDER BY region LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def for_region(self, region: str) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        rows = self.connect().execute(
            "SELECT name, url, status, http_code, detail FROM portal_health "
            "WHERE region=? ORDER BY name", (region,)).fetchall()
        return [dict(r) for r in rows]


def probe(http, url: str, timeout: float = 15.0) -> tuple[int | None, str | None]:
    """One portal. HEAD first; some hosts only answer GET.

    Never raises — a probe that blows up is a result, not an exception.
    """
    try:
        resp = http.head(url, timeout=timeout, follow_redirects=True)
        if resp.status_code in (403, 405, 501):
            resp = http.get(url, timeout=timeout, follow_redirects=True)
        return resp.status_code, None
    except Exception as exc:  # noqa: BLE001
        return None, type(exc).__name__


def check_all(health: PortalHealth, http, portals: Iterable[tuple[str, str, str, str]],
              *, progress=None) -> dict[str, Any]:
    """Probe every (region, kind, name, url) and record the outcome."""
    seen: set[str] = set()
    counts = {"fetchable": 0, "link_only": 0, "blocked_by_guard": 0, "broken": 0}
    for i, (region, kind, name, url) in enumerate(portals, 1):
        if url in seen:
            continue
        seen.add(url)
        code, err = probe(http, url)
        counts[health.record(region, kind, name, url, code, err)] += 1
        if progress:
            progress(i, url)
    return {"checked": len(seen), **counts}
