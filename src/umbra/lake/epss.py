"""EPSS — the owned exploitation-probability lake.

CISA KEV answers *"is this being exploited?"* — an **observation**, bounded to
1,687 entries. That is the actionable set, and it is why the wiki carries KEV
rather than all 384,910 published CVEs.

But `cve_lookup` already names the gap KEV leaves, in its own docstring:

    No KEV entry does **not** mean no vulnerabilities — nginx has plenty of
    CVEs and zero KEV entries.

EPSS (FIRST) closes exactly that. It scores **366,527 CVEs** with the modelled
probability of exploitation in the next 30 days. So the pair reads:

    in KEV        → observed exploited. Act.
    not in KEV,
      EPSS 0.94   → not seen yet, but the model says treat it as urgent.
    not in KEV,
      EPSS 0.0004 → genuinely low priority, and now you can say so.

**A prediction is not an observation, and this module must never blur them.**
KEV is a catalogue of things that happened. EPSS is a model output with a
version and a score date, which change daily and disagree with yesterday. Every
score returned here carries the model version and the date it was produced, and
the wording that renders it says "modelled", never "is". Conflating the two
would be the same failure as reporting an unreachable source as clean.

Stored as a lake, not as wiki pages: it is one number per CVE that changes every
day. Markdown is the wrong shape for that, and 366k pages would be a corpus
nobody can clone.

Source: https://epss.cyentia.com/epss_scores-current.csv.gz — free, no key,
attribution to FIRST.org. Roughly 2.5 MB gzipped.
"""
from __future__ import annotations

import csv
import gzip
import io
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

ATTRIBUTION = "EPSS by FIRST.org (https://www.first.org/epss) — free with attribution"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS epss (
  cve TEXT PRIMARY KEY,
  score REAL NOT NULL,
  percentile REAL NOT NULL
);
-- Ordering by score is the whole point of having this: "which of these 40 CVEs
-- should I look at first".
CREATE INDEX IF NOT EXISTS idx_epss_score ON epss(score DESC);
"""

#: Bands used when talking to a human. EPSS is a probability, and "0.94" means
#: little to most readers without an anchor. Thresholds follow FIRST's own
#: guidance that the great majority of CVEs score below 0.1.
_BANDS = [
    (0.50, "high", "modelled as very likely to be exploited in the next 30 days"),
    (0.10, "elevated", "modelled well above the median CVE"),
    (0.01, "low", "modelled as unlikely, but not negligible"),
    (0.0, "very low", "modelled as very unlikely"),
]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)


def default_epss_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "epss.sqlite"


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def band(score: float) -> tuple[str, str]:
    """(label, plain-English meaning) for a score."""
    for threshold, label, meaning in _BANDS:
        if score >= threshold:
            return label, meaning
    return "very low", _BANDS[-1][2]


def parse_header(line: str) -> dict[str, str]:
    """The feed's first line carries its own provenance:

        #model_version:v2026.06.15,score_date:2026-08-31T12:00:22Z

    Dropping it would leave scores with no way to say how old they are or which
    model produced them, which is most of what makes a prediction usable.
    """
    out: dict[str, str] = {}
    for part in line.lstrip("#").strip().split(","):
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        out[key.strip()] = value.strip()
    return out


def parse_rows(text: Iterable[str]) -> tuple[dict[str, str], list[tuple[str, float, float]]]:
    """Parse the bulk CSV into (header meta, rows). Pure — no network, no disk."""
    header: dict[str, str] = {}
    rows: list[tuple[str, float, float]] = []

    buffered = []
    for line in text:
        if line.startswith("#"):
            header.update(parse_header(line))
            continue
        buffered.append(line)

    reader = csv.DictReader(buffered)
    for record in reader:
        cve = (record.get("cve") or "").strip().upper()
        if not _CVE_RE.match(cve):
            continue
        try:
            score = float(record["epss"])
            percentile = float(record["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        rows.append((cve, score, percentile))
    return header, rows


class EpssLake:
    """SQLite-backed CVE → exploitation probability."""

    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_epss_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @classmethod
    def from_settings(cls, settings) -> "EpssLake":
        return cls(default_epss_path(getattr(settings, "data_dir", None)))

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

    def get_meta(self, key: str) -> str | None:
        row = self.connect().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.connect().execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def row_count(self) -> int:
        if not self.path.is_file():
            return 0
        return int(self.connect().execute("SELECT COUNT(*) AS n FROM epss").fetchone()["n"])

    def score(self, cve: str) -> dict[str, Any] | None:
        """One CVE's score, or None when this lake has nothing for it.

        None means *unscored*, which is not the same as low. A CVE published
        after the last sync has no row here, and answering 0.0 for it would be
        a confident lie about a vulnerability nobody has modelled yet.
        """
        if not self.path.is_file():
            return None
        row = self.connect().execute(
            "SELECT cve, score, percentile FROM epss WHERE cve=?", (cve.strip().upper(),)
        ).fetchone()
        if not row:
            return None
        label, meaning = band(row["score"])
        return {
            "cve": row["cve"],
            "score": row["score"],
            "percentile": row["percentile"],
            "band": label,
            "meaning": meaning,
            # Provenance travels with the number, always.
            "model_version": self.get_meta("model_version"),
            "score_date": self.get_meta("score_date"),
            "source": "FIRST EPSS (owned lake)",
        }

    def top(self, cves: Iterable[str], limit: int = 10) -> list[dict[str, Any]]:
        """The given CVEs, worst modelled risk first. Unscored ones are dropped
        from the ranking but the caller is expected to say how many."""
        scored = [s for s in (self.score(c) for c in cves) if s]
        scored.sort(key=lambda s: s["score"], reverse=True)
        return scored[:limit]

    def replace_all(self, header: dict[str, str], rows: list[tuple[str, float, float]]) -> int:
        """Swap the table contents atomically.

        A half-written lake is worse than a stale one: it answers "unscored" for
        whatever had not been inserted yet, and the caller cannot tell that from
        a genuinely unscored CVE.
        """
        conn = self.connect()
        with self._lock, conn:
            conn.execute("DELETE FROM epss")
            conn.executemany("INSERT INTO epss(cve, score, percentile) VALUES(?,?,?)", rows)
            for key in ("model_version", "score_date"):
                if header.get(key):
                    self.set_meta(key, header[key])
            self.set_meta("imported_at", _now())
            self.set_meta("attribution", ATTRIBUTION)
            self.set_meta("rows", str(len(rows)))
        return len(rows)

    def status(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "available": self.available,
            "rows": self.row_count(),
            "model_version": self.get_meta("model_version") if self.available else None,
            "score_date": self.get_meta("score_date") if self.available else None,
            "imported_at": self.get_meta("imported_at") if self.available else None,
            "attribution": ATTRIBUTION,
        }


def sync(lake: EpssLake, http, *, url: str = BULK_URL, timeout: float = 120.0) -> dict[str, Any]:
    """Download the current bulk feed and replace the lake.

    `http` is injected so the caller supplies a GuardedClient — this fetches a
    URL like any collector does, and egress rules are not optional for one
    module.
    """
    resp = http.get(url, timeout=timeout, follow_redirects=True)
    resp.raise_for_status()
    raw = gzip.decompress(resp.content)
    header, rows = parse_rows(io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8"))
    if not rows:
        raise ValueError(f"EPSS feed at {url} parsed to zero rows — refusing to wipe the lake")
    count = lake.replace_all(header, rows)
    return {
        "rows": count,
        "model_version": header.get("model_version"),
        "score_date": header.get("score_date"),
        "url": url,
    }
