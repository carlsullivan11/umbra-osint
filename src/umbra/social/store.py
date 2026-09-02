"""What has been posted, what it cost, and what the cap allows.

Two things make an owned store non-optional here rather than nice to have.

**Money.** X moved to pay-per-use in February 2026 and there is no free tier
for new developers. A post costs $0.015 — but **$0.20 if it contains a link**,
and every post this bot makes contains a link, because driving traffic is the
entire point. At ten posts a day that is roughly $60/month. A bug that
double-posts is not an embarrassment, it is a bill, so spend is counted here
and capped before the API is ever called.

**Suspension.** X's automation policy flags "identical content posted at
scale — the same tweet template with minor variations". Re-posting a CVE
because a restart lost track of it is exactly that pattern. `already_posted`
is what makes the bot idempotent across restarts.

Dry runs are recorded too, with `dry_run = 1`. A preview that leaves no trace
cannot be reviewed later, and reviewing what the bot *would* have said is the
only way to judge it before letting it speak.
"""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS social_posts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  platform    TEXT NOT NULL DEFAULT 'x',
  kind        TEXT NOT NULL,        -- kev_addition | ...
  ref         TEXT NOT NULL,        -- the thing posted about, e.g. CVE-2026-1
  text        TEXT NOT NULL,
  url         TEXT,
  remote_id   TEXT,                 -- the platform's post id, when live
  dry_run     INTEGER NOT NULL DEFAULT 1,
  cost_cents  REAL NOT NULL DEFAULT 0,
  posted_at   TEXT NOT NULL
);
-- Only *live* posts make a ref spent; a dry run must not block the real one.
CREATE UNIQUE INDEX IF NOT EXISTS idx_social_ref_live
  ON social_posts(platform, kind, ref) WHERE dry_run = 0;
CREATE INDEX IF NOT EXISTS idx_social_posted_at ON social_posts(posted_at);
"""

#: X pay-per-use, 2026. A link makes a post more than 13x more expensive, and
#: every post here carries one.
COST_CENTS_WITH_LINK = 20.0
COST_CENTS_PLAIN = 1.5


def default_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "social.sqlite"


class SocialStore:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @classmethod
    def from_settings(cls, settings) -> "SocialStore":
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

    # -- reads -------------------------------------------------------------

    def already_posted(self, kind: str, ref: str, platform: str = "x") -> bool:
        """Has this exact thing gone out for real? Dry runs do not count."""
        row = self.connect().execute(
            "SELECT 1 FROM social_posts WHERE platform=? AND kind=? AND ref=? "
            "AND dry_run=0 LIMIT 1", (platform, kind, ref)).fetchone()
        return row is not None

    def posted_today(self, platform: str = "x") -> int:
        today = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d")
        return int(self.connect().execute(
            "SELECT COUNT(*) FROM social_posts WHERE platform=? AND dry_run=0 "
            "AND substr(posted_at,1,10)=?", (platform, today)).fetchone()[0])

    def spend_cents(self, days: int = 30, platform: str = "x") -> float:
        rows = self.connect().execute(
            "SELECT COALESCE(SUM(cost_cents),0) FROM social_posts "
            "WHERE platform=? AND dry_run=0 AND posted_at >= date('now', ?)",
            (platform, f"-{int(days)} days")).fetchone()
        return float(rows[0] or 0.0)

    def recent(self, limit: int = 20, platform: str = "x") -> list[dict[str, Any]]:
        rows = self.connect().execute(
            "SELECT kind, ref, text, url, dry_run, cost_cents, posted_at "
            "FROM social_posts WHERE platform=? ORDER BY id DESC LIMIT ?",
            (platform, limit)).fetchall()
        return [dict(r) for r in rows]

    def status(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"live": 0, "dry": 0, "today": 0, "spend_30d_usd": 0.0,
                    "last": None}
        conn = self.connect()
        live = conn.execute(
            "SELECT COUNT(*) FROM social_posts WHERE dry_run=0").fetchone()[0]
        dry = conn.execute(
            "SELECT COUNT(*) FROM social_posts WHERE dry_run=1").fetchone()[0]
        last = conn.execute(
            "SELECT MAX(posted_at) FROM social_posts WHERE dry_run=0").fetchone()[0]
        return {"live": int(live), "dry": int(dry), "today": self.posted_today(),
                "spend_30d_usd": round(self.spend_cents() / 100.0, 2),
                "last": last}

    # -- writes ------------------------------------------------------------

    def record(self, *, kind: str, ref: str, text: str, url: str | None,
               dry_run: bool, remote_id: str | None = None,
               platform: str = "x") -> None:
        cost = 0.0 if dry_run else (COST_CENTS_WITH_LINK if url else COST_CENTS_PLAIN)
        conn = self.connect()
        with self._lock, conn:
            conn.execute(
                "INSERT OR IGNORE INTO social_posts"
                "(platform, kind, ref, text, url, remote_id, dry_run, cost_cents, posted_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (platform, kind, ref, text, url, remote_id, int(dry_run), cost,
                 datetime.now(tz=timezone.utc).isoformat()),
            )
