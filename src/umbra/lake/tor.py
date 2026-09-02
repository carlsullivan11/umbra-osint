"""Owned Tor relay lake — every relay, not just the exits.

Umbra checked `check.torproject.org/torbulkexitlist`, which is **exit nodes
only**. Measured 2026-09-01 against the full consensus:

    relays in the consensus        15,794
    carrying the Exit flag          6,021
    guards / middles / bridges      9,773   invisible to the exit list

So 62% of Tor relays produced no answer at all. An operator looking up a guard
relay was told nothing, and — worse — the absence read like a clean result.
That is the report that prompted this: an address on a Tor list that Umbra had
nothing to say about.

**Exit and non-exit are different facts and are kept apart.** An exit relay can
originate a connection to your service, so seeing one in your logs has an
obvious meaning. A middle relay cannot: it only carries traffic between other
relays, so finding one in a log is usually a coincidence or a scan, not Tor
traffic reaching you. Collapsing both into "Tor" would invite exactly the wrong
inference.

**Running a relay is not wrongdoing.** The lake records a role, never a
verdict. `BadExit` is the one flag the directory authorities use to mark a
relay as misbehaving, and it is preserved distinctly for that reason.

**Three sources, authoritative first.**

The Tor **directory-authority consensus** is the ground truth everything else
is derived from: signed by the authorities, republished hourly, and served by
nine independent machines. It carries what the derived sources drop — the exit
**policy** (a relay can hold the Exit flag and still `reject 1-65535`, which 5
of 2,558 did when measured) and `valid-after`/`fresh-until`, so the age of the
data is a fact rather than a guess.

Nine servers is the reliability story. Fetching them from this network on
2026-09-01, two returned **722 bytes of ISP block page with HTTP 200** —
AT&T interstitials claiming "malware, phishing" — while two returned real
consensus documents. A source that answers 200 with the wrong body is the
recurring hazard here, so a document is only accepted after it identifies
itself as a consensus.

**Two derived sources, official first.** `onionoo.torproject.org` is the Tor Project's
own API: documented, no rate-limit games, and its `details` endpoint carries
nicknames, addresses and flags in one 1.6 MB response.

`https://www.dan.me.uk/tornodes` is kept as an alternative because it lists
more relays (15,794 against Onionoo's 10,185 running) — but it is rate limited
and enforces that in a way worth knowing about. Fetching twice inside the
window returns **HTTP 200 with the node list silently removed**: 12 KB of page
furniture instead of 2.4 MB of data. Observed on 2026-09-01 while building
this. So a parse that yields nothing is treated as a source failure and never
as "no relays", and `sync()` will not fetch inside the 30-minute window at all.
"""
from __future__ import annotations

import re
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS tor_relay (
  ip         TEXT PRIMARY KEY,
  nickname   TEXT,
  or_port    INTEGER,
  dir_port   INTEGER,
  flags      TEXT NOT NULL DEFAULT '',
  is_exit    INTEGER NOT NULL DEFAULT 0,
  is_guard   INTEGER NOT NULL DEFAULT 0,
  is_bad_exit INTEGER NOT NULL DEFAULT 0,
  version    TEXT,
  exit_policy TEXT,
  seen_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tor_exit ON tor_relay(is_exit);
CREATE TABLE IF NOT EXISTS tor_sync (
  source     TEXT PRIMARY KEY,
  synced_at  TEXT NOT NULL,
  rows       INTEGER NOT NULL
);
"""

DAN_URL = "https://www.dan.me.uk/tornodes"
ONIONOO_URL = (
    "https://onionoo.torproject.org/details"
    "?running=true&fields=nickname,or_addresses,flags"
)

#: dan.me.uk's stated limit. Fetching more often gets the caller blocked, and
#: the consensus only changes hourly anyway.
MIN_FETCH_INTERVAL = timedelta(minutes=30)

#: The nine directory authorities. Tried in turn: any one of them serves the
#: same signed consensus, so this is redundancy against an outage, a hostile
#: middlebox, or one authority being unreachable from a given network.
DIRECTORY_AUTHORITIES = (
    ("moria1", "128.31.0.39:9131"),
    ("tor26", "86.59.21.38:80"),
    ("dizum", "45.66.33.45:80"),
    ("gabelmoo", "131.188.40.189:80"),
    ("dannenberg", "193.23.244.244:80"),
    ("maatuska", "171.25.193.9:443"),
    ("longclaw", "199.58.81.140:80"),
    ("bastet", "204.13.164.118:80"),
    ("faravahar", "216.218.219.41:80"),
)
CONSENSUS_PATH = "/tor/status-vote/current/consensus"

#: Directory-authority flags, as single letters in the source document.
FLAG_NAMES = {
    "A": "Authority", "B": "BadExit", "D": "V2Dir", "E": "Exit",
    "F": "Fast", "G": "Guard", "H": "HSDir", "R": "Running",
    "S": "Stable", "V": "Valid", "X": "NoEdConsensus",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def parse_dan(text: str) -> list[dict[str, Any]]:
    """Rows from the pipe-delimited consensus document.

    `ip|nickname|or_port|dir_port|flags|uptime|version|contact`

    Tolerant on purpose: the document is HTML with the data inline, contact
    fields contain arbitrary user text including stray pipes, and a malformed
    line must skip rather than abort a sync of 15,000 relays.
    """
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if line.count("|") < 5:
            continue
        parts = line.split("|")
        ip = parts[0].strip()
        if not _IPV4.match(ip) or ip in seen:
            continue
        seen.add(ip)
        flags = parts[4].strip()
        def as_int(v: str) -> int | None:
            v = v.strip()
            return int(v) if v.isdigit() else None
        out.append({
            "ip": ip,
            "nickname": parts[1].strip()[:64] or None,
            "or_port": as_int(parts[2]),
            "dir_port": as_int(parts[3]),
            "flags": flags,
            "is_exit": int("E" in flags),
            "is_guard": int("G" in flags),
            "is_bad_exit": int("B" in flags),
            "version": parts[6].strip()[:48] if len(parts) > 6 else None,
        })
    return out


def parse_consensus(text: str) -> tuple[list[dict[str, Any]], str | None]:
    """(relays, valid_after) from a directory-authority consensus.

    Returns `([], None)` unless the document identifies itself as a consensus.
    That check is the point: two authorities answered with an ISP block page
    at HTTP 200, and parsing that would have produced zero relays and wiped
    the lake.

    Relay entries are `r` (nickname, address, ports), `s` (flags) and `p`
    (exit policy). A relay holding the Exit flag whose policy rejects
    everything is recorded as a relay but not as an exit — the flag says the
    authorities *could* use it as one, the policy says what it actually does.
    """
    head = text[:400]
    if "network-status-version 3" not in head or "vote-status consensus" not in head:
        return [], None
    valid_after = None
    m = re.search(r"^valid-after (.+)$", text, re.M)
    if m:
        valid_after = m.group(1).strip()

    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    seen: set[str] = set()
    for line in text.splitlines():
        if line.startswith("r "):
            parts = line.split()
            cur = None
            if len(parts) >= 8 and _IPV4.match(parts[6]):
                ip = parts[6]
                if ip in seen:
                    continue
                seen.add(ip)
                cur = {"ip": ip, "nickname": parts[1][:64] or None,
                       "or_port": int(parts[7]) if parts[7].isdigit() else None,
                       "dir_port": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else None,
                       "flags": "", "is_exit": 0, "is_guard": 0, "is_bad_exit": 0,
                       "version": None, "exit_policy": None}
                out.append(cur)
        elif cur is not None and line.startswith("s "):
            words = line[2:].split()
            letter = {v: k for k, v in FLAG_NAMES.items()}
            cur["flags"] = "".join(sorted({letter[w] for w in words if w in letter}))
            cur["is_guard"] = int("Guard" in words)
            cur["is_bad_exit"] = int("BadExit" in words)
            cur["_exit_flag"] = "Exit" in words
        elif cur is not None and line.startswith("v "):
            cur["version"] = line[2:].strip()[:48]
        elif cur is not None and line.startswith("p "):
            policy = line[2:].strip()
            cur["exit_policy"] = policy[:120]
            # The flag says the authorities may treat it as an exit; the policy
            # says what it will actually carry. Both must agree.
            cur["is_exit"] = int(cur.pop("_exit_flag", False)
                                 and not policy.startswith("reject 1-65535"))
    for r in out:
        r.pop("_exit_flag", None)
    return out, valid_after


def parse_onionoo(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Rows from the Tor Project's own API.

    Flags arrive as words rather than letters, so they are folded back to the
    same single-letter form the rest of this module uses — one storage format,
    whichever source filled the lake.
    """
    letter = {v: k for k, v in FLAG_NAMES.items()}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in payload.get("relays") or []:
        flags = r.get("flags") or []
        compact = "".join(sorted({letter[f] for f in flags if f in letter}))
        for addr in r.get("or_addresses") or []:
            host, _, port = addr.rpartition(":")
            host = host.strip("[]")
            if not _IPV4.match(host) or host in seen:
                continue
            seen.add(host)
            out.append({
                "ip": host,
                "nickname": (r.get("nickname") or "")[:64] or None,
                "or_port": int(port) if port.isdigit() else None,
                "dir_port": None,
                "flags": compact,
                "is_exit": int("Exit" in flags),
                "is_guard": int("Guard" in flags),
                "is_bad_exit": int("BadExit" in flags),
                "version": None,
            })
    return out


def describe_flags(flags: str) -> list[str]:
    """Human names for the flag letters actually present."""
    return [FLAG_NAMES[c] for c in flags if c in FLAG_NAMES]


def default_path(data_dir: Path | None = None) -> Path:
    base = Path(data_dir) if data_dir else Path.home() / "umbra" / "data"
    return base / "lake" / "tor.sqlite"


class TorLake:
    def __init__(self, path: Path | str | None = None) -> None:
        self.path = Path(path) if path else default_path()
        self._lock = threading.Lock()
        self._conn: sqlite3.Connection | None = None

    @classmethod
    def from_settings(cls, settings) -> "TorLake":
        return cls(default_path(getattr(settings, "data_dir", None)))

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(SCHEMA)
            self._reconcile(self._conn)
        return self._conn

    @staticmethod
    def _reconcile(conn: sqlite3.Connection) -> None:
        """Rebuild the relay table when its columns no longer match the model.

        `CREATE TABLE IF NOT EXISTS` silently leaves an older table in place, so
        adding `exit_policy` produced "no column named exit_policy" against any
        lake created before it — a failure that only appears on an existing
        install, which is every install that matters.

        Dropping is safe precisely here: the lake is derived, and the next sync
        refetches the whole consensus. It is not safe for tables holding
        anything Umbra observed itself.
        """
        have = {r[1] for r in conn.execute("PRAGMA table_info(tor_relay)")}
        want = {"ip", "nickname", "or_port", "dir_port", "flags", "is_exit",
                "is_guard", "is_bad_exit", "version", "exit_policy", "seen_at"}
        if have and not want.issubset(have):
            with conn:
                conn.execute("DROP TABLE IF EXISTS tor_relay")
                conn.execute("DELETE FROM tor_sync")
            conn.executescript(SCHEMA)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def available(self) -> bool:
        return self.path.is_file()

    # -- reads -------------------------------------------------------------

    def lookup(self, ip: str) -> dict[str, Any] | None:
        """The relay at this address, or None.

        None means *not in the consensus we hold*. When the lake has never
        synced that is unchecked, not absent — `synced_at()` is what tells the
        caller which it is.
        """
        if not self.path.is_file():
            return None
        row = self.connect().execute(
            "SELECT * FROM tor_relay WHERE ip = ?", ((ip or "").strip(),)).fetchone()
        return dict(row) if row else None

    def synced_at(self) -> str | None:
        if not self.path.is_file():
            return None
        row = self.connect().execute(
            "SELECT MAX(synced_at) t FROM tor_sync").fetchone()
        return row["t"] if row else None

    def status(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"synced": False, "relays": 0, "exits": 0, "guards": 0,
                    "bad_exits": 0, "synced_at": None}
        c = self.connect()
        n = c.execute("SELECT COUNT(*) FROM tor_relay").fetchone()[0]
        e = c.execute("SELECT COUNT(*) FROM tor_relay WHERE is_exit=1").fetchone()[0]
        g = c.execute("SELECT COUNT(*) FROM tor_relay WHERE is_guard=1").fetchone()[0]
        b = c.execute("SELECT COUNT(*) FROM tor_relay WHERE is_bad_exit=1").fetchone()[0]
        return {"synced": bool(n), "relays": n, "exits": e, "guards": g,
                "bad_exits": b, "synced_at": self.synced_at()}

    def due_for_fetch(self, now: datetime | None = None) -> bool:
        """False inside the source's rate-limit window."""
        last = self.synced_at()
        if not last:
            return True
        try:
            when = datetime.fromisoformat(last)
        except ValueError:
            return True
        now = now or datetime.now(tz=timezone.utc)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (now - when) >= MIN_FETCH_INTERVAL

    # -- writes ------------------------------------------------------------

    def replace_all(self, relays: Iterable[dict[str, Any]], source: str = "dan.me.uk") -> int:
        """Swap in a fresh consensus.

        Replaces rather than merges: a relay that has left the consensus is no
        longer a relay, and keeping it would report a stale role as current.
        """
        rows = list(relays)
        if not rows:
            return 0
        now = datetime.now(tz=timezone.utc).isoformat()
        conn = self.connect()
        with self._lock, conn:
            conn.execute("DELETE FROM tor_relay")
            conn.executemany(
                "INSERT OR REPLACE INTO tor_relay"
                "(ip,nickname,or_port,dir_port,flags,is_exit,is_guard,is_bad_exit,"
                "version,exit_policy,seen_at)"
                " VALUES(:ip,:nickname,:or_port,:dir_port,:flags,:is_exit,:is_guard,"
                ":is_bad_exit,:version,:exit_policy,:seen_at)",
                [{"exit_policy": None, **r, "seen_at": now} for r in rows],
            )
            conn.execute(
                "INSERT INTO tor_sync(source,synced_at,rows) VALUES(?,?,?) "
                "ON CONFLICT(source) DO UPDATE SET synced_at=excluded.synced_at, "
                "rows=excluded.rows",
                (source, now, len(rows)),
            )
        return len(rows)


def fetch_consensus(http, authorities=DIRECTORY_AUTHORITIES) -> tuple[list, str | None, list[str]]:
    """The signed consensus from whichever authority answers with one.

    Nine servers publish the same document. Trying them in turn is the whole
    reliability argument: on 2026-09-01 two of them returned an ISP block page
    at HTTP 200 while others returned 3 MB of real consensus. A response is
    only accepted once it identifies itself as a consensus, so a middlebox
    cannot empty the lake by answering cheerfully.
    """
    notes: list[str] = []
    for name, hostport in authorities:
        try:
            resp = http.get(f"http://{hostport}{CONSENSUS_PATH}", timeout=90)
            if resp.status_code != 200:
                notes.append(f"{name}: HTTP {resp.status_code}")
                continue
            relays, valid_after = parse_consensus(resp.text)
            if relays:
                notes.append(f"{name}: {len(relays):,} relays")
                return relays, valid_after, notes
            notes.append(f"{name}: answered {len(resp.text)}B that is not a consensus")
        except Exception as exc:  # noqa: BLE001
            notes.append(f"{name}: {type(exc).__name__}")
    return [], None, notes


def enrich_exit_addresses(http, relays: list[dict[str, Any]]) -> int:
    """Add exit IPs that differ from a relay's published OR address.

    A relay may exit from an address it does not advertise — 22 did when
    measured, across 10 distinct IPs. Those are precisely the addresses that
    appear in someone's logs, so without this the most useful lookup of all
    answers "not in the consensus".
    """
    try:
        resp = http.get(
            "https://onionoo.torproject.org/details"
            "?running=true&flag=Exit&fields=nickname,or_addresses,exit_addresses,flags",
            timeout=120)
        resp.raise_for_status()
        payload = resp.json()
    except Exception:  # noqa: BLE001
        return 0
    known = {r["ip"] for r in relays}
    added = 0
    for r in payload.get("relays") or []:
        flags = r.get("flags") or []
        for addr in r.get("exit_addresses") or []:
            ip = addr.strip("[]")
            if not _IPV4.match(ip) or ip in known:
                continue
            known.add(ip)
            added += 1
            relays.append({
                "ip": ip, "nickname": (r.get("nickname") or "")[:64] or None,
                "or_port": None, "dir_port": None, "flags": "E",
                "is_exit": 1, "is_guard": int("Guard" in flags),
                "is_bad_exit": int("BadExit" in flags), "version": None,
                "exit_policy": "exit address (not this relay's OR address)",
            })
    return added


def sync(http, lake: TorLake, *, force: bool = False,
         source: str = "consensus") -> dict[str, Any]:
    """Fetch the relay consensus into the lake.

    Default order is authoritative-first: the signed consensus from the
    directory authorities, then enriched with exit addresses from Onionoo.
    `source="onionoo"` or `"dan"` select a single derived source instead.
    """
    notes: list[str] = []
    relays: list[dict[str, Any]] = []
    valid_after = None

    if source == "consensus":
        relays, valid_after, notes = fetch_consensus(http)
        if relays:
            extra = enrich_exit_addresses(http, relays)
            if extra:
                notes.append(f"onionoo: +{extra} exit address(es) not advertised as OR")
    elif source == "dan":
        if not force and not lake.due_for_fetch():
            return {"fetched": False,
                    "reason": (f"last sync was under "
                               f"{int(MIN_FETCH_INTERVAL.total_seconds()//60)} minutes ago; "
                               f"dan.me.uk serves an empty page to callers who fetch "
                               f"more often"),
                    **lake.status()}
        try:
            resp = http.get(DAN_URL, timeout=90)
            resp.raise_for_status()
            relays = parse_dan(resp.text)
        except Exception as exc:  # noqa: BLE001
            return {"fetched": False, "reason": f"{type(exc).__name__}: {exc}", **lake.status()}
    else:
        try:
            resp = http.get(ONIONOO_URL, timeout=120)
            resp.raise_for_status()
            relays = parse_onionoo(resp.json())
        except Exception as exc:  # noqa: BLE001
            return {"fetched": False, "reason": f"{type(exc).__name__}: {exc}", **lake.status()}

    if not relays:
        # Never wipe the lake on an empty answer. Two authorities returned an
        # ISP block page at HTTP 200, and dan.me.uk drops its data silently
        # when rate limited; treating either as "no relays exist" would turn
        # every later lookup into a confident wrong answer.
        return {"fetched": False,
                "reason": f"{source}: no relay rows — keeping the previous consensus",
                "notes": notes, **lake.status()}

    n = lake.replace_all(relays, source=source)
    return {"fetched": True, "stored": n, "source": source,
            "valid_after": valid_after, "notes": notes, **lake.status()}
