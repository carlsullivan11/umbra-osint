"""Owned people / obituary lake — durable person-map corpus.

Collectors discover public obituaries, parse them, and **upsert** into this
SQLite lake so Umbra builds a searchable people database over time (links +
structured fields + kinship), independent of any single case graph.

Path: ``$UMBRA_DATA_DIR/lake/people.sqlite``

Lawful public sources only; no paywall bypass. Records are candidates until
operator verification on the case graph.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS people (
  id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  norm_name TEXT NOT NULL,
  birth_date TEXT,
  death_date TEXT,
  age INTEGER,
  birth_place TEXT,
  death_place TEXT,
  residence TEXT,
  occupation TEXT,
  funeral_home TEXT,
  cemetery TEXT,
  military TEXT,
  aka_json TEXT,
  props_json TEXT,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_people_norm ON people(norm_name);
CREATE INDEX IF NOT EXISTS idx_people_death ON people(death_date);

CREATE TABLE IF NOT EXISTS obituary_sources (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  person_id TEXT NOT NULL,
  title TEXT,
  source_host TEXT,
  published_date TEXT,
  excerpt TEXT,
  parsed_json TEXT,
  http_status INTEGER,
  fetched_at TEXT NOT NULL,
  FOREIGN KEY(person_id) REFERENCES people(id)
);
CREATE INDEX IF NOT EXISTS idx_obit_person ON obituary_sources(person_id);
CREATE INDEX IF NOT EXISTS idx_obit_host ON obituary_sources(source_host);

CREATE TABLE IF NOT EXISTS kinship (
  id TEXT PRIMARY KEY,
  person_id TEXT NOT NULL,
  relative_name TEXT NOT NULL,
  relative_norm TEXT NOT NULL,
  role TEXT,
  living INTEGER,
  evidence_span TEXT,
  source_url TEXT,
  confidence REAL,
  first_seen TEXT NOT NULL,
  confirmation TEXT NOT NULL DEFAULT 'unknown',
  FOREIGN KEY(person_id) REFERENCES people(id)
);
CREATE INDEX IF NOT EXISTS idx_kin_person ON kinship(person_id);
CREATE INDEX IF NOT EXISTS idx_kin_rel ON kinship(relative_norm);

CREATE TABLE IF NOT EXISTS county_sources (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  person_name TEXT,
  person_norm TEXT,
  region TEXT,
  kind TEXT,
  title TEXT,
  source_host TEXT,
  excerpt TEXT,
  name_hit INTEGER NOT NULL DEFAULT 0,
  http_status INTEGER,
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_county_person ON county_sources(person_norm);
CREATE INDEX IF NOT EXISTS idx_county_host ON county_sources(source_host);

CREATE TABLE IF NOT EXISTS land_facts (
  id TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  person_name TEXT,
  person_norm TEXT,
  apn TEXT,
  situs TEXT,
  region TEXT,
  excerpt TEXT,
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_land_person ON land_facts(person_norm);

CREATE TABLE IF NOT EXISTS corp_facts (
  id TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  person_name TEXT,
  person_norm TEXT,
  org_name TEXT NOT NULL,
  file_number TEXT,
  region TEXT,
  excerpt TEXT,
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_corp_person ON corp_facts(person_norm);

CREATE TABLE IF NOT EXISTS sor_sources (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL UNIQUE,
  person_name TEXT,
  person_norm TEXT,
  region TEXT,
  source_host TEXT,
  title TEXT,
  name_hit INTEGER NOT NULL DEFAULT 0,
  excerpt TEXT,
  parsed_json TEXT,
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sor_person ON sor_sources(person_norm);

CREATE TABLE IF NOT EXISTS sor_facts (
  id TEXT PRIMARY KEY,
  source_url TEXT NOT NULL,
  person_name TEXT,
  person_norm TEXT,
  registry_id TEXT,
  dob TEXT,
  address TEXT,
  aliases_json TEXT,
  offenses_json TEXT,
  tier TEXT,
  excerpt TEXT,
  fetched_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sorf_person ON sor_facts(person_norm);
"""


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _norm_name(name: str) -> str:
    return " ".join((name or "").lower().split())


def _id(*parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return h[:32]


def default_path(settings=None) -> Path:
    if settings is not None:
        base = Path(settings.data_dir) / "lake"
    else:
        from umbra.core.config import get_settings

        base = get_settings().data_dir / "lake"
    base.mkdir(parents=True, exist_ok=True)
    return base / "people.sqlite"


@dataclass
class PeopleLakeStatus:
    path: str
    people: int
    obituaries: int
    kinship_edges: int
    county_records: int = 0
    land_facts: int = 0
    corp_facts: int = 0
    sor_records: int = 0
    synced: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "people": self.people,
            "obituaries": self.obituaries,
            "kinship_edges": self.kinship_edges,
            "county_records": self.county_records,
            "land_facts": self.land_facts,
            "corp_facts": self.corp_facts,
            "sor_records": self.sor_records,
            "synced": self.synced,
        }


class PeopleLake:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(kinship)")}
        if "confirmation" not in cols:
            self._conn.execute(
                "ALTER TABLE kinship ADD COLUMN confirmation TEXT NOT NULL DEFAULT 'unknown'"
            )

    @classmethod
    def from_settings(cls, settings) -> "PeopleLake":
        return cls(default_path(settings))

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def status(self) -> PeopleLakeStatus:
        with self._lock:
            people = self._conn.execute("SELECT COUNT(*) FROM people").fetchone()[0]
            obits = self._conn.execute("SELECT COUNT(*) FROM obituary_sources").fetchone()[0]
            kin = self._conn.execute("SELECT COUNT(*) FROM kinship").fetchone()[0]
            try:
                county = self._conn.execute("SELECT COUNT(*) FROM county_sources").fetchone()[0]
            except sqlite3.OperationalError:
                county = 0
            try:
                land = self._conn.execute("SELECT COUNT(*) FROM land_facts").fetchone()[0]
            except sqlite3.OperationalError:
                land = 0
            try:
                corp = self._conn.execute("SELECT COUNT(*) FROM corp_facts").fetchone()[0]
            except sqlite3.OperationalError:
                corp = 0
            try:
                sor = self._conn.execute("SELECT COUNT(*) FROM sor_sources").fetchone()[0]
            except sqlite3.OperationalError:
                sor = 0
        return PeopleLakeStatus(
            path=str(self.path),
            people=people,
            obituaries=obits,
            kinship_edges=kin,
            county_records=county,
            land_facts=land,
            corp_facts=corp,
            sor_records=sor,
            synced=people > 0 or obits > 0 or county > 0 or land > 0 or corp > 0 or sor > 0,
        )

    def upsert_person_from_parse(
        self,
        *,
        decedent_name: str,
        parse: dict[str, Any],
        source_url: str,
        title: str | None = None,
        source_host: str | None = None,
        http_status: int | None = None,
        excerpt: str | None = None,
        confidence: float = 0.5,
    ) -> str:
        """Write/merge person + obituary source + kinship rows. Returns person_id."""
        name = (decedent_name or parse.get("decedent_name") or "").strip()
        if not name:
            raise ValueError("decedent_name required")
        norm = _norm_name(name)
        pid = _id("person", norm)
        now = _now()
        aka = parse.get("aka") or []
        props = {
            "service_info": parse.get("service_info"),
            "raw_survivor_clauses": (parse.get("raw_survivor_clauses") or [])[:5],
        }

        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM people WHERE id = ?", (pid,)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    """
                    INSERT INTO people (
                      id, full_name, norm_name, birth_date, death_date, age,
                      birth_place, death_place, residence, occupation,
                      funeral_home, cemetery, military, aka_json, props_json,
                      first_seen, last_seen
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        pid,
                        name,
                        norm,
                        parse.get("birth_date"),
                        parse.get("death_date"),
                        parse.get("age"),
                        parse.get("birth_place"),
                        parse.get("death_place"),
                        parse.get("residence"),
                        parse.get("occupation"),
                        parse.get("funeral_home"),
                        parse.get("cemetery"),
                        parse.get("military"),
                        json.dumps(aka, ensure_ascii=False),
                        json.dumps(props, ensure_ascii=False),
                        now,
                        now,
                    ),
                )
            else:
                # Fill empty fields; always bump last_seen
                self._conn.execute(
                    """
                    UPDATE people SET
                      last_seen = ?,
                      birth_date = COALESCE(birth_date, ?),
                      death_date = COALESCE(death_date, ?),
                      age = COALESCE(age, ?),
                      birth_place = COALESCE(birth_place, ?),
                      death_place = COALESCE(death_place, ?),
                      residence = COALESCE(residence, ?),
                      occupation = COALESCE(occupation, ?),
                      funeral_home = COALESCE(funeral_home, ?),
                      cemetery = COALESCE(cemetery, ?),
                      military = COALESCE(military, ?),
                      aka_json = CASE
                        WHEN aka_json IS NULL OR aka_json = '[]' THEN ?
                        ELSE aka_json END
                    WHERE id = ?
                    """,
                    (
                        now,
                        parse.get("birth_date"),
                        parse.get("death_date"),
                        parse.get("age"),
                        parse.get("birth_place"),
                        parse.get("death_place"),
                        parse.get("residence"),
                        parse.get("occupation"),
                        parse.get("funeral_home"),
                        parse.get("cemetery"),
                        parse.get("military"),
                        json.dumps(aka, ensure_ascii=False),
                        pid,
                    ),
                )

            if source_url:
                oid = _id("obit", source_url.strip())
                host = source_host
                if not host:
                    try:
                        from urllib.parse import urlsplit

                        host = (urlsplit(source_url).hostname or "").lower()
                    except Exception:
                        host = None
                self._conn.execute(
                    """
                    INSERT INTO obituary_sources (
                      id, url, person_id, title, source_host, published_date,
                      excerpt, parsed_json, http_status, fetched_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(url) DO UPDATE SET
                      title = COALESCE(excluded.title, obituary_sources.title),
                      excerpt = COALESCE(excluded.excerpt, obituary_sources.excerpt),
                      parsed_json = excluded.parsed_json,
                      http_status = COALESCE(excluded.http_status, obituary_sources.http_status),
                      fetched_at = excluded.fetched_at
                    """,
                    (
                        oid,
                        source_url.strip(),
                        pid,
                        title,
                        host,
                        parse.get("death_date"),
                        (excerpt or "")[:2000] or None,
                        json.dumps(parse, ensure_ascii=False),
                        http_status,
                        now,
                    ),
                )

                # kinship from survivors + preceded
                for bucket, living_flag in (
                    (parse.get("survivors") or [], 1),
                    (parse.get("preceded") or [], 0),
                ):
                    for s in bucket:
                        rname = (s.get("name") if isinstance(s, dict) else getattr(s, "name", "")) or ""
                        rname = rname.strip()
                        if not rname:
                            continue
                        role = (
                            s.get("role")
                            if isinstance(s, dict)
                            else getattr(s, "role", "unknown")
                        ) or "unknown"
                        span = (
                            s.get("evidence_span")
                            if isinstance(s, dict)
                            else getattr(s, "evidence_span", "")
                        ) or ""
                        rnorm = _norm_name(rname)
                        kid = _id("kin", pid, rnorm, role, source_url)
                        self._conn.execute(
                            """
                            INSERT OR IGNORE INTO kinship (
                              id, person_id, relative_name, relative_norm, role,
                              living, evidence_span, source_url, confidence, first_seen
                            ) VALUES (?,?,?,?,?,?,?,?,?,?)
                            """,
                            (
                                kid,
                                pid,
                                rname,
                                rnorm,
                                role,
                                living_flag,
                                span[:400],
                                source_url,
                                confidence,
                                now,
                            ),
                        )

            self._conn.execute(
                "INSERT INTO meta(key,value) VALUES('last_upsert', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (now,),
            )
            self._conn.commit()
        return pid

    def lookup_name(self, name: str, *, limit: int = 20) -> list[dict[str, Any]]:
        norm = _norm_name(name)
        like = f"%{norm}%"
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT p.*, (
                  SELECT COUNT(*) FROM obituary_sources o WHERE o.person_id = p.id
                ) AS obit_count,
                (
                  SELECT COUNT(*) FROM kinship k WHERE k.person_id = p.id
                ) AS kin_count
                FROM people p
                WHERE p.norm_name = ? OR p.norm_name LIKE ? OR p.full_name LIKE ?
                ORDER BY p.last_seen DESC
                LIMIT ?
                """,
                (norm, like, f"%{name}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def obituaries_for_person(self, person_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM obituary_sources WHERE person_id = ? ORDER BY fetched_at DESC",
                (person_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def kinship_for_person(self, person_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM kinship WHERE person_id = ? ORDER BY role, relative_name",
                (person_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def confirm_kinship(
        self,
        person_name: str,
        relative_name: str,
        verdict: str,
    ) -> int:
        """Mark kinship candidate(s) true/false/unknown. Returns rows updated."""
        v = (verdict or "").strip().lower()
        if v in {"true", "t", "yes", "confirmed"}:
            v = "true"
        elif v in {"false", "f", "no", "rejected"}:
            v = "false"
        elif v in {"unknown", "u", "clear", "reset"}:
            v = "unknown"
        else:
            raise ValueError("verdict must be true, false, or unknown")
        pnorm = _norm_name(person_name)
        rnorm = _norm_name(relative_name)
        with self._lock:
            people = self._conn.execute(
                "SELECT id FROM people WHERE norm_name = ? OR full_name LIKE ?",
                (pnorm, f"%{person_name}%"),
            ).fetchall()
            if not people:
                return 0
            ids = [row[0] for row in people]
            placeholders = ",".join("?" * len(ids))
            cur = self._conn.execute(
                f"""
                UPDATE kinship SET confirmation = ?
                WHERE person_id IN ({placeholders})
                  AND (relative_norm = ? OR relative_name LIKE ?)
                """,
                (v, *ids, rnorm, f"%{relative_name}%"),
            )
            self._conn.commit()
            return int(cur.rowcount or 0)

    def upsert_county_source(
        self,
        *,
        url: str,
        person_name: str | None = None,
        region: str | None = None,
        kind: str | None = None,
        title: str | None = None,
        excerpt: str | None = None,
        name_hit: bool = False,
        http_status: int | None = None,
    ) -> str:
        url = (url or "").strip()
        if not url:
            raise ValueError("url required")
        host = ""
        try:
            from urllib.parse import urlsplit

            host = (urlsplit(url).hostname or "").lower()
        except Exception:
            pass
        cid = _id("county", url.lower())
        now = _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO county_sources (
                  id, url, person_name, person_norm, region, kind, title,
                  source_host, excerpt, name_hit, http_status, fetched_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(url) DO UPDATE SET
                  person_name = COALESCE(excluded.person_name, county_sources.person_name),
                  person_norm = COALESCE(excluded.person_norm, county_sources.person_norm),
                  region = COALESCE(excluded.region, county_sources.region),
                  kind = COALESCE(excluded.kind, county_sources.kind),
                  title = COALESCE(excluded.title, county_sources.title),
                  excerpt = COALESCE(excluded.excerpt, county_sources.excerpt),
                  name_hit = MAX(county_sources.name_hit, excluded.name_hit),
                  http_status = COALESCE(excluded.http_status, county_sources.http_status),
                  fetched_at = excluded.fetched_at
                """,
                (
                    cid,
                    url,
                    person_name,
                    _norm_name(person_name or ""),
                    region,
                    kind,
                    (title or "")[:200] or None,
                    host,
                    (excerpt or "")[:2000] or None,
                    1 if name_hit else 0,
                    http_status,
                    now,
                ),
            )
            self._conn.commit()
        return cid

    def county_for_name(self, name: str, limit: int = 20) -> list[dict[str, Any]]:
        n = _norm_name(name)
        if not n:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM county_sources
                WHERE person_norm LIKE ? OR person_name LIKE ?
                ORDER BY name_hit DESC, fetched_at DESC
                LIMIT ?
                """,
                (f"%{n}%", f"%{name}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_land_fact(
        self,
        *,
        source_url: str,
        person_name: str | None = None,
        apn: str | None = None,
        situs: str | None = None,
        region: str | None = None,
        excerpt: str | None = None,
    ) -> str:
        url = (source_url or "").strip()
        if not url or not (apn or situs):
            raise ValueError("land fact needs url and apn or situs")
        lid = _id("land", url.lower(), (apn or "").lower(), (situs or "").lower())
        now = _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO land_facts (
                  id, source_url, person_name, person_norm, apn, situs, region, excerpt, fetched_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  excerpt = COALESCE(excluded.excerpt, land_facts.excerpt),
                  fetched_at = excluded.fetched_at
                """,
                (
                    lid,
                    url,
                    person_name,
                    _norm_name(person_name or ""),
                    apn,
                    situs,
                    region,
                    (excerpt or "")[:500] or None,
                    now,
                ),
            )
            self._conn.commit()
        return lid

    def upsert_corp_fact(
        self,
        *,
        source_url: str,
        org_name: str,
        person_name: str | None = None,
        file_number: str | None = None,
        region: str | None = None,
        excerpt: str | None = None,
    ) -> str:
        url = (source_url or "").strip()
        org = (org_name or "").strip()
        if not url or not org:
            raise ValueError("corp fact needs url and org_name")
        cid = _id("corp", url.lower(), org.lower())
        now = _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO corp_facts (
                  id, source_url, person_name, person_norm, org_name, file_number,
                  region, excerpt, fetched_at
                ) VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  file_number = COALESCE(excluded.file_number, corp_facts.file_number),
                  excerpt = COALESCE(excluded.excerpt, corp_facts.excerpt),
                  fetched_at = excluded.fetched_at
                """,
                (
                    cid,
                    url,
                    person_name,
                    _norm_name(person_name or ""),
                    org,
                    file_number,
                    region,
                    (excerpt or "")[:500] or None,
                    now,
                ),
            )
            self._conn.commit()
        return cid

    def land_for_name(self, name: str, limit: int = 20) -> list[dict[str, Any]]:
        n = _norm_name(name)
        if not n:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM land_facts
                WHERE person_norm LIKE ? OR person_name LIKE ?
                ORDER BY fetched_at DESC LIMIT ?
                """,
                (f"%{n}%", f"%{name}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def corps_for_name(self, name: str, limit: int = 20) -> list[dict[str, Any]]:
        n = _norm_name(name)
        if not n:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM corp_facts
                WHERE person_norm LIKE ? OR person_name LIKE ? OR org_name LIKE ?
                ORDER BY fetched_at DESC LIMIT ?
                """,
                (f"%{n}%", f"%{name}%", f"%{name}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def upsert_sor_source(
        self,
        *,
        url: str,
        person_name: str | None = None,
        region: str | None = None,
        title: str | None = None,
        name_hit: bool = False,
        excerpt: str | None = None,
        parsed: dict[str, Any] | None = None,
    ) -> str:
        u = (url or "").strip()
        if not u:
            raise ValueError("sor source needs url")
        from urllib.parse import urlsplit

        host = urlsplit(u).netloc.lower()
        sid = _id("sor", u.lower())
        now = _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sor_sources (
                  id, url, person_name, person_norm, region, source_host, title,
                  name_hit, excerpt, parsed_json, fetched_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(url) DO UPDATE SET
                  name_hit = MAX(sor_sources.name_hit, excluded.name_hit),
                  excerpt = COALESCE(excluded.excerpt, sor_sources.excerpt),
                  parsed_json = COALESCE(excluded.parsed_json, sor_sources.parsed_json),
                  fetched_at = excluded.fetched_at
                """,
                (
                    sid,
                    u,
                    person_name,
                    _norm_name(person_name or ""),
                    region,
                    host,
                    title,
                    1 if name_hit else 0,
                    (excerpt or "")[:500] or None,
                    json.dumps(parsed) if parsed else None,
                    now,
                ),
            )
            self._conn.commit()
        return sid

    def upsert_sor_fact(
        self,
        *,
        source_url: str,
        person_name: str,
        registry_id: str | None = None,
        dob: str | None = None,
        address: str | None = None,
        aliases: list[str] | None = None,
        offenses: list[str] | None = None,
        tier: str | None = None,
        excerpt: str | None = None,
    ) -> str:
        url = (source_url or "").strip()
        if not url or not person_name:
            raise ValueError("sor fact needs url and person")
        fid = _id("sorf", url.lower(), _norm_name(person_name), (registry_id or "").lower())
        now = _now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sor_facts (
                  id, source_url, person_name, person_norm, registry_id, dob, address,
                  aliases_json, offenses_json, tier, excerpt, fetched_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  dob = COALESCE(excluded.dob, sor_facts.dob),
                  address = COALESCE(excluded.address, sor_facts.address),
                  excerpt = COALESCE(excluded.excerpt, sor_facts.excerpt),
                  fetched_at = excluded.fetched_at
                """,
                (
                    fid,
                    url,
                    person_name,
                    _norm_name(person_name),
                    registry_id,
                    dob,
                    address,
                    json.dumps(aliases or []),
                    json.dumps(offenses or []),
                    tier,
                    (excerpt or "")[:500] or None,
                    now,
                ),
            )
            self._conn.commit()
        return fid

    def sor_for_name(self, name: str, limit: int = 20) -> list[dict[str, Any]]:
        n = _norm_name(name)
        if not n:
            return []
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM sor_facts
                WHERE person_norm LIKE ? OR person_name LIKE ?
                ORDER BY fetched_at DESC LIMIT ?
                """,
                (f"%{n}%", f"%{name}%", limit),
            ).fetchall()
        return [dict(r) for r in rows]
