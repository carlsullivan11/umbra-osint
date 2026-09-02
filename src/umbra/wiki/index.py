"""SQLite FTS5 index for wiki pages."""

from __future__ import annotations

import re
import logging
import sqlite3
from pathlib import Path

from umbra.wiki.parse import load_corpus

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.I)
# "RFC 826", "rfc-826", "RFC0826" all mean RFC826 (index ids are unpadded)
_RFC_RE = re.compile(r"\bRFC[\s-]*0*(\d{1,5})\b", re.I)


logger = logging.getLogger(__name__)


class WikiIndex:
    def __init__(self, index_path: Path) -> None:
        self.index_path = Path(index_path)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.index_path))
        conn.row_factory = sqlite3.Row
        return conn

    def rebuild(self, corpus_dir: Path) -> int:
        pages = load_corpus(corpus_dir)
        conn = self._connect()
        try:
            conn.executescript(
                """
                DROP TABLE IF EXISTS wiki_fts;
                DROP TABLE IF EXISTS wiki_page;
                CREATE TABLE wiki_page (
                  slug TEXT PRIMARY KEY,
                  title TEXT NOT NULL,
                  page_type TEXT,
                  summary TEXT,
                  body TEXT,
                  path TEXT,
                  tags TEXT,
                  mitre_ids TEXT,
                  cve_ids TEXT,
                  cwe_ids TEXT,
                  standards TEXT,
                  related TEXT,
                  provenance TEXT,
                  -- The page's own updated_at, so the sitemap can publish a
                  -- lastmod that is true. rebuild() drops and recreates this
                  -- table, so adding a column needs no migration.
                  updated_at TEXT
                );
                CREATE VIRTUAL TABLE wiki_fts USING fts5(
                  slug, title, summary, body, tags, ids, related
                );
                """
            )
            for p in pages:
                ids = " ".join(p.mitre_ids + p.cve_ids + p.cwe_ids + p.standards)
                tags = " ".join(p.tags)
                related = " ".join(p.related)
                conn.execute(
                    """
                    -- OR REPLACE, not plain INSERT: the corpus takes community
                    -- PRs and runs several importers (KEV and NVD both emit
                    -- cve/<ID> slugs). A duplicate previously raised
                    -- IntegrityError and aborted the WHOLE rebuild, leaving
                    -- every lookup empty. Last page wins; duplicates are logged.
                    INSERT OR REPLACE INTO wiki_page(slug, title, page_type, summary, body, path, tags,
                                          mitre_ids, cve_ids, cwe_ids, standards, related, provenance,
                                          updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        p.slug,
                        p.title,
                        p.page_type,
                        p.summary,
                        p.body,
                        p.path,
                        tags,
                        " ".join(p.mitre_ids),
                        " ".join(p.cve_ids),
                        " ".join(p.cwe_ids),
                        " ".join(p.standards),
                        related,
                        p.provenance,
                        p.updated_at,
                    ),
                )
                conn.execute("DELETE FROM wiki_fts WHERE slug = ?", (p.slug,))
                conn.execute(
                    """
                    INSERT INTO wiki_fts(slug, title, summary, body, tags, ids, related)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (p.slug, p.title, p.summary, p.body, tags, ids, related),
                )
            conn.commit()
            indexed = conn.execute("SELECT COUNT(*) FROM wiki_page").fetchone()[0]
            dupes = len(pages) - indexed
            if dupes > 0:
                logger.warning(
                    "%s duplicate slug(s) collapsed during index rebuild "
                    "(last page wins); run scripts/validate_corpus.py to find them",
                    dupes,
                )
            return indexed
        finally:
            conn.close()

    def count(self) -> int:
        """Indexed pages. Lower than the *.md file count — non-pages (README,
        SCHEMA) are deliberately excluded from the corpus."""
        conn = self._connect()
        try:
            return int(conn.execute("SELECT COUNT(*) FROM wiki_page").fetchone()[0])
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    def slugs(self, limit: int = 50_000) -> list[str]:
        """All indexed slugs for sitemap generation (ordered, capped)."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT slug FROM wiki_page ORDER BY slug LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
            return [str(r[0]) for r in rows if r[0]]
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def slugs_with_dates(self, limit: int = 50_000) -> list[tuple[str, str | None]]:
        """(slug, updated_at) for the sitemap's `lastmod`.

        Falls back to dateless rows against an index built before `updated_at`
        existed. A stale index must still yield a complete sitemap — dropping
        4,515 URLs because one column is missing would be a far worse outcome
        than omitting a date, and the daily rebuild fills it in anyway.
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT slug, updated_at FROM wiki_page ORDER BY slug LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
            return [(str(r[0]), (str(r[1]) if r[1] else None)) for r in rows if r[0]]
        except sqlite3.Error:
            return [(s, None) for s in self.slugs(limit)]
        finally:
            conn.close()

    def counts_by_type(self) -> list[tuple[str, int]]:
        """(page_type, count), biggest topic first.

        Entry points for browsing a corpus that was previously reachable only
        by search or a direct link.
        """
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT COALESCE(NULLIF(page_type,''),'other') t, COUNT(*) n "
                "FROM wiki_page GROUP BY t ORDER BY n DESC, t").fetchall()
            return [(str(r[0]), int(r[1])) for r in rows]
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def pages_of_type(self, page_type: str, limit: int = 200,
                      offset: int = 0) -> list[dict]:
        """One topic's pages, paged — 1,704 CVEs must not render at once."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT slug, title, summary, page_type FROM wiki_page "
                "WHERE page_type = ? ORDER BY slug LIMIT ? OFFSET ?",
                (page_type, max(1, int(limit)), max(0, int(offset)))).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []
        finally:
            conn.close()

    def get(self, slug: str) -> dict | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM wiki_page WHERE slug = ?", (slug,)).fetchone()
            return dict(row) if row else None
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def canonical_slug(self, slug: str) -> str | None:
        """The stored spelling of `slug`, matched without regard to case.

        Slugs are case-sensitive (`cve/CVE-2021-44228`), but inbound links and
        typed URLs are routinely lowercased, and every one of those 404s. This
        finds the real spelling so the route can redirect instead of dead-end.
        Returns None when nothing matches, and never the input unchanged — the
        caller only wants this when the exact lookup already missed.
        """
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT slug FROM wiki_page WHERE slug = ? COLLATE NOCASE LIMIT 1",
                (slug,)).fetchone()
            return row["slug"] if row and row["slug"] != slug else None
        except sqlite3.Error:
            return None
        finally:
            conn.close()

    def search(self, query: str, limit: int = 8) -> list[dict]:
        q = (query or "").strip()
        if not q:
            return []
        conn = self._connect()
        try:
            cve = _CVE_RE.search(q)
            if cve:
                token = cve.group(0).upper()
                rows = conn.execute(
                    """
                    SELECT * FROM wiki_page
                    WHERE upper(cve_ids) LIKE ? OR upper(slug) LIKE ? OR upper(title) LIKE ?

                    ORDER BY
                      CASE
                        WHEN upper(slug) LIKE ? THEN 0   -- slug is the id (canonical page)
                        WHEN upper(cve_ids) LIKE ? THEN 1  -- id is declared in frontmatter
                        ELSE 2                            -- only mentioned in prose
                      END,
                      length(slug)
                    LIMIT ?
                    """,
                    (
                        f"%{token}%", f"%{token}%", f"%{token}%",
                        f"%/{token}", f"%{token}%",
                        limit,
                    ),
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            rfc = _RFC_RE.search(q)
            if rfc:
                token = f"RFC{int(rfc.group(1))}"
                rows = conn.execute(
                    """
                    SELECT * FROM wiki_page
                    WHERE upper(standards) LIKE ? OR upper(slug) LIKE ? OR upper(title) LIKE ?
                    ORDER BY
                      CASE
                        WHEN upper(slug) LIKE ? THEN 0   -- slug is the id (canonical page)
                        WHEN upper(standards) LIKE ? THEN 1
                        ELSE 2
                      END,
                      length(slug)
                    LIMIT ?
                    """,
                    (
                        f"%{token}%", f"%{token}%", f"%{token}%",
                        f"%/{token}", f"%{token}%",
                        limit,
                    ),
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            cwe = _CWE_RE.search(q)
            if cwe:
                token = cwe.group(0).upper()
                rows = conn.execute(
                    """
                    SELECT * FROM wiki_page
                    WHERE upper(cwe_ids) LIKE ? OR upper(slug) LIKE ? OR upper(title) LIKE ?
                    ORDER BY
                      CASE
                        WHEN upper(slug) LIKE ? THEN 0   -- slug is the id (canonical page)
                        WHEN upper(cwe_ids) LIKE ? THEN 1
                        ELSE 2
                      END,
                      length(slug)
                    LIMIT ?
                    """,
                    (
                        f"%{token}%", f"%{token}%", f"%{token}%",
                        f"%/{token}", f"%{token}%",
                        limit,
                    ),
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            mitre = _MITRE_RE.search(q)
            if mitre:
                token = mitre.group(0).upper()
                rows = conn.execute(
                    """
                    SELECT * FROM wiki_page
                    WHERE upper(mitre_ids) LIKE ? OR upper(slug) LIKE ? OR upper(title) LIKE ?

                    ORDER BY
                      CASE
                        WHEN upper(slug) LIKE ? THEN 0   -- slug is the id (canonical page)
                        WHEN upper(mitre_ids) LIKE ? THEN 1  -- id is declared in frontmatter
                        ELSE 2                            -- only mentioned in prose
                      END,
                      length(slug)
                    LIMIT ?
                    """,
                    (
                        f"%{token}%", f"%{token}%", f"%{token}%",
                        f"%/{token}", f"%{token}%",
                        limit,
                    ),
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]

            tokens = re.findall(r"[A-Za-z0-9_\-\.]+", q)
            if not tokens:
                return []
            # Prefer phrase-ish: all tokens
            fts_q = " AND ".join(tokens)
            try:
                rows = conn.execute(
                    """
                    SELECT p.*
                    FROM wiki_fts f
                    JOIN wiki_page p ON p.slug = f.slug
                    WHERE wiki_fts MATCH ?
                    LIMIT ?
                    """,
                    (fts_q, limit),
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            except sqlite3.OperationalError:
                pass
            # OR tokens
            try:
                fts_or = " OR ".join(tokens)
                rows = conn.execute(
                    """
                    SELECT p.*
                    FROM wiki_fts f
                    JOIN wiki_page p ON p.slug = f.slug
                    WHERE wiki_fts MATCH ?
                    LIMIT ?
                    """,
                    (fts_or, limit),
                ).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            except sqlite3.OperationalError:
                pass
            like = f"%{q}%"
            rows = conn.execute(
                """
                SELECT * FROM wiki_page
                WHERE title LIKE ? OR summary LIKE ? OR body LIKE ? OR slug LIKE ? OR tags LIKE ?
                LIMIT ?
                """,
                (like, like, like, like, like, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
