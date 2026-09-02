"""High-level wiki service: update corpus, rebuild index, lookup."""

from __future__ import annotations

import logging

import os
import shutil
import subprocess
from pathlib import Path

from umbra.wiki.index import WikiIndex
from umbra.wiki.paths import default_corpus_dir, default_index_path

logger = logging.getLogger(__name__)


DEFAULT_WIKI_REPO = os.environ.get(
    "UMBRA_WIKI_REPO",
    "https://github.com/example-org/umbra-wiki.git",
)


class WikiService:
    def __init__(
        self,
        corpus_dir: Path | None = None,
        index_path: Path | None = None,
    ) -> None:
        self.corpus_dir = Path(corpus_dir) if corpus_dir else default_corpus_dir()
        self.index_path = Path(index_path) if index_path else default_index_path()
        self.index = WikiIndex(self.index_path)

    def rebuild_index(self) -> int:
        return self.index.rebuild(self.corpus_dir)

    def lookup(self, query: str, limit: int = 8) -> list[dict]:
        if not self.index_path.is_file():
            if self.corpus_dir.is_dir():
                self.rebuild_index()
            else:
                # No corpus at all is a normal state on a fresh install, not a
                # fault. Silence is correct here.
                return []
        hits = self.index.search(query, limit=limit)
        if not hits:
            self._check_index_health()
        return hits

    def explain(self, query: str, *, settings=None) -> dict | None:
        """Why a lookup found nothing — when the query was a real identifier.

        Returns None for free text, where "no results" is a complete answer.
        For a well-formed CVE / RFC / CWE / CAPEC / ATT&CK id it distinguishes
        "outside this corpus's declared scope" from "not a real document", and
        surfaces what Umbra knows from elsewhere. The corpus holds CISA KEV, not
        all 384,910 CVEs; saying "no hits" for POODLE while the EPSS lake next
        door scores it 0.99999 is the lookup-shaped version of calling an
        unchecked source clean.
        """
        from umbra.wiki.identifiers import explain_miss, recognise

        ident = recognise(query)
        if ident is None:
            return None

        epss = None
        if ident.kind == "cve":
            try:
                from umbra.core.config import get_settings
                from umbra.lake.epss import EpssLake

                lake = EpssLake.from_settings(settings or get_settings())
                try:
                    epss = lake.score(ident.canonical)
                finally:
                    lake.close()
            except Exception:  # noqa: BLE001
                epss = None  # a missing lake must not break a lookup

        return explain_miss(ident, epss=epss)

    def _check_index_health(self) -> None:
        """Distinguish "no match" from "the index is empty" (E2).

        This is the S9 failure mode: one duplicate slug aborted the whole rebuild
        and every lookup silently returned nothing, which reads exactly like a
        miss. Only fires when the corpus has pages on disk but the index has
        none — a real miss stays silent.
        """
        try:
            if self.index.count() > 0 or not self.corpus_dir.is_dir():
                return
            pages_on_disk = sum(1 for _ in self.corpus_dir.rglob("*.md"))
            if pages_on_disk == 0:
                return

            from umbra.ops.events import emit

            emit(
                severity="S3",
                kind="wiki_miss",
                title=f"wiki index is empty while {pages_on_disk} pages exist on disk",
                detail={
                    "corpus_dir": str(self.corpus_dir),
                    "index_path": str(self.index_path),
                    "pages_on_disk": pages_on_disk,
                    "indexed": 0,
                    "hint": "rebuild the index (`umbra wiki update --no-git`); "
                            "a duplicate slug can abort a rebuild",
                },
                fingerprint_key="wiki_index_empty",
                source="api",
            )
        except Exception:  # noqa: BLE001 - a health check must not break lookup
            logger.warning("wiki index health check failed", exc_info=True)

    def get(self, slug: str) -> dict | None:
        if not self.index_path.is_file() and self.corpus_dir.is_dir():
            self.rebuild_index()
        return self.index.get(slug)

    def counts_by_type(self) -> list[tuple[str, int]]:
        return self.index.counts_by_type()

    def pages_of_type(self, page_type: str, limit: int = 200, offset: int = 0) -> list[dict]:
        return self.index.pages_of_type(page_type, limit=limit, offset=offset)

    def canonical_slug(self, slug: str) -> str | None:
        """Case-insensitive match for a slug that missed. See WikiIndex."""
        try:
            return self.index.canonical_slug(slug)
        except Exception:  # noqa: BLE001
            return None

    def update_from_git(self, repo_url: str | None = None) -> str:
        """Clone or pull umbra-wiki into corpus_dir."""
        url = repo_url or DEFAULT_WIKI_REPO
        self.corpus_dir.parent.mkdir(parents=True, exist_ok=True)
        git_dir = self.corpus_dir / ".git"
        if git_dir.is_dir():
            subprocess.run(
                ["git", "-C", str(self.corpus_dir), "pull", "--ff-only"],
                check=True,
                capture_output=True,
                text=True,
            )
            action = "pulled"
        elif self.corpus_dir.is_dir() and any(self.corpus_dir.iterdir()):
            # non-git corpus (local seed) — leave in place
            action = "local-corpus"
        else:
            if self.corpus_dir.exists():
                shutil.rmtree(self.corpus_dir)
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(self.corpus_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            action = "cloned"
        n = self.rebuild_index()
        return f"{action} {self.corpus_dir} · indexed {n} pages"
