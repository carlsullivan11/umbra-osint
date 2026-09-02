"""Tests for wiki parse + FTS lookup."""

from __future__ import annotations

from pathlib import Path

import pytest

from umbra.wiki.index import WikiIndex
from umbra.wiki.parse import load_corpus, parse_wiki_markdown
from umbra.wiki.service import WikiService

FIX = Path(__file__).parent / "fixtures" / "wiki_corpus"


def test_parse_frontmatter_lists():
    text = """---
slug: protocol/arp
title: ARP
page_type: protocol
tags: [network, l2]
mitre_ids:
  - T1557.002
related:
  - concept/arp-cache-poisoning
provenance: curated
---

Body about ARP poisoning and caches.
"""
    p = parse_wiki_markdown(text)
    assert p is not None
    assert p.slug == "protocol/arp"
    assert "network" in p.tags
    assert "T1557.002" in p.mitre_ids
    assert "concept/arp-cache-poisoning" in p.related


def test_load_fixture_corpus():
    pages = load_corpus(FIX)
    assert len(pages) >= 3
    slugs = {p.slug for p in pages}
    assert "protocol/arp" in slugs or any("arp" in s for s in slugs)


def test_index_search_arp(tmp_path: Path):
    # ensure fixture has arp - may need copy from umbra-wiki
    if not list(FIX.rglob("*.md")):
        pytest.skip("no fixture pages")
    idx_path = tmp_path / "idx.sqlite"
    idx = WikiIndex(idx_path)
    n = idx.rebuild(FIX)
    assert n >= 1
    hits = idx.search("ARP poisoning", limit=5)
    assert hits, "expected ARP-related hit"
    titles = " ".join(h["title"].lower() for h in hits)
    assert "arp" in titles


def test_lookup_service(tmp_path: Path):
    svc = WikiService(corpus_dir=FIX, index_path=tmp_path / "w.sqlite")
    hits = svc.lookup("DNS")
    assert hits


# --- duplicate slugs must not destroy the whole corpus (S3 guard) ---------

def test_duplicate_slug_does_not_break_rebuild(tmp_path):
    """A public corpus takes PRs and runs multiple importers. Before this,
    two pages sharing a slug raised IntegrityError and the ENTIRE index
    rebuild failed — one bad page made every lookup return nothing. A
    duplicate must be tolerated (last one wins) so the corpus stays usable."""
    from umbra.wiki.service import WikiService

    page = """---
slug: cve/CVE-2021-44228
title: "{t}"
page_type: cve
---
body {t}
"""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "x.md").write_text(page.format(t="from-kev"))
    (tmp_path / "b" / "y.md").write_text(page.format(t="from-nvd"))

    svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "idx.sqlite")
    n = svc.rebuild_index()          # must not raise
    assert n >= 1
    assert svc.lookup("CVE-2021-44228"), "corpus must remain queryable"


def test_distinct_slugs_all_indexed(tmp_path):
    from umbra.wiki.service import WikiService

    # top-level .md files are skipped by design (README/SCHEMA), so pages must
    # live in a subdirectory like the real corpus
    sub = tmp_path / "imports" / "nvd-cve"
    sub.mkdir(parents=True)
    for i in range(3):
        (sub / f"p{i}.md").write_text(
            f'---\nslug: cve/CVE-2024-000{i}\ntitle: "t{i}"\npage_type: cve\n---\nbody\n'
        )
    svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "idx.sqlite")
    assert svc.rebuild_index() == 3


# --- exact identifier lookups must rank the canonical page first (S4) -----

def _corpus_with_id_pages(tmp_path):
    """A technique page plus two prose pages that merely mention the id —
    exactly the shape that mis-ranked in the real corpus."""
    sub = tmp_path / "imports" / "mitre-attack" / "T1557"
    sub.mkdir(parents=True)
    (sub / "T1557.002.md").write_text(
        '---\nslug: technique/T1557.002\ntitle: "T1557.002 — ARP Cache Poisoning"\n'
        'page_type: technique\nmitre_ids: [T1557.002]\n---\nCanonical technique page.\n'
    )
    cur = tmp_path / "curated" / "concept"
    cur.mkdir(parents=True)
    # curated pages that only *mention* the id in prose
    (cur / "arp.md").write_text(
        '---\nslug: concept/arp-cache-poisoning\ntitle: "ARP cache poisoning"\n'
        'page_type: concept\nmitre_ids: [T1557.002]\n---\n'
        'ARP poisoning maps to T1557.002 in ATT&CK. ' * 20 + "\n"
    )
    (cur / "proto.md").write_text(
        '---\nslug: protocol/arp\ntitle: "ARP"\npage_type: protocol\n'
        'mitre_ids: [T1557.002]\n---\nSee T1557.002. ' * 20 + "\n"
    )
    return tmp_path


def test_exact_technique_id_ranks_its_own_page_first(tmp_path):
    """Regression: searching T1557.002 returned the curated concept page first
    and the actual technique page THIRD, because the id fast-path had no
    ORDER BY and fell back to insert order. Looking up a precise identifier
    must land on that identifier's page."""
    from umbra.wiki.service import WikiService

    root = _corpus_with_id_pages(tmp_path)
    svc = WikiService(corpus_dir=root, index_path=root / "idx.sqlite")
    svc.rebuild_index()

    rows = svc.lookup("T1557.002", limit=5)
    assert rows, "no results"
    assert rows[0]["slug"] == "technique/T1557.002", [r["slug"] for r in rows]


def test_exact_cve_id_ranks_its_own_page_first(tmp_path):
    from umbra.wiki.service import WikiService

    imports = tmp_path / "imports" / "cisa-kev" / "2021"
    imports.mkdir(parents=True)
    (imports / "CVE-2021-44228.md").write_text(
        '---\nslug: cve/CVE-2021-44228\ntitle: "CVE-2021-44228"\npage_type: cve\n'
        'cve_ids: [CVE-2021-44228]\n---\nCanonical.\n'
    )
    cur = tmp_path / "curated" / "concept"
    cur.mkdir(parents=True)
    (cur / "log4shell.md").write_text(
        '---\nslug: concept/log4shell\ntitle: "Log4Shell"\npage_type: concept\n'
        'cve_ids: [CVE-2021-44228]\n---\n' + "Discussion of CVE-2021-44228. " * 30
    )
    svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "idx.sqlite")
    svc.rebuild_index()
    rows = svc.lookup("CVE-2021-44228", limit=5)
    assert rows[0]["slug"] == "cve/CVE-2021-44228", [r["slug"] for r in rows]


def test_related_pages_still_returned_after_the_exact_match(tmp_path):
    """Boosting the canonical page must not hide the contextual pages."""
    from umbra.wiki.service import WikiService

    root = _corpus_with_id_pages(tmp_path)
    svc = WikiService(corpus_dir=root, index_path=root / "idx.sqlite")
    svc.rebuild_index()
    slugs = [r["slug"] for r in svc.lookup("T1557.002", limit=5)]
    assert "concept/arp-cache-poisoning" in slugs


def test_exact_cwe_id_ranks_its_own_page_first(tmp_path):
    """Same defect class as the CVE/ATT&CK fix, which did not cover CWE because
    no CWE pages existed yet: `lookup CWE-79` returned weakness/CWE-352 (a page
    that merely references 79) instead of the CWE-79 page itself."""
    from umbra.wiki.service import WikiService

    imports = tmp_path / "imports" / "mitre-cwe"
    imports.mkdir(parents=True)
    (imports / "CWE-79.md").write_text(
        '---\nslug: weakness/CWE-79\ntitle: "CWE-79 — Cross-site Scripting"\n'
        'page_type: weakness\ncwe_ids: [CWE-79]\n---\nCanonical XSS weakness page.\n'
    )
    # a page that merely cites CWE-79 many times
    (imports / "CWE-352.md").write_text(
        '---\nslug: weakness/CWE-352\ntitle: "CWE-352 — CSRF"\npage_type: weakness\n'
        'cwe_ids: [CWE-352, CWE-79]\n---\n' + "Related to CWE-79. " * 40
    )
    svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "idx.sqlite")
    svc.rebuild_index()

    rows = svc.lookup("CWE-79", limit=5)
    assert rows, "no results"
    assert rows[0]["slug"] == "weakness/CWE-79", [r["slug"] for r in rows]


def test_cwe_related_pages_still_listed(tmp_path):
    from umbra.wiki.service import WikiService

    imports = tmp_path / "imports" / "mitre-cwe"
    imports.mkdir(parents=True)
    (imports / "CWE-79.md").write_text(
        '---\nslug: weakness/CWE-79\ntitle: "CWE-79"\npage_type: weakness\n'
        'cwe_ids: [CWE-79]\n---\nCanonical.\n'
    )
    (imports / "CWE-352.md").write_text(
        '---\nslug: weakness/CWE-352\ntitle: "CWE-352"\npage_type: weakness\n'
        'cwe_ids: [CWE-352, CWE-79]\n---\n' + "See CWE-79. " * 40
    )
    svc = WikiService(corpus_dir=tmp_path, index_path=tmp_path / "idx.sqlite")
    svc.rebuild_index()
    slugs = [r["slug"] for r in svc.lookup("CWE-79", limit=5)]
    assert "weakness/CWE-352" in slugs


def _rfc_corpus(tmp_path):
    imports = tmp_path / "imports" / "ietf-rfc"
    imports.mkdir(parents=True)
    (imports / "RFC826.md").write_text(
        '---\nslug: rfc/RFC826\ntitle: "RFC826 — An Ethernet Address Resolution Protocol"\n'
        'page_type: rfc\nstandards: [RFC826]\n---\nCanonical ARP RFC page.\n'
    )
    (imports / "RFC1034.md").write_text(
        '---\nslug: rfc/RFC1034\ntitle: "RFC1034 — Domain names"\npage_type: rfc\n'
        'standards: [RFC1034]\n---\n' + "DNS concepts. " * 60
    )
    cur = tmp_path / "curated" / "protocols"
    cur.mkdir(parents=True)
    (cur / "arp.md").write_text(
        '---\nslug: protocol/arp\ntitle: "ARP"\npage_type: protocol\n'
        'standards: [RFC826]\n---\n' + "ARP is defined in RFC 826. " * 30
    )
    return tmp_path


def test_exact_rfc_id_ranks_its_own_page_first(tmp_path):
    """S7 acceptance. Before the fast-path, `RFC826` returned protocol/arp and
    `RFC 826` (with a space) returned rfc/RFC1034 — a completely unrelated RFC."""
    from umbra.wiki.service import WikiService

    root = _rfc_corpus(tmp_path)
    svc = WikiService(corpus_dir=root, index_path=root / "idx.sqlite")
    svc.rebuild_index()
    assert svc.lookup("RFC826", limit=5)[0]["slug"] == "rfc/RFC826"


def test_rfc_lookup_tolerates_a_space(tmp_path):
    """Operators type "RFC 826" as often as "RFC826"."""
    from umbra.wiki.service import WikiService

    root = _rfc_corpus(tmp_path)
    svc = WikiService(corpus_dir=root, index_path=root / "idx.sqlite")
    svc.rebuild_index()
    for q in ("RFC 826", "rfc 826", "rfc826", "RFC0826"):
        rows = svc.lookup(q, limit=5)
        assert rows and rows[0]["slug"] == "rfc/RFC826", f"{q} → {[r['slug'] for r in rows]}"


def test_rfc_context_pages_still_listed(tmp_path):
    from umbra.wiki.service import WikiService

    root = _rfc_corpus(tmp_path)
    svc = WikiService(corpus_dir=root, index_path=root / "idx.sqlite")
    svc.rebuild_index()
    slugs = [r["slug"] for r in svc.lookup("RFC826", limit=5)]
    assert "protocol/arp" in slugs
