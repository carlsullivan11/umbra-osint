"""Rank 3, designed rather than transcribed.

`references/nvd-cve-collector.md` specifies an `nvd_cve` collector hitting the
NVD REST API and a new `Vulnerability` entity. The entity model is kept; the
data source is not.

**A `vulnerability` entity type is right here even though `event` was refused.**
A CVE is globally identified, stable, and a *join node* — "which of my assets
are affected by Log4Shell" is a graph traversal through the CVE, so it has to be
a node for the question to exist. It is already the primary key of 1,665 wiki
pages, so the entity value and its page slug are one string.

**The corpus beats the API.** NVD for "nginx" returns hundreds of mostly old,
unexploited CVEs — the graph explosion deep-scan budgets exist to prevent. CISA
KEV is the exploited-in-the-wild subset: bounded, actionable, already imported
daily, no key, works offline.

**And no KEV entry is not no vulnerabilities.** nginx has plenty of CVEs and no
KEV entries. Getting that sentence wrong is the unchecked-versus-clean failure
again.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from umbra.core.models import EntityType
from umbra.core.normalize import entity_key

LOG4J_PAGE = {
    "slug": "cve/CVE-2021-44228", "page_type": "cve",
    "title": "CVE-2021-44228 — Apache Log4j2 Remote Code Execution Vulnerability",
    "body": ("| | |\n|--|--|\n| Vendor / project | Apache |\n| Product | Log4j2 |\n"
             "| Date added | 2021-12-10 |\n| Ransomware campaign use | Known |\n"),
}
UNRELATED_PAGE = {
    "slug": "cve/CVE-2019-0001", "page_type": "cve", "title": "CVE-2019-0001 — Juniper",
    "body": "| Vendor / project | Juniper |\n| Product | Junos OS |\n"
            "Mentions log4j2 in passing.\n",
}
CONCEPT_PAGE = {"slug": "concept/cve-anatomy", "page_type": "concept",
                "title": "CVE anatomy", "body": "about Log4j2 and others"}


def _run(pages, product="Log4j2", monkeypatch=None):
    import umbra.collectors.cve_lookup as mod

    monkeypatch.setattr(mod, "_corpus_hits", lambda q, limit: pages)
    ent = SimpleNamespace(type="technology", value=product, confidence=0.8,
                          norm_key=entity_key(EntityType.TECHNOLOGY, product), props={})
    ctx = SimpleNamespace(settings=SimpleNamespace(), case_id="c", run_id="r", http=None)
    return mod.CveLookupCollector().collect(ent, ctx)


# --- the entity model -----------------------------------------------------

def test_a_cve_becomes_a_vulnerability_entity(monkeypatch):
    res = _run([LOG4J_PAGE], monkeypatch=monkeypatch)
    vulns = [e for e in res.entities if e.type == EntityType.VULNERABILITY]
    assert vulns and vulns[0].value == "CVE-2021-44228"


def test_the_entity_value_is_the_wiki_slug_identifier(monkeypatch):
    """One identifier for the node and its page, so the graph and the corpus
    join without a translation table."""
    res = _run([LOG4J_PAGE], monkeypatch=monkeypatch)
    v = next(e for e in res.entities if e.type == EntityType.VULNERABILITY)
    assert v.props["wiki_slug"] == f"cve/{v.value}"


def test_the_technology_is_linked_to_the_vulnerability(monkeypatch):
    res = _run([LOG4J_PAGE], monkeypatch=monkeypatch)
    assert any(e.rel.value == "affected_by" for e in res.edges)


def test_a_cve_id_normalises_canonically():
    from umbra.core.normalize import normalize_value

    assert normalize_value(EntityType.VULNERABILITY, " cve-2021-44228 ") == "CVE-2021-44228"
    with pytest.raises(ValueError):
        normalize_value(EntityType.VULNERABILITY, "not-a-cve")


# --- precision ------------------------------------------------------------

def test_a_page_that_merely_mentions_the_product_is_not_a_match(monkeypatch):
    """Full-text search returns prose mentions. The Vendor/Product table is the
    affected-product list; anything else is a false positive on someone's
    asset inventory."""
    res = _run([UNRELATED_PAGE], monkeypatch=monkeypatch)
    assert not [e for e in res.entities if e.type == EntityType.VULNERABILITY]


def test_non_cve_pages_are_ignored(monkeypatch):
    res = _run([CONCEPT_PAGE], monkeypatch=monkeypatch)
    assert not res.entities


def test_the_vendor_also_counts_as_a_match(monkeypatch):
    res = _run([LOG4J_PAGE], product="Apache", monkeypatch=monkeypatch)
    assert [e for e in res.entities if e.type == EntityType.VULNERABILITY]


def test_results_are_capped(monkeypatch):
    import umbra.collectors.cve_lookup as mod

    many = [dict(LOG4J_PAGE, slug=f"cve/CVE-2021-{40000+i}") for i in range(40)]
    res = _run(many, monkeypatch=monkeypatch)
    assert len([e for e in res.entities if e.type == EntityType.VULNERABILITY]) <= mod.MAX_CVES


def test_a_one_letter_technology_is_not_searched(monkeypatch):
    res = _run([LOG4J_PAGE], product="R", monkeypatch=monkeypatch)
    assert not res.entities


# --- honesty --------------------------------------------------------------

def test_no_kev_entry_is_not_reported_as_no_vulnerabilities(monkeypatch):
    """nginx has many CVEs and zero KEV entries. Saying "no vulnerabilities"
    would be false, and it is the sentence an operator would act on."""
    res = _run([], product="nginx", monkeypatch=monkeypatch)
    note = " ".join(res.notes).lower()
    assert "known-exploited" in note or "known exploited" in note
    assert "not 'no vulnerabilities'" in note or "not no vulnerabilities" in note


def test_ransomware_use_is_carried_through(monkeypatch):
    """KEV records it, and it is the single most actionable field in the entry."""
    res = _run([LOG4J_PAGE], monkeypatch=monkeypatch)
    v = next(e for e in res.entities if e.type == EntityType.VULNERABILITY)
    assert v.props["known_ransomware_use"] is True
    assert "ransomware" in res.evidence[0].summary.lower()


def test_evidence_carries_provenance(monkeypatch):
    res = _run([LOG4J_PAGE], monkeypatch=monkeypatch)
    raw = res.evidence[0].raw
    for field in ("cve_id", "wiki_slug", "vendor", "kev_date_added", "source"):
        assert field in raw
    assert raw["source"] == "cisa_kev"


def test_a_missing_corpus_degrades_instead_of_raising(monkeypatch):
    """A fresh install has no corpus. The guard lives in the query seam, so it
    returns nothing and the collector reports "nothing known" — the same path a
    genuine miss takes."""
    import umbra.collectors.cve_lookup as mod

    class _Broken:
        def __init__(self, *a, **k):
            raise RuntimeError("no corpus on this machine")

    monkeypatch.setattr("umbra.wiki.service.WikiService", _Broken)
    assert mod._corpus_hits("Log4j2", 5) == [], "the seam must swallow it"

    ent = SimpleNamespace(type="technology", value="Log4j2", confidence=0.8,
                          norm_key=entity_key(EntityType.TECHNOLOGY, "Log4j2"), props={})
    ctx = SimpleNamespace(settings=SimpleNamespace(), case_id="c", run_id="r", http=None)
    res = mod.CveLookupCollector().collect(ent, ctx)
    assert res.entities == []
    assert res.notes


# --- wiring ---------------------------------------------------------------

def test_registered_and_trusted():
    from umbra.collectors.base import default_registry
    from umbra.core.scoring import COLLECTOR_TRUST

    col = default_registry().get("cve_lookup")
    assert col is not None and EntityType.TECHNOLOGY in col.inputs
    assert "cve_lookup" in COLLECTOR_TRUST


def test_the_planner_runs_it_for_domains():
    """tech_fingerprint produces the technology entities this consumes, so the
    two belong in the same plan."""
    from umbra.intent.plan import _DOMAIN_CORE

    assert "cve_lookup" in _DOMAIN_CORE
    assert _DOMAIN_CORE.index("tech_fingerprint") < _DOMAIN_CORE.index("cve_lookup")
