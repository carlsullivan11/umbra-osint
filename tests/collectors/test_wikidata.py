"""Phase 2 — the `wikidata` collector (references/wikidata-integration.md).

Distinct from the existing `wikidata_search`, which does a label lookup and
returns a flat blob of hits. This one takes a QID or a label, walks the mapped
claims, and records **each claim as its own evidence with its own provenance**:
which property, which QID, which reference URLs, when it was retrieved.

Three rules the schema doc and the API shape impose, and the reasons they are
not optional:

- **Deprecated claims are excluded.** A deprecated rank is Wikidata saying "this
  statement is known wrong". Ingesting it imports an error as a fact — the same
  failure as importing revoked ATT&CK techniques.
- **An unsourced claim is recorded as unsourced.** Most claims carry no
  reference at all; presenting them as sourced would be the confidence theatre
  the project exists to avoid.
- **Nothing is fetched twice.** Wikidata asks for caching and a real user agent;
  a collector that re-fetches the same QID per run is both rude and slow.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umbra.core.models import EntityType
from umbra.core.normalize import entity_key

CLOUDFLARE = "Q4778915"

# Shaped exactly like the live API (verified against Q4778915 in Phase 1).
ENTITY_PAYLOAD = {
    "entities": {
        CLOUDFLARE: {
            "id": CLOUDFLARE,
            "labels": {"en": {"language": "en", "value": "Cloudflare"}},
            "descriptions": {"en": {"language": "en", "value": "American technology company"}},
            "claims": {
                "P31": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                         "datavalue": {"value": {"id": "Q4830453"}}}, "references": []}],
                "P856": [{"rank": "normal", "mainsnak": {"datatype": "url",
                          "datavalue": {"value": "https://www.cloudflare.com/"}},
                          "references": [{"snaks": {"P143": [{"datavalue": {"value": {"id": "Q328"}}}]}}]}],
                "P159": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                          "datavalue": {"value": {"id": "Q62"}}},
                          "references": [{"snaks": {
                              "P854": [{"datavalue": {"value": "https://fortune.com/unicorns/2016/cloudflare/"}}],
                              "P248": [{"datavalue": {"value": {"id": "Q97466108"}}}]}}]}],
                "P112": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                          "datavalue": {"value": {"id": "Q51665553"}}}, "references": []}],
                "P1324": [{"rank": "deprecated", "mainsnak": {"datatype": "url",
                           "datavalue": {"value": "https://example.invalid/wrong"}}, "references": []}],
            },
        }
    }
}

LABELS_PAYLOAD = {
    "entities": {
        "Q62": {"id": "Q62", "labels": {"en": {"value": "San Francisco"}},
                "claims": {"P31": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                                    "datavalue": {"value": {"id": "Q515"}}}, "references": []}]}},
        "Q51665553": {"id": "Q51665553", "labels": {"en": {"value": "Matthew Prince"}},
                      "claims": {"P31": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                                          "datavalue": {"value": {"id": "Q5"}}}, "references": []}]}},
        "Q4830453": {"id": "Q4830453", "labels": {"en": {"value": "business"}}, "claims": {}},
    }
}

SEARCH_PAYLOAD = {"search": [{"id": CLOUDFLARE, "label": "Cloudflare",
                              "description": "American technology company"}]}


def _transport(calls: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        action = request.url.params.get("action")
        if action == "wbsearchentities":
            return httpx.Response(200, json=SEARCH_PAYLOAD)
        ids = (request.url.params.get("ids") or "").split("|")
        if CLOUDFLARE in ids:
            return httpx.Response(200, json=ENTITY_PAYLOAD)
        known = {k: v for k, v in LABELS_PAYLOAD["entities"].items() if k in ids}
        return httpx.Response(200, json={"entities": known})
    return httpx.MockTransport(handler)


@pytest.fixture
def ctx(tmp_path: Path):
    calls: list = []
    client = httpx.Client(transport=_transport(calls))
    settings = SimpleNamespace(cache_dir=tmp_path / "cache", user_agent="umbra-test/0.1",
                               request_timeout_s=10)
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    c = SimpleNamespace(settings=settings, case_id="c_t", run_id="r_t", http=client)
    c.calls = calls
    return c


def _entity(value: str, type_: EntityType = EntityType.ORG):
    # Mirrors the real Entity row the orchestrator passes in, confidence included.
    return SimpleNamespace(type=type_.value, value=value,
                           norm_key=entity_key(type_, value), props={},
                           confidence=0.9)


def _collect(ctx, value="Cloudflare", type_=EntityType.ORG):
    from umbra.collectors.wikidata import WikidataCollector
    return WikidataCollector().collect(_entity(value, type_), ctx)


# --- lookup ---------------------------------------------------------------

def test_a_qid_is_fetched_directly(ctx):
    """`Q4778915` is unambiguous — searching for it by label would be a wasted
    request and a chance to match the wrong item."""
    res = _collect(ctx, CLOUDFLARE)
    assert res.evidence
    assert not any("wbsearchentities" in c for c in ctx.calls)


def test_a_label_is_resolved_through_search(ctx):
    res = _collect(ctx, "Cloudflare")
    assert any("wbsearchentities" in c for c in ctx.calls)
    assert res.evidence


def test_an_unknown_label_returns_nothing_rather_than_guessing(ctx, monkeypatch):
    import umbra.collectors.wikidata as wd

    monkeypatch.setattr(wd, "_search_qid", lambda *a, **k: None)
    res = _collect(ctx, "no such organisation anywhere")
    assert res.entities == [] and res.evidence == []
    assert any("no wikidata match" in n.lower() for n in res.notes)


# --- claims become evidence with provenance -------------------------------

def test_each_claim_is_its_own_evidence(ctx):
    """One blob for the whole entity would make a single claim impossible to
    cite, contradict, or age out."""
    res = _collect(ctx, CLOUDFLARE)
    props = {e.raw.get("property_id") for e in res.evidence if isinstance(e.raw, dict)}
    assert {"P856", "P159", "P112"} <= props


def test_provenance_fields_required_by_the_schema_doc_are_present(ctx):
    res = _collect(ctx, CLOUDFLARE)
    ev = next(e for e in res.evidence if e.raw.get("property_id") == "P159")
    for field in ("source", "wikidata_qid", "property_id", "reference_urls", "retrieved_at"):
        assert field in ev.raw, f"missing {field}"
    assert ev.raw["source"] == "wikidata"
    assert ev.raw["wikidata_qid"] == CLOUDFLARE


def test_reference_urls_are_captured(ctx):
    res = _collect(ctx, CLOUDFLARE)
    ev = next(e for e in res.evidence if e.raw.get("property_id") == "P159")
    assert "https://fortune.com/unicorns/2016/cloudflare/" in ev.raw["reference_urls"]


def test_an_unsourced_claim_says_so(ctx):
    """Most claims carry no reference. Presenting them as sourced is exactly the
    provenance theatre this project exists to avoid."""
    res = _collect(ctx, CLOUDFLARE)
    ev = next(e for e in res.evidence if e.raw.get("property_id") == "P112")
    assert ev.raw["reference_urls"] == []
    assert ev.confidence < max(
        e.confidence for e in res.evidence if e.raw.get("reference_urls"))


def test_deprecated_claims_are_not_ingested(ctx):
    """A deprecated rank is Wikidata recording a statement as known wrong."""
    res = _collect(ctx, CLOUDFLARE)
    assert not any(e.raw.get("property_id") == "P1324" for e in res.evidence)
    assert not any("example.invalid" in str(e.value) for e in res.entities)


# --- graph ----------------------------------------------------------------

def test_the_official_website_becomes_a_url_and_a_domain(ctx):
    res = _collect(ctx, CLOUDFLARE)
    assert any(e.type == EntityType.URL and "cloudflare.com" in e.value for e in res.entities)
    assert any(e.type == EntityType.DOMAIN and e.value == "cloudflare.com" for e in res.entities)


def test_headquarters_becomes_a_location_entity_and_edge(ctx):
    """Phase 4 starts with Organization and Location, and `location` did not
    exist as an entity type before this collector."""
    res = _collect(ctx, CLOUDFLARE)
    assert any(e.type == EntityType.LOCATION and e.value == "San Francisco" for e in res.entities)
    assert any(edge.rel.value == "headquartered_in" for edge in res.edges)


def test_the_founder_becomes_a_person_edge(ctx):
    res = _collect(ctx, CLOUDFLARE)
    assert any(e.type == EntityType.PERSON and e.value == "Matthew Prince" for e in res.entities)
    assert any(edge.rel.value == "founded_by" for edge in res.edges)


def test_related_items_are_labelled_not_left_as_qids(ctx):
    """`Q62` in a case graph is unreadable; the label is the whole point of
    resolving it."""
    res = _collect(ctx, CLOUDFLARE)
    assert not any(str(e.value).startswith("Q") and str(e.value)[1:].isdigit()
                   for e in res.entities)


def test_the_qid_is_recorded_on_the_entity(ctx):
    res = _collect(ctx, CLOUDFLARE)
    org = next(e for e in res.entities if e.type == EntityType.ORG)
    assert org.props.get("wikidata_qid") == CLOUDFLARE


# --- politeness -----------------------------------------------------------

def test_a_repeat_lookup_is_served_from_cache(ctx):
    _collect(ctx, CLOUDFLARE)
    first = len(ctx.calls)
    _collect(ctx, CLOUDFLARE)
    assert len(ctx.calls) == first, "the second run should not hit the API again"


def test_related_qids_are_resolved_in_one_batched_request(ctx):
    """wbgetentities takes up to 50 ids. One request per referenced QID would be
    a burst of small calls against a free public endpoint."""
    _collect(ctx, CLOUDFLARE)
    batched = [c for c in ctx.calls if "wbgetentities" in c and "%7C" in c or "|" in c]
    assert batched, "related items should be fetched together"


def test_the_collector_identifies_itself(ctx):
    """Wikidata's policy asks for a descriptive User-Agent; anonymous bulk
    clients get blocked."""
    from umbra.collectors.wikidata import USER_AGENT

    assert "umbra" in USER_AGENT.lower()
    assert "http" in USER_AGENT.lower()


# --- wiring ---------------------------------------------------------------

def test_the_collector_is_registered_and_typed():
    from umbra.collectors.base import default_registry

    col = default_registry().get("wikidata")
    assert col is not None
    assert {EntityType.ORG, EntityType.PERSON, EntityType.LOCATION} <= col.inputs


def test_it_has_a_trust_weight():
    from umbra.core.scoring import COLLECTOR_TRUST

    assert "wikidata" in COLLECTOR_TRUST


def test_a_broken_api_response_does_not_fail_the_run(ctx, monkeypatch):
    """Collectors fail soft; a 500 from Wikidata must not take a case down."""
    def boom(request):
        return httpx.Response(500, text="upstream error")

    ctx.http = httpx.Client(transport=httpx.MockTransport(boom))
    res = _collect(ctx, CLOUDFLARE)
    assert res.entities == [] and res.evidence == []
    assert res.notes


# --- incidents map onto types that already exist --------------------------
#
# The Event decision, resolved: Wikidata does not model incidents as events at
# all (cyberattack is a *method*, data breach is a *process* sibling of
# "occurrence"), so no root class catches them. Rather than invent an `event`
# entity type that duplicates `breach`, incident claims land on the types Umbra
# already has and keeps investing in — the breach module, the CVE corpus, and
# the wiki pages those feed.

BREACH_PAYLOAD = {
    "entities": {
        "Q52529288": {
            "id": "Q52529288",
            "labels": {"en": {"value": "Equifax data breach"}},
            "claims": {
                "P31": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                         "datavalue": {"value": {"id": "Q1172486"}}}, "references": []}],
            },
        }
    }
}

VULN_PAYLOAD = {
    "entities": {
        "Q110068433": {
            "id": "Q110068433",
            "labels": {"en": {"value": "Log4Shell"}},
            "claims": {
                "P31": [{"rank": "normal", "mainsnak": {"datatype": "wikibase-item",
                         "datavalue": {"value": {"id": "Q631425"}}}, "references": []}],
                "P3587": [{"rank": "normal", "mainsnak": {"datatype": "external-id",
                           "datavalue": {"value": "CVE-2021-44228"}}, "references": []}],
            },
        }
    }
}


def _payload_ctx(tmp_path, payload):
    calls: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.params.get("action") == "wbsearchentities":
            qid = next(iter(payload["entities"]))
            return httpx.Response(200, json={"search": [{"id": qid, "label": "x"}]})
        ids = (request.url.params.get("ids") or "").split("|")
        known = {k: v for k, v in payload["entities"].items() if k in ids}
        if known:
            return httpx.Response(200, json={"entities": known})
        # class labels for P31 targets
        return httpx.Response(200, json={"entities": {i: {"id": i, "labels": {
            "en": {"value": {"Q1172486": "data breach", "Q631425": "vulnerability"}.get(i, i)}},
            "claims": {}} for i in ids}})

    settings = SimpleNamespace(cache_dir=tmp_path / "c", user_agent="t", request_timeout_s=10)
    settings.cache_dir.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(settings=settings, case_id="c", run_id="r",
                           http=httpx.Client(transport=httpx.MockTransport(handler)))


def test_a_data_breach_item_becomes_a_breach_entity(tmp_path):
    """Umbra already has a `breach` type that HIBP populates and the watch
    module monitors. Wikidata's "Equifax data breach" is the same real-world
    thing, so it merges there instead of into a new node type."""
    ctx = _payload_ctx(tmp_path, BREACH_PAYLOAD)
    res = _collect(ctx, "Q52529288")
    assert any(e.type == EntityType.BREACH and "equifax" in e.value.lower()
               for e in res.entities)


def test_no_event_entity_type_was_invented(tmp_path):
    ctx = _payload_ctx(tmp_path, BREACH_PAYLOAD)
    _collect(ctx, "Q52529288")
    assert not hasattr(EntityType, "EVENT"), \
        "incidents map onto breach/CVE; Wikidata has no usable event root"


def test_a_named_vulnerability_yields_its_cve_id(tmp_path):
    """P3587 is the bridge to everything Umbra already has about CVEs: the wiki
    corpus page, the KEV/NVD imports, and the news feed's planned CVE chips."""
    ctx = _payload_ctx(tmp_path, VULN_PAYLOAD)
    res = _collect(ctx, "Q110068433")
    ev = next(e for e in res.evidence if e.raw.get("property_id") == "P3587")
    assert ev.raw["value"] == "CVE-2021-44228"
    assert ev.raw["cve_id"] == "CVE-2021-44228"


def test_the_cve_links_to_the_wiki_page_that_already_exists(tmp_path):
    ctx = _payload_ctx(tmp_path, VULN_PAYLOAD)
    res = _collect(ctx, "Q110068433")
    ev = next(e for e in res.evidence if e.raw.get("property_id") == "P3587")
    assert ev.raw["wiki_slug"] == "cve/CVE-2021-44228"
