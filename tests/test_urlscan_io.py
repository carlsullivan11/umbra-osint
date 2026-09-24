"""urlscan.io — search the public corpus, never submit a scan.

The distinction is the whole design. `GET /api/v1/search/` reads scans other
people already ran and published; `POST /api/v1/scan/` makes urlscan fetch a URL
with a real browser. The second is a live connection to a host a visitor named,
originating from urlscan on Umbra's behalf, and it publishes that fetch — so it
must never fire from the web front door, `/reputation`, or `POST /run`. This
collector has no submit path at all, which is a stronger guarantee than a flag.

The other half is honesty about absence. urlscan indexes what people chose to
scan and chose to make public. A URL nobody submitted is simply unknown, and a
429 or a missing key means Umbra did not look. Neither is "this URL is clean" —
and a phishing URL an hour old is exactly the case where the corpus is empty.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from umbra.collectors.base import CollectorContext, default_registry
from umbra.collectors.urlscan_io import API_SEARCH, UrlscanIoCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _entity(kind: EntityType, value: str) -> Entity:
    return Entity(id="e1", case_id="c1", type=kind.value, value=value,
                  norm_key=entity_key(kind, value), props={}, confidence=1.0,
                  is_seed=True)


def _ctx() -> CollectorContext:
    return CollectorContext(settings=Settings(), case_id="c", run_id="r",
                            http=httpx.Client(timeout=5))


def _result(n: int = 2, *, verdict_score: int | None = None) -> dict:
    results = []
    for i in range(n):
        row = {
            "_id": f"uuid-{i}",
            "task": {
                "url": f"http://evil.test/{i}",
                "time": f"2026-08-0{i + 1}T10:00:00.000Z",
                "visibility": "public",
            },
            "page": {"domain": "evil.test", "ip": "203.0.113.5"},
            "result": f"https://urlscan.io/api/v1/result/uuid-{i}/",
            "screenshot": f"https://urlscan.io/screenshots/uuid-{i}.png",
        }
        if verdict_score is not None:
            row["verdicts"] = {"overall": {"malicious": True, "score": verdict_score}}
        results.append(row)
    return {"results": results, "total": n, "has_more": False}


def run(entity, *, api_key: str | None = None):
    return UrlscanIoCollector().collect(entity, _ctx())


# --- what it searches ------------------------------------------------------

@respx.mock
def test_a_domain_searches_the_domain_index():
    route = respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result()))
    run(_entity(EntityType.DOMAIN, "evil.test"))
    assert route.called
    q = route.calls[0].request.url.params["q"]
    # Quoted, so the assertion is on the field and the value, not on an exact
    # spelling that the DSL escaping is free to change.
    assert q.startswith("domain:") and "evil.test" in q


@respx.mock
def test_a_url_searches_by_page_url():
    route = respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result()))
    run(_entity(EntityType.URL, "http://evil.test/login"))
    q = route.calls[0].request.url.params["q"]
    assert "page.url" in q


@respx.mock
def test_the_query_is_quoted_so_a_url_cannot_inject_query_syntax():
    """A URL is attacker-supplied text going into a search DSL."""
    route = respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(0)))
    run(_entity(EntityType.URL, "http://evil.test/a AND page.domain:bank.example"))
    q = route.calls[0].request.url.params["q"]
    assert q.count('"') >= 2


# --- it never submits ------------------------------------------------------

@respx.mock
def test_it_never_posts_a_scan():
    """POST /api/v1/scan/ makes urlscan fetch the target with a real browser and
    publishes the result. Reading the corpus is not that."""
    submit = respx.post("https://urlscan.io/api/v1/scan/").mock(
        return_value=httpx.Response(200, json={}))
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result()))
    run(_entity(EntityType.DOMAIN, "evil.test"))
    assert not submit.called


def test_the_module_contains_no_submit_endpoint():
    """A stronger guarantee than a runtime flag: there is no code path.

    Checked against the module's *constants* and its calls, not its raw text —
    the docstring names `/api/v1/scan/` precisely in order to say it is never
    used, and a naive substring search on the source would forbid explaining
    the design.
    """
    import inspect

    import umbra.collectors.urlscan_io as mod

    src = inspect.getsource(mod)
    assert ".post(" not in src, "no POST call may exist in this module"

    # Real constants only: __doc__ is where the design is explained, and the
    # explanation has to be allowed to name the thing it forbids.
    constants = {
        name: value for name, value in vars(mod).items()
        if isinstance(value, str) and not name.startswith("__")
    }
    offenders = {n: v for n, v in constants.items() if "/api/v1/scan" in v}
    assert not offenders, f"no constant may hold the submit endpoint: {offenders}"


@respx.mock
def test_it_makes_no_connection_to_the_target_itself():
    """Umbra reads urlscan's corpus. It does not open TCP to the host the
    visitor named — that is what http_probe and tls_cert are for, and they are
    not in this collector's job."""
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result()))
    target = respx.get("http://evil.test/").mock(return_value=httpx.Response(200))
    run(_entity(EntityType.DOMAIN, "evil.test"))
    assert not target.called


# --- results ---------------------------------------------------------------

@respx.mock
def test_a_hit_produces_evidence_with_the_permalink():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(1)))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    assert res.evidence
    raw = res.evidence[0].raw
    assert raw["uuid"] == "uuid-0"
    assert raw["permalink"] == "https://urlscan.io/result/uuid-0/"


@respx.mock
def test_the_scan_time_is_recorded():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(1)))
    assert run(_entity(EntityType.DOMAIN, "evil.test")).evidence[0].raw["scanned_at"]


@respx.mock
def test_the_screenshot_is_linked_not_downloaded():
    """Link their CDN; do not save PNGs. Storing third-party screenshots of
    arbitrary pages is a content-liability problem Umbra has no reason to take
    on, and the link is just as useful."""
    img = respx.get("https://urlscan.io/screenshots/uuid-0.png").mock(
        return_value=httpx.Response(200, content=b"\x89PNG"))
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(1)))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    assert not img.called
    assert res.evidence[0].raw["screenshot"].startswith("https://urlscan.io/")


@respx.mock
def test_a_verdict_is_carried_when_urlscan_supplies_one():
    respx.get(API_SEARCH).mock(
        return_value=httpx.Response(200, json=_result(1, verdict_score=100)))
    raw = run(_entity(EntityType.DOMAIN, "evil.test")).evidence[0].raw
    assert raw["verdict_malicious"] is True
    assert raw["verdict_score"] == 100


@respx.mock
def test_no_verdict_is_none_rather_than_benign():
    """Most public scans carry no verdict at all. Defaulting to 'not malicious'
    would manufacture an all-clear out of a missing field."""
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(1)))
    raw = run(_entity(EntityType.DOMAIN, "evil.test")).evidence[0].raw
    assert raw["verdict_malicious"] is None


@respx.mock
def test_at_most_five_scans_are_attached():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(12)))
    assert len(run(_entity(EntityType.DOMAIN, "evil.test")).evidence) == 5


@respx.mock
def test_the_cap_is_stated_rather_than_silent():
    """Never a silent cap: 12 public scans is a fact about the domain."""
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(12)))
    notes = " ".join(run(_entity(EntityType.DOMAIN, "evil.test")).notes)
    assert "12" in notes and "5" in notes


# --- absence is unchecked, never clean -------------------------------------

@respx.mock
def test_no_results_never_says_the_url_is_clean():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(0)))
    res = run(_entity(EntityType.URL, "http://evil.test/new"))
    notes = " ".join(res.notes).lower()
    assert not res.evidence
    assert "clean" not in notes
    assert "not been scanned" in notes or "no public scan" in notes


@respx.mock
def test_no_results_explains_that_the_corpus_is_opt_in():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(0)))
    notes = " ".join(run(_entity(EntityType.URL, "http://evil.test/new")).notes)
    assert "public" in notes.lower()


@respx.mock
def test_a_429_is_unchecked_not_empty():
    """Rate limited means Umbra did not look. Rendering that as 'no scans' is
    the exact failure the run-notes work was about."""
    respx.get(API_SEARCH).mock(return_value=httpx.Response(429, text="slow down"))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    notes = " ".join(res.notes).lower()
    assert not res.evidence
    assert "rate" in notes or "429" in notes
    assert "clean" not in notes


@respx.mock
def test_a_429_reads_differently_from_a_genuine_miss():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(429))
    limited = " ".join(run(_entity(EntityType.DOMAIN, "evil.test")).notes)
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(0)))
    miss = " ".join(run(_entity(EntityType.DOMAIN, "evil.test")).notes)
    assert limited != miss


@respx.mock
def test_a_server_error_is_reported_as_a_source_failure():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(503))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    assert not res.evidence
    assert res.notes


@respx.mock
def test_malformed_json_does_not_take_the_run_down():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, text="not json"))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    assert not res.evidence
    assert res.notes


# --- the API key -----------------------------------------------------------

@respx.mock
def test_the_api_key_is_sent_when_configured(monkeypatch):
    monkeypatch.setenv("UMBRA_URLSCAN_API_KEY", "secret-key-value")
    route = respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(0)))
    run(_entity(EntityType.DOMAIN, "evil.test"))
    assert route.calls[0].request.headers.get("API-Key") == "secret-key-value"


@respx.mock
def test_no_key_still_searches(monkeypatch):
    """The search endpoint is usable unauthenticated. A missing key lowers the
    rate limit; it does not disable the collector."""
    monkeypatch.delenv("UMBRA_URLSCAN_API_KEY", raising=False)
    route = respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_result(1)))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    assert "API-Key" not in route.calls[0].request.headers
    assert res.evidence


@respx.mock
def test_the_key_never_reaches_a_note_or_the_evidence(monkeypatch):
    monkeypatch.setenv("UMBRA_URLSCAN_API_KEY", "secret-key-value")
    respx.get(API_SEARCH).mock(return_value=httpx.Response(401, text="bad key secret-key-value"))
    res = run(_entity(EntityType.DOMAIN, "evil.test"))
    blob = " ".join(res.notes) + repr([e.raw for e in res.evidence])
    assert "secret-key-value" not in blob


@respx.mock
def test_the_key_is_not_logged(monkeypatch, caplog):
    monkeypatch.setenv("UMBRA_URLSCAN_API_KEY", "secret-key-value")
    respx.get(API_SEARCH).mock(return_value=httpx.Response(500))
    with caplog.at_level("DEBUG"):
        run(_entity(EntityType.DOMAIN, "evil.test"))
    assert "secret-key-value" not in caplog.text


# --- wiring ----------------------------------------------------------------

def test_it_is_registered():
    assert "urlscan_io" in {c.name for c in default_registry().list()}


def test_it_accepts_urls_and_domains_only():
    reg = {c.name: c for c in default_registry().list()}
    assert reg["urlscan_io"].inputs == {EntityType.URL, EntityType.DOMAIN}


def test_it_has_a_trust_score():
    from umbra.core.scoring import COLLECTOR_TRUST

    assert 0.6 <= COLLECTOR_TRUST["urlscan_io"] <= 0.8


def test_the_playbook_still_matches_the_registry():
    from umbra.cli.playbook_cmd import _PLAYBOOK_COLLECTORS

    assert set(_PLAYBOOK_COLLECTORS) == {c.name for c in default_registry().list()}
