"""obituary_search collector + portals integration tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umbra.collectors.obituary_search import ObituarySearchCollector
from umbra.collectors.public_records_portals import (
    PublicRecordsPortalsCollector,
    name_query_urls,
    resolve_regions,
)
from umbra.core.models import EdgeType, EntityType
from umbra.core.normalize import entity_key
from umbra.people.obituary_parse import parse_obituary_text


@pytest.fixture
def ctx(tmp_path: Path):
    settings = SimpleNamespace(
        user_agent="umbra-test/0.1",
        request_timeout_s=10,
        data_dir=tmp_path,
    )
    (tmp_path / "lake").mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(settings=settings, case_id="c_t", run_id="r_t", http=httpx.Client())


def _person(value: str, **props):
    return SimpleNamespace(
        type=EntityType.PERSON.value,
        value=value,
        norm_key=entity_key(EntityType.PERSON, value),
        props=props,
        confidence=0.9,
    )


def test_resolve_regions_bentonville_gets_ar_and_obituary():
    regs = resolve_regions({"location": "Bentonville, AR"})
    assert "us-ar-benton" in regs
    assert "us-obituary" in regs


def test_resolve_regions_san_diego():
    regs = resolve_regions({"location": "San Diego, CA"})
    assert "us-ca-san-diego" in regs
    assert "us-ca" in regs


def test_resolve_regions_fayetteville_washington_county():
    regs = resolve_regions({"location": "Fayetteville, AR"})
    assert "us-ar-washington" in regs
    assert "us-ar" in regs


def test_resolve_regions_houston_harris():
    regs = resolve_regions({"location": "Houston, TX"})
    assert "us-tx-harris" in regs
    assert "us-tx" in regs


def test_resolve_regions_chicago_cook():
    regs = resolve_regions({"location": "Chicago, IL"})
    assert "us-il-cook" in regs
    assert "us-il" in regs


def test_resolve_regions_phoenix_maricopa():
    regs = resolve_regions({"location": "Phoenix, AZ"})
    assert "us-az-maricopa" in regs
    assert "us-az" in regs


def test_resolve_regions_seattle_king():
    regs = resolve_regions({"location": "Seattle, WA"})
    assert "us-wa-king" in regs
    assert "us-wa" in regs


def test_resolve_regions_miami():
    regs = resolve_regions({"location": "Miami, FL"})
    assert "us-fl-miami-dade" in regs
    assert "us-fl" in regs


def test_resolve_regions_minneapolis_hennepin():
    regs = resolve_regions({"location": "Minneapolis, MN"})
    assert "us-mn-hennepin" in regs
    assert "us-mn" in regs


def test_resolve_regions_nashville():
    regs = resolve_regions({"location": "Nashville, TN"})
    assert "us-tn-davidson" in regs


def test_name_query_urls_include_fec_and_courtlistener():
    urls = name_query_urls("Jane Marie Doe")
    joined = " ".join(p["url"] for p in urls)
    assert "api.open.fec.gov" in joined
    assert "courtlistener.com/api" in joined


def test_name_query_urls_split_first_last():
    urls = name_query_urls("Jane Marie Doe")
    assert any("legacy.com" in p["url"] for p in urls)


def test_public_records_attaches_portals(ctx):
    col = PublicRecordsPortalsCollector()
    res = col.collect(_person("Jane Doe", location="Bentonville, Arkansas"), ctx)
    assert res.evidence
    kinds = {e.props.get("portal_kind") for e in res.entities if e.type == EntityType.URL}
    assert "obituary" in kinds


def test_obituary_search_fetches_and_stores_lake(ctx, tmp_path: Path):
    ddg_html = """
    <a class="result__a" href="https://www.legacy.com/us/obituaries/name/john-doe-obituary">
      John Doe Obituary
    </a>
    <div class="result__snippet">Teaser.</div>
    """
    page_html = """
    <html><head><title>John Doe Obituary</title></head><body>
    <p>John Doe, 72, of Bentonville, passed away March 1, 2024.
    He is survived by his wife Mary Doe and son Robert Doe.
    Smith Funeral Home. Interment at Oak Cemetery.</p>
    </body></html>
    """

    class _Resp:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError("http")

    class _Http:
        def post(self, *a, **k):
            return _Resp(ddg_html)

        def get(self, url, **k):
            return _Resp(page_html)

    ctx.http = _Http()
    col = ObituarySearchCollector()
    res = col.collect(_person("John Doe", location="Bentonville, AR"), ctx)

    people = {e.value for e in res.entities if e.type == EntityType.PERSON}
    assert "Mary Doe" in people
    assert "Robert Doe" in people
    assert any(e.rel == EdgeType.RELATED_TO for e in res.edges)
    assert any(ev.source_name == "public_obituary_page" for ev in res.evidence)

    # People lake should have the link
    from umbra.lake.people import PeopleLake

    lake = PeopleLake.from_settings(ctx.settings)
    hits = lake.lookup_name("John Doe")
    assert hits
    obits = lake.obituaries_for_person(hits[0]["id"])
    assert any("legacy.com" in o["url"] for o in obits)
    assert hits[0]["age"] == 72
    lake.close()


def test_fallback_urls_when_ddg_empty(ctx):
    class _Resp:
        text = "<html></html>"
        status_code = 200

        def raise_for_status(self):
            return None

    class _Http:
        def post(self, *a, **k):
            return _Resp()

        def get(self, url, **k):
            r = _Resp()
            r.text = (
                "<html><title>Jane Example</title><body>"
                "Jane Example is survived by her husband John Example."
                "</body></html>"
            )
            return r

    ctx.http = _Http()
    col = ObituarySearchCollector()
    res = col.collect(_person("Jane Example"), ctx)
    assert any("DDG returned no links" in n for n in res.notes)
    people = {e.value for e in res.entities if e.type == EntityType.PERSON}
    assert "John Example" in people


def test_obituary_search_requires_full_name(ctx):
    col = ObituarySearchCollector()
    res = col.collect(_person("Madonna"), ctx)
    assert res.notes
    assert not res.entities


def test_parse_helper_still_used():
    p = parse_obituary_text(
        "Survived by wife Alice Example.", decedent_name="Bob Example"
    )
    assert any(s.name == "Alice Example" for s in p.survivors)
