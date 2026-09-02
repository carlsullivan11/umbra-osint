"""county_records: allowlisted public GET, no login paths."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umbra.collectors.county_records import CountyRecordsCollector, scrape_allowed
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.lake.people import PeopleLake


def test_scrape_allowed_gov_and_skips_login():
    assert scrape_allowed("https://www.bentoncountyar.gov/assessor/")
    assert not scrape_allowed("https://www.bentoncountyar.gov/efile/login")
    assert not scrape_allowed("https://evil.example/records")


def test_county_records_fetches_and_stores(tmp_path: Path):
    settings = SimpleNamespace(
        user_agent="umbra-test/0.1",
        request_timeout_s=10,
        data_dir=tmp_path,
        scrape_pause_s=0,
    )
    (tmp_path / "lake").mkdir(parents=True, exist_ok=True)

    html = """
    <html><head><title>Benton County Assessor</title></head>
    <body>Public search. Jane Doe parcel APN 12-345-678 at 100 Main Street. Call (479) 555-0100.</body></html>
    """

    class _Resp:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status

    class _Http:
        def get(self, url, **kwargs):
            return _Resp(html)

    ctx = SimpleNamespace(
        settings=settings, case_id="c", run_id="r", http=_Http()
    )
    person = SimpleNamespace(
        type=EntityType.PERSON.value,
        value="Jane Doe",
        norm_key=entity_key(EntityType.PERSON, "Jane Doe"),
        props={"location": "Bentonville, AR"},
        confidence=0.9,
    )
    res = CountyRecordsCollector().collect(person, ctx)
    assert res.evidence
    urls = [e.value for e in res.entities if e.type == EntityType.URL]
    assert any("bentoncountyar.gov" in u for u in urls)
    lake = PeopleLake.from_settings(settings)
    rows = lake.county_for_name("Jane Doe")
    lake.close()
    assert rows
    assert any(r.get("name_hit") for r in rows)
    lake = PeopleLake.from_settings(settings)
    land = lake.land_for_name("Jane Doe")
    lake.close()
    assert land
    assert any(r.get("apn") for r in land)
