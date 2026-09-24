"""inmate_locator: first+last register hit is a candidate, never identity.

Fixtures only — nothing here calls the live BOP endpoint.
"""
from __future__ import annotations

from types import SimpleNamespace

from umbra.collectors.base import CollectorContext
from umbra.collectors.inmate_locator import FCRA_NOTE, PORTAL_URL, InmateLocatorCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.lake.people import PeopleLake

HIT_PAYLOAD = {
    "Captcha": False,
    "InmateLocator": [
        {
            "nameLast": "SMITH",
            "nameFirst": "JOHN",
            "nameMiddle": "LEE",
            "sex": "Male",
            "race": "Black",
            "age": "80",
            "inmateNum": "00123-871",
            "releaseCode": "R",
            "faclCode": "CDT",
            "faclName": "Detroit",
            "faclType": "RRM",
            "faclURL": "/locations/ccm/cdt/",
            "actRelDate": "02/17/1994",
        }
    ],
}

MISS_PAYLOAD = {"Captcha": False, "InmateLocator": []}
CAPTCHA_PAYLOAD = {"Captcha": True, "InmateLocator": []}


class Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class Http:
    def __init__(self, resp=None, exc=None):
        self._resp = resp
        self._exc = exc
        self.calls = []

    def post(self, url, **kw):
        self.calls.append((url, kw.get("data", {})))
        if self._exc:
            raise self._exc
        return self._resp


def ctx(http, tmp_path):
    return CollectorContext(
        settings=Settings(data_dir=tmp_path), case_id="c", run_id="r", http=http
    )


def person(name="John Smith"):
    return SimpleNamespace(type=EntityType.PERSON.value, value=name, display_name=name, props={})


def test_skips_single_token_name(tmp_path):
    c = InmateLocatorCollector()
    result = c.collect(person("Madonna"), ctx(Http(), tmp_path))
    assert result.entities == []
    assert any("first and last" in n for n in result.notes)


def test_portal_url_always_stored_on_success(tmp_path):
    c = InmateLocatorCollector()
    http = Http(Resp(HIT_PAYLOAD))
    result = c.collect(person(), ctx(http, tmp_path))
    urls = [e.value for e in result.entities if e.type == EntityType.URL]
    assert PORTAL_URL in urls


def test_portal_url_stored_even_on_http_error(tmp_path):
    c = InmateLocatorCollector()
    http = Http(exc=RuntimeError("connection reset"))
    result = c.collect(person(), ctx(http, tmp_path))
    urls = [e.value for e in result.entities if e.type == EntityType.URL]
    assert PORTAL_URL in urls
    assert any("unknown rather than clean" in n for n in result.notes)


def test_portal_url_stored_on_captcha_challenge(tmp_path):
    c = InmateLocatorCollector()
    http = Http(Resp(CAPTCHA_PAYLOAD))
    result = c.collect(person(), ctx(http, tmp_path))
    urls = [e.value for e in result.entities if e.type == EntityType.URL]
    assert PORTAL_URL in urls
    assert any("captcha" in n.lower() for n in result.notes)
    assert not any(e.type == EntityType.LOCATION for e in result.entities)


def test_first_and_last_hit_produces_facility_candidate(tmp_path):
    c = InmateLocatorCollector()
    http = Http(Resp(HIT_PAYLOAD))
    result = c.collect(person(), ctx(http, tmp_path))
    locs = [e for e in result.entities if e.type == EntityType.LOCATION]
    assert len(locs) == 1
    assert locs[0].value == "Detroit"
    assert locs[0].props["kind"] == "inmate_candidate"
    assert locs[0].props["identity_confirmed"] is False
    assert locs[0].confidence <= 0.5


def test_no_hit_is_reported_as_absence_not_clean(tmp_path):
    c = InmateLocatorCollector()
    http = Http(Resp(MISS_PAYLOAD))
    result = c.collect(person(), ctx(http, tmp_path))
    assert not any(e.type == EntityType.LOCATION for e in result.entities)
    assert any("no first+last register match" in n for n in result.notes)


def test_last_name_only_match_is_not_a_hit(tmp_path):
    payload = {
        "Captcha": False,
        "InmateLocator": [
            {"nameLast": "SMITH", "nameFirst": "JANE", "faclName": "Alderson", "inmateNum": "1"}
        ],
    }
    c = InmateLocatorCollector()
    result = c.collect(person("John Smith"), ctx(Http(Resp(payload)), tmp_path))
    assert not any(e.type == EntityType.LOCATION for e in result.entities)


def test_fcra_note_on_every_hit(tmp_path):
    c = InmateLocatorCollector()
    result = c.collect(person(), ctx(Http(Resp(HIT_PAYLOAD)), tmp_path))
    assert FCRA_NOTE in result.notes


def test_sends_first_and_last_as_separate_fields(tmp_path):
    c = InmateLocatorCollector()
    http = Http(Resp(HIT_PAYLOAD))
    c.collect(person("John Smith"), ctx(http, tmp_path))
    assert http.calls[0][1]["nameFirst"] == "John"
    assert http.calls[0][1]["nameLast"] == "Smith"


def test_hit_is_written_to_the_lake(tmp_path):
    c = InmateLocatorCollector()
    http = Http(Resp(HIT_PAYLOAD))
    c.collect(person(), ctx(http, tmp_path))
    lake = PeopleLake.from_settings(Settings(data_dir=tmp_path))
    try:
        facts = lake.inmate_for_name("John Smith")
        assert facts
        assert facts[0]["register_number"] == "00123-871"
    finally:
        lake.close()
