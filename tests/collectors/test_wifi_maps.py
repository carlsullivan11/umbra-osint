"""wifi_maps: portals, survey ingest, no map-UI scrape."""

from types import SimpleNamespace

from umbra.collectors.wifi_maps import WifiMapsCollector, parse_network_survey
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key


def test_parse_network_survey():
    rows = parse_network_survey(
        {
            "wifiAccessPoints": [
                {"bssid": "00:11:22:33:44:55", "ssid": "CafeWiFi", "lat": 36.37, "lon": -94.20}
            ]
        }
    )
    assert rows[0]["ssid"] == "CafeWiFi"
    assert rows[0]["bssid"].startswith("00")


def test_wifi_maps_attaches_portals_without_keys():
    settings = SimpleNamespace(
        user_agent="umbra-test/0.1",
        request_timeout_s=5,
        wigle_api_name=None,
        wigle_api_token=None,
    )

    class _Http:
        def get(self, *a, **k):
            raise AssertionError("no live HTTP without mocks")

        def post(self, *a, **k):
            raise AssertionError("no live HTTP without mocks")

    person = SimpleNamespace(
        type=EntityType.PERSON.value,
        value="Jane Doe",
        norm_key=entity_key(EntityType.PERSON, "Jane Doe"),
        props={},
        confidence=0.9,
    )
    res = WifiMapsCollector().collect(person, SimpleNamespace(settings=settings, http=_Http(), case_id="c", run_id="r"))
    urls = [e.value for e in res.entities if e.type == EntityType.URL]
    assert any("wigle.net" in u for u in urls)
    assert any("deflock.me" in u for u in urls)
    assert any("openwifimap.net" in u for u in urls)
    assert any("networksurvey.app" in u for u in urls)


def test_survey_prop_emits_mac_and_location():
    settings = SimpleNamespace(user_agent="t", request_timeout_s=5, wigle_api_name=None, wigle_api_token=None)
    loc = SimpleNamespace(
        type=EntityType.LOCATION.value,
        value="Bentonville, AR",
        norm_key=entity_key(EntityType.LOCATION, "Bentonville, AR"),
        props={
            "rf_survey": [
                {"bssid": "00:11:22:33:44:55", "ssid": "HomeNet", "lat": 36.372, "lon": -94.208}
            ]
        },
        confidence=0.8,
    )

    class _Http:
        def get(self, url, **kwargs):
            return SimpleNamespace(status_code=404, json=lambda: [])

        def post(self, url, **kwargs):
            return SimpleNamespace(status_code=404, json=lambda: {})

    res = WifiMapsCollector().collect(loc, SimpleNamespace(settings=settings, http=_Http(), case_id="c", run_id="r"))
    assert any(e.type == EntityType.MAC for e in res.entities)
    assert any(e.rel.value == "observed_at" for e in res.edges)
