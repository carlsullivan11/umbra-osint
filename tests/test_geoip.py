"""IP geolocation lake + collector tests (offline fixtures only)."""

from __future__ import annotations

import gzip
from pathlib import Path
from types import SimpleNamespace

import pytest

from umbra.collectors.base import default_registry
from umbra.collectors.ip_geo import IpGeoCollector
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.core.scoring import COLLECTOR_TRUST
from umbra.lake.geoip import GeoIpStore, candidate_dbip_urls


def _run(ip: str, store: GeoIpStore):
    col = IpGeoCollector(store=store)
    entity = SimpleNamespace(
        type="ip",
        value=ip,
        norm_key=entity_key(EntityType.IP, ip),
        props={},
    )
    ctx = SimpleNamespace(settings=None, case_id="c_test", run_id="r_test", http=None)
    return col.collect(entity, ctx)


@pytest.fixture()
def mini_csv(tmp_path: Path) -> Path:
    lines = [
        "8.8.8.0,8.8.8.255,NA,US,California,Mountain View,37.386,-122.084\n",
        "1.1.1.0,1.1.1.255,OC,AU,Queensland,South Brisbane,-27.4767,153.017\n",
        # public-looking IPv6 (not documentation/reserved) for lookup path
        "2606:4700::,2606:4700::ffff,NA,US,California,San Francisco,37.7749,-122.4194\n",
    ]
    p = tmp_path / "mini.csv"
    p.write_text("".join(lines), encoding="utf-8")
    return p


@pytest.fixture()
def store(tmp_path: Path, mini_csv: Path) -> GeoIpStore:
    db = tmp_path / "geoip.sqlite"
    s = GeoIpStore(db)
    stats = s.import_csv_file(mini_csv, edition="fixture")
    assert stats["rows_v4"] == 2
    assert stats["rows_v6"] == 1
    return s


def test_candidate_urls_newest_first():
    urls = candidate_dbip_urls()
    assert len(urls) == 3
    assert all(u.startswith("https://download.db-ip.com/free/dbip-city-lite-") for u in urls)
    assert all(u.endswith(".csv.gz") for u in urls)


def test_lookup_city(store: GeoIpStore):
    hit = store.lookup("8.8.8.8")
    assert hit is not None
    assert hit.country == "US"
    assert hit.city == "Mountain View"
    assert hit.latitude == pytest.approx(37.386)
    assert "Mountain View" in hit.location_label()


def test_lookup_miss(store: GeoIpStore):
    assert store.lookup("9.9.9.9") is None


def test_lookup_private_returns_none(store: GeoIpStore):
    assert store.lookup("10.0.0.1") is None
    assert store.lookup("127.0.0.1") is None


def test_lookup_ipv6(store: GeoIpStore):
    hit = store.lookup("2606:4700::1")
    assert hit is not None
    assert hit.country == "US"
    assert hit.city == "San Francisco"


def test_import_gz(tmp_path: Path, mini_csv: Path):
    gz = tmp_path / "mini.csv.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write(mini_csv.read_text(encoding="utf-8"))
    s = GeoIpStore(tmp_path / "g.sqlite")
    stats = s.import_csv_file(gz, edition="gz-fixture")
    assert stats["rows_v4"] == 2
    assert s.lookup("1.1.1.1").country == "AU"


def test_collector_unchecked_without_lake(tmp_path: Path):
    empty = GeoIpStore(tmp_path / "empty.sqlite")
    res = _run("8.8.8.8", empty)
    joined = " ".join(res.notes).lower()
    assert "not loaded" in joined or "unchecked" in joined
    assert not res.entities


def test_collector_private_ip(store: GeoIpStore):
    res = _run("192.168.1.1", store)
    assert any("private" in n.lower() for n in res.notes)
    assert not res.evidence


def test_collector_hit_emits_location(store: GeoIpStore):
    res = _run("8.8.8.8", store)
    assert res.evidence
    locs = [e for e in res.entities if e.type == EntityType.LOCATION]
    assert locs
    assert any(e.rel.value == "located_in" for e in res.edges)
    ip_ents = [e for e in res.entities if e.type == EntityType.IP]
    assert ip_ents and ip_ents[0].props.get("geo_country") == "US"


def test_registry_and_trust():
    reg = default_registry()
    assert reg.get("ip_geo") is not None
    assert "ip_geo" in COLLECTOR_TRUST
    # trust keys must be subset of registry (guard test style)
    names = {c.name for c in reg.list()}
    stale = set(COLLECTOR_TRUST) - names
    assert not stale, f"stale trust weights: {stale}"
