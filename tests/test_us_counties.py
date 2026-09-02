"""US county tracker + resolve."""

from umbra.collectors.public_records_portals import resolve_regions
from umbra.geo.us_counties import coverage_payload, coverage_rollup, counties_for_state, lookup_county


def test_coverage_rollup_has_all_counties():
    r = coverage_rollup()
    assert r["states"] == 51
    assert r["counties"] >= 3100
    assert r["l1_state_packs"] == 51
    assert r["l2_county_deep"] >= 70


def test_coverage_payload_state_and_unknown():
    all_us = coverage_payload()
    assert "AR" in all_us["states"]
    assert "counties" not in all_us
    ar = coverage_payload(state="ar")
    assert ar["state"] == "AR"
    assert any(c["name"] == "Benton County" for c in ar["counties"])
    open_only = coverage_payload(state="AR", open_only=True)
    assert all(c.get("status") != "deep" for c in open_only["counties"])
    bad = coverage_payload(state="ZZ")
    assert "error" in bad


def test_counties_for_arkansas():
    rows = counties_for_state("AR")
    names = {c["n"] for c in rows}
    assert "Benton County" in names
    assert "Washington County" in names
    assert len(rows) >= 70


def test_lookup_benton_county_ar():
    hit = lookup_county("Benton County, AR")
    assert hit is not None
    assert hit["fips"] == "05007"
    assert hit["pack"] == "us-ar-benton"
    assert hit["status"] == "deep"


def test_lookup_open_county():
    hit = lookup_county("Baxter County, AR")
    assert hit is not None
    assert hit["status"] == "open"
    assert hit.get("pack") in (None, "")


def test_lookup_harris_deep():
    hit = lookup_county("Harris County, TX")
    assert hit is not None
    assert hit["pack"] == "us-tx-harris"
    assert hit["status"] == "deep"


def test_resolve_regions_uses_county_tracker():
    regs = resolve_regions({"location": "Benton County, AR"})
    assert "us-ar-benton" in regs
    assert "us-ar" in regs
