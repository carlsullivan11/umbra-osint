"""Parcel-layer discovery: a catalog entry is a claim, a probe is evidence.

Properties of the code only — no live ArcGIS, no operator data. The discovery
sweep talks to other people's servers, so everything here is stubbed.
"""
from __future__ import annotations

import json

import pytest

from umbra.lake.parcel_sources import ParcelSourceLake
from umbra.records.discover import (
    Candidate,
    locate,
    looks_like_names,
    search_catalog,
    sync,
    verify,
)


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _Http:
    """Routes by URL substring so a whole probe chain can be scripted."""

    def __init__(self, routes: dict, default=None):
        self.routes = routes
        self.default = default if default is not None else {}
        self.calls: list[str] = []

    def get(self, url, **kw):
        self.calls.append(url)
        for frag, payload in self.routes.items():
            if frag in url:
                if isinstance(payload, Exception):
                    raise payload
                return _Resp(payload)
        return _Resp(self.default)


@pytest.fixture
def lake(tmp_path):
    lk = ParcelSourceLake(tmp_path / "parcel_sources.sqlite")
    yield lk
    lk.close()


def _layer(fields, max_records=200):
    return {"fields": [{"name": f} for f in fields], "maxRecordCount": max_records}


def _rows(field, values):
    return {"features": [{"attributes": {field: v}} for v in values]}


# --- gate 3: the field name says owner, the values decide ------------------

def test_names_are_recognised():
    assert looks_like_names(["SMITH, JANE A", "SMITH ROBERT T & AMY"])
    assert looks_like_names(["Smith Deirdre", "ROOSEVELT SMITH LLC"])


def test_mailing_addresses_are_rejected():
    """`OWNER_MAIL` and `TaxPayerAddr1` match an ownerish regex and are not names."""
    assert not looks_like_names(["123 MAIN ST", "4488 OAK RIDGE RD", "77 W 5TH AVE"])


def test_empty_and_numeric_values_are_rejected():
    assert not looks_like_names([])
    assert not looks_like_names(["", "  ", None])  # type: ignore[list-item]
    assert not looks_like_names(["001234", "0", "99999"])


def test_verify_rejects_an_address_field_that_looks_like_an_owner_field():
    http = _Http({
        "/FeatureServer/0/query": _rows("OWNER_MAIL", ["123 MAIN ST", "9 ELM RD"]),
        "/FeatureServer/0": _layer(["OBJECTID", "OWNER_MAIL"]),
        "/FeatureServer": {"layers": [{"id": 0}]},
    })
    good, reason = verify(http, Candidate("i", "Madison", "org", "https://x/rest/services/p/FeatureServer"))
    assert good is None
    assert "values are not" in reason


def test_verify_accepts_a_real_owner_field_and_maps_the_others():
    http = _Http({
        "/FeatureServer/0/query": _rows("OWNERNAME", ["SMITH, JANE", "SMITH ROBERT"]),
        "/FeatureServer/0": _layer(
            ["OBJECTID", "OWNERNAME", "SITUS_ADDRESS", "CITY", "PARCELID", "TOTALVALUE"]),
        "/FeatureServer": {"layers": [{"id": 0}]},
    })
    good, reason = verify(http, Candidate("i", "T", "o", "https://x/rest/services/p/FeatureServer"))
    assert reason == "verified"
    assert good.owner_field == "OWNERNAME"
    assert good.address_field == "SITUS_ADDRESS"
    assert good.parcel_field == "PARCELID"
    assert good.sample


def test_verify_rejects_a_geometry_only_layer():
    """Many counties publish parcels without owner names, on purpose."""
    http = _Http({
        "/FeatureServer/0": _layer(["OBJECTID", "PIN", "ACRES", "SHAPE"]),
        "/FeatureServer": {"layers": [{"id": 0}]},
    })
    good, reason = verify(http, Candidate("i", "T", "o", "https://x/rest/services/p/FeatureServer"))
    assert good is None
    assert "no queryable owner-name field" in reason


def test_verify_rejects_an_arcgis_error_body():
    """ArcGIS answers 200 with an error payload; that is not a verified layer."""
    http = _Http({
        "/FeatureServer/0/query": {"error": {"message": "Invalid field"}},
        "/FeatureServer/0": _layer(["OBJECTID", "OWNERNAME"]),
        "/FeatureServer": {"layers": [{"id": 0}]},
    })
    good, _ = verify(http, Candidate("i", "T", "o", "https://x/rest/services/p/FeatureServer"))
    assert good is None


def test_verify_survives_a_dead_service():
    http = _Http({"/FeatureServer": RuntimeError("boom")})
    good, reason = verify(http, Candidate("i", "T", "o", "https://x/rest/services/p/FeatureServer"))
    assert good is None
    assert "unreadable" in reason


# --- gate 4: geography resolves or stays NULL ------------------------------

def test_locate_resolves_a_us_extent():
    http = _Http({"geo.fcc.gov": {"results": [
        {"state_code": "AR", "county_name": "Benton County", "county_fips": "05007"}]}})
    assert locate(http, [[-94.5, 36.0], [-93.8, 36.6]]) == ("AR", "Benton County", "05007")


def test_locate_refuses_non_us_extents_without_calling_out():
    """The catalog is global; Brisbane's parcels are not a US county record."""
    http = _Http({})
    assert locate(http, [[152.9, -27.6], [153.2, -27.3]]) == (None, None, None)
    assert http.calls == []


def test_locate_returns_none_rather_than_guessing_when_lookup_fails():
    """A parcel in the wrong state is worse than one in no state."""
    http = _Http({"geo.fcc.gov": RuntimeError("down")})
    assert locate(http, [[-94.5, 36.0], [-93.8, 36.6]]) == (None, None, None)
    assert locate(http, None) == (None, None, None)


# --- the registry ----------------------------------------------------------

def test_never_synced_is_distinguishable_from_nothing_found(lake):
    assert lake.status()["synced"] is False
    lake.record({"layer_url": "https://a/0", "owner_field": "OWNER",
                 "status": "rejected", "detail": "no owner field"})
    assert lake.status()["synced"] is True
    assert lake.status()["verified"] == 0


def test_rejected_rows_are_kept_and_never_searched(lake):
    lake.record({"layer_url": "https://a/0", "owner_field": "-",
                 "status": "rejected", "detail": "geometry only"})
    lake.record({"layer_url": "https://b/0", "owner_field": "OWNER",
                 "state": "PA", "status": "verified", "sample": ["SMITH, J"]})
    assert [r["layer_url"] for r in lake.verified()] == ["https://b/0"]
    assert lake.status()["rejected"] == 1


def test_states_are_derived_from_verified_rows_only(lake):
    lake.record({"layer_url": "https://a/0", "owner_field": "O", "state": "PA",
                 "status": "verified"})
    lake.record({"layer_url": "https://b/0", "owner_field": "O", "state": "TX",
                 "status": "rejected"})
    assert lake.states() == ["PA"]


def test_a_rejected_row_does_not_violate_the_page_default(lake):
    """Explicit NULL beats a column DEFAULT in SQLite."""
    lake.record({"layer_url": "https://a/0", "owner_field": "-", "status": "rejected"})
    row = lake.connect().execute("SELECT page FROM parcel_sources").fetchone()
    assert row["page"] == 200


def test_seen_items_are_not_reprobed(lake):
    lake.mark_seen("item-1", "verified")
    assert "item-1" in lake.already_seen()


# --- the sweep -------------------------------------------------------------

def test_sync_records_both_outcomes_and_respects_its_bound(lake):
    catalog = {"results": [
        {"id": f"i{n}", "title": f"T{n}", "owner": "org",
         "url": "https://x/rest/services/p/FeatureServer",
         "extent": [[-94.5, 36.0], [-93.8, 36.6]]}
        for n in range(5)]}
    http = _Http({
        "sharing/rest/search": catalog,
        "geo.fcc.gov": {"results": [{"state_code": "AR", "county_name": "Benton County",
                                     "county_fips": "05007"}]},
        "/FeatureServer/0/query": _rows("OWNERNAME", ["SMITH, JANE"]),
        "/FeatureServer/0": _layer(["OBJECTID", "OWNERNAME"]),
        "/FeatureServer": {"layers": [{"id": 0}]},
    })
    stats = sync(http, lake, max_items=3)
    assert stats["probed"] == 3
    assert stats["verified"] >= 1
    assert lake.status()["synced"] is True


def test_sync_is_resumable_and_skips_what_it_already_probed(lake):
    lake.mark_seen("i0", "verified")
    catalog = {"results": [{"id": "i0", "title": "T", "owner": "o",
                            "url": "https://x/rest/services/p/FeatureServer"}]}
    http = _Http({"sharing/rest/search": catalog})
    stats = sync(http, lake, max_items=5)
    assert stats["probed"] == 0
    assert stats["skipped_seen"] >= 1


def test_search_catalog_drops_items_without_a_rest_url():
    http = _Http({"sharing/rest/search": {"results": [
        {"id": "a", "title": "web map", "url": "https://example.com/app"},
        {"id": "b", "title": "ok", "url": "https://x/rest/services/p/FeatureServer"},
    ]}})
    assert [c.item_id for c in search_catalog(http, "q")] == ["b"]


# --- integration with search ----------------------------------------------

def test_registry_layers_are_searched_when_a_state_is_named(tmp_path):
    from umbra.core.config import Settings
    from umbra.records import parcels

    lk = ParcelSourceLake(parcels_path := tmp_path / "lake" / "parcel_sources.sqlite")
    lk.record({"layer_url": "https://county/FeatureServer/0", "owner_field": "OWNER",
               "address_field": "ADDR", "title": "Crawford", "org": "janetcourson",
               "state": "PA", "county": "Crawford County", "status": "verified"})
    lk.close()
    assert parcels_path.is_file()

    settings = Settings(data_dir=tmp_path)
    srcs, _ = parcels.registry_sources(settings, ["PA"])
    assert len(srcs) == 1
    assert srcs[0].owner == "OWNER"
    # The publishing account is a named individual; it must not be the public
    # attribution on a stranger's property record.
    assert "janetcourson" not in srcs[0].attribution
    assert "Crawford County PA" in srcs[0].attribution


def test_unscoped_search_does_not_fan_out_across_every_county(tmp_path):
    """One request per county on an unscoped name search is slow and rude."""
    from umbra.core.config import Settings
    from umbra.records import parcels

    lk = ParcelSourceLake(tmp_path / "lake" / "parcel_sources.sqlite")
    for n in range(4):
        lk.record({"layer_url": f"https://c{n}/FeatureServer/0", "owner_field": "OWNER",
                   "state": "PA", "county": f"C{n}", "status": "verified"})
    lk.close()

    class _Stub:
        def __init__(self):
            self.urls = []

        def get(self, url, **kw):
            self.urls.append(url)
            return _Resp({"features": []})

    http = _Stub()
    out = parcels.search("Jane Smith", http=http, settings=Settings(data_dir=tmp_path))
    assert not any("https://c" in u for u in http.urls)
    assert any("NOT searched" in n for n in out.notes)


def test_registry_is_optional_and_absent_is_not_an_error(tmp_path):
    from umbra.core.config import Settings
    from umbra.records import parcels

    srcs, notes = parcels.registry_sources(Settings(data_dir=tmp_path), ["PA"])
    assert srcs == []
    assert notes == []


def test_sample_round_trips_as_json(lake):
    lake.record({"layer_url": "https://a/0", "owner_field": "O", "state": "PA",
                 "status": "verified", "sample": ["SMITH, JANE", "SMITH ROBERT"]})
    stored = lake.verified()[0]["sample"]
    assert json.loads(stored)[0] == "SMITH, JANE"


# --- the notes must not contradict the results -----------------------------

def _record_search_with(tmp_path, region, parcel_rows):
    """Run records.search with a stubbed http that returns given parcel rows."""
    from umbra.core.config import Settings
    from umbra import records

    lk = ParcelSourceLake(tmp_path / "lake" / "parcel_sources.sqlite")
    lk.record({"layer_url": "https://county/FeatureServer/0", "owner_field": "OWNER",
               "address_field": "ADDR", "title": "Albany", "state": "NY",
               "county": "Albany County", "status": "verified"})
    lk.close()

    class _H:
        def get(self, url, **kw):
            if "courtlistener" in url:
                return _Resp({"count": 0, "results": []})
            return _Resp({"features": [{"attributes": {"OWNER": v, "ADDR": "1 MAIN ST"}}
                                       for v in parcel_rows]})

    return records.search("Jane Sullivan", http=_H(),
                          settings=Settings(data_dir=tmp_path), region=region)


def test_no_coverage_note_is_absent_when_registry_layers_found_records(tmp_path):
    """'No parcel layer for NY' above 75 New York parcels is the bug."""
    out = _record_search_with(tmp_path, "us-ny-albany", ["SULLIVAN, JOHN R."])
    assert out.parcels
    assert not any("No parcel layer for NY" in n for n in out.notes)


def test_no_coverage_note_is_present_when_nothing_was_found(tmp_path):
    out = _record_search_with(tmp_path, "us-ny-albany", [])
    assert out.parcels == []
    assert any("No parcel layer for NY" in n for n in out.notes)


def test_county_note_does_not_claim_a_statewide_layer_that_does_not_exist(tmp_path):
    """NY has no statewide layer; the note must not say one was searched."""
    out = _record_search_with(tmp_path, "us-ny-albany", ["SULLIVAN, JOHN R."])
    county_notes = [n for n in out.notes if "albany county" in n.lower()]
    assert county_notes
    assert not any("statewide layer was searched" in n for n in county_notes)
    assert any("no statewide layer" in n for n in county_notes)
