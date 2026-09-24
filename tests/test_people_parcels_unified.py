"""`unified_search` must include `ParcelLake.lookup`, the same way it already
includes the FEC contributor lake.

`parcels.sqlite` is already 1.1 GB on the VPS and `ParcelLake.lookup(name)`
exists — but `unified_search` (`src/umbra/people/search.py`) only queried
`people` and FEC. Same hole FEC had: the largest *owned* owner-roll in the
product was invisible to its own search box.

Two rules, same as FEC:

**No identity merging.** A county owner string and a person or FEC filer that
name the same string are not the same identity. They come back in their own,
separately labelled group.

**A miss is coverage, not an absence of the person.** `ParcelLake` only holds
the counties that have been ingested. A name absent from it means the county
was never paged — never "owns no property", which this lake cannot know.

Fixture sqlite only; no live ArcGIS, no `parcels-sync`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.parcels import ParcelLake, ParcelRow
from umbra.lake.people import PeopleLake
from umbra.people.names import canonical
from umbra.people.search import unified_search


def _row(owner, state, county, address="1 Main St", city="Springfield",
         parcel_id="P-1", layer_url="https://gis.test/FeatureServer/0"):
    return ParcelRow(
        owner=owner,
        owner_canonical=canonical(owner),
        address=address,
        city=city,
        parcel_id=parcel_id,
        state=state,
        county=county,
        layer_url=layer_url,
    )


@pytest.fixture
def parcel_lake(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "parcels.sqlite"))
    lake = ParcelLake(tmp_path / "parcels.sqlite")
    lake._write([
        _row("Ada Lovelace", "TX", "Travis", parcel_id="P-TX-1",
             layer_url="https://gis.test/tx/FeatureServer/0"),
        _row("Ada Lovelace", "CA", "Alameda", parcel_id="P-CA-1",
             layer_url="https://gis.test/ca/FeatureServer/0"),
        _row("Jose Rivera", "FL", "Hillsborough", parcel_id="P-FL-1",
             address=None),
    ])
    lake.close()
    yield tmp_path / "parcels.sqlite"


@pytest.fixture
def people_lake(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    yield lake
    lake.close()


# --- the gap this closes ---------------------------------------------------

def test_parcels_group_is_populated(parcel_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.parcels
    assert {p["state"] for p in res.parcels} == {"TX", "CA"}


def test_parcels_are_a_separate_group_not_merged_into_people_or_fec(parcel_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.people == []
    assert res.contributors == []
    assert res.parcels
    # Parcel fields only exist in the parcels group.
    assert "layer_url" in res.parcels[0]
    assert "layer_url" not in res.as_dict()


def test_two_owners_same_name_different_states_are_both_returned(parcel_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert len(res.parcels) == 2
    states = sorted(p["state"] for p in res.parcels)
    assert states == ["CA", "TX"]


def test_two_owners_same_name_different_states_is_flagged_ambiguous(parcel_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.parcels_ambiguous is True
    assert "TX" in res.parcels_note and "CA" in res.parcels_note


def test_a_state_filter_narrows_the_parcels_group(parcel_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace", state="TX")
    assert len(res.parcels) == 1
    assert res.parcels[0]["state"] == "TX"
    assert res.parcels_ambiguous is False


# --- Jose vs José -----------------------------------------------------------

def test_jose_and_jose_with_accent_match_the_same_canonical_owner(parcel_lake, people_lake):
    res_plain = unified_search(people_lake, "Jose Rivera")
    res_accented = unified_search(people_lake, "Jos\u00e9 Rivera")
    assert res_plain.parcels
    assert res_accented.parcels
    assert res_plain.parcels[0]["parcel_id"] == res_accented.parcels[0]["parcel_id"]


# --- the miss note is coverage, never an absence of the person -------------

def test_a_miss_says_coverage_is_partial_not_that_they_own_nothing(parcel_lake, people_lake):
    res = unified_search(people_lake, "Nobody Here")
    assert res.parcels == []
    note = res.parcels_note.lower()
    assert "owns no property" not in note
    assert "coverage" in note or "not been ingested" in note


def test_an_absent_parcel_lake_is_not_an_outage(tmp_path, monkeypatch, people_lake):
    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "missing.sqlite"))
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.parcels == []
    assert "coverage" in res.parcels_note.lower() or "not been ingested" in res.parcels_note.lower()


# --- nullish ArcGIS fields never surface as the literal string "None" ------

def test_a_null_address_is_none_not_the_literal_string_none(parcel_lake, people_lake):
    res = unified_search(people_lake, "Jose Rivera")
    assert res.parcels
    row = res.parcels[0]
    assert row["address"] is None
    import json

    payload = json.dumps(res.as_dict())
    assert '"None"' not in payload


# --- index-backed lookup -----------------------------------------------------

def test_parcel_lookup_uses_the_owner_index(parcel_lake):
    lake = ParcelLake(parcel_lake)
    try:
        plan = lake._conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM parcel WHERE owner_canonical = ?",
            (canonical("Ada Lovelace"),),
        ).fetchall()
    finally:
        lake.close()
    text = " ".join(str(r[-1]) for r in plan).upper()
    assert "IDX_PARCEL_OWNER" in text
    assert "SCAN PARCEL" not in text


# --- serialisation -----------------------------------------------------------

def test_results_serialise(parcel_lake, people_lake):
    import json

    json.dumps(unified_search(people_lake, "Ada Lovelace").as_dict())
