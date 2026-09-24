"""`unified_search` must include `UlsLake.lookup`, the same way it already
includes the FEC contributor lake, the parcel lake, the IRS 990 officer lake
and the NPPES clinician lake.

Two rules, same as the other lakes:

**No identity merging.** A ULS licensee row and a person, FEC filer, parcel
owner, officer or clinician that name the same string are not the same
identity. They come back in their own, separately labelled `licensees` group.

**A miss is lake coverage, never "not a licensee".** `UlsLake` only holds
what has been imported. A name absent from it means the lake is empty or not
imported — never a claim that this person does not hold an FCC license,
which this lake cannot know.

Fixture sqlite only; no live FCC download.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from umbra.lake.people import PeopleLake
from umbra.lake.uls import ENTITY_TYPE_LICENSEE, UlsLake
from umbra.people.search import unified_search


def _hd(usi, callsign, status="A", radio_service="HA"):
    return f"HD|{usi}||EBF001|{callsign}|{status}|{radio_service}|"


def _en(usi, *, callsign="", entity_type=ENTITY_TYPE_LICENSEE, entity_name="",
        first="", mi="", last="", suffix="", street="", city="", state="",
        zip5=""):
    return (
        f"EN|{usi}||EBF001|{callsign}|{entity_type}|LIC001|{entity_name}|"
        f"{first}|{mi}|{last}|{suffix}||||{street}|{city}|{state}|{zip5}|"
    )


def _zip(tmp_path: Path, hd_lines, en_lines, name="l_amat.zip") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("HD.dat", "\n".join(hd_lines) + "\n")
        z.writestr("EN.dat", "\n".join(en_lines) + "\n")
    return p


@pytest.fixture
def uls_lake(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_ULS_DB", str(tmp_path / "uls.sqlite"))
    lake = UlsLake(tmp_path / "uls.sqlite")
    lake.import_zip(_zip(
        tmp_path,
        [_hd("1000000001", "KA1ABC"), _hd("1000000002", "KB2XYZ")],
        [
            _en("1000000001", callsign="KA1ABC", first="ADA", last="LOVELACE",
                street="1 MAIN ST", city="AUSTIN", state="TX", zip5="787010000"),
            _en("1000000002", callsign="KB2XYZ", first="ADA", last="LOVELACE",
                street="2 ELM ST", city="OAKLAND", state="CA", zip5="946120000"),
        ],
    ))
    lake.close()
    yield tmp_path / "uls.sqlite"


@pytest.fixture
def people_lake(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    yield lake
    lake.close()


# --- the gap this closes ---------------------------------------------------

def test_licensees_group_is_populated(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.licensees
    assert {u["state"] for u in res.licensees} == {"TX", "CA"}


def test_licensees_are_a_separate_group_not_merged_into_other_groups(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.people == []
    assert res.contributors == []
    assert res.parcels == []
    assert res.officers == []
    assert res.clinicians == []
    assert res.licensees
    # callsign is a licensee-only field.
    assert "callsign" in res.licensees[0]
    assert "callsign" not in res.as_dict()


def test_fcc_uls_id_is_unique_per_row(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    ids = [u["fcc_uls_id"] for u in res.licensees]
    assert len(ids) == len(set(ids))


def test_no_field_bleed_onto_other_groups(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    for row in res.people:
        assert "callsign" not in row
        assert "radio_service" not in row
    for row in res.contributors:
        assert "callsign" not in row
        assert "radio_service" not in row
    for row in res.parcels:
        assert "callsign" not in row
    for row in res.officers:
        assert "callsign" not in row
    for row in res.clinicians:
        assert "callsign" not in row


def test_two_licensees_same_name_different_states_are_both_returned(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert len(res.licensees) == 2
    states = sorted(u["state"] for u in res.licensees)
    assert states == ["CA", "TX"]


def test_two_licensees_same_name_different_states_is_flagged_ambiguous(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.licensees_ambiguous is True
    assert "TX" in res.licensees_note and "CA" in res.licensees_note


def test_a_state_filter_narrows_the_licensees_group(uls_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace", state="TX")
    assert len(res.licensees) == 1
    assert res.licensees[0]["state"] == "TX"
    assert res.licensees_ambiguous is False


# --- the miss note is lake coverage, never "not a licensee" -----------------

def test_a_miss_says_lake_coverage_never_not_a_licensee(uls_lake, people_lake):
    res = unified_search(people_lake, "Nobody Here")
    assert res.licensees == []
    note = res.licensees_note.lower()
    assert "not a licensee" not in note
    assert "empty" in note or "not imported" in note


def test_an_absent_uls_lake_is_not_an_outage(tmp_path, monkeypatch, people_lake):
    monkeypatch.setenv("UMBRA_ULS_DB", str(tmp_path / "missing.sqlite"))
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.licensees == []
    note = res.licensees_note.lower()
    assert "not a licensee" not in note
    assert "empty" in note or "not imported" in note


# --- index-backed lookup -----------------------------------------------------

def test_licensee_lookup_uses_the_name_index(uls_lake):
    lake = UlsLake(uls_lake)
    try:
        plan = lake._conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM license WHERE name_canonical = ?",
            ("ada lovelace",),
        ).fetchall()
    finally:
        lake.close()
    text = " ".join(str(r[-1]) for r in plan).upper()
    assert "IDX_LICENSE_NAME" in text
    assert "SCAN LICENSE" not in text


# --- serialisation -----------------------------------------------------------

def test_results_serialise(uls_lake, people_lake):
    import json

    json.dumps(unified_search(people_lake, "Ada Lovelace").as_dict())
