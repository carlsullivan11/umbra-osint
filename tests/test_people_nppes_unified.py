"""`unified_search` must include `NppesLake.lookup`, the same way it already
includes the FEC contributor lake and the parcel lake.

Two rules, same as parcels:

**No identity merging.** An NPPES registry row and a person, FEC filer or
parcel owner that name the same string are not the same identity. They come
back in their own, separately labelled `clinicians` group.

**A miss is lake coverage, never "not a clinician".** `NppesLake` only holds
what has been imported. A name absent from it means the lake is empty or not
imported — never a claim that this person is not a clinician, which this
lake cannot know.

Fixture sqlite only; no live CMS download.
"""
from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path

import pytest

from umbra.lake.nppes import NppesLake
from umbra.lake.people import PeopleLake
from umbra.people.search import unified_search

HEADER = [
    "NPI",
    "Entity Type Code",
    "Provider Last Name (Legal Name)",
    "Provider First Name",
    "Provider Middle Name",
    "Provider First Line Business Practice Location Address",
    "Provider Second Line Business Practice Location Address",
    "Provider Business Practice Location Address City Name",
    "Provider Business Practice Location Address State Name",
    "Provider Business Practice Location Address Postal Code",
    "Provider Enumeration Date",
    "Healthcare Provider Taxonomy Code_1",
]


def _row(npi, first, last, city, state, zip5="021432389", middle=""):
    return {
        "NPI": npi,
        "Entity Type Code": "1",
        "Provider Last Name (Legal Name)": last,
        "Provider First Name": first,
        "Provider Middle Name": middle,
        "Provider First Line Business Practice Location Address": "1 Main St",
        "Provider Second Line Business Practice Location Address": "",
        "Provider Business Practice Location Address City Name": city,
        "Provider Business Practice Location Address State Name": state,
        "Provider Business Practice Location Address Postal Code": zip5,
        "Provider Enumeration Date": "01/01/2010",
        "Healthcare Provider Taxonomy Code_1": "207Q00000X",
    }


def _zip(tmp_path: Path, rows, filename="npidata_pfile_20050523-20260908.csv") -> Path:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=HEADER)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    p = tmp_path / "NPPES_Data_Dissemination.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(filename, buf.getvalue())
    return p


@pytest.fixture
def nppes_lake(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_NPPES_DB", str(tmp_path / "nppes.sqlite"))
    lake = NppesLake(tmp_path / "nppes.sqlite")
    lake.import_zip(_zip(tmp_path, [
        _row("1111111111", "ADA", "LOVELACE", "AUSTIN", "TX"),
        _row("2222222222", "ADA", "LOVELACE", "OAKLAND", "CA"),
        _row("3333333333", "JOSE", "RIVERA", "TAMPA", "FL"),
    ]))
    lake.close()
    yield tmp_path / "nppes.sqlite"


@pytest.fixture
def people_lake(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    yield lake
    lake.close()


# --- the gap this closes ---------------------------------------------------

def test_clinicians_group_is_populated(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.clinicians
    assert {c["state"] for c in res.clinicians} == {"TX", "CA"}


def test_clinicians_are_a_separate_group_not_merged_into_other_groups(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.people == []
    assert res.contributors == []
    assert res.parcels == []
    assert res.clinicians
    # NPI is a clinician-only field.
    assert "npi" in res.clinicians[0]
    assert "npi" not in res.as_dict()


def test_npi_is_unique_per_row(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    npis = [c["npi"] for c in res.clinicians]
    assert len(npis) == len(set(npis))


def test_no_field_bleed_onto_people_or_fec_rows(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    for row in res.people:
        assert "npi" not in row
        assert "taxonomy" not in row
    for row in res.contributors:
        assert "npi" not in row
        assert "taxonomy" not in row


def test_two_clinicians_same_name_different_states_are_both_returned(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert len(res.clinicians) == 2
    states = sorted(c["state"] for c in res.clinicians)
    assert states == ["CA", "TX"]


def test_two_clinicians_same_name_different_states_is_flagged_ambiguous(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.clinicians_ambiguous is True
    assert "TX" in res.clinicians_note and "CA" in res.clinicians_note


def test_a_state_filter_narrows_the_clinicians_group(nppes_lake, people_lake):
    res = unified_search(people_lake, "Ada Lovelace", state="TX")
    assert len(res.clinicians) == 1
    assert res.clinicians[0]["state"] == "TX"
    assert res.clinicians_ambiguous is False


# --- the miss note is lake coverage, never "not a clinician" ---------------

def test_a_miss_says_lake_coverage_never_not_a_clinician(nppes_lake, people_lake):
    res = unified_search(people_lake, "Nobody Here")
    assert res.clinicians == []
    note = res.clinicians_note.lower()
    assert "not a clinician" not in note
    assert "empty" in note or "not imported" in note


def test_an_absent_nppes_lake_is_not_an_outage(tmp_path, monkeypatch, people_lake):
    monkeypatch.setenv("UMBRA_NPPES_DB", str(tmp_path / "missing.sqlite"))
    res = unified_search(people_lake, "Ada Lovelace")
    assert res.clinicians == []
    note = res.clinicians_note.lower()
    assert "not a clinician" not in note
    assert "empty" in note or "not imported" in note


# --- index-backed lookup -----------------------------------------------------

def test_clinician_lookup_uses_the_name_index(nppes_lake):
    lake = NppesLake(nppes_lake)
    try:
        plan = lake._conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM provider WHERE name_canonical = ?",
            ("ada lovelace",),
        ).fetchall()
    finally:
        lake.close()
    text = " ".join(str(r[-1]) for r in plan).upper()
    assert "IDX_PROVIDER_NAME" in text
    assert "SCAN PROVIDER" not in text


# --- serialisation -----------------------------------------------------------

def test_results_serialise(nppes_lake, people_lake):
    import json

    json.dumps(unified_search(people_lake, "Ada Lovelace").as_dict())
