"""`unified_search` must include the federal BOP inmate locator lake
(`inmate_facts`), the same way it already includes parcels, IRS 990 officers
and NPPES clinicians.

Rules specific to this group (issue #26):

**First and last name required.** The collector never records a hit on less
than a first+last register match, and the query side matches: a single name
token never triggers a lookup here.

**No identity merging.** A register hit names the same string as a `people`
row, an FEC filer, a parcel owner, a 990 officer or an NPPES clinician — not
the same identity. `identity_confirmed` is always `False` and an FCRA note is
attached to every hit.

**A miss is never "not an inmate".** No match, a captcha challenge, or only
the portal source stored — none of those license the claim that this person
is not an inmate, which this lake cannot make.

Fixture only — rows are written directly with `PeopleLake.upsert_inmate_*`,
no live BOP call, no Chromium, no captcha bypass.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.people import PeopleLake
from umbra.people.search import unified_search

PORTAL_URL = "https://www.bop.gov/inmateloc/"


@pytest.fixture
def people_lake(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    yield lake
    lake.close()


def _seed_hit(lake: PeopleLake, name: str, **fact_kwargs) -> None:
    lake.upsert_inmate_source(url=PORTAL_URL, person_name=name, name_hit=True, total_rows=1)
    lake.upsert_inmate_fact(source_url=PORTAL_URL, person_name=name, **fact_kwargs)


# --- the gap this closes ---------------------------------------------------

def test_inmates_group_is_populated_on_first_last_match(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="12345-678", facility="FCI Sample")
    res = unified_search(people_lake, "John Smith")
    assert res.inmates
    assert res.inmates[0]["register_number"] == "12345-678"
    assert res.inmates[0]["facility"] == "FCI Sample"


def test_inmates_are_a_separate_group_not_merged_into_other_groups(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="12345-678")
    res = unified_search(people_lake, "John Smith")
    assert res.people == []
    assert res.contributors == []
    assert res.parcels == []
    assert res.officers == []
    assert res.clinicians == []
    assert res.inmates
    assert "register_number" in res.inmates[0]
    assert "register_number" not in res.as_dict()


def test_no_field_bleed_onto_people_or_fec_rows(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="12345-678")
    res = unified_search(people_lake, "John Smith")
    for row in res.people:
        assert "register_number" not in row
    for row in res.contributors:
        assert "register_number" not in row


# --- first+last required ----------------------------------------------------

def test_a_single_name_token_never_triggers_a_lookup(people_lake):
    _seed_hit(people_lake, "Smith", register_number="99999-000")
    res = unified_search(people_lake, "Smith")
    assert res.inmates == []
    assert "first and last name" in res.inmates_note.lower()


def test_first_and_last_both_required_even_if_data_exists(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="12345-678")
    res = unified_search(people_lake, "John")
    assert res.inmates == []


# --- identity_confirmed and FCRA --------------------------------------------

def test_identity_confirmed_is_always_false(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="12345-678")
    res = unified_search(people_lake, "John Smith")
    assert all(i["identity_confirmed"] is False for i in res.inmates)


def test_fcra_note_present_on_every_hit(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="12345-678")
    res = unified_search(people_lake, "John Smith")
    for i in res.inmates:
        assert "fcra" in i["fcra_note"].lower()
        assert "consumer report" in i["fcra_note"].lower()
    assert "fcra" in res.inmates_note.lower()


def test_multiple_hits_for_the_same_name_are_all_returned(people_lake):
    _seed_hit(people_lake, "John Smith", register_number="11111-111", facility="FCI A")
    people_lake.upsert_inmate_fact(
        source_url=PORTAL_URL, person_name="John Smith",
        register_number="22222-222", facility="FCI B",
    )
    res = unified_search(people_lake, "John Smith")
    assert len(res.inmates) == 2
    regs = sorted(i["register_number"] for i in res.inmates)
    assert regs == ["11111-111", "22222-222"]


# --- miss note is never "not an inmate" -------------------------------------

def test_a_miss_never_says_not_an_inmate(people_lake):
    res = unified_search(people_lake, "Nobody Here")
    assert res.inmates == []
    note = res.inmates_note.lower()
    assert "not an inmate" not in note


def test_an_empty_lake_is_not_an_outage(tmp_path):
    lake = PeopleLake(tmp_path / "empty.sqlite")
    try:
        res = unified_search(lake, "John Smith")
    finally:
        lake.close()
    assert res.inmates == []
    assert "not an inmate" not in res.inmates_note.lower()


# --- serialisation -----------------------------------------------------------

def test_results_serialise(people_lake):
    import json

    _seed_hit(people_lake, "John Smith", register_number="12345-678")
    json.dumps(unified_search(people_lake, "John Smith").as_dict())
