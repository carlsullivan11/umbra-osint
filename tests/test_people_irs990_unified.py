"""`unified_search` must include `Irs990Lake.lookup` as its own labelled group,
the same way it already includes FEC contributors and county parcels.

Two rules, same as FEC and parcels:

**No identity merging.** A 990 officer/director/trustee name and a person, FEC
filer, or parcel owner that name the same string are not the same identity.
They come back in their own, separately labelled group — `officers`.

**A miss is coverage, not "not an officer".** `Irs990Lake` only holds the
filing years that have been imported. A name absent from it means the lake is
empty or that filing was never imported — never that the person holds no
office at any organization, which this lake cannot know.

Fixture sqlite only; no live IRS fetch, no `irs990-sync`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.irs990 import Irs990Lake
from umbra.lake.people import PeopleLake
from umbra.people.names import canonical
from umbra.people.search import unified_search

NS = "http://www.irs.gov/efile"


def _filing_xml(ein: str, org_name: str, tax_year: str,
                 city: str, state: str, officers: list[tuple[str, str]]) -> bytes:
    officer_xml = "".join(
        f"""
        <Form990PartVIISectionAGrp>
          <PersonNm>{name}</PersonNm>
          <TitleTxt>{title}</TitleTxt>
        </Form990PartVIISectionAGrp>"""
        for name, title in officers
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Return xmlns="{NS}">
  <ReturnHeader>
    <TaxYr>{tax_year}</TaxYr>
    <Filer>
      <EIN>{ein}</EIN>
      <BusinessName>
        <BusinessNameLine1Txt>{org_name}</BusinessNameLine1Txt>
      </BusinessName>
      <USAddress>
        <CityNm>{city}</CityNm>
        <StateAbbreviationCd>{state}</StateAbbreviationCd>
      </USAddress>
    </Filer>
  </ReturnHeader>
  <ReturnData>
    <IRS990>{officer_xml}
    </IRS990>
  </ReturnData>
</Return>
"""
    return xml.encode("utf-8")


FILING_A = _filing_xml(
    "111111111", "Alpha Foundation", "2023", "Boston", "MA",
    [("Jordan Smith", "President"), ("Casey Smith", "Treasurer")],
)
FILING_B = _filing_xml(
    "222222222", "Beta Trust", "2023", "Denver", "CO",
    [("Jordan Smith", "Trustee")],
)


@pytest.fixture
def irs990_lake(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_IRS990_DB", str(tmp_path / "irs990.sqlite"))
    lake = Irs990Lake(tmp_path / "irs990.sqlite")
    lake.import_filing_xml(FILING_A, "https://irs.test/A_public.xml")
    lake.import_filing_xml(FILING_B, "https://irs.test/B_public.xml")
    lake.close()
    yield tmp_path / "irs990.sqlite"


@pytest.fixture
def people_lake(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    yield lake
    lake.close()


# --- the gap this closes ---------------------------------------------------

def test_officers_group_is_populated(irs990_lake, people_lake):
    res = unified_search(people_lake, "Jordan Smith")
    assert res.officers
    assert {o["ein"] for o in res.officers} == {"111111111", "222222222"}


def test_officers_are_a_separate_group_not_merged_into_other_groups(irs990_lake, people_lake):
    res = unified_search(people_lake, "Jordan Smith")
    assert res.people == []
    assert res.contributors == []
    assert res.parcels == []
    assert res.officers
    assert "source_url" in res.officers[0]


# --- same name, two EINs stay two rows --------------------------------------

def test_same_name_two_eins_stay_two_rows(irs990_lake, people_lake):
    res = unified_search(people_lake, "Jordan Smith")
    assert len(res.officers) == 2
    eins = sorted(o["ein"] for o in res.officers)
    assert eins == ["111111111", "222222222"]


def test_no_field_bleed_between_officer_rows(irs990_lake, people_lake):
    res = unified_search(people_lake, "Jordan Smith")
    by_ein = {o["ein"]: o for o in res.officers}
    assert by_ein["111111111"]["org_name"] == "Alpha Foundation"
    assert by_ein["111111111"]["title"] == "President"
    assert by_ein["111111111"]["state"] == "MA"
    assert by_ein["222222222"]["org_name"] == "Beta Trust"
    assert by_ein["222222222"]["title"] == "Trustee"
    assert by_ein["222222222"]["state"] == "CO"
    # Casey Smith's title never leaks onto a Jordan Smith row.
    assert all(o["name_raw"] == "Jordan Smith" for o in res.officers)
    assert all(o["title"] != "Treasurer" for o in res.officers)


# --- Jordan vs Jordán --------------------------------------------------------

def test_accented_name_matches_the_same_canonical_officer(irs990_lake, people_lake):
    res_plain = unified_search(people_lake, "Jordan Smith")
    res_accented = unified_search(people_lake, "Jord\u00e1n Smith")
    assert res_plain.officers
    assert res_accented.officers
    assert {o["ein"] for o in res_plain.officers} == {o["ein"] for o in res_accented.officers}


# --- the miss note is lake coverage, never "not an officer" -----------------

def test_a_miss_with_lake_present_says_coverage_never_not_an_officer(irs990_lake, people_lake):
    res = unified_search(people_lake, "Nobody Here")
    assert res.officers == []
    note = res.officers_note.lower()
    assert "not an officer" not in note
    assert "coverage" in note or "not imported" in note or "not in the filings" in note


def test_an_empty_or_missing_lake_says_empty_never_not_an_officer(tmp_path, monkeypatch, people_lake):
    monkeypatch.setenv("UMBRA_IRS990_DB", str(tmp_path / "missing.sqlite"))
    res = unified_search(people_lake, "Jordan Smith")
    assert res.officers == []
    note = res.officers_note.lower()
    assert "not an officer" not in note
    assert "empty" in note or "not imported" in note


def test_an_absent_irs990_lake_is_not_an_outage(tmp_path, monkeypatch, people_lake):
    monkeypatch.setenv("UMBRA_IRS990_DB", str(tmp_path / "missing.sqlite"))
    res = unified_search(people_lake, "Jordan Smith")
    assert res.officers == []
    assert res.as_dict()  # unified_search never raises


# --- index-backed lookup ------------------------------------------------------

def test_officer_lookup_uses_the_name_index(irs990_lake):
    lake = Irs990Lake(irs990_lake)
    try:
        plan = lake._conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM officer WHERE name_canonical = ?",
            (canonical("Jordan Smith"),),
        ).fetchall()
    finally:
        lake.close()
    text = " ".join(str(r[-1]) for r in plan).upper()
    assert "IDX_OFFICER_NAME" in text
    assert "SCAN OFFICER" not in text


# --- serialisation -----------------------------------------------------------

def test_results_serialise(irs990_lake, people_lake):
    import json

    json.dumps(unified_search(people_lake, "Jordan Smith").as_dict())
