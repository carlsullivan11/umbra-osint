"""`umbra people find NAME --city CITY` narrows the city-carrying groups.

`unified_search` already narrows by state. A city is a finer location: two
"Ada Lovelace" records in the same state but different cities are still two
records, and the CLI should be able to tell them apart.

What must hold:

- `--city` filters **parcels**, **clinicians** and **licensees** — the three
  groups that carry a city — case-insensitively;
- **people**, **contributors** and **officers** are left unchanged: they carry
  no city field, so a city filter must not silently drop them;
- an empty `--city` is ignored, not a crash;
- fixture sqlite only; no live downloads.

The CLI surface is tested through `unified_search` (the same function the web
and API use) plus one end-to-end `CliRunner` invocation of
`umbra people find NAME --city CITY`.
"""
from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.main import app
from umbra.lake.fec import FecLake
from umbra.lake.irs990 import Irs990Lake
from umbra.lake.nppes import NppesLake
from umbra.lake.parcels import ParcelLake, ParcelRow
from umbra.lake.people import PeopleLake
from umbra.lake.uls import ENTITY_TYPE_LICENSEE, UlsLake
from umbra.people.names import canonical
from umbra.people.search import unified_search

NS = "http://www.irs.gov/efile"


def _fec_row(name, city, state, zip9, occ="ATTORNEY", emp="ACME"):
    return (f"C001|N|12P|P2024|2024|15E|IND|{name}|{city}|{state}|{zip9}|"
            f"{emp}|{occ}|08052024|250|C002|1|1|||9")


def _parcel_row(owner, state, county, city, parcel_id):
    return ParcelRow(
        owner=owner,
        owner_canonical=canonical(owner),
        address="1 Main St",
        city=city,
        parcel_id=parcel_id,
        state=state,
        county=county,
        layer_url="https://gis.test/FeatureServer/0",
    )


NPPES_HEADER = [
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


def _nppes_row(npi, first, last, city, state):
    return {
        "NPI": npi,
        "Entity Type Code": "1",
        "Provider Last Name (Legal Name)": last,
        "Provider First Name": first,
        "Provider Middle Name": "",
        "Provider First Line Business Practice Location Address": "1 Main St",
        "Provider Second Line Business Practice Location Address": "",
        "Provider Business Practice Location Address City Name": city,
        "Provider Business Practice Location Address State Name": state,
        "Provider Business Practice Location Address Postal Code": "021432389",
        "Provider Enumeration Date": "01/01/2010",
        "Healthcare Provider Taxonomy Code_1": "207Q00000X",
    }


def _uls_hd(usi, callsign):
    return f"HD|{usi}||EBF001|{callsign}|A|HA|"


def _uls_en(usi, *, callsign, first, last, city, state):
    return (
        f"EN|{usi}||EBF001|{callsign}|{ENTITY_TYPE_LICENSEE}|LIC001||"
        f"{first}||{last}|||||1 MAIN ST|{city}|{state}|787010000|"
    )


def _irs990_xml(ein, org_name, city, state, officer_name) -> bytes:
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<Return xmlns="{NS}">
  <ReturnHeader>
    <TaxYr>2023</TaxYr>
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
    <IRS990>
      <Form990PartVIISectionAGrp>
        <PersonNm>{officer_name}</PersonNm>
        <TitleTxt>President</TitleTxt>
      </Form990PartVIISectionAGrp>
    </IRS990>
  </ReturnData>
</Return>
"""
    return xml.encode("utf-8")


@pytest.fixture
def lakes(tmp_path: Path, monkeypatch):
    """Every lake `unified_search` reads, all naming "Ada Lovelace" in two
    cities: AUSTIN TX and OAKLAND CA."""
    monkeypatch.setenv("UMBRA_FEC_DB", str(tmp_path / "fec.sqlite"))
    z = tmp_path / "fec.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("itcont.txt", "\n".join([
            _fec_row("LOVELACE, ADA", "AUSTIN", "TX", "787011234"),
            _fec_row("LOVELACE, ADA", "OAKLAND", "CA", "946120000"),
        ]) + "\n")
    fec = FecLake(tmp_path / "fec.sqlite")
    fec.import_zip(z)
    fec.close()

    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "parcels.sqlite"))
    parcel_lake = ParcelLake(tmp_path / "parcels.sqlite")
    parcel_lake._write([
        _parcel_row("Ada Lovelace", "TX", "Travis", "Austin", "P-TX-1"),
        _parcel_row("Ada Lovelace", "CA", "Alameda", "Oakland", "P-CA-1"),
    ])
    parcel_lake.close()

    monkeypatch.setenv("UMBRA_NPPES_DB", str(tmp_path / "nppes.sqlite"))
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=NPPES_HEADER)
    writer.writeheader()
    for row in [
        _nppes_row("1111111111", "ADA", "LOVELACE", "AUSTIN", "TX"),
        _nppes_row("2222222222", "ADA", "LOVELACE", "OAKLAND", "CA"),
    ]:
        writer.writerow(row)
    nppes_zip = tmp_path / "nppes.zip"
    with zipfile.ZipFile(nppes_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("npidata_pfile_20050523-20260908.csv", buf.getvalue())
    nppes = NppesLake(tmp_path / "nppes.sqlite")
    nppes.import_zip(nppes_zip)
    nppes.close()

    monkeypatch.setenv("UMBRA_ULS_DB", str(tmp_path / "uls.sqlite"))
    uls_zip = tmp_path / "uls.zip"
    with zipfile.ZipFile(uls_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("HD.dat", "\n".join([
            _uls_hd("1000000001", "KA1ABC"),
            _uls_hd("1000000002", "KB2XYZ"),
        ]) + "\n")
        zf.writestr("EN.dat", "\n".join([
            _uls_en("1000000001", callsign="KA1ABC", first="ADA", last="LOVELACE",
                    city="AUSTIN", state="TX"),
            _uls_en("1000000002", callsign="KB2XYZ", first="ADA", last="LOVELACE",
                    city="OAKLAND", state="CA"),
        ]) + "\n")
    uls = UlsLake(tmp_path / "uls.sqlite")
    uls.import_zip(uls_zip)
    uls.close()

    monkeypatch.setenv("UMBRA_IRS990_DB", str(tmp_path / "irs990.sqlite"))
    irs990 = Irs990Lake(tmp_path / "irs990.sqlite")
    irs990.import_filing_xml(
        _irs990_xml("111111111", "Alpha Foundation", "Boston", "MA", "Ada Lovelace"),
        "https://irs.test/A_public.xml",
    )
    irs990.close()

    people = PeopleLake(tmp_path / "people.sqlite")
    people.upsert_person_from_parse(
        decedent_name="Ada Lovelace", parse={},
        source_url="https://x.test/ada", title="Ada Lovelace")
    yield people
    people.close()


# --- the city filter narrows the city-carrying groups -----------------------

def test_city_narrows_parcels(lakes):
    res = unified_search(lakes, "Ada Lovelace", city="Austin")
    assert [p["city"] for p in res.parcels] == ["Austin"]
    assert res.parcels_ambiguous is False


def test_city_narrows_clinicians(lakes):
    res = unified_search(lakes, "Ada Lovelace", city="Oakland")
    assert [c["city"] for c in res.clinicians] == ["OAKLAND"]
    assert res.clinicians_ambiguous is False


def test_city_narrows_licensees(lakes):
    res = unified_search(lakes, "Ada Lovelace", city="austin")
    assert [u["city"] for u in res.licensees] == ["AUSTIN"]
    assert res.licensees_ambiguous is False


def test_city_filter_is_case_insensitive(lakes):
    for city in ("austin", "AUSTIN", "AuStIn"):
        res = unified_search(lakes, "Ada Lovelace", city=city)
        assert len(res.parcels) == 1
        assert res.parcels[0]["city"] == "Austin"


def test_a_city_that_matches_nobody_is_empty_not_everybody(lakes):
    res = unified_search(lakes, "Ada Lovelace", city="Denver")
    assert res.parcels == []
    assert res.clinicians == []
    assert res.licensees == []


# --- people / contributors / officers are unchanged -------------------------

def test_city_leaves_people_unchanged(lakes):
    plain = unified_search(lakes, "Ada Lovelace")
    filtered = unified_search(lakes, "Ada Lovelace", city="Austin")
    assert filtered.people == plain.people
    assert filtered.people


def test_city_leaves_contributors_unchanged(lakes):
    plain = unified_search(lakes, "Ada Lovelace")
    filtered = unified_search(lakes, "Ada Lovelace", city="Austin")
    assert filtered.contributors == plain.contributors
    assert len(filtered.contributors) == 2


def test_city_leaves_officers_unchanged(lakes):
    plain = unified_search(lakes, "Ada Lovelace")
    filtered = unified_search(lakes, "Ada Lovelace", city="Austin")
    assert filtered.officers == plain.officers
    assert filtered.officers


# --- an empty city is ignored, not a crash ----------------------------------

def test_an_empty_city_is_ignored(lakes):
    for empty in ("", "   "):
        res = unified_search(lakes, "Ada Lovelace", city=empty)
        assert len(res.parcels) == 2
        assert len(res.clinicians) == 2
        assert len(res.licensees) == 2


def test_an_empty_city_does_not_crash_the_cli(lakes, tmp_path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(app, ["people", "find", "Ada Lovelace", "--city", ""])
    assert result.exit_code == 0
    assert "AUSTIN" in result.stdout and "OAKLAND" in result.stdout


# --- the CLI surface --------------------------------------------------------

def test_cli_find_with_city_filters_the_city_carrying_groups(lakes, tmp_path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(
        app, ["people", "find", "Ada Lovelace", "--city", "Austin", "--json"])
    assert result.exit_code == 0
    import json

    body = json.loads(result.stdout)
    assert [p["city"] for p in body["parcels"]] == ["Austin"]
    assert [c["city"] for c in body["clinicians"]] == ["AUSTIN"]
    assert [u["city"] for u in body["licensees"]] == ["AUSTIN"]


def test_cli_find_with_city_keeps_contributors(lakes, tmp_path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(
        app, ["people", "find", "Ada Lovelace", "--city", "Austin", "--json"])
    assert result.exit_code == 0
    import json

    body = json.loads(result.stdout)
    assert {c["city"] for c in body["contributors"]} == {"AUSTIN", "OAKLAND"}


# --- serialisation -----------------------------------------------------------

def test_results_serialise_with_city(lakes):
    import json

    payload = json.dumps(unified_search(lakes, "Ada Lovelace", city="Austin").as_dict())
    assert '"city": "austin"' in payload
