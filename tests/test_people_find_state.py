"""`umbra people find NAME --state XX` must filter the location-bearing
registry groups — parcels, clinicians, licensees — to that state, and must
ignore an empty or invalid `--state` instead of crashing or returning
"no records in ZZ".

The people, contributors, and officers groups are unchanged by this PR: the
people lake has no state field, `Irs990Lake.lookup` has no state filter, and
the FEC group keeps the state narrowing it has had since the original
`unified_search` PR. The state filter here narrows parcels, clinicians, and
licensees only.

Fixture sqlite only; no live downloads.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.people_cmd import people_app
from umbra.lake.fec import FecLake
from umbra.lake.irs990 import Irs990Lake
from umbra.lake.nppes import NppesLake
from umbra.lake.parcels import ParcelLake, ParcelRow
from umbra.lake.people import PeopleLake
from umbra.lake.uls import ENTITY_TYPE_LICENSEE, UlsLake
from umbra.people.names import canonical
from umbra.people.search import unified_search

NAME = "Pat Rivera"
NS = "http://www.irs.gov/efile"


def _fec_row(i, state):
    # FecLake.lookup matches on exact canonical name, so the filed name must
    # be "Pat Rivera" exactly; distinct rows come from distinct ZIP5s.
    return (f"C00{i}|N|12P|P2024|2024|15E|IND|RIVERA, PAT|CITY{i}|{state}|"
            f"7870{i}1234|ACME|CLERK|08052024|250|C002|1|1|||9")


def _filing_xml(ein, i, state):
    # Irs990Lake.lookup matches on exact canonical name (distinct rows come
    # from distinct EINs), so the officer name must be "Pat Rivera" exactly.
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Return xmlns="{NS}">
  <ReturnHeader>
    <TaxYr>2023</TaxYr>
    <Filer>
      <EIN>{ein}</EIN>
      <BusinessName><BusinessNameLine1Txt>Org {i}</BusinessNameLine1Txt></BusinessName>
      <USAddress><CityNm>City{i}</CityNm><StateAbbreviationCd>{state}</StateAbbreviationCd></USAddress>
    </Filer>
  </ReturnHeader>
  <ReturnData>
    <IRS990>
      <Form990PartVIISectionAGrp>
        <PersonNm>Pat Rivera</PersonNm>
        <TitleTxt>Officer</TitleTxt>
      </Form990PartVIISectionAGrp>
    </IRS990>
  </ReturnData>
</Return>
""".encode("utf-8")


def _parcel_row(i, state):
    return ParcelRow(
        owner="Pat Rivera", owner_canonical=canonical("Pat Rivera"),
        address="1 Main St", city=f"City{i}", parcel_id=f"P-{i}",
        state=state, county="Travis",
        layer_url="https://gis.test/FeatureServer/0",
    )


NPPES_HEADER = [
    "NPI", "Entity Type Code", "Provider Last Name (Legal Name)",
    "Provider First Name", "Provider Middle Name",
    "Provider First Line Business Practice Location Address",
    "Provider Second Line Business Practice Location Address",
    "Provider Business Practice Location Address City Name",
    "Provider Business Practice Location Address State Name",
    "Provider Business Practice Location Address Postal Code",
    "Provider Enumeration Date", "Healthcare Provider Taxonomy Code_1",
]


def _nppes_row(npi, i, state):
    # NppesLake.lookup matches on exact canonical name (distinct rows come
    # from distinct NPIs), so no middle name is filled in.
    return {
        "NPI": npi, "Entity Type Code": "1",
        "Provider Last Name (Legal Name)": "RIVERA",
        "Provider First Name": "PAT",
        "Provider Middle Name": "",
        "Provider First Line Business Practice Location Address": "1 Main St",
        "Provider Second Line Business Practice Location Address": "",
        "Provider Business Practice Location Address City Name": f"City{i}",
        "Provider Business Practice Location Address State Name": state,
        "Provider Business Practice Location Address Postal Code": "787010000",
        "Provider Enumeration Date": "01/01/2010",
        "Healthcare Provider Taxonomy Code_1": "207Q00000X",
    }


def _nppes_zip(tmp_path: Path, rows) -> Path:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=NPPES_HEADER)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    p = tmp_path / "NPPES_Data_Dissemination.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("npidata_pfile_20050523-20260908.csv", buf.getvalue())
    return p


def _uls_hd(usi, callsign):
    return f"HD|{usi}||EBF001|{callsign}|A|HA|"


def _uls_en(usi, callsign, i, state):
    return (f"EN|{usi}||EBF001|{callsign}|{ENTITY_TYPE_LICENSEE}|LIC001||"
            f"PAT||RIVERA|||||1 MAIN ST|City{i}|{state}|787010000|")


def _uls_zip(tmp_path: Path, hd_lines, en_lines) -> Path:
    p = tmp_path / "l_amat.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("HD.dat", "\n".join(hd_lines) + "\n")
        z.writestr("EN.dat", "\n".join(en_lines) + "\n")
    return p


@pytest.fixture
def lakes(tmp_path: Path, monkeypatch):
    # people: one person, no state field
    people = PeopleLake(tmp_path / "people.sqlite")
    people.upsert_person_from_parse(
        decedent_name=NAME, parse={},
        source_url="https://x.test/1", title=NAME)

    # contributors (FEC): one TX, one CA
    monkeypatch.setenv("UMBRA_FEC_DB", str(tmp_path / "fec.sqlite"))
    z = tmp_path / "i.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("itcont.txt", "\n".join([
            _fec_row(0, "TX"), _fec_row(1, "CA"),
        ]) + "\n")
    fec = FecLake(tmp_path / "fec.sqlite")
    fec.import_zip(z)
    fec.close()

    # parcels: one TX, one CA
    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "parcels.sqlite"))
    parcels = ParcelLake(tmp_path / "parcels.sqlite")
    parcels._write([_parcel_row(0, "TX"), _parcel_row(1, "CA")])
    parcels.close()

    # officers (IRS 990): one TX, one CA
    monkeypatch.setenv("UMBRA_IRS990_DB", str(tmp_path / "irs990.sqlite"))
    irs990 = Irs990Lake(tmp_path / "irs990.sqlite")
    irs990.import_filing_xml(
        _filing_xml("100000000", 0, "TX"), "https://irs.test/0_public.xml")
    irs990.import_filing_xml(
        _filing_xml("200000000", 1, "CA"), "https://irs.test/1_public.xml")
    irs990.close()

    # clinicians (NPPES): one TX, one CA
    monkeypatch.setenv("UMBRA_NPPES_DB", str(tmp_path / "nppes.sqlite"))
    nppes = NppesLake(tmp_path / "nppes.sqlite")
    nppes.import_zip(_nppes_zip(tmp_path, [
        _nppes_row("1111111111", 0, "TX"),
        _nppes_row("2222222222", 1, "CA"),
    ]))
    nppes.close()

    # licensees (FCC ULS): one TX, one CA
    monkeypatch.setenv("UMBRA_ULS_DB", str(tmp_path / "uls.sqlite"))
    uls = UlsLake(tmp_path / "uls.sqlite")
    uls.import_zip(_uls_zip(
        tmp_path,
        [_uls_hd("1000000000", "KA1ABC"), _uls_hd("2000000000", "KA2ABC")],
        [_uls_en("1000000000", "KA1ABC", 0, "TX"),
         _uls_en("2000000000", "KA2ABC", 1, "CA")],
    ))
    uls.close()

    yield people
    people.close()


# --- --state CA filters parcels, clinicians, licensees ---------------------

def test_state_ca_filters_parcels_to_ca(lakes):
    res = unified_search(lakes, NAME, state="CA")
    assert res.parcels
    assert {p["state"] for p in res.parcels} == {"CA"}


def test_state_ca_filters_clinicians_to_ca(lakes):
    res = unified_search(lakes, NAME, state="CA")
    assert res.clinicians
    assert {c["state"] for c in res.clinicians} == {"CA"}


def test_state_ca_filters_licensees_to_ca(lakes):
    res = unified_search(lakes, NAME, state="CA")
    assert res.licensees
    assert {u["state"] for u in res.licensees} == {"CA"}


def test_state_tx_filters_all_three_groups_to_tx(lakes):
    res = unified_search(lakes, NAME, state="TX")
    assert {p["state"] for p in res.parcels} == {"TX"}
    assert {c["state"] for c in res.clinicians} == {"TX"}
    assert {u["state"] for u in res.licensees} == {"TX"}


# --- empty / invalid --state is ignored, never a crash ----------------------

def test_empty_state_is_ignored(lakes):
    plain = unified_search(lakes, NAME)
    res = unified_search(lakes, NAME, state="")
    assert res.parcels == plain.parcels
    assert res.clinicians == plain.clinicians
    assert res.licensees == plain.licensees


def test_whitespace_state_is_ignored(lakes):
    plain = unified_search(lakes, NAME)
    res = unified_search(lakes, NAME, state="   ")
    assert res.parcels == plain.parcels
    assert res.clinicians == plain.clinicians
    assert res.licensees == plain.licensees


def test_invalid_state_is_ignored(lakes):
    """'ZZ' is not a US state — it must behave like no filter, not return
    'no records in ZZ'."""
    plain = unified_search(lakes, NAME)
    res = unified_search(lakes, NAME, state="ZZ")
    assert res.parcels == plain.parcels
    assert res.clinicians == plain.clinicians
    assert res.licensees == plain.licensees


def test_invalid_state_never_crashes(lakes):
    for bad in ("ZZ", "XX", "Texas", "TEX", "1"):
        res = unified_search(lakes, NAME, state=bad)
        assert res.parcels or res.clinicians or res.licensees


# --- people / contributors / officers unchanged -----------------------------

def test_people_group_unchanged_by_state(lakes):
    """The people lake has no state field — --state must not touch it."""
    plain = unified_search(lakes, NAME)
    res = unified_search(lakes, NAME, state="CA")
    assert res.people == plain.people


def test_officers_group_unchanged_by_state(lakes):
    """Irs990Lake.lookup has no state filter — --state must not touch it."""
    plain = unified_search(lakes, NAME)
    res = unified_search(lakes, NAME, state="CA")
    assert res.officers == plain.officers


def test_contributors_group_keeps_existing_narrowing(lakes):
    """The FEC group has narrowed by state since the original unified_search
    PR; this PR adds no new filtering to it."""
    res = unified_search(lakes, NAME, state="CA")
    assert res.contributors
    assert {c["state"] for c in res.contributors} == {"CA"}


# --- CLI --------------------------------------------------------------------

def _patch_lake(monkeypatch, lakes):
    from umbra.lake import people as people_mod

    monkeypatch.setattr(people_mod.PeopleLake, "from_settings",
                        staticmethod(lambda settings: lakes))
    monkeypatch.setattr(lakes, "close", lambda: None)


def test_cli_find_state_ca_filters_parcels_clinicians_licensees(lakes, monkeypatch):
    _patch_lake(monkeypatch, lakes)
    result = CliRunner().invoke(
        people_app, ["find", NAME, "--state", "CA", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert {p["state"] for p in payload["parcels"]} == {"CA"}
    assert {c["state"] for c in payload["clinicians"]} == {"CA"}
    assert {u["state"] for u in payload["licensees"]} == {"CA"}


def test_cli_find_empty_state_is_ignored(lakes, monkeypatch):
    _patch_lake(monkeypatch, lakes)
    plain = CliRunner().invoke(people_app, ["find", NAME, "--json"])
    filtered = CliRunner().invoke(
        people_app, ["find", NAME, "--state", "", "--json"])
    assert filtered.exit_code == 0, filtered.output
    assert json.loads(filtered.output)["parcels"] == json.loads(plain.output)["parcels"]
    assert json.loads(filtered.output)["clinicians"] == json.loads(plain.output)["clinicians"]
    assert json.loads(filtered.output)["licensees"] == json.loads(plain.output)["licensees"]


def test_cli_find_invalid_state_is_ignored_no_crash(lakes, monkeypatch):
    _patch_lake(monkeypatch, lakes)
    plain = CliRunner().invoke(people_app, ["find", NAME, "--json"])
    filtered = CliRunner().invoke(
        people_app, ["find", NAME, "--state", "ZZ", "--json"])
    assert filtered.exit_code == 0, filtered.output
    assert json.loads(filtered.output)["parcels"] == json.loads(plain.output)["parcels"]
    assert json.loads(filtered.output)["clinicians"] == json.loads(plain.output)["clinicians"]
    assert json.loads(filtered.output)["licensees"] == json.loads(plain.output)["licensees"]
