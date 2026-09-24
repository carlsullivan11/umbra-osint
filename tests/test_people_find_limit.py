"""`umbra people find NAME --limit N` (default 20, max 100) must be honored
for every labelled group `unified_search` returns — `people`, `contributors`,
`parcels`, `officers`, `clinicians`, `licensees` — not just `contributors`,
which is all `test_the_limit_is_honoured_across_both_groups` in
`test_people_unified_search.py` checks.

Fixture lakes only; no live downloads.
"""
from __future__ import annotations

import io
import csv
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.people_cmd import FIND_DEFAULT_LIMIT, FIND_MAX_LIMIT, people_app
from umbra.lake.fec import FecLake
from umbra.lake.irs990 import Irs990Lake
from umbra.lake.nppes import NppesLake
from umbra.lake.parcels import ParcelLake, ParcelRow
from umbra.lake.people import PeopleLake
from umbra.lake.uls import ENTITY_TYPE_LICENSEE, UlsLake
from umbra.people.names import canonical
from umbra.people.search import unified_search

NAME = "Pat Rivera"
MIDDLES = ["B", "C", "D", "E", "F"]  # five distinct people, same first/last
NS = "http://www.irs.gov/efile"


def _fec_row(middle, i):
    # FecLake.lookup matches on exact canonical name, so the filed name must
    # be "Pat Rivera" exactly; distinct rows come from distinct ZIP5s.
    return (f"C00{i}|N|12P|P2024|2024|15E|IND|RIVERA, PAT|CITY{i}|TX|"
            f"7870{i}1234|ACME|CLERK|08052024|250|C002|1|1|||9")


def _filing_xml(ein, middle, i):
    # Irs990Lake.lookup matches on exact canonical name (distinct rows come
    # from distinct EINs), so the officer name must be "Pat Rivera" exactly.
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Return xmlns="{NS}">
  <ReturnHeader>
    <TaxYr>2023</TaxYr>
    <Filer>
      <EIN>{ein}</EIN>
      <BusinessName><BusinessNameLine1Txt>Org {i}</BusinessNameLine1Txt></BusinessName>
      <USAddress><CityNm>City{i}</CityNm><StateAbbreviationCd>TX</StateAbbreviationCd></USAddress>
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


def _nppes_row(npi, middle, i):
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
        "Provider Business Practice Location Address State Name": "TX",
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


def _uls_en(usi, callsign, i):
    return (f"EN|{usi}||EBF001|{callsign}|{ENTITY_TYPE_LICENSEE}|LIC001||"
            f"PAT||RIVERA|||||1 MAIN ST|City{i}|TX|787010000|")


def _uls_zip(tmp_path: Path, hd_lines, en_lines) -> Path:
    p = tmp_path / "l_amat.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("HD.dat", "\n".join(hd_lines) + "\n")
        z.writestr("EN.dat", "\n".join(en_lines) + "\n")
    return p


@pytest.fixture
def lakes(tmp_path: Path, monkeypatch):
    # people: 5 distinct people, same first/last, different middle initials
    people = PeopleLake(tmp_path / "people.sqlite")
    for m in MIDDLES:
        people.upsert_person_from_parse(
            decedent_name=f"Pat {m} Rivera", parse={},
            source_url=f"https://x.test/{m}", title=f"Pat {m} Rivera")

    # contributors (FEC)
    monkeypatch.setenv("UMBRA_FEC_DB", str(tmp_path / "fec.sqlite"))
    z = tmp_path / "i.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("itcont.txt", "\n".join(
            _fec_row(m, i) for i, m in enumerate(MIDDLES)) + "\n")
    fec = FecLake(tmp_path / "fec.sqlite")
    fec.import_zip(z)
    fec.close()

    # parcels
    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "parcels.sqlite"))
    parcels = ParcelLake(tmp_path / "parcels.sqlite")
    # ParcelLake.lookup matches on exact canonical owner name, so the owner
    # string must be "Pat Rivera" exactly; distinct rows come from distinct
    # parcel ids.
    parcels._write([
        ParcelRow(
            owner="Pat Rivera", owner_canonical=canonical("Pat Rivera"),
            address="1 Main St", city=f"City{i}", parcel_id=f"P-{i}",
            state="TX", county="Travis",
            layer_url="https://gis.test/FeatureServer/0",
        )
        for i, m in enumerate(MIDDLES)
    ])
    parcels.close()

    # officers (IRS 990)
    monkeypatch.setenv("UMBRA_IRS990_DB", str(tmp_path / "irs990.sqlite"))
    irs990 = Irs990Lake(tmp_path / "irs990.sqlite")
    for i, m in enumerate(MIDDLES):
        irs990.import_filing_xml(
            _filing_xml(f"{i}00000000", m, i), f"https://irs.test/{i}_public.xml")
    irs990.close()

    # clinicians (NPPES)
    monkeypatch.setenv("UMBRA_NPPES_DB", str(tmp_path / "nppes.sqlite"))
    nppes = NppesLake(tmp_path / "nppes.sqlite")
    nppes.import_zip(_nppes_zip(tmp_path, [
        _nppes_row(f"{i}111111111", m, i) for i, m in enumerate(MIDDLES)
    ]))
    nppes.close()

    # licensees (FCC ULS)
    monkeypatch.setenv("UMBRA_ULS_DB", str(tmp_path / "uls.sqlite"))
    uls = UlsLake(tmp_path / "uls.sqlite")
    uls.import_zip(_uls_zip(
        tmp_path,
        [_uls_hd(f"100000000{i}", f"KA{i}ABC") for i in range(len(MIDDLES))],
        [_uls_en(f"100000000{i}", f"KA{i}ABC", i) for i in range(len(MIDDLES))],
    ))
    uls.close()

    yield people
    people.close()


# --- every group is sliced to the requested limit --------------------------

def test_people_group_is_limited(lakes):
    res = unified_search(lakes, NAME, limit=2)
    assert len(res.people) <= 2


def test_contributors_group_is_limited(lakes):
    res = unified_search(lakes, NAME, limit=2)
    assert len(res.contributors) <= 2


def test_parcels_group_is_limited(lakes):
    res = unified_search(lakes, NAME, limit=2)
    assert len(res.parcels) <= 2


def test_officers_group_is_limited(lakes):
    res = unified_search(lakes, NAME, limit=2)
    assert len(res.officers) <= 2


def test_clinicians_group_is_limited(lakes):
    res = unified_search(lakes, NAME, limit=2)
    assert len(res.clinicians) <= 2


def test_licensees_group_is_limited(lakes):
    res = unified_search(lakes, NAME, limit=2)
    assert len(res.licensees) <= 2


def test_all_groups_actually_have_more_than_the_limit_available(lakes):
    """The slicing tests above are only meaningful if each fixture lake holds
    more rows than the limit being tested — confirm that at a high limit
    before trusting the limit=2 assertions."""
    res = unified_search(lakes, NAME, limit=100)
    assert len(res.people) > 2
    assert len(res.contributors) > 2
    assert len(res.parcels) > 2
    assert len(res.officers) > 2
    assert len(res.clinicians) > 2
    assert len(res.licensees) > 2


def test_a_higher_limit_returns_more_rows_in_every_group(lakes):
    small = unified_search(lakes, NAME, limit=1)
    large = unified_search(lakes, NAME, limit=5)
    assert len(large.people) >= len(small.people)
    assert len(large.contributors) > len(small.contributors)
    assert len(large.parcels) > len(small.parcels)
    assert len(large.officers) > len(small.officers)
    assert len(large.clinicians) > len(small.clinicians)
    assert len(large.licensees) > len(small.licensees)


# --- CLI: default 20, clamp to max 100 --------------------------------------

def test_cli_find_default_limit_constant_is_20():
    assert FIND_DEFAULT_LIMIT == 20


def test_cli_find_max_limit_constant_is_100():
    assert FIND_MAX_LIMIT == 100


def _spy_unified_search(monkeypatch, captured):
    import umbra.people.search as search_mod
    real = search_mod.unified_search

    def spy(lake, name, **kw):
        captured["limit"] = kw.get("limit")
        return real(lake, name, **kw)

    monkeypatch.setattr(search_mod, "unified_search", spy)


def _patch_lake(monkeypatch, lakes):
    from umbra.lake import people as people_mod

    monkeypatch.setattr(people_mod.PeopleLake, "from_settings",
                         staticmethod(lambda settings: lakes))
    monkeypatch.setattr(lakes, "close", lambda: None)


def test_cli_find_passes_the_default_limit(lakes, monkeypatch):
    _patch_lake(monkeypatch, lakes)
    captured: dict = {}
    _spy_unified_search(monkeypatch, captured)

    runner = CliRunner()
    result = runner.invoke(people_app, ["find", NAME])
    assert result.exit_code == 0, result.output
    assert captured["limit"] == FIND_DEFAULT_LIMIT


def test_cli_find_clamps_a_limit_above_the_max(lakes, monkeypatch):
    _patch_lake(monkeypatch, lakes)
    captured: dict = {}
    _spy_unified_search(monkeypatch, captured)

    runner = CliRunner()
    result = runner.invoke(people_app, ["find", NAME, "--limit", "500"])
    assert result.exit_code == 0, result.output
    assert captured["limit"] == FIND_MAX_LIMIT


def test_cli_find_clamps_a_limit_below_one(lakes, monkeypatch):
    _patch_lake(monkeypatch, lakes)
    captured: dict = {}
    _spy_unified_search(monkeypatch, captured)

    runner = CliRunner()
    result = runner.invoke(people_app, ["find", NAME, "--limit", "0"])
    assert result.exit_code == 0, result.output
    assert captured["limit"] == 1
