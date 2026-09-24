"""CMS NPPES — the National Provider Identifier registry, FEC-shaped.

NPPES is CMS's public monthly bulk download of every enumerated healthcare
provider: NPI, legal name, practice address and taxonomy. Header names come
from the published NPPES data dictionary and are pinned as constants in
`lake/nppes.py` the same way `lake/fec.py` pins column indexes.

Two shaping decisions the tests pin:

**NPI is the identity key.** Unlike FEC's coarse name+state+ZIP key, every
provider has exactly one NPI for life, so `provider.npi` is a real primary
key — but the *name* on the row is still just a name, and a match is a
registry row, not an identification.

**Individuals only, a separate table.** Entity Type Code 2 (organizations) is
skipped, and NPI rows are never merged into `people` or the FEC contributor
table.
"""
from __future__ import annotations

import csv
import io
import zipfile
from pathlib import Path

import pytest

from umbra.lake.nppes import (
    ENTITY_INDIVIDUAL,
    ENTITY_ORGANIZATION,
    NppesLake,
    parse_row,
)

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

# Five fixture rows: four individuals, one organization.
ROW_A = {
    "NPI": "1234567890",
    "Entity Type Code": "1",
    "Provider Last Name (Legal Name)": "JENNINGS",
    "Provider First Name": "EMILY",
    "Provider Middle Name": "R",
    "Provider First Line Business Practice Location Address": "100 MAIN ST",
    "Provider Second Line Business Practice Location Address": "",
    "Provider Business Practice Location Address City Name": "SOMERVILLE",
    "Provider Business Practice Location Address State Name": "MA",
    "Provider Business Practice Location Address Postal Code": "021432389",
    "Provider Enumeration Date": "05/23/2005",
    "Healthcare Provider Taxonomy Code_1": "207Q00000X",
}
ROW_B = {
    "NPI": "1234567901",
    "Entity Type Code": "1",
    "Provider Last Name (Legal Name)": "NULAND",
    "Provider First Name": "VICTORIA",
    "Provider Middle Name": "",
    "Provider First Line Business Practice Location Address": "200 ELM ST",
    "Provider Second Line Business Practice Location Address": "SUITE 4",
    "Provider Business Practice Location Address City Name": "MCLEAN",
    "Provider Business Practice Location Address State Name": "VA",
    "Provider Business Practice Location Address Postal Code": "221012425",
    "Provider Enumeration Date": "01/10/2010",
    "Healthcare Provider Taxonomy Code_1": "208D00000X",
}
ROW_C = {
    "NPI": "1234567912",
    "Entity Type Code": "1",
    "Provider Last Name (Legal Name)": "GARCIA",
    "Provider First Name": "JOSE",
    "Provider Middle Name": "",
    "Provider First Line Business Practice Location Address": "300 OAK AVE",
    "Provider Second Line Business Practice Location Address": "",
    "Provider Business Practice Location Address City Name": "MIAMI",
    "Provider Business Practice Location Address State Name": "FL",
    "Provider Business Practice Location Address Postal Code": "331010000",
    "Provider Enumeration Date": "03/01/2015",
    "Healthcare Provider Taxonomy Code_1": "207R00000X",
}
#: Same person as ROW_A, later record update (e.g. moved practice).
ROW_A2 = dict(ROW_A, **{
    "Provider First Line Business Practice Location Address": "500 NEW AVE",
    "Provider Business Practice Location Address City Name": "CAMBRIDGE",
})
#: An organization, not a person.
ROW_ORG = {
    "NPI": "1234567923",
    "Entity Type Code": ENTITY_ORGANIZATION,
    "Provider Last Name (Legal Name)": "",
    "Provider First Name": "",
    "Provider Middle Name": "",
    "Provider First Line Business Practice Location Address": "1 HOSPITAL WAY",
    "Provider Second Line Business Practice Location Address": "",
    "Provider Business Practice Location Address City Name": "BOSTON",
    "Provider Business Practice Location Address State Name": "MA",
    "Provider Business Practice Location Address Postal Code": "021150000",
    "Provider Enumeration Date": "06/06/2006",
    "Healthcare Provider Taxonomy Code_1": "282N00000X",
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


# --- parsing -----------------------------------------------------------------

def test_a_row_parses_into_a_provider():
    rec = parse_row(ROW_A)
    assert rec is not None
    assert rec.npi == "1234567890"
    assert rec.name_raw == "EMILY R JENNINGS"
    assert rec.city == "SOMERVILLE"
    assert rec.state == "MA"
    assert rec.taxonomy == "207Q00000X"


def test_name_canonical_uses_people_names_canonical():
    """ROW_A carries a middle initial ("R"); canonical keeps every token, the
    same as `people.names.canonical` does for any other source."""
    assert parse_row(ROW_A).name_canonical == "emily r jennings"


def test_the_zip_is_kept_as_five_digits():
    assert parse_row(ROW_A).zip5 == "02143"


def test_practice_address_joins_both_lines():
    assert parse_row(ROW_B).practice_address == "200 ELM ST, SUITE 4"


def test_practice_address_is_just_line_one_when_line_two_is_blank():
    assert parse_row(ROW_A).practice_address == "100 MAIN ST"


def test_an_organization_row_is_not_a_provider():
    assert parse_row(ROW_ORG) is None


def test_entity_type_individual_is_the_documented_code():
    assert ENTITY_INDIVIDUAL == "1"


def test_a_row_with_no_npi_is_dropped():
    assert parse_row(dict(ROW_A, NPI="")) is None


def test_a_row_with_no_name_is_dropped():
    bad = dict(ROW_A, **{
        "Provider Last Name (Legal Name)": "", "Provider First Name": "",
    })
    assert parse_row(bad) is None


@pytest.mark.parametrize("bad", [{}, None])
def test_junk_rows_are_dropped_not_raised(bad):
    assert parse_row(bad) is None


# --- ingest ------------------------------------------------------------------

def test_import_keys_on_npi_not_name(tmp_path):
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        stats = lake.import_zip(_zip(tmp_path, [ROW_A, ROW_B, ROW_C, ROW_ORG]))
        assert stats["rows"] == 4
        assert stats["providers"] == 3
        assert stats["skipped_organization"] == 1
    finally:
        lake.close()


def test_a_second_record_for_the_same_npi_updates_in_place(tmp_path):
    """NPI is a real unique identity key, unlike FEC's name+ZIP: the same
    provider re-appearing with new practice details is one row, updated."""
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A]))
        lake.import_zip(_zip(tmp_path, [ROW_A2], filename="npidata_pfile_2.csv"))
        assert lake.count() == 1
        row = lake.by_npi("1234567890")
        assert row["city"] == "CAMBRIDGE"
    finally:
        lake.close()


def test_a_zip_without_the_data_member_is_refused(tmp_path):
    p = tmp_path / "bad.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "nope")
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        with pytest.raises(ValueError, match="npidata_pfile"):
            lake.import_zip(p)
    finally:
        lake.close()


def test_reimport_of_the_same_file_is_a_noop(tmp_path):
    z = _zip(tmp_path, [ROW_A, ROW_B])
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        lake.import_zip(z)
        stats = lake.import_zip(z)
        assert stats["already_imported"] is True
        assert lake.count() == 2
    finally:
        lake.close()


# --- lookup ------------------------------------------------------------------

def test_lookup_by_name_finds_the_provider(tmp_path):
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A, ROW_B, ROW_C]))
        hits = lake.lookup("Emily R Jennings")
        assert len(hits) == 1
        assert hits[0]["npi"] == "1234567890"
    finally:
        lake.close()


def test_lookup_accepts_an_accent_free_typed_name():
    """"Garcia" (typed) must still find "Jose Garcia" via canonical folding."""
    assert parse_row(ROW_C).name_canonical == "jose garcia"


def test_lookup_can_be_narrowed_by_state(tmp_path):
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A]))
        assert lake.lookup("Emily R Jennings", state="MA")
        assert lake.lookup("Emily R Jennings", state="CA") == []
    finally:
        lake.close()


def test_a_miss_is_empty_not_an_error(tmp_path):
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A]))
        assert lake.lookup("Nobody Here") == []
    finally:
        lake.close()


def test_lookup_on_an_unbuilt_lake_is_empty(tmp_path):
    lake = NppesLake(tmp_path / "none.sqlite")
    try:
        assert lake.lookup("Emily Jennings") == []
        assert lake.status()["available"] is False
    finally:
        lake.close()


def test_status_reports_what_was_imported(tmp_path):
    lake = NppesLake(tmp_path / "nppes.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A, ROW_B]))
        st = lake.status()
        assert st["providers"] == 2
        assert st["imported_at"]
        assert st["available"] is True
    finally:
        lake.close()


# --- memory ------------------------------------------------------------------

def test_the_reader_streams_rather_than_reading_the_member():
    """A multi-GB monthly file. `.read()`/`.readlines()` on the member would
    OOM the container; the import must never materialise it."""
    import inspect

    import umbra.lake.nppes as mod

    src = inspect.getsource(mod)
    assert ".read()" not in src, "no whole-member read"
    assert "readlines()" not in src
