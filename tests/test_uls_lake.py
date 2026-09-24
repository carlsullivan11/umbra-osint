"""FCC ULS — per-radio-service bulk license extract, NPPES/FAA-shaped.

`HD.dat` (callsign, status, radio service) is joined to `EN.dat` (licensee
name/address) by Unique System Identifier — never by callsign alone, since
the callsign only appears on `HD.dat`'s own row until the join happens.

Five fixture rows, matching the issue's "5-row fixture": three individual
licensees, one company (`Entity Name` populated, no personal name — skipped),
and one non-licensee entity type (skipped, not a company signal at all).
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from umbra.lake.uls import (
    ENTITY_TYPE_LICENSEE,
    UlsLake,
    parse_en_row,
    parse_hd_row,
)


def _hd(usi, callsign, status="A", radio_service="HA"):
    # Position: [HD]|usi|file_num|ebf|callsign|status|radio_service|...
    return f"HD|{usi}||EBF001|{callsign}|{status}|{radio_service}|"


def _en(usi, *, callsign="", entity_type=ENTITY_TYPE_LICENSEE, entity_name="",
        first="", mi="", last="", suffix="", street="", city="", state="",
        zip5=""):
    # Position: [EN]|usi|file_num|ebf|callsign|entity_type|licensee_id|
    #   entity_name|first|mi|last|suffix|phone|fax|email|street|city|state|zip
    return (
        f"EN|{usi}||EBF001|{callsign}|{entity_type}|LIC001|{entity_name}|"
        f"{first}|{mi}|{last}|{suffix}||||{street}|{city}|{state}|{zip5}|"
    )


HD_ROW_1 = _hd("1000000001", "KA1ABC")
HD_ROW_2 = _hd("1000000002", "KB2XYZ")
HD_ROW_3 = _hd("1000000003", "WC3DEF")
HD_ROW_4 = _hd("1000000004", "KD4ORG")
HD_ROW_5 = _hd("1000000005", "KE5CON", status="C", radio_service="PW")

EN_ROW_1 = _en("1000000001", callsign="KA1ABC", first="JOHN", mi="Q",
               last="PUBLIC", street="100 MAIN ST", city="BOSTON",
               state="MA", zip5="021081234")
EN_ROW_2 = _en("1000000002", callsign="KB2XYZ", first="MARIA", last="GARCIA",
               street="200 ELM ST", city="MCLEAN", state="VA", zip5="221012425")
EN_ROW_3 = _en("1000000003", callsign="WC3DEF", first="JOSE", last="GARCIA",
               street="300 OAK AVE", city="MIAMI", state="FL", zip5="331010000")
#: Same USI as EN_ROW_1, later amendment (moved).
EN_ROW_1B = _en("1000000001", callsign="KA1ABC", first="JOHN", mi="Q",
                last="PUBLIC", street="500 NEW AVE", city="CAMBRIDGE",
                state="MA", zip5="021390000")
#: A club, not a person: Entity Name populated, no personal name.
EN_ROW_4 = _en("1000000004", callsign="KD4ORG",
               entity_name="AMATEUR RADIO CLUB INC")
#: Not the licensee row at all (a contact record) — skipped by entity type,
#: independent of the company signal.
EN_ROW_5 = _en("1000000005", callsign="KE5CON", entity_type="CL",
               first="PAT", last="CONTACT")


def _zip(tmp_path: Path, hd_lines, en_lines, name="l_amat.zip") -> Path:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("HD.dat", "\n".join(hd_lines) + "\n")
        z.writestr("EN.dat", "\n".join(en_lines) + "\n")
    return p


ALL_HD = [HD_ROW_1, HD_ROW_2, HD_ROW_3, HD_ROW_4, HD_ROW_5]
ALL_EN = [EN_ROW_1, EN_ROW_2, EN_ROW_3, EN_ROW_4, EN_ROW_5]


# --- parsing -----------------------------------------------------------------

def test_hd_row_parses_usi_callsign_status_service():
    assert parse_hd_row(HD_ROW_1) == ("1000000001", "KA1ABC", "A", "HA")


def test_a_blank_hd_line_is_dropped_not_raised():
    assert parse_hd_row("") is None
    assert parse_hd_row("HD||||||") is None


def test_en_row_parses_into_a_licensee_entity():
    rec = parse_en_row(EN_ROW_1)
    assert rec is not None
    assert rec.usi == "1000000001"
    assert rec.name_raw == "JOHN Q PUBLIC"
    assert rec.city == "BOSTON"
    assert rec.state == "MA"
    assert rec.zip == "02108"


def test_name_canonical_uses_people_names_canonical():
    assert parse_en_row(EN_ROW_1).name_canonical == "john q public"


def test_a_company_entity_name_row_is_not_a_licensee():
    assert parse_en_row(EN_ROW_4) is None


def test_a_non_licensee_entity_type_is_skipped():
    assert parse_en_row(EN_ROW_5) is None


def test_accent_free_typed_name_still_canonicalizes():
    assert parse_en_row(EN_ROW_3).name_canonical == "jose garcia"


@pytest.mark.parametrize("bad", ["", "EN||"])
def test_junk_en_lines_are_dropped_not_raised(bad):
    assert parse_en_row(bad) is None


# --- ingest ------------------------------------------------------------------

def test_import_joins_hd_to_en_by_usi(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        stats = lake.import_zip(_zip(tmp_path, ALL_HD, ALL_EN))
        assert stats["rows"] == 5
        assert stats["licenses"] == 3
        assert stats["skipped_company"] == 2
    finally:
        lake.close()


def test_a_kept_license_carries_callsign_name_and_service(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, ALL_HD, ALL_EN))
        row = lake.by_callsign("KA1ABC")
        assert row["name_raw"] == "JOHN Q PUBLIC"
        assert row["city"] == "BOSTON"
        assert row["radio_service"] == "HA"
        assert row["status"] == "A"
        assert row["source"] == "fcc_uls_bulk"
    finally:
        lake.close()


def test_a_cancelled_license_status_is_stored_as_filed(tmp_path):
    """USI 5's EN row is a non-licensee contact, not a company — it is
    skipped for a different reason, but the status code itself is neither
    interpreted nor upgraded when it is present."""
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, ALL_HD, ALL_EN))
        assert lake.by_callsign("KE5CON") is None
    finally:
        lake.close()


def test_a_second_import_updates_the_same_license_in_place(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [HD_ROW_1], [EN_ROW_1]))
        lake.import_zip(_zip(tmp_path, [HD_ROW_1], [EN_ROW_1B], name="l_amat2.zip"))
        assert lake.count() == 1
        row = lake.by_callsign("KA1ABC")
        assert row["city"] == "CAMBRIDGE"
    finally:
        lake.close()


def test_a_zip_without_the_hd_en_pair_is_refused(tmp_path):
    p = tmp_path / "bad.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "nope")
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        with pytest.raises(ValueError, match="HD.dat"):
            lake.import_zip(p)
    finally:
        lake.close()


def test_reimport_of_the_same_file_is_a_noop(tmp_path):
    z = _zip(tmp_path, ALL_HD, ALL_EN)
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(z)
        stats = lake.import_zip(z)
        assert stats["already_imported"] is True
        assert lake.count() == 3
    finally:
        lake.close()


# --- lookup ------------------------------------------------------------------

def test_lookup_by_name_finds_the_license(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, ALL_HD, ALL_EN))
        hits = lake.lookup("John Q Public")
        assert len(hits) == 1
        assert hits[0]["callsign"] == "KA1ABC"
    finally:
        lake.close()


def test_lookup_can_be_narrowed_by_state(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [HD_ROW_1], [EN_ROW_1]))
        assert lake.lookup("John Q Public", state="MA")
        assert lake.lookup("John Q Public", state="CA") == []
    finally:
        lake.close()


def test_a_miss_is_empty_not_an_error(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [HD_ROW_1], [EN_ROW_1]))
        assert lake.lookup("Nobody Here") == []
    finally:
        lake.close()


def test_lookup_on_an_unbuilt_lake_is_empty(tmp_path):
    lake = UlsLake(tmp_path / "none.sqlite")
    try:
        assert lake.lookup("John Public") == []
        assert lake.status()["available"] is False
    finally:
        lake.close()


def test_status_reports_what_was_imported(tmp_path):
    lake = UlsLake(tmp_path / "uls.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, ALL_HD, ALL_EN))
        st = lake.status()
        assert st["licenses"] == 3
        assert st["imported_at"]
        assert st["available"] is True
    finally:
        lake.close()


# --- memory ------------------------------------------------------------------

def test_the_reader_streams_rather_than_reading_the_member():
    """Both `.dat` members can be large; the import must never materialise
    either one — no `.read()`/`.readlines()` on a zip member."""
    import inspect

    import umbra.lake.uls as mod

    src = inspect.getsource(mod)
    assert ".read()" not in src, "no whole-member read"
    assert "readlines()" not in src
