"""Owned FAA aircraft-registration lake.

Same shape as the GeoIP and OUI lakes: ingest a primary source once, then answer
offline forever. No live ADS-B, no Flightradar24, no scraping registry.faa.gov.

The fixture below uses the **real** header lines from
`https://registry.faa.gov/database/ReleasableAircraft.zip`, read off the actual
archive on 2026-09-02, because three properties of that file are easy to guess
wrong and each produces a lake that looks fine and answers wrongly:

1. **The source omits the leading N.** MASTER.txt row one is `100  ,...` for
   N100. A lake keyed on the raw column never matches anything a user types.
2. **Every field is space-padded** to a fixed width, and `NAME` is 50 columns.
   Unstripped, the registrant is `"BENE MARY D" + 39 spaces`.
3. **The header itself is not clean** — there is a UTF-8 BOM on `CODE`, a
   leading space on `' KIT MODEL'`, and a trailing comma that yields an empty
   final column. Matching columns by exact header string fails on all three.

The honesty rule this lake inherits: a miss is **unchecked**, never
"not registered". The FAA also runs a PII-withholding programme under
49 U.S.C. § 44114(b), so an absent registrant may be a live aircraft whose
owner asked to be withheld — which is precisely why absence cannot mean
absence of registration.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from umbra.lake.faa import FaaLake, normalize_n_number

from faa_fixtures import (
    ACFTREF_HEADER,
    MASTER_HEADER,
    _acftref_row,
    _master_row,
    build_zip,
)


@pytest.fixture
def lake(tmp_path: Path) -> FaaLake:
    zip_path = build_zip(
        tmp_path / "ReleasableAircraft.zip",
        [
            _master_row(n_number="100", name="BENE MARY D", mfr_code="7100510"),
            _master_row(n_number="737KL", name="ACME AVIATION LLC", mfr_code="0020901",
                        type_reg="7", city="RENO", state="NV"),
            _master_row(n_number="9876Z", name="SOME COUNTY SHERIFF",
                        mfr_code="0020901", type_reg="5"),
        ],
        [
            _acftref_row(code="7100510", mfr="PIPER", model="J3C-65"),
            _acftref_row(code="0020901", mfr="AAR AIRLIFT GROUP INC", model="UH-60A",
                         seats="015", engines="02"),
        ],
    )
    lk = FaaLake(tmp_path / "faa.sqlite")
    lk.import_zip(zip_path)
    return lk


# --- normalize -------------------------------------------------------------

@pytest.mark.parametrize("raw,expect", [
    ("N123AB", "N123AB"),
    ("n123ab", "N123AB"),
    ("N-123AB", "N123AB"),
    ("  n-123-ab  ", "N123AB"),
    ("N1", "N1"),
    ("N99999", "N99999"),
])
def test_normalize_accepts_the_forms_people_actually_type(raw, expect):
    assert normalize_n_number(raw) == expect


def test_normalize_adds_the_n_the_faa_file_omits():
    """MASTER.txt stores N100 as `100`. Without this the lake keys on a form
    nobody types and every lookup misses."""
    assert normalize_n_number("100") == "N100"
    assert normalize_n_number("737KL") == "N737KL"


@pytest.mark.parametrize("bad", [
    "", "   ", "N", "N123456", "NABCDEF", "123-456-7890",
    "example.com", "N12/34", "ZZ123",
])
def test_normalize_rejects_what_is_not_an_n_number(bad):
    assert normalize_n_number(bad) is None


def test_normalize_is_idempotent():
    once = normalize_n_number("n-737-kl")
    assert once and normalize_n_number(once) == once


# --- import ----------------------------------------------------------------

def test_import_reads_both_files(lake):
    st = lake.status()
    assert st["aircraft"] == 3
    assert st["models"] == 2


def test_import_records_when_and_from_what(lake):
    st = lake.status()
    assert st["imported_at"]
    assert "ReleasableAircraft" in (st["edition"] or "")
    assert st["available"] is True


def test_a_zip_without_master_is_refused_rather_than_half_imported(tmp_path):
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("ACFTREF.txt", ACFTREF_HEADER + "\n")
    lk = FaaLake(tmp_path / "faa.sqlite")
    with pytest.raises(ValueError, match="MASTER"):
        lk.import_zip(path)
    assert lk.status()["available"] is False


def test_a_failed_import_leaves_the_previous_lake_intact(lake, tmp_path):
    """Built into a temp file and swapped, like the geoip lake — a half-written
    corpus that still answers is worse than one that says it is empty."""
    before = lake.status()["aircraft"]
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("ACFTREF.txt", ACFTREF_HEADER + "\n")
    with pytest.raises(ValueError):
        lake.import_zip(bad)
    assert lake.status()["aircraft"] == before


def test_reimport_replaces_rather_than_appends(lake, tmp_path):
    zip2 = build_zip(tmp_path / "again.zip",
                     [_master_row(n_number="1", name="ONLY ONE", mfr_code="7100510")],
                     [_acftref_row(code="7100510", mfr="PIPER", model="J3C-65")])
    lake.import_zip(zip2)
    assert lake.status()["aircraft"] == 1


# --- lookup ----------------------------------------------------------------

def test_lookup_finds_the_registrant_of_record(lake):
    hit = lake.lookup("N100")
    assert hit is not None
    assert hit.registrant_name == "BENE MARY D"


def test_lookup_strips_the_fixed_width_padding(lake):
    """NAME is a 50-column field. Unstripped it drags 39 spaces into evidence."""
    hit = lake.lookup("N100")
    assert hit.registrant_name == hit.registrant_name.strip()
    assert hit.city == "KETCHUM"


def test_lookup_accepts_the_hyphenated_form(lake):
    assert lake.lookup("n-737-kl").registrant_name == "ACME AVIATION LLC"


def test_lookup_joins_the_airframe_by_model_code(lake):
    hit = lake.lookup("N737KL")
    assert hit.manufacturer == "AAR AIRLIFT GROUP INC"
    assert hit.model == "UH-60A"
    assert hit.seats == 15
    assert hit.engines == 2


def test_an_aircraft_whose_model_code_is_unknown_still_returns_the_registrant(tmp_path):
    """ACFTREF is a join, not a gate. A missing model must not hide the
    registration — that would read as 'no such aircraft'."""
    z = build_zip(tmp_path / "z.zip",
                  [_master_row(n_number="500", name="ORPHAN OWNER", mfr_code="9999999")],
                  [_acftref_row(code="7100510", mfr="PIPER", model="J3C-65")])
    lk = FaaLake(tmp_path / "faa.sqlite")
    lk.import_zip(z)
    hit = lk.lookup("N500")
    assert hit.registrant_name == "ORPHAN OWNER"
    assert hit.manufacturer is None and hit.model is None


def test_a_miss_is_none_not_an_empty_record(lake):
    assert lake.lookup("N99999") is None


def test_an_invalid_n_number_is_a_miss_not_a_crash(lake):
    assert lake.lookup("not-a-tail-number") is None


def test_lookup_on_an_unbuilt_lake_returns_none(tmp_path):
    """Absence of a lake is not absence of an aircraft — the collector turns
    this into 'unchecked', and it must not raise to get there."""
    lk = FaaLake(tmp_path / "nope.sqlite")
    assert lk.lookup("N100") is None
    assert lk.status()["available"] is False


# --- registrant type -------------------------------------------------------

def test_registrant_type_is_decoded(lake):
    assert lake.lookup("N737KL").registrant_type == "LLC"
    assert lake.lookup("N100").registrant_type == "Individual"
    assert lake.lookup("N9876Z").registrant_type == "Government"


def test_an_individual_registrant_is_marked_as_not_an_org(lake):
    """Drives the collector: an individual's name must not become an ORG node,
    and is person data the FAA lets owners withhold under 49 USC 44114(b)."""
    assert lake.lookup("N100").registrant_is_org is False
    assert lake.lookup("N737KL").registrant_is_org is True


def test_an_unknown_registrant_code_does_not_invent_a_type(tmp_path):
    z = build_zip(tmp_path / "z.zip",
                  [_master_row(n_number="1", name="X", mfr_code="7100510", type_reg="Z")],
                  [_acftref_row(code="7100510", mfr="PIPER", model="J3C-65")])
    lk = FaaLake(tmp_path / "faa.sqlite")
    lk.import_zip(z)
    hit = lk.lookup("N1")
    assert hit.registrant_type is None
    assert hit.registrant_is_org is False


# --- facts carried through -------------------------------------------------

def test_mode_s_hex_is_carried(lake):
    assert lake.lookup("N100").mode_s_hex == "A00001"


def test_status_and_year_are_carried(lake):
    hit = lake.lookup("N100")
    assert hit.year_manufactured == 1978
    assert hit.status_code == "V"


def test_a_blank_year_is_none_not_zero(tmp_path):
    z = build_zip(tmp_path / "z.zip",
                  [_master_row(n_number="1", name="X", mfr_code="7100510", year="    ")],
                  [_acftref_row(code="7100510", mfr="PIPER", model="J3C-65")])
    lk = FaaLake(tmp_path / "faa.sqlite")
    lk.import_zip(z)
    assert lk.lookup("N1").year_manufactured is None


def test_as_dict_is_json_safe(lake):
    import json

    json.dumps(lake.lookup("N737KL").as_dict())
