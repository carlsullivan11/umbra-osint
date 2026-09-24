"""IRS Form 990 officers/directors — org-officer candidates, not people.

Fixtures below are minimal, hand-built XML shaped like the real MeF elements
(`Form990PartVIISectionAGrp/PersonNm`, `TitleTxt`, `ReturnHeader/Filer/EIN`,
`BusinessNameLine1Txt`, `TaxYr`) documented in `lake/irs990.py` — no live IRS
fetch happens in these tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.irs990 import Irs990Lake, officer_key, parse_filing_xml

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


# --- parsing ----------------------------------------------------------------

def test_parses_all_officers_in_a_filing():
    officers = parse_filing_xml(FILING_A, "https://example.test/a.xml")
    assert len(officers) == 2
    names = {o.name_raw for o in officers}
    assert names == {"Jordan Smith", "Casey Smith"}


def test_officer_carries_the_filer_header_fields():
    officers = parse_filing_xml(FILING_A, "https://example.test/a.xml")
    rec = officers[0]
    assert rec.ein == "111111111"
    assert rec.org_name == "Alpha Foundation"
    assert rec.tax_year == "2023"
    assert rec.city == "Boston"
    assert rec.state == "MA"


def test_title_is_kept_as_filed():
    officers = parse_filing_xml(FILING_A, "https://example.test/a.xml")
    titles = {o.name_raw: o.title for o in officers}
    assert titles["Jordan Smith"] == "President"
    assert titles["Casey Smith"] == "Treasurer"


def test_name_canonical_uses_the_shared_canonicalizer():
    from umbra.people.names import canonical

    officers = parse_filing_xml(FILING_A, "https://example.test/a.xml")
    rec = next(o for o in officers if o.name_raw == "Jordan Smith")
    assert rec.name_canonical == canonical("Jordan Smith")


def test_malformed_xml_returns_no_officers_not_an_exception():
    assert parse_filing_xml(b"<Return><oops", "https://example.test/bad.xml") == []


def test_a_filing_with_no_officers_group_is_empty():
    xml = FILING_A.replace(b"Form990PartVIISectionAGrp", b"SomethingElseGrp")
    assert parse_filing_xml(xml, "https://example.test/none.xml") == []


# --- identity key: same surname, different EIN --------------------------

def test_two_officers_same_surname_different_ein_get_different_keys():
    """Jordan Smith at Alpha and Jordan Smith at Beta share a surname (and in
    this fixture, the whole name) but sit at two different organizations —
    they must never collapse into one identity."""
    a = next(o for o in parse_filing_xml(FILING_A, "u1") if o.name_raw == "Jordan Smith")
    b = next(o for o in parse_filing_xml(FILING_B, "u2") if o.name_raw == "Jordan Smith")
    assert a.ein != b.ein
    assert a.name_canonical == b.name_canonical
    assert officer_key(a) != officer_key(b)


def test_import_keeps_both_officers_as_separate_rows(tmp_path: Path):
    lake = Irs990Lake(tmp_path / "irs990.sqlite")
    try:
        lake.import_filing_xml(FILING_A, "https://example.test/a.xml",
                                year="2023", object_id="a")
        lake.import_filing_xml(FILING_B, "https://example.test/b.xml",
                                year="2023", object_id="b")
        rows = lake._conn.execute(
            "SELECT ein, name_canonical, org_name FROM officer "
            "WHERE name_canonical = ? ORDER BY ein",
            (parse_filing_xml(FILING_A, "u")[0].name_canonical,),
        ).fetchall()
        assert len(rows) == 2
        eins = {r["ein"] for r in rows}
        assert eins == {"111111111", "222222222"}
        orgs = {r["org_name"] for r in rows}
        assert orgs == {"Alpha Foundation", "Beta Trust"}
    finally:
        lake.close()


def test_import_is_idempotent_per_object_id(tmp_path: Path):
    lake = Irs990Lake(tmp_path / "irs990.sqlite")
    try:
        lake.import_filing_xml(FILING_A, "https://example.test/a.xml",
                                year="2023", object_id="a")
        n_before = lake.count()
        # Re-import of the same object_id should not create duplicate rows
        # (upsert on the stable key), and status still reports one file.
        lake.import_filing_xml(FILING_A, "https://example.test/a.xml",
                                year="2023", object_id="a")
        assert lake.count() == n_before
        st = lake.status()
        assert st["files_imported"] == 1
    finally:
        lake.close()


def test_status_reports_officers_and_years(tmp_path: Path):
    lake = Irs990Lake(tmp_path / "irs990.sqlite")
    try:
        lake.import_filing_xml(FILING_A, "https://example.test/a.xml",
                                year="2023", object_id="a")
        st = lake.status()
        assert st["available"] is True
        assert st["officers"] == 2
        assert st["years"] == ["2023"]
    finally:
        lake.close()


def test_lake_never_merges_into_people_or_fec_or_nppes():
    """No cross-lake import anywhere in the module — the isolation is
    structural, not just documented."""
    import inspect

    import umbra.lake.irs990 as mod

    src = inspect.getsource(mod)
    assert "lake.people" not in src
    assert "lake.fec" not in src
    assert "lake.nppes" not in src


def test_an_empty_lake_reports_unavailable(tmp_path: Path):
    lake = Irs990Lake(tmp_path / "none.sqlite")
    try:
        st = lake.status()
        assert st["available"] is False
        assert st["officers"] == 0
    finally:
        lake.close()
