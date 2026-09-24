"""Records → people lake.

`county_sources`, `land_facts` and `sor_sources` have existed with indexes since
the lake was built and have held **zero rows** the whole time. Meanwhile
`RecordSearch` already unifies court opinions, parcel owner-name hits and portal
pointers across 100 verified sources, and the lake already has a writer for each
kind. Nothing was missing except the wire between them.

Two rules the bridge has to hold:

**A portal is not a record.** `RecordHit.is_record` is False for portals — they
are a pointer at a place to look, not a finding about anybody. Writing them into
the lake as county records would turn "here is the county's search page" into
"this person appears in county records".

**A name hit is not an identification.** A parcel whose owner field contains
"John Smith" is a John Smith, not necessarily *the* John Smith. The lake records
that, and `name_hit` stays a flag rather than becoming a claim.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.people import PeopleLake
from umbra.people.enrich import enrich_from_records
from umbra.records import RecordHit, RecordSearch


@pytest.fixture
def lake(tmp_path: Path):
    lk = PeopleLake(tmp_path / "people.sqlite")
    yield lk
    lk.close()


def _search(**kw) -> RecordSearch:
    return RecordSearch(query=kw.pop("query", "John Smith"), **kw)


LAND = RecordHit(kind="land", title="123 Main St", url="https://gis.test/p/1",
                 detail="APN 123-45-678 · owner JOHN SMITH", region="AR-Pulaski",
                 source="gis.arkansas.gov")
COURT = RecordHit(kind="court_opinion", title="Smith v. Acme",
                  url="https://courtlistener.test/o/1",
                  detail="9th Cir. 2019", source="courtlistener.com")
PORTAL = RecordHit(kind="portal", title="Pulaski County Assessor",
                   url="https://assessor.test/", is_record=False,
                   reachable="link_only", region="AR-Pulaski")


# --- land ------------------------------------------------------------------

def test_a_land_hit_becomes_a_land_fact(lake):
    stats = enrich_from_records(lake, "John Smith", _search(parcels=[LAND]))
    assert stats["land"] == 1
    row = lake._conn.execute("SELECT person_name, apn, region FROM land_facts").fetchone()
    assert row[0] == "John Smith"
    assert row[2] == "AR-Pulaski"


def test_the_apn_is_pulled_out_of_the_detail(lake):
    enrich_from_records(lake, "John Smith", _search(parcels=[LAND]))
    apn = lake._conn.execute("SELECT apn FROM land_facts").fetchone()[0]
    assert apn == "123-45-678"


def test_a_land_hit_with_no_apn_still_records_the_address(lake):
    """upsert_land_fact needs an apn *or* a situs. An address alone is a fact."""
    hit = RecordHit(kind="land", title="9 Elm St", url="https://gis.test/p/2",
                    detail="owner JANE ROE", region="VT-Addison")
    stats = enrich_from_records(lake, "Jane Roe", _search(parcels=[hit]))
    assert stats["land"] == 1
    assert lake._conn.execute("SELECT situs FROM land_facts").fetchone()[0] == "9 Elm St"


# --- court -----------------------------------------------------------------

def test_a_court_hit_becomes_a_county_source_row(lake):
    stats = enrich_from_records(lake, "John Smith", _search(court=[COURT]))
    assert stats["court"] == 1
    row = lake._conn.execute(
        "SELECT kind, title, name_hit FROM county_sources").fetchone()
    assert row[0] == "court_opinion"
    assert row[1] == "Smith v. Acme"


def test_a_court_hit_is_marked_as_a_name_hit_not_an_identification(lake):
    """CourtListener matched a string. It did not confirm a person."""
    enrich_from_records(lake, "John Smith", _search(court=[COURT]))
    assert lake._conn.execute("SELECT name_hit FROM county_sources").fetchone()[0] == 1


# --- portals are not records -----------------------------------------------

def test_a_portal_is_never_written_as_a_record(lake):
    """is_record=False. A pointer at the county's search page is not evidence
    that anybody appears in county records."""
    stats = enrich_from_records(lake, "John Smith", _search(portals=[PORTAL]))
    assert stats["county"] == 0
    assert stats["land"] == 0
    assert lake._conn.execute("SELECT COUNT(*) FROM county_sources").fetchone()[0] == 0


def test_portals_are_counted_separately_so_the_skip_is_visible(lake):
    stats = enrich_from_records(lake, "John Smith", _search(portals=[PORTAL]))
    assert stats["portals_skipped"] == 1


def test_a_hit_flagged_not_a_record_is_skipped_whatever_its_kind(lake):
    hit = RecordHit(kind="land", title="x", url="https://gis.test/p/9",
                    detail="APN 1", is_record=False)
    stats = enrich_from_records(lake, "John Smith", _search(parcels=[hit]))
    assert stats["land"] == 0


# --- the person is linked --------------------------------------------------

def test_the_person_is_created_if_absent(lake):
    enrich_from_records(lake, "John Smith", _search(parcels=[LAND]))
    assert lake.search_name("John Smith")


def test_an_existing_person_is_reused_not_duplicated(lake):
    lake.upsert_person_from_parse(decedent_name="John Smith", parse={},
                                  source_url="https://x.test/1", title="John Smith")
    before = lake._conn.execute("SELECT COUNT(*) FROM people").fetchone()[0]
    enrich_from_records(lake, "John Smith", _search(parcels=[LAND]))
    assert lake._conn.execute("SELECT COUNT(*) FROM people").fetchone()[0] == before


def test_records_are_findable_from_the_person(lake):
    """The point of the whole exercise: search a name, get their records."""
    enrich_from_records(lake, "John Smith", _search(parcels=[LAND], court=[COURT]))
    recs = lake.records_for_name("John Smith")
    assert len(recs["land"]) == 1
    assert len(recs["county"]) == 1


def test_records_for_an_unknown_name_are_empty_not_an_error(lake):
    assert lake.records_for_name("Nobody Here") == {"land": [], "county": []}


# --- idempotence and honesty ----------------------------------------------

def test_running_twice_does_not_duplicate(lake):
    for _ in range(2):
        enrich_from_records(lake, "John Smith", _search(parcels=[LAND], court=[COURT]))
    assert lake._conn.execute("SELECT COUNT(*) FROM land_facts").fetchone()[0] == 1
    assert lake._conn.execute("SELECT COUNT(*) FROM county_sources").fetchone()[0] == 1


def test_an_empty_search_writes_nothing_and_says_so(lake):
    stats = enrich_from_records(lake, "John Smith", _search())
    assert stats["land"] == stats["court"] == stats["county"] == 0
    assert stats["note"]


def test_the_note_never_claims_the_person_has_no_records(lake):
    """Nothing found means the sources checked had nothing, not that none exist."""
    note = enrich_from_records(lake, "John Smith", _search())["note"].lower()
    assert "no records" not in note
    assert "unchecked" in note or "searched" in note


def test_a_blank_name_is_refused(lake):
    for bad in ("", "   "):
        stats = enrich_from_records(lake, bad, _search(parcels=[LAND]))
        assert stats["land"] == 0


# --- the writer and the reader must normalise identically -------------------
#
# `upsert_land_fact` computed `person_norm` with the lake's old `_norm_name`
# (lowercase + collapse whitespace) while `records_for_name` looked up with the
# new `canonical` (which also folds diacritics, drops suffixes and un-reverses
# "Last, First"). They agree on "John Smith" and diverge on everything else, so
# a record written for "José García" was stored under 'josé garcía' and searched
# for under 'jose garcia' — written, indexed, and unreachable.

@pytest.mark.parametrize("name", [
    "José García", "John Smith Jr.", "Ginsburg, Ruth", "Renée Zellweger",
])
def test_a_record_is_readable_back_under_the_name_it_was_written_with(lake, name):
    hit = RecordHit(kind="land", title="1 Main St", url=f"https://gis.test/{name}",
                    detail="APN 9-9-9", region="XX")
    enrich_from_records(lake, name, _search(query=name, parcels=[hit]))
    assert lake.records_for_name(name)["land"], f"{name} written but not findable"


def test_a_record_is_findable_by_an_equivalent_spelling(lake):
    """The point of one shared normaliser: written accented, found plain."""
    hit = RecordHit(kind="land", title="1 Main St", url="https://gis.test/g",
                    detail="APN 9-9-9")
    enrich_from_records(lake, "José García", _search(query="x", parcels=[hit]))
    assert lake.records_for_name("Jose Garcia")["land"]
