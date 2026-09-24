"""Indexed people search on top of the name keys.

The old lookup was `norm_name = ? OR norm_name LIKE ? OR full_name LIKE ?`.
This replaces it with an equality join against `person_name_key`, so the query
planner can use an index, and returns *how* each row matched so an exact hit and
an initials hit are not presented as the same fact.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.people import PeopleLake
from umbra.people.names import MatchStrength


@pytest.fixture
def lake(tmp_path: Path):
    lk = PeopleLake(tmp_path / "people.sqlite")
    for name in ("Ruth Bader Ginsburg", "Robert Smith", "Jane Smith",
                 "José García", "Cher"):
        lk.upsert_person_from_parse(
            decedent_name=name, parse={}, source_url=f"https://x.test/{name}",
            title=name)
    yield lk
    lk.close()


def names(rows) -> list[str]:
    return [r["full_name"] for r in rows]


# --- the variants that used to miss ----------------------------------------

def test_the_exact_name_is_found(lake):
    assert "Ruth Bader Ginsburg" in names(lake.search_name("Ruth Bader Ginsburg"))


def test_a_dropped_middle_name_is_found(lake):
    assert "Ruth Bader Ginsburg" in names(lake.search_name("Ruth Ginsburg"))


def test_the_reversed_form_is_found(lake):
    assert "Ruth Bader Ginsburg" in names(lake.search_name("Ginsburg, Ruth"))


def test_an_initial_is_found(lake):
    assert "Ruth Bader Ginsburg" in names(lake.search_name("R. Ginsburg"))


def test_an_accented_name_is_found_without_the_accent(lake):
    assert "José García" in names(lake.search_name("Jose Garcia"))


def test_a_nickname_finds_the_formal_record(lake):
    assert "Robert Smith" in names(lake.search_name("Bob Smith"))


def test_a_suffix_does_not_prevent_a_match(lake):
    assert "Robert Smith" in names(lake.search_name("Robert Smith Jr."))


def test_a_single_name_is_found(lake):
    assert "Cher" in names(lake.search_name("Cher"))


# --- match strength is reported --------------------------------------------

def test_an_exact_match_is_labelled_exact(lake):
    row = lake.search_name("Ruth Bader Ginsburg")[0]
    assert row["match"] == MatchStrength.EXACT.value


def test_a_dropped_middle_name_is_labelled_partial(lake):
    row = lake.search_name("Ruth Ginsburg")[0]
    assert row["match"] == MatchStrength.PARTIAL.value


def test_an_initial_match_is_labelled_weak(lake):
    row = lake.search_name("R. Ginsburg")[0]
    assert row["match"] == MatchStrength.WEAK.value


def test_stronger_matches_sort_first(lake):
    """'J. Smith' matches Jane and (weakly) nobody exactly; 'Jane Smith' must
    put the exact hit above any initials hit."""
    rows = lake.search_name("Jane Smith")
    assert rows[0]["full_name"] == "Jane Smith"
    assert rows[0]["match"] == MatchStrength.EXACT.value


def test_an_ambiguous_initial_returns_both_and_says_so(lake):
    rows = lake.search_name("J. Smith")
    assert {"Jane Smith", "Robert Smith"} & set(names(rows))
    assert all(r["match"] == MatchStrength.WEAK.value for r in rows)


# --- what must not happen --------------------------------------------------

def test_a_bare_surname_browses_and_says_that_is_what_it_did(lake):
    """Searching a surname is a real thing users do, and refusing it was the
    wrong call — an earlier readiness test already relied on it working.

    What matters is that it is not silently presented as identifying a person:
    the rows come back labelled SURNAME, so a caller can render "3 people named
    Smith" rather than implying a match on anyone in particular. The limit is
    what keeps a 450k-row lake from answering with a directory dump.
    """
    rows = lake.search_name("Smith")
    assert {"Robert Smith", "Jane Smith"} <= set(names(rows))
    assert all(r["match"] == MatchStrength.SURNAME.value for r in rows)


def test_a_surname_browse_is_capped(lake):
    assert len(lake.search_name("Smith", limit=1)) == 1


def test_an_unknown_name_returns_nothing(lake):
    assert lake.search_name("Nobody Here") == []


def test_junk_returns_nothing_rather_than_everything(lake):
    for junk in ("", "   ", "%", "'"):
        assert lake.search_name(junk) == []


def test_a_wildcard_is_not_interpreted(lake):
    """The old path used LIKE, so '%' matched every row."""
    assert lake.search_name("%%%") == []


def test_the_limit_is_honoured(lake):
    assert len(lake.search_name("J. Smith", limit=1)) == 1


# --- the index exists ------------------------------------------------------

def test_keys_are_stored_and_indexed(lake):
    tables = {r[0] for r in lake._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "person_name_key" in tables
    idx = {r[0] for r in lake._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    assert any("name_key" in i for i in idx)


def test_the_lookup_uses_the_index_not_a_scan(lake):
    """The reason this exists: LIKE '%x%' cannot use an index, and at 450k rows
    every search becomes a full table scan."""
    plan = lake._conn.execute(
        "EXPLAIN QUERY PLAN SELECT p.* FROM people p "
        "JOIN person_name_key k ON k.person_id = p.id WHERE k.key = ?",
        ("ruth bader ginsburg",)).fetchall()
    text = " ".join(str(r[-1]) for r in plan).upper()
    assert "SCAN PERSON_NAME_KEY" not in text, text


def test_reindexing_is_idempotent(lake):
    before = lake._conn.execute("SELECT COUNT(*) FROM person_name_key").fetchone()[0]
    lake.reindex_names()
    after = lake._conn.execute("SELECT COUNT(*) FROM person_name_key").fetchone()[0]
    assert before == after


def test_reindex_backfills_rows_written_before_the_index_existed(lake):
    lake._conn.execute("DELETE FROM person_name_key")
    lake._conn.commit()
    assert lake.search_name("Ruth Bader Ginsburg") == []
    n = lake.reindex_names()
    assert n > 0
    assert "Ruth Bader Ginsburg" in names(lake.search_name("Ruth Bader Ginsburg"))
