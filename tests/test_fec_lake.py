"""FEC individual contributions — the bulk source of living people.

Wikidata tops out at ~454k deceased US humans. Getting to millions means
living people, and the largest lawful bulk source with an occupation attached
is FEC campaign finance: name, city, state, ZIP, employer, occupation, and a
date, published by the FEC as public record for exactly this purpose.

Format confirmed against the real 2024 file (`indiv24.zip`, 3.95 GB, ZIP64):
21 pipe-delimited columns, no header row, and `NAME` in **"LAST, FIRST"** form —
which `people.names.canonical` already un-reverses.

Two shaping decisions the tests pin:

**Aggregated, not transactional.** 70M contribution rows are a donations
database. Umbra wants a person index, so rows collapse to one record per
(name, state, ZIP) with counts and date ranges. Storing every transaction would
be a different product.

**A separate table, not merged into `people`.** `people` holds deceased
notables with obituaries and kinship. Merging millions of living donors into it
would destroy what a row there means, and a name+ZIP match is not an
identification. Same discipline as `land_facts`.
"""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from umbra.lake.fec import (
    ENTITY_INDIVIDUAL,
    FecLake,
    contributor_key,
    parse_line,
)

# Real rows, verbatim from indiv24.zip.
ROW_A = ("C00878454|N|12P|P2024|202408299675313804|15E|IND|JENNINGS, EMILY|"
         "SOMERVILLE|MA|021432389|SKADDEN ARPS|ATTORNEY|08052024|250|"
         "C00401224|4187316|1813451||* EARMARKED|4083020242017155126")
ROW_B = ("C00878454|N|12P|P2024|202408299675314106|15E|IND|NULAND, VICTORIA|"
         "MCLEAN|VA|221012425|NOT EMPLOYED|NOT EMPLOYED|08052024|300|"
         "C00401224|4187311|1813451||* EARMARKED|4083020242017156032")
#: Same person, second contribution, different amount and date.
ROW_A2 = ROW_A.replace("|08052024|250|", "|09122024|500|")
#: A committee, not a person.
ROW_ORG = ROW_A.replace("|IND|", "|ORG|").replace("JENNINGS, EMILY", "ACME PAC")


def _zip(tmp_path: Path, rows) -> Path:
    p = tmp_path / "indiv24.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("itcont.txt", "\n".join(rows) + "\n")
    return p


# --- parsing ---------------------------------------------------------------

def test_a_row_parses_into_a_contributor():
    rec = parse_line(ROW_A)
    assert rec is not None
    assert rec.name_raw == "JENNINGS, EMILY"
    assert rec.city == "SOMERVILLE"
    assert rec.state == "MA"
    assert rec.employer == "SKADDEN ARPS"
    assert rec.occupation == "ATTORNEY"


def test_the_last_first_form_is_un_reversed():
    """FEC stores "JENNINGS, EMILY". Phase A's canonical already handles it,
    which is the whole reason this source drops in cleanly."""
    assert parse_line(ROW_A).name_canonical == "emily jennings"


def test_the_zip_is_kept_as_five_digits():
    """FEC ships ZIP+4. Five is the identity-useful part and the +4 is close
    enough to a street address to be worth not storing."""
    assert parse_line(ROW_A).zip5 == "02143"


def test_the_date_becomes_iso():
    assert parse_line(ROW_A).date == "2024-08-05"


def test_the_amount_is_an_integer_of_dollars():
    assert parse_line(ROW_A).amount == 250


def test_a_committee_row_is_not_a_person():
    """ENTITY_TP separates individuals from PACs and companies."""
    assert parse_line(ROW_ORG) is None


def test_entity_type_individual_is_the_documented_code():
    assert ENTITY_INDIVIDUAL == "IND"


def test_not_employed_is_kept_as_stated_not_nulled():
    """"NOT EMPLOYED" is what the filer declared. Turning it into NULL would
    lose a fact and make it look unasked."""
    rec = parse_line(ROW_B)
    assert rec.employer == "NOT EMPLOYED"
    assert rec.occupation == "NOT EMPLOYED"


@pytest.mark.parametrize("bad", [
    "", "   ", "too|few|columns", "|".join([""] * 21),
])
def test_junk_rows_are_dropped_not_raised(bad):
    assert parse_line(bad) is None


def test_a_row_with_no_name_is_dropped():
    assert parse_line(ROW_A.replace("JENNINGS, EMILY", "")) is None


# --- identity key ----------------------------------------------------------

def test_the_same_person_gets_the_same_key():
    assert contributor_key(parse_line(ROW_A)) == contributor_key(parse_line(ROW_A2))


def test_a_different_zip_is_a_different_key():
    """Two Emily Jennings in different places are two people, and nothing here
    is able to tell whether they are the same one who moved."""
    other = ROW_A.replace("|021432389|", "|100011234|")
    assert contributor_key(parse_line(ROW_A)) != contributor_key(parse_line(other))


def test_a_different_name_is_a_different_key():
    other = ROW_A.replace("JENNINGS, EMILY", "JENNINGS, EMMA")
    assert contributor_key(parse_line(ROW_A)) != contributor_key(parse_line(other))


# --- ingest ----------------------------------------------------------------

def test_import_aggregates_rather_than_storing_transactions(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        stats = lake.import_zip(_zip(tmp_path, [ROW_A, ROW_A2, ROW_B]))
        assert stats["rows"] == 3
        assert stats["contributors"] == 2
        n = lake._conn.execute("SELECT COUNT(*) FROM contributor").fetchone()[0]
        assert n == 2
    finally:
        lake.close()


def test_repeat_contributions_roll_up(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A, ROW_A2]))
        row = lake._conn.execute(
            "SELECT contributions, total_amount, first_seen, last_seen "
            "FROM contributor WHERE name_canonical = 'emily jennings'").fetchone()
        assert row[0] == 2
        assert row[1] == 750
        assert row[2] == "2024-08-05"
        assert row[3] == "2024-09-12"
    finally:
        lake.close()


def test_committees_are_excluded_from_the_count(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        stats = lake.import_zip(_zip(tmp_path, [ROW_A, ROW_ORG]))
        assert stats["contributors"] == 1
        assert stats["skipped_non_individual"] == 1
    finally:
        lake.close()


def test_employers_and_occupations_are_collected(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        moved = ROW_A.replace("SKADDEN ARPS|ATTORNEY", "LATHAM WATKINS|PARTNER")
        lake.import_zip(_zip(tmp_path, [ROW_A, moved]))
        row = lake._conn.execute(
            "SELECT employers, occupations FROM contributor "
            "WHERE name_canonical = 'emily jennings'").fetchone()
        assert "SKADDEN ARPS" in row[0] and "LATHAM WATKINS" in row[0]
        assert "ATTORNEY" in row[1] and "PARTNER" in row[1]
    finally:
        lake.close()


def test_reimport_is_idempotent(tmp_path):
    """A re-run of the same cycle file must not double every total."""
    z = _zip(tmp_path, [ROW_A, ROW_A2])
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        lake.import_zip(z)
        lake.import_zip(z)
        row = lake._conn.execute(
            "SELECT contributions, total_amount FROM contributor").fetchone()
        assert tuple(row) == (2, 750)  # sqlite3.Row != tuple
    finally:
        lake.close()


def test_a_zip_without_the_data_member_is_refused(tmp_path):
    p = tmp_path / "bad.zip"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("readme.txt", "nope")
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        with pytest.raises(ValueError, match="itcont"):
            lake.import_zip(p)
    finally:
        lake.close()


# --- lookup ----------------------------------------------------------------

def test_lookup_by_name_finds_the_contributor(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A, ROW_B]))
        hits = lake.lookup("Emily Jennings")
        assert len(hits) == 1
        assert hits[0]["state"] == "MA"
    finally:
        lake.close()


def test_lookup_accepts_the_reversed_form_too(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A]))
        assert lake.lookup("Jennings, Emily")
    finally:
        lake.close()


def test_a_miss_is_empty_not_an_error(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A]))
        assert lake.lookup("Nobody Here") == []
    finally:
        lake.close()


def test_lookup_on_an_unbuilt_lake_is_empty(tmp_path):
    lake = FecLake(tmp_path / "none.sqlite")
    try:
        assert lake.lookup("Emily Jennings") == []
        assert lake.status()["available"] is False
    finally:
        lake.close()


def test_status_reports_what_was_imported(tmp_path):
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        lake.import_zip(_zip(tmp_path, [ROW_A, ROW_B]))
        st = lake.status()
        assert st["contributors"] == 2
        assert st["imported_at"]
        assert st["available"] is True
    finally:
        lake.close()


# --- memory ----------------------------------------------------------------

def test_wal_and_a_bounded_busy_timeout_on_a_temp_lake(tmp_path):
    """The growth timer writes while the web serves reads; WAL plus a
    bounded busy_timeout is what keeps that from producing "database is
    locked" errors."""
    lake = FecLake(tmp_path / "fec.sqlite")
    try:
        mode = lake._conn.execute("PRAGMA journal_mode").fetchone()[0]
        timeout_ms = lake._conn.execute("PRAGMA busy_timeout").fetchone()[0]
        assert mode.lower() == "wal"
        assert timeout_ms == 5000
    finally:
        lake.close()


def test_the_reader_streams_rather_than_reading_the_member(tmp_path):
    """The real file is 3.95 GB compressed. `.read()` on the member would OOM
    the container; the import must never materialise it."""
    import inspect

    import umbra.lake.fec as mod

    src = inspect.getsource(mod)
    assert ".read()" not in src, "no whole-member read"
    assert "readlines()" not in src

