"""People lake upsert + lookup tests."""

from __future__ import annotations

from pathlib import Path

from umbra.lake.people import PeopleLake
from umbra.people.obituary_parse import parse_obituary_text


def test_wal_and_a_bounded_busy_timeout_on_a_temp_lake(tmp_path: Path):
    """The growth timer writes while the web serves reads; WAL plus a
    bounded busy_timeout is what keeps that from producing "database is
    locked" errors."""
    lake = PeopleLake(tmp_path / "people.sqlite")
    mode = lake._conn.execute("PRAGMA journal_mode").fetchone()[0]
    timeout_ms = lake._conn.execute("PRAGMA busy_timeout").fetchone()[0]
    assert mode.lower() == "wal"
    assert timeout_ms == 5000


def test_people_lake_upsert_and_lookup(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    text = (
        "Jane Roe, 70, of Oakland, CA, passed away March 1, 2025. "
        "She is survived by her husband John Roe and son Mark Roe. "
        "Smith Funeral Home handling arrangements."
    )
    parsed = parse_obituary_text(text, decedent_name="Jane Roe").to_dict()
    url = "https://www.legacy.com/us/obituaries/jane-roe-obituary"
    pid = lake.upsert_person_from_parse(
        decedent_name="Jane Roe",
        parse=parsed,
        source_url=url,
        title="Jane Roe Obituary",
        http_status=200,
        excerpt=text,
    )
    assert pid
    st = lake.status()
    assert st.people >= 1
    assert st.obituaries >= 1
    assert st.kinship_edges >= 1

    hits = lake.lookup_name("Jane Roe")
    assert hits
    assert hits[0]["full_name"] == "Jane Roe"
    assert hits[0]["age"] == 70

    obits = lake.obituaries_for_person(pid)
    assert obits and obits[0]["url"] == url

    kin = lake.kinship_for_person(pid)
    names = {k["relative_name"] for k in kin}
    assert "John Roe" in names or "Mark Roe" in names
    lake.close()


def test_people_lake_second_obit_merges(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    p1 = parse_obituary_text(
        "Bob Lee died. Survived by wife Ann Lee.", decedent_name="Bob Lee"
    ).to_dict()
    p2 = parse_obituary_text(
        "Bob Lee, age 88. Survived by son Tim Lee.", decedent_name="Bob Lee"
    ).to_dict()
    pid1 = lake.upsert_person_from_parse(
        decedent_name="Bob Lee",
        parse=p1,
        source_url="https://www.findagrave.com/memorial/1/bob-lee",
        http_status=200,
    )
    pid2 = lake.upsert_person_from_parse(
        decedent_name="Bob Lee",
        parse=p2,
        source_url="https://en.wikipedia.org/wiki/Bob_Lee",
        http_status=200,
    )
    assert pid1 == pid2
    st = lake.status()
    assert st.obituaries == 2
    assert st.people == 1
    kin_names = {k["relative_name"] for k in lake.kinship_for_person(pid1)}
    assert "Ann Lee" in kin_names
    assert "Tim Lee" in kin_names
    lake.close()


def test_confirm_kinship(tmp_path: Path):
    lake = PeopleLake(tmp_path / "people.sqlite")
    parsed = parse_obituary_text(
        "Bob Lee died. Survived by wife Ann Lee.", decedent_name="Bob Lee"
    ).to_dict()
    lake.upsert_person_from_parse(
        decedent_name="Bob Lee",
        parse=parsed,
        source_url="https://en.wikipedia.org/wiki/Bob_Lee",
        http_status=200,
    )
    n = lake.confirm_kinship("Bob Lee", "Ann Lee", "true")
    assert n >= 1
    kin = lake.kinship_for_person(lake.lookup_name("Bob Lee")[0]["id"])
    assert any(k["relative_name"] == "Ann Lee" and k["confirmation"] == "true" for k in kin)
    lake.close()
