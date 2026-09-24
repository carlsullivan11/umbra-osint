"""Clearing prose the old parser wrote into residence/occupation.

The bar is deliberately asymmetric. Deleting a real value is worse than leaving
a bad one, because the claims pass can overwrite a bad value later but cannot
recover a deleted good one. So the detector must keep 'Los Angeles' even at the
cost of keeping some junk it cannot prove is junk.

Every "prose" example below is a real value read out of the production lake.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.people.repair import looks_like_prose, repair_prose_fields


# --- real places must survive ----------------------------------------------

@pytest.mark.parametrize("value", [
    "Los Angeles", "St. Louis", "New York City", "Boca Raton", "Ceylon",
    "Hanover", "Kunming", "Orient", "Openshaw", "Washington, D.C.",
])
def test_a_real_place_is_kept(value):
    assert looks_like_prose(value, max_words=5) is False


@pytest.mark.parametrize("value", [
    "singer", "actor", "professor emeritus", "United States Senator",
    "singer, actor, musician",
])
def test_a_real_occupation_is_kept(value):
    assert looks_like_prose(value, max_words=6) is False


# --- production garbage must go --------------------------------------------

@pytest.mark.parametrize("value", [
    "Cuba from",                     # dangling preposition
    "New York in",
    "Fame in",
    "The Monkees and for his solo work. His",   # sentence boundary inside
    "Andy Warhol's underground films filmed at",
])
def test_prose_residence_is_cleared(value):
    assert looks_like_prose(value, max_words=5) is True


@pytest.mark.parametrize("value", ["The Manhattan Transfer", "ARP Instruments"])
def test_junk_indistinguishable_from_a_place_is_kept(value):
    """These are real garbage from prod, and the sweep does not catch them.

    Nothing separates "The Manhattan Transfer" from a place name by shape, and
    the stated bar is that deleting a real value is worse than keeping a bad
    one — the claims pass overwrites it on the next harvest of that person,
    whereas a deleted city never comes back. Pinned so the tradeoff is a
    decision on the record rather than a gap someone later "fixes" by loosening
    the detector."""
    assert looks_like_prose(value, max_words=5) is False


@pytest.mark.parametrize("value", [
    "a child actress under the stage name Dawn O'Day, she adopted the stage",
    "movies and television spanned 77 years, from 1937 to 2014",
    "the late 1920s in bit parts in films",
    "an entertainer, but it was not successful",
])
def test_prose_occupation_is_cleared(value):
    assert looks_like_prose(value, max_words=6) is True


def test_empty_and_none_are_not_prose():
    assert looks_like_prose(None, max_words=5) is False
    assert looks_like_prose("", max_words=5) is False
    assert looks_like_prose("   ", max_words=5) is False


# --- the sweep -------------------------------------------------------------

def _lake(tmp_path: Path):
    from umbra.lake.people import PeopleLake

    lake = PeopleLake(tmp_path / "people.sqlite")
    # Real-looking names: `canonical` strips digits (correct — names do not
    # contain them), so "Person 0".."Person 3" all normalise to "person" and
    # collapse into a single row.
    for name, res, occ in [
        ("Ada Lovelace", "Los Angeles", "singer"),
        ("Grace Hopper", "Cuba from",
         "movies and television spanned 77 years, from 1937 to 2014"),
        ("Alan Turing", "The Manhattan Transfer", None),
        ("Katherine Johnson", None, None),
    ]:
        lake.upsert_person_from_parse(
            decedent_name=name,
            parse={"residence": res, "occupation": occ},
            source_url=f"https://example.test/{name}",
            title=name,
        )
    return lake


def test_dry_run_reports_without_writing(tmp_path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    lake = _lake(tmp_path / "lake_dir")
    lake.close()
    monkeypatch.setattr("umbra.lake.people.PeopleLake.from_settings",
                        classmethod(lambda cls, s: _reopen(tmp_path)))
    before = _count_residence(tmp_path)
    stats = repair_prose_fields(apply=False)
    assert stats["applied"] is False
    assert _count_residence(tmp_path) == before, "dry run must not write"
    assert stats["residence"] >= 1


def test_apply_clears_only_the_prose(tmp_path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    lake = _lake(tmp_path / "lake_dir")
    lake.close()
    monkeypatch.setattr("umbra.lake.people.PeopleLake.from_settings",
                        classmethod(lambda cls, s: _reopen(tmp_path)))
    stats = repair_prose_fields(apply=True)
    assert stats["applied"] is True

    kept = _reopen(tmp_path)
    try:
        rows = dict(kept._conn.execute(
            "SELECT full_name, residence FROM people").fetchall())
        assert rows["Ada Lovelace"] == "Los Angeles", "a real place was deleted"
        assert rows["Grace Hopper"] is None
        # 'The Manhattan Transfer' survives by design — see
        # test_junk_indistinguishable_from_a_place_is_kept.
        assert rows["Alan Turing"] == "The Manhattan Transfer"
        occ = dict(kept._conn.execute(
            "SELECT full_name, occupation FROM people").fetchall())
        assert occ["Ada Lovelace"] == "singer", "a real occupation was deleted"
        assert occ["Grace Hopper"] is None
    finally:
        kept.close()


def _reopen(tmp_path: Path):
    from umbra.lake.people import PeopleLake

    return PeopleLake(tmp_path / "lake_dir" / "people.sqlite")


def _count_residence(tmp_path: Path) -> int:
    lake = _reopen(tmp_path)
    try:
        return lake._conn.execute(
            "SELECT COUNT(*) FROM people WHERE residence IS NOT NULL").fetchone()[0]
    finally:
        lake.close()
