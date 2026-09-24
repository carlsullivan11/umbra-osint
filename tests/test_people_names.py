"""Name matching — the part that decides whether a people search is usable.

`_norm_name` was `" ".join(name.lower().split())` and lookup was
`WHERE norm_name = ? OR norm_name LIKE ? OR full_name LIKE ?`. Two problems, and
the second gets worse as the lake grows:

**It only matches what you typed.** "Ruth Bader Ginsburg" finds her;
"Ginsburg, Ruth", "R. B. Ginsburg", "Ruth Ginsburg" and "José García" (stored
with the accent, typed without) all miss. Investigators do not have the stored
spelling — that is the whole reason they are searching.

**`LIKE %x%` cannot use an index.** At 12k rows that is invisible. At the
454,614 this lake is heading for, every search is a full table scan.

So: normalise hard, generate the variants a person might type, and store them as
indexed keys. Matching becomes an equality join on a key, and ranking says how
the match was made — an exact hit and a dropped-middle-name hit are both useful
and must not look identical.
"""
from __future__ import annotations

import pytest

from umbra.people.names import (
    MatchStrength,
    canonical,
    name_keys,
    query_keys,
    split_display,
)


# --- canonicalisation ------------------------------------------------------

@pytest.mark.parametrize("raw,expect", [
    ("Ruth Bader Ginsburg", "ruth bader ginsburg"),
    ("  RUTH   BADER  GINSBURG ", "ruth bader ginsburg"),
    ("Ruth Bader Ginsburg.", "ruth bader ginsburg"),
    ("O'Brien, Conan", "conan o brien"),
])
def test_canonical_collapses_case_space_and_punctuation(raw, expect):
    assert canonical(raw) == expect


@pytest.mark.parametrize("raw,expect", [
    ("José García", "jose garcia"),
    ("Zoë Kravitz", "zoe kravitz"),
    ("Renée Zellweger", "renee zellweger"),
    ("Beyoncé Knowles", "beyonce knowles"),
])
def test_diacritics_fold_so_a_plain_keyboard_finds_the_name(raw, expect):
    """The stored spelling has the accent. Nobody types it."""
    assert canonical(raw) == expect


@pytest.mark.parametrize("raw", [
    "John Smith Jr.", "John Smith Jr", "John Smith Sr.", "John Smith III",
    "John Smith, MD", "John Smith PhD", "John Smith II",
])
def test_suffixes_and_credentials_are_dropped(raw):
    """A junior and his father are different people, but the suffix is not how
    a searcher distinguishes them — it is how the record was typed."""
    assert canonical(raw) == "john smith"


def test_last_comma_first_is_reordered():
    """Government and funeral records store 'Ginsburg, Ruth'."""
    assert canonical("Ginsburg, Ruth Bader") == "ruth bader ginsburg"


def test_a_comma_that_is_not_a_reversal_is_left_alone():
    assert canonical("John Smith, MD") == "john smith"


def test_empty_input_is_empty_not_an_error():
    for bad in ("", "   ", None):
        assert canonical(bad) == ""


# --- display splitting -----------------------------------------------------

def test_split_gives_first_and_last():
    first, last = split_display("Ruth Bader Ginsburg")
    assert (first, last) == ("ruth", "ginsburg")


def test_split_handles_a_single_token():
    assert split_display("Cher") == ("cher", "cher")


def test_split_handles_empty():
    assert split_display("") == ("", "")


# --- index keys ------------------------------------------------------------

def test_the_full_name_is_always_a_key():
    assert "ruth bader ginsburg" in name_keys("Ruth Bader Ginsburg")


def test_first_and_last_without_the_middle_is_a_key():
    """'Ruth Ginsburg' must find 'Ruth Bader Ginsburg'."""
    assert "ruth ginsburg" in name_keys("Ruth Bader Ginsburg")


def test_initial_and_last_is_a_key():
    """'R. Ginsburg' and 'R Ginsburg' both canonicalise into this."""
    assert "r ginsburg" in name_keys("Ruth Bader Ginsburg")


def test_a_two_token_name_still_yields_keys():
    keys = name_keys("John Smith")
    assert "john smith" in keys
    assert "j smith" in keys


def test_nicknames_expand_to_the_formal_name():
    """A record says Robert; the searcher types Bob."""
    assert "robert smith" in name_keys("Bob Smith")


def test_the_formal_name_also_yields_the_nickname():
    """And the reverse: stored Robert, searched Bob."""
    assert "bob smith" in name_keys("Robert Smith")


def test_nickname_expansion_does_not_fire_on_a_surname():
    """'Bob' as a last name is not a nickname for anything."""
    keys = name_keys("Alice Bob")
    assert "alice robert" not in keys


def test_keys_are_deduplicated():
    keys = name_keys("John Smith")
    assert len(keys) == len(set(keys))


def test_a_one_word_name_yields_itself_and_a_surname_key():
    """A mononym is both a person ("Cher") and, for someone else, a surname."""
    from umbra.people.names import SURNAME_PREFIX

    assert name_keys("Cher") == ["cher", f"{SURNAME_PREFIX}cher"]


def test_a_surname_key_is_namespaced_so_it_cannot_match_a_full_name():
    """Without the prefix, a bare "smith" search would collide with anyone
    whose entire recorded name is the single word "Smith"."""
    from umbra.people.names import SURNAME_PREFIX

    keys = name_keys("John Smith")
    assert f"{SURNAME_PREFIX}smith" in keys
    assert "smith" not in keys


def test_junk_yields_no_keys():
    assert name_keys("") == []
    assert name_keys("   ") == []


# --- query keys are ordered by how good the match would be -----------------

def test_an_exact_query_ranks_first():
    ranked = query_keys("Ruth Bader Ginsburg")
    assert ranked[0][0] == "ruth bader ginsburg"
    assert ranked[0][1] is MatchStrength.EXACT


def test_a_dropped_middle_name_ranks_below_exact():
    ranked = query_keys("Ruth Bader Ginsburg")
    strengths = [s for _, s in ranked]
    assert MatchStrength.EXACT in strengths
    assert MatchStrength.PARTIAL in strengths
    assert strengths.index(MatchStrength.EXACT) < strengths.index(MatchStrength.PARTIAL)


def test_an_initial_match_ranks_weakest():
    ranked = query_keys("Ruth Bader Ginsburg")
    order = [s for _, s in ranked]
    assert order[-1] is MatchStrength.WEAK


def test_every_query_key_is_also_producible_as_an_index_key():
    """If the query generates a key the indexer never writes, it can only miss."""
    stored = set(name_keys("Ruth Bader Ginsburg"))
    for key, _ in query_keys("Ruth Bader Ginsburg"):
        assert key in stored, key


def test_a_nickname_query_finds_the_formal_record():
    stored = set(name_keys("Robert Smith"))
    assert any(k in stored for k, _ in query_keys("Bob Smith"))


def test_a_reversed_query_finds_the_forward_record():
    stored = set(name_keys("Ruth Bader Ginsburg"))
    assert any(k in stored for k, _ in query_keys("Ginsburg, Ruth Bader"))


def test_an_accented_record_is_found_by_a_plain_query():
    stored = set(name_keys("José García"))
    assert any(k in stored for k, _ in query_keys("Jose Garcia"))


# --- what must NOT match ---------------------------------------------------

def test_different_people_do_not_collide_on_a_strong_key():
    """John and Jane Smith must never match at EXACT or PARTIAL strength."""
    jane = set(name_keys("Jane Smith"))
    for key, strength in query_keys("John Smith"):
        if strength is not MatchStrength.WEAK:
            assert key not in jane, f"{key} ({strength}) collides"


def test_an_initial_search_is_allowed_to_be_ambiguous():
    """"J. Smith" really does match both, and pretending otherwise would drop a
    result the searcher asked for. That is what WEAK exists to label — the
    ambiguity is reported, not hidden, and never silently ranked as an exact
    hit."""
    jane = set(name_keys("Jane Smith"))
    weak = [k for k, s in query_keys("John Smith") if s is MatchStrength.WEAK]
    assert any(k in jane for k in weak)


def test_a_shared_surname_alone_is_not_a_key():
    """'Smith' must not match every Smith — that is a browse, not a search."""
    assert "smith" not in name_keys("John Smith")


def test_a_shared_first_name_alone_is_not_a_key():
    assert "john" not in name_keys("John Smith")
