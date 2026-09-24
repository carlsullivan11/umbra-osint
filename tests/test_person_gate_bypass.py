"""The person consent gate was one keystroke wide.

    "Dustin Moore"   -> person 0.60, include=False   gate holds, opt-in required
    "dustin moore"   -> org    0.55, include=True    runs immediately
    "JANICE M MILLER"-> org    0.55, include=True    runs immediately

Same person either way. The capitalized-name rule in `intent.extract` emits
PERSON at 0.6, below the inclusion threshold, so N1's declaration is required.
Lowercase misses that rule entirely and falls through to the bare-query
fallback, which emits ORG at 0.55 — a value its own comment describes as
"exactly the include threshold" — and organisations need no opt-in.

So the control worked precisely until somebody typed the way people actually
type.

The fix is to notice that a bare query can be *name-shaped* and seed it as a
person, which puts it behind the same gate the capitalized spelling gets.

**It errs toward the gate on purpose.** "united airlines" is two alphabetic
words with no corporate marker and will now be treated as a person, so searching
it asks for a basis first. That is a mild annoyance. The opposite error — a real
person searched with no declaration because of a lowercase keyboard — is the one
this project promised not to make.
"""
from __future__ import annotations

import pytest

from umbra.intent import AnalyzeRequest, analyze_intent


def _seeds(text: str):
    plan = analyze_intent(AnalyzeRequest(text=text))
    return [(getattr(s.type, "value", s.type), s.value, s.include) for s in plan.seeds]


def _types(text: str):
    return {t for t, _v, _i in _seeds(text)}


def _included(text: str):
    return [v for _t, v, inc in _seeds(text) if inc]


# --- the bypass -------------------------------------------------------------

@pytest.mark.parametrize("typed", [
    "dustin moore", "Dustin Moore", "DUSTIN MOORE", "dustin Moore",
])
def test_a_name_is_a_person_however_it_is_typed(typed):
    assert "person" in _types(typed), f"{typed!r} did not seed a person"


@pytest.mark.parametrize("typed", ["dustin moore", "DUSTIN MOORE", "janice m miller"])
def test_a_lowercase_name_does_not_run_without_a_declaration(typed):
    """The whole point: no included seed means the plan asks first."""
    assert _included(typed) == [], f"{typed!r} ran without an opt-in"


def test_the_capitalised_spelling_still_behaves_the_same():
    assert _included("Dustin Moore") == []


def test_a_three_word_name_is_also_gated():
    assert "person" in _types("janice m miller")
    assert _included("janice m miller") == []


# --- what must keep working -------------------------------------------------

def test_a_single_word_brand_still_runs():
    """`Cloudflare` is why the bare-query fallback exists. Without it the plan
    came back with nothing selected."""
    assert _included("Cloudflare"), "a one-word org query stopped working"


@pytest.mark.parametrize("org", [
    "acme corp", "acme inc", "acme llc", "acme ltd", "acme co",
    "acme corporation", "acme & sons", "acme holdings",
])
def test_a_corporate_marker_keeps_it_an_organisation(org):
    assert "org" in _types(org), f"{org!r} stopped being an org"
    assert _included(org), f"{org!r} now needs an opt-in"


def test_infrastructure_is_untouched():
    for value in ("example.com", "1.1.1.1", "someone@example.com", "+14155552671"):
        assert _included(value), f"{value!r} regressed"


def test_an_explicit_person_prefix_is_unchanged():
    seeds = _seeds("person: Jane Doe")
    assert any(t == "person" for t, _v, _i in seeds)


# --- the trade, stated ------------------------------------------------------

def test_a_two_word_company_without_a_marker_errs_toward_the_gate():
    """Recorded rather than hidden: "united airlines" is name-shaped and will be
    gated. Asking for a basis to search an airline is a smaller harm than
    searching a person without one."""
    assert _included("united airlines") == []
