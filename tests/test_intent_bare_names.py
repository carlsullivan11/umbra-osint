"""Typing a company name into the one box should do something.

The north star is "search anything": paste a seed, get a plan. But a bare
`Cloudflare` extracted **nothing** — `_ORG_HINT_RE` needs a keyword ("company
Cloudflare") and `_PERSON_RE` needs two capitalized tokens. The E2 `intent_empty`
signal exists to surface exactly this, and it did.

The fix has to be narrow. Treating any capitalized word as an organisation would
turn "Check this domain" into a case about a company called Check. Two rules
that cannot do that:

1. **A corporate suffix is unambiguous** — "Acme Inc", "Foo GmbH" is a company
   wherever it appears in a sentence.
2. **A bare query is a deliberate act.** If the whole input is one or two words
   and nothing else matched, the person typed a name on purpose. It seeds at low
   confidence, so the plan page shows it as a chip to uncheck rather than a fact.
"""
from __future__ import annotations

import pytest

from umbra.core.models import EntityType
from umbra.intent.extract import extract_hits
from umbra.intent.plan import analyze_intent
from umbra.intent.schema import AnalyzeRequest


def _types(text):
    return {(h.type, h.value) for h in extract_hits(text)}


def _orgs(text):
    return [h for h in extract_hits(text) if h.type == EntityType.ORG]


# --- corporate suffixes ---------------------------------------------------

@pytest.mark.parametrize("text,expected", [
    ("Acme Inc", "acme inc"),
    ("Contoso LLC", "contoso llc"),
    ("Siemens AG", "siemens ag"),
    ("Barclays PLC", "barclays plc"),
    ("Example Ltd", "example ltd"),
])
def test_a_corporate_suffix_is_an_organisation(text, expected):
    assert any(h.value == expected for h in _orgs(text)), f"{text} should seed an org"


def test_a_suffix_works_mid_sentence():
    """Unambiguous wherever it appears — no need for a 'company' keyword."""
    assert any("acme" in h.value for h in _orgs("look into Acme Inc and their domains"))


def test_a_suffixed_name_is_confident():
    hit = _orgs("Acme Inc")[0]
    assert hit.confidence >= 0.7


# --- the bare query -------------------------------------------------------

def test_a_bare_company_name_seeds_something():
    """The reported failure: this produced no seeds at all."""
    hits = _orgs("Cloudflare")
    assert hits, "a one-word query should still give the operator something to run"
    assert hits[0].value == "cloudflare"


def test_a_bare_name_is_low_confidence_and_says_why():
    """It is a guess. The plan page renders it as a chip the operator can
    uncheck, which only works if we are honest that it is a guess."""
    hit = _orgs("Cloudflare")[0]
    assert hit.confidence <= 0.6
    assert hit.notes and "assum" in hit.notes.lower()


def test_two_bare_words_still_work():
    assert _orgs("Deutsche Bank") or True  # may be read as a person; either is a seed
    assert extract_hits("Deutsche Bank"), "should not be empty"


# --- what it must not do --------------------------------------------------

def test_a_sentence_does_not_become_a_company():
    """The guess only applies when the query *is* the name. Otherwise 'Check
    this domain' becomes a case about a company called Check."""
    assert not _orgs("Check this domain for me please")


def test_it_does_not_fire_when_something_real_was_found():
    """A query with a domain in it has a seed already; guessing an org from the
    remaining words would add noise to every search."""
    hits = extract_hits("cloudflare.com")
    assert any(h.type == EntityType.DOMAIN for h in hits)
    assert not [h for h in hits if h.type == EntityType.ORG]


def test_an_email_query_is_not_also_an_org():
    hits = extract_hits("security@example.com")
    assert not [h for h in hits if h.type == EntityType.ORG]


@pytest.mark.parametrize("junk", ["please help me", "what is this", "find everything", ""])
def test_common_phrases_are_not_companies(junk):
    assert not _orgs(junk)


def test_a_long_query_is_never_guessed():
    assert not _orgs("i would really like to know more about this whole situation")


# --- end to end -----------------------------------------------------------

def test_a_bare_name_now_produces_a_runnable_plan():
    plan = analyze_intent(AnalyzeRequest(text="Cloudflare", authorization_basis="other",
                                         use_llm=False))
    assert plan.included_seeds(), "still no seeds"
    assert "wikidata" in plan.collectors, "the org path should be planned"
