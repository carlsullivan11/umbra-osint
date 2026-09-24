"""An N-number is an aircraft, not a person and not a web search.

Before this, `N123AB` fell through every extractor to the bare-org guess at 0.55
confidence, and the planner then sent it to DuckDuckGo — so the answer to "who
is this aircraft registered to" was a web search for the string "n123ab".

The MAC and phone seeds already refuse that fallthrough for the same reason:
they are offline table reads, and a plan that silently becomes a person-shaped
web search is worse than a plan that says it has one collector.
"""
from __future__ import annotations

from umbra.core.models import EntityType
from umbra.intent.extract import extract_hits, hits_to_seeds
from umbra.intent.schema import IntentFlags
from umbra.intent.plan import select_collectors


def seeds(text: str):
    return hits_to_seeds(extract_hits(text))


def types_for(text: str) -> set[EntityType]:
    return {s.type for s in seeds(text) if s.include}


# --- extraction ------------------------------------------------------------

def test_a_bare_n_number_is_an_aircraft():
    assert EntityType.AIRCRAFT in types_for("N123AB")


def test_the_hyphenated_form_is_an_aircraft():
    assert EntityType.AIRCRAFT in types_for("N-123AB")


def test_an_all_digit_registration_is_an_aircraft():
    assert EntityType.AIRCRAFT in types_for("N12345")


def test_the_seed_is_canonical_not_as_typed():
    """Both spellings must reach the lake as the same key."""
    values = {s.value for s in seeds("n-737-kl") if s.type == EntityType.AIRCRAFT}
    assert values == {"n737kl"} or values == {"N737KL"}


def test_an_n_number_in_a_sentence_is_found():
    assert EntityType.AIRCRAFT in types_for("Cessna N737KL was parked at KRNO")


def test_an_n_number_is_not_a_person():
    """It used to become a capitalized-name guess, which then fed person
    collectors — the most misleading possible reading of a tail number."""
    assert EntityType.PERSON not in types_for("N123AB")


def test_an_n_number_is_not_a_bare_org():
    assert EntityType.ORG not in types_for("N123AB")


# --- things that merely look like N-numbers --------------------------------

def test_a_word_starting_with_n_is_not_an_aircraft():
    for text in ("Nginx", "NASA", "November", "NOT", "Nevada"):
        assert EntityType.AIRCRAFT not in types_for(text), text


def test_a_domain_is_not_an_aircraft():
    assert EntityType.AIRCRAFT not in types_for("n123ab.example.com")


def test_an_email_local_part_is_not_an_aircraft():
    assert EntityType.AIRCRAFT not in types_for("n123ab@example.com")


def test_too_long_to_be_a_registration_is_not_an_aircraft():
    assert EntityType.AIRCRAFT not in types_for("N1234567890")


def test_a_hash_prefix_is_not_an_aircraft():
    assert EntityType.AIRCRAFT not in types_for("commit N1a2b3c4d5e6f")


# --- planning --------------------------------------------------------------

def test_an_aircraft_plans_the_faa_collector():
    plan = select_collectors(seeds("N123AB"), IntentFlags())
    assert "faa_registry" in plan


def test_an_aircraft_plans_only_the_faa_collector():
    """This slice is the registry lake. No ADS-B, no FR24, no FCC ULS."""
    plan = select_collectors(seeds("N123AB"), IntentFlags())
    assert plan == ["faa_registry"]


def test_an_aircraft_never_falls_through_to_a_web_search():
    """The bug this replaces: `N123AB` became a DuckDuckGo query."""
    plan = select_collectors(seeds("N123AB"), IntentFlags())
    assert "ddg_search" not in plan


def test_an_explicit_web_search_request_is_still_honoured():
    """The no-fallthrough rule is about silence, not about overriding a user
    who asked for a web search."""
    plan = select_collectors(seeds("N123AB"), IntentFlags(want_web_search=True))
    assert "ddg_search" in plan


def test_an_aircraft_alongside_a_domain_still_plans_both():
    plan = select_collectors(seeds("N123AB and example.com"), IntentFlags())
    assert "faa_registry" in plan
    assert any(c.startswith("dns_") or c == "rdap_domain" for c in plan)
