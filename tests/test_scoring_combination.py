"""How independent sources combine into one number.

Measured on 2026-09-01 against the Tranco top 5,000 and the owned abuse.ch
lakes, to replace assumptions with data:

    top-5,000 domains with any malware URL   : 2 (github.com, mediafire.com)
    abuse.ch hosts listed by 2+ of its feeds : 17 of 9,223 (0.18%)

The second number killed my first hypothesis. abuse.ch's four feeds barely
overlap — URLhaus is malware distribution URLs, ThreatFox is C2 IOCs, Feodo is
banking-trojan C2 — so they are complementary, not redundant, and "worst source
wins" loses almost nothing *between them*.

The real loss is across **providers**. A domain lookup consults Spamhaus (0.7),
OpenPhish (0.85) and abuse.ch (0.9). Under `max`, all three agreeing scores
exactly the same as one of them alone — 90 either way. Three independent
organisations reaching the same conclusion is stronger evidence than one, and
the old score could not say so.

Noisy-OR is used rather than a full Bayesian posterior on purpose. A posterior
needs a prior — the base rate of malicious domains among *things people paste
into /reputation* — and there is no honest way to estimate that. Tranco's rate
is not it; people do not paste the top 5,000. Noisy-OR needs no prior, is
monotonic, is bounded, and answers the question actually being asked: how
strong is the combined evidence.

**The number is evidence strength, not a probability.** It is not calibrated
against ground truth and cannot be, because the sources Umbra reads *are* its
ground truth — scoring them against themselves would measure nothing.
"""
from __future__ import annotations

import pytest

from umbra.collectors.platforms import lookup_platform
from umbra.collectors.reputation import (
    ReputationHit,
    combine_listed,
    provider_of,
    verdict_from_hits,
)


def hit(source, weight, listed=True, scope="domain"):
    return ReputationHit(source=source, listed=listed, weight=weight,
                         detail="d", scope=scope)


# --- provider grouping -----------------------------------------------------

def test_abusech_feeds_are_one_provider():
    """Four feeds, one organisation and one collection methodology. Counting
    them as four independent confirmations would inflate a single opinion."""
    for f in ("urlhaus", "threatfox", "feodo_tracker", "sslbl"):
        assert provider_of(f) == "abuse.ch", f

def test_spamhaus_zones_are_one_provider():
    assert provider_of("spamhaus_dbl") == provider_of("spamhaus_zen") == "spamhaus"


def test_distinct_organisations_stay_distinct():
    assert len({provider_of("openphish"), provider_of("spamhaus_dbl"),
                provider_of("urlhaus"), provider_of("abuseipdb")}) == 4


def test_an_unknown_source_is_its_own_provider():
    """A new feed must not silently join an existing group."""
    assert provider_of("some_new_feed") == "some_new_feed"


# --- combination -----------------------------------------------------------

def test_one_source_scores_its_own_weight():
    assert combine_listed([hit("urlhaus", 0.9)]) == pytest.approx(0.9)


def test_two_independent_providers_beat_one():
    """The whole point. Spamhaus and OpenPhish agreeing is stronger than
    either alone, and `max` could not express that."""
    one = combine_listed([hit("spamhaus_dbl", 0.7)])
    two = combine_listed([hit("spamhaus_dbl", 0.7), hit("openphish", 0.85)])
    assert two > one
    assert two == pytest.approx(1 - (0.3 * 0.15))


def test_three_providers_beat_two():
    two = combine_listed([hit("spamhaus_dbl", 0.7), hit("openphish", 0.85)])
    three = combine_listed([hit("spamhaus_dbl", 0.7), hit("openphish", 0.85),
                            hit("urlhaus", 0.9)])
    assert three > two
    # Raw noisy-OR would give 0.9955; the certainty ceiling holds it below 1.
    assert three == pytest.approx(0.99)


def test_two_feeds_from_one_provider_do_not_corroborate():
    """URLhaus and ThreatFox agreeing is abuse.ch saying it twice."""
    both = combine_listed([hit("urlhaus", 0.9), hit("threatfox", 0.9)])
    assert both == pytest.approx(0.9)


def test_the_strongest_feed_wins_inside_a_provider():
    assert combine_listed([hit("urlhaus", 0.6), hit("threatfox", 0.9)]) == pytest.approx(0.9)


def test_combining_never_weakens_the_strongest_signal():
    """A corroborating source must never drag a strong verdict down."""
    strong = [hit("urlhaus", 0.9)]
    assert combine_listed(strong + [hit("spamhaus_dbl", 0.3)]) >= combine_listed(strong)


def test_nothing_listed_is_zero():
    assert combine_listed([]) == 0.0


# --- being a Tor exit is not an accusation ---------------------------------

def test_tor_exit_never_contributes_to_a_verdict():
    """Running a Tor exit is a network role, not wrongdoing. Under a combining
    rule it would otherwise push spamhaus_zen (0.6) to 0.70 and turn a
    suspicious IP malicious on the strength of being an exit node."""
    without = combine_listed([hit("spamhaus_zen", 0.6)])
    with_tor = combine_listed([hit("spamhaus_zen", 0.6), hit("tor_exit", 0.25)])
    assert with_tor == pytest.approx(without)


def test_a_tor_exit_alone_is_clean():
    verdict, score, _ = verdict_from_hits([hit("tor_exit", 0.25)])
    assert verdict == "clean"
    assert score == 0


def test_tor_is_still_reported():
    """Suppressing its authority must not suppress the fact."""
    _, _, sources = verdict_from_hits([hit("tor_exit", 0.25)])
    assert "tor_exit" in sources


# --- verdicts still mean what they meant -----------------------------------

def test_a_single_high_confidence_source_still_condemns():
    verdict, score, _ = verdict_from_hits([hit("openphish", 0.85)])
    assert verdict == "malicious"
    assert score == 85


def test_corroboration_can_promote_suspicious_to_malicious():
    """Two providers at 0.7 and 0.6 are individually only suspicious."""
    assert verdict_from_hits([hit("spamhaus_dbl", 0.7)])[0] == "suspicious"
    v, s, _ = verdict_from_hits([hit("spamhaus_dbl", 0.7), hit("abuseipdb", 0.6)])
    assert v == "malicious"
    assert s == 88


def test_clean_and_unknown_are_unchanged():
    assert verdict_from_hits([])[0] == "unknown"
    assert verdict_from_hits([hit("urlhaus", 0.0, listed=False)])[0] == "clean"


def test_the_platform_rule_still_applies_on_top():
    """Content-scope listings still do not condemn a user-content platform,
    however many providers report them."""
    gh = lookup_platform("github.com")
    v, s, sources = verdict_from_hits(
        [hit("urlhaus", 0.9, scope="content"), hit("threatfox", 0.9, scope="content")],
        platform=gh)
    assert v == "clean" and s == 0
    assert "urlhaus" in sources


def test_a_domain_scope_listing_still_condemns_a_platform():
    gh = lookup_platform("github.com")
    v, _, _ = verdict_from_hits(
        [hit("spamhaus_dbl", 0.9), hit("urlhaus", 0.9, scope="content")], platform=gh)
    assert v == "malicious"


# --- the score is bounded and monotonic ------------------------------------

def test_score_stays_within_0_and_100():
    many = [hit(f"src_{i}", 0.9) for i in range(20)]
    _, score, _ = verdict_from_hits(many)
    assert 0 <= score <= 100


def test_adding_a_listing_never_lowers_the_score():
    base = [hit("spamhaus_dbl", 0.7)]
    prev = verdict_from_hits(base)[1]
    for i, w in enumerate((0.3, 0.5, 0.85)):
        base = base + [hit(f"other_{i}", w)]
        now = verdict_from_hits(base)[1]
        assert now >= prev
        prev = now


def test_no_amount_of_agreement_reaches_certainty():
    """Three providers agreeing reached exactly 100/100. A score of 100 claims
    proof, and third-party blocklists do not supply proof."""
    many = [hit(f"org_{i}", 0.95) for i in range(8)]
    _, score, _ = verdict_from_hits(many)
    assert score < 100
    assert score >= 95, "but it should still be emphatic"
