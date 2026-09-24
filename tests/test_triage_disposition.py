"""`decide()` truth table and invariants (docs/JEV-SOC.md §4.3, docs/TRIAGE.md)."""
from __future__ import annotations

import itertools

import pytest

from umbra.jev.client import Answer
from umbra.triage.disposition import (
    BENIGN_ROLES, CLOSE_MAX_P, ESCALATE, ESCALATE_MIN_P, MALICIOUS_ROLES, NEEDS_ANALYST,
    SUGGEST_CLOSE, decide, worst,
)


def answers(role="clean", p=0.05, canary=None, conf=0.9):
    out = {
        "role": Answer(type="choice", value=role, probabilities={role: conf}, confidence=conf),
        "malware_or_c2": Answer(type="noul", probability=p),
        "ordinary_business": Answer(type="noul", probability=0.8),
        "urgency": Answer(type="score", value="low: review this week"),
    }
    if canary is not None:
        out["_injection_canary"] = Answer(type="noul", probability=canary)
    return out


def test_a_listing_escalates_whatever_jev_says():
    d = decide("malicious", ["feodo"], answers("clean", 0.01))
    assert d.disposition == ESCALATE and "feodo" in d.reasons[0]


def test_confidently_benign_and_unlisted_is_suggested_for_closing():
    assert decide("clean", [], answers("clean", 0.05)).disposition == SUGGEST_CLOSE


def test_the_band_between_thresholds_goes_to_a_person():
    assert decide("clean", [], answers("clean", (CLOSE_MAX_P + ESCALATE_MIN_P) / 2)).disposition == NEEDS_ANALYST


def test_high_probability_escalates():
    d = decide("clean", [], answers("clean", ESCALATE_MIN_P))
    assert d.disposition == ESCALATE


def test_a_malicious_role_escalates_even_at_low_probability():
    assert decide("clean", [], answers("dedicated_malicious_infra", 0.05)).disposition == ESCALATE


@pytest.mark.parametrize("kw", [{"canary": 0.9}, {}])
def test_planted_text_escalates(kw):
    a = answers("clean", 0.01, **kw)
    d = decide("clean", [], a, injection_suspected=not kw)
    assert d.disposition == ESCALATE and d.injection_flag


def test_without_jev_nothing_unlisted_is_cleared():
    assert decide("clean", [], None).disposition == NEEDS_ANALYST
    assert decide("unknown", [], None).disposition == NEEDS_ANALYST


def test_a_partial_listing_is_never_suggested_for_closing():
    assert decide("suspicious", ["spamhaus_zen"], answers("clean", 0.01)).disposition == NEEDS_ANALYST


def test_unenriched_and_critical_are_never_suggested_for_closing():
    assert decide("clean", [], answers("clean", 0.01), enriched=False).disposition == NEEDS_ANALYST
    assert decide("clean", [], answers("clean", 0.01), critical_asset=True).disposition == NEEDS_ANALYST


def test_an_incomplete_blocklist_check_is_not_closed():
    assert decide("unknown", [], answers("clean", 0.01)).disposition == NEEDS_ANALYST


def test_an_unclear_role_is_not_closed():
    assert decide("clean", [], answers("none_of_these", 0.01)).disposition == NEEDS_ANALYST


ROLES = sorted(MALICIOUS_ROLES | BENIGN_ROLES | {"none_of_these"})


@pytest.mark.parametrize("listing,role,p,canary,enriched,critical", list(itertools.product(
    ["clean", "suspicious", "malicious", "unknown"], ROLES, [0.0, 0.1, 0.12, 0.3, 0.5, 0.9],
    [None, 0.2, 0.7], [True, False], [False, True])))
def test_invariants(listing, role, p, canary, enriched, critical):
    d = decide(listing, [], answers(role, p, canary), enriched=enriched, critical_asset=critical)
    if d.disposition == SUGGEST_CLOSE:
        assert listing == "clean" and enriched and not critical
        assert role in BENIGN_ROLES and p <= CLOSE_MAX_P
        assert canary is None or canary < 0.5
    if listing == "malicious" or (canary is not None and canary >= 0.5):
        assert d.disposition == ESCALATE
    assert d.reasons


def test_worst_takes_the_most_serious():
    assert worst([SUGGEST_CLOSE, ESCALATE, NEEDS_ANALYST]) == ESCALATE
    assert worst([SUGGEST_CLOSE, SUGGEST_CLOSE]) == SUGGEST_CLOSE
    assert worst([]) == NEEDS_ANALYST
