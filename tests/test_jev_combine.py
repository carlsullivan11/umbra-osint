"""`combine()` truth table and invariants — docs/JEV.md §3."""
from __future__ import annotations

import itertools

import pytest

from umbra.jev.client import Answer
from umbra.jev.combine import combine
from umbra.jev.questions import INFRA_ROLES, INJECTION_CANARY_KEY, PHISH_ROLES

VERDICTS = ("clean", "suspicious", "malicious")
RANK = {v: i for i, v in enumerate(VERDICTS)}


def role(value: str, conf: float, key: str = "role") -> dict[str, Answer]:
    return {key: Answer(type="choice", value=value, probabilities={value: conf}, confidence=conf)}


@pytest.mark.parametrize("det,value,conf,canary,creds", list(itertools.product(
    VERDICTS,
    list(INFRA_ROLES) + list(PHISH_ROLES),
    (0.2, 0.69, 0.7, 0.99),
    (0.0, 0.95),
    (0.0, 0.95),
)))
def test_jev_never_lowers_and_never_accuses_alone(det, value, conf, canary, creds):
    answers = role(value, conf, "site_kind" if value in PHISH_ROLES else "role")
    answers[INJECTION_CANARY_KEY] = Answer(type="noul", probability=canary)
    answers["solicits_credentials"] = Answer(type="noul", probability=creds)
    out = combine(det, answers)
    assert RANK[out.verdict] >= RANK[det]
    if det != "malicious":
        assert out.verdict != "malicious"
    if out.verdict != det:
        assert out.ai_assessed


def test_no_answers_is_the_deterministic_verdict():
    for det in VERDICTS:
        out = combine(det, None)
        assert out.verdict == det and not out.ai_assessed and not out.public


def test_unknown_verdict_string_is_treated_as_clean():
    assert combine("weird", None).verdict == "clean"


def test_confident_impersonation_raises_clean_to_ai_suspicious():
    out = combine("clean", role("brand_impersonation", 0.87, "site_kind"))
    assert out.verdict == "suspicious" and out.ai_assessed and out.public
    assert "brand impersonation" in out.reasons[0]


def test_low_confidence_accusation_changes_nothing_and_stays_private():
    out = combine("clean", role("dedicated_malicious_infra", 0.55))
    assert out.verdict == "clean" and not out.ai_assessed and not out.public
    assert out.role == "dedicated_malicious_infra"  # recorded for operators


def test_malicious_listing_is_never_cleared_but_disagreement_is_flagged():
    out = combine("malicious", role("clean", 0.95))
    assert out.verdict == "malicious"
    assert out.disagreement


def test_tor_role_annotates_without_changing_the_verdict():
    out = combine("suspicious", role("anonymity_network", 0.9))
    assert out.verdict == "suspicious" and out.role == "anonymity_network"
    assert not out.ai_assessed and not out.disagreement


def test_injection_canary_is_evidence_for_malice_and_always_shown():
    answers = role("clean", 0.3)
    answers[INJECTION_CANARY_KEY] = Answer(type="noul", probability=0.9)
    out = combine("clean", answers)
    assert out.verdict == "suspicious" and out.injection_flag and out.public


def test_dual_ask_injection_signal_raises_too():
    out = combine("clean", role("clean", 0.9), injection_suspected=True)
    assert out.verdict == "suspicious" and out.injection_flag


def test_credential_solicitation_needs_the_impersonation_reading():
    answers = role("unrelated_legitimate", 0.5, "site_kind")
    answers["solicits_credentials"] = Answer(type="noul", probability=0.95)
    assert combine("clean", answers).verdict == "clean"
    answers = role("brand_impersonation", 0.5, "site_kind")
    answers["solicits_credentials"] = Answer(type="noul", probability=0.95)
    assert combine("clean", answers).verdict == "suspicious"


def test_site_kind_unknown_does_not_mask_the_infra_role():
    answers = {**role("unknown", 0.99, "site_kind"), **role("dedicated_malicious_infra", 0.8)}
    out = combine("clean", answers)
    assert out.role == "dedicated_malicious_infra" and out.verdict == "suspicious"
