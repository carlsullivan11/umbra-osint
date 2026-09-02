"""Alignment, not pass/fail (E2).

`dkim=pass` means *somebody* signed the message. It does not mean the sender is
who the `From:` header claims. The finding worth reporting is whether the
`From:` domain **aligns** with the DKIM `d=` domain and the `Return-Path` — a
message from `security@yourbank.example`, validly signed for
`d=mailer.random-vps.tld`, with SPF passing for that same stranger, is a
textbook spoof that passes every check read individually.

The other half of this module is refusing to overstate. A message with no
`Authentication-Results` header was **not checked**; reporting that as a failed
check invents a finding, which is the same sin as rendering a DNSBL timeout as
clean, pointed the other way.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.email.parse import parse_headers  # noqa: E402
from umbra.email.verdict import judge  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def keys(findings) -> set[str]:
    return {f.key for f in findings}


@pytest.fixture
def good():
    return judge(parse_headers(load("google_aligned.eml")))


@pytest.fixture
def spoofed():
    return judge(parse_headers(load("m365_spoofed.eml")))


@pytest.fixture
def forged():
    return judge(parse_headers(load("postfix_forged_chain.eml")))


@pytest.fixture
def internal():
    return judge(parse_headers(load("exchange_internal.eml")))


# --- the legitimate message should be quiet -------------------------------

def test_an_aligned_message_raises_nothing_serious(good):
    assert not [f for f in good if f.severity in {"high", "medium"}]


def test_alignment_is_stated_positively_when_it_holds(good):
    """"Nothing found" and "checked and it lines up" are different messages, and
    the analyst deserves the second one."""
    assert "dkim_aligned" in keys(good)


def test_a_subdomain_signature_still_aligns():
    """`d=mail.example.com` signing for `From: x@example.com` is relaxed
    alignment, which is what nearly every bulk sender uses."""
    blob = (
        "Authentication-Results: mx.carls-employer.com; dkim=pass "
        "header.d=mail.example.com; spf=pass; dmarc=pass\n"
        "Received: from mail.example.com (mail.example.com [198.51.100.30])\n"
        "\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
        " Tue, 19 Aug 2026 09:00:00 -0700\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=mail.example.com; s=k1; b=xx\n"
        "Return-Path: <bounce@mail.example.com>\n"
        "From: Billing <billing@example.com>\n"
    )
    assert "dkim_unaligned" not in keys(judge(parse_headers(blob)))


# --- the spoof -------------------------------------------------------------

def test_a_valid_signature_for_a_stranger_is_the_headline(spoofed):
    finding = next(f for f in spoofed if f.key == "dkim_unaligned")
    assert finding.severity == "high"
    assert "mailer.random-vps.tld" in finding.detail
    assert "yourbank.example" in finding.detail


def test_the_envelope_sender_not_matching_is_reported(spoofed):
    assert "spf_unaligned" in keys(spoofed)


def test_a_dmarc_failure_is_reported(spoofed):
    assert "dmarc_fail" in keys(spoofed)


def test_two_passes_and_no_dmarc_still_gets_flagged():
    """The failure this module exists to prevent: a reader sees `dkim=pass` and
    `spf=pass`, concludes the mail is genuine, and clicks the link."""
    blob = (
        "Authentication-Results: mx.carls-employer.com; dkim=pass "
        "header.d=mailer.random-vps.tld; spf=pass "
        "smtp.mailfrom=bounce@mailer.random-vps.tld\n"
        "Received: from mailer.random-vps.tld (mailer.random-vps.tld [203.0.113.44])\n"
        "\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
        " Tue, 19 Aug 2026 09:00:00 -0700\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=mailer.random-vps.tld; s=d; b=xx\n"
        "Return-Path: <bounce@mailer.random-vps.tld>\n"
        "From: YourBank <security@yourbank.example>\n"
    )
    findings = judge(parse_headers(blob))
    assert "dkim_unaligned" in keys(findings)
    assert "spf_unaligned" in keys(findings)
    assert any(f.severity == "high" for f in findings)


def test_a_reply_to_pointing_somewhere_else_is_reported(spoofed):
    finding = next(f for f in spoofed if f.key == "reply_to_mismatch")
    assert "secure-yourbank-verify.tld" in finding.detail


def test_the_message_id_disagreeing_with_the_from_domain_is_noted(spoofed):
    assert "message_id_mismatch" in keys(spoofed)


# --- refusing to overstate -------------------------------------------------

def test_no_authentication_results_is_reported_as_unchecked(forged):
    """Not "authentication failed". The receiving server did not record a
    check, and an absent check is not a negative result."""
    finding = next(f for f in forged if f.key == "auth_not_checked")
    assert finding.severity == "info"
    lowered = (finding.title + finding.detail).lower()
    assert "not" in lowered
    assert "fail" not in finding.title.lower()


def test_an_unchecked_message_produces_no_dkim_or_spf_verdict(forged):
    assert "dkim_pass" not in keys(forged)
    assert "dkim_fail" not in keys(forged)
    assert "dmarc_fail" not in keys(forged)


def test_results_added_outside_the_boundary_are_worth_nothing():
    """A sender can write their own `Authentication-Results` saying everything
    passed. Position in the block is the only thing that makes it evidence."""
    blob = (
        "Received: from evil.example (evil.example [198.51.100.66])\n"
        "\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
        " Tue, 19 Aug 2026 09:00:00 -0700\n"
        "Authentication-Results: mx.evil.example; dkim=pass "
        "header.d=carls-employer.com; spf=pass; dmarc=pass\n"
        "From: ceo@carls-employer.com\n"
    )
    findings = judge(parse_headers(blob))
    assert "auth_untrusted" in keys(findings)
    assert next(f for f in findings if f.key == "auth_untrusted").severity == "high"
    # and its verdicts must not be reported as if they meant something
    assert "dkim_aligned" not in keys(findings)


def test_a_planted_results_header_below_the_real_one_does_not_condemn_the_message():
    """Headers are prepended, so the receiving server's own results header sits
    on top and anything the sender wrote sits below it. Only the topmost one
    decides.

    Reading the whole list instead meant a legitimate, aligned, DMARC-passing
    message got a `high` finding — the loudest thing on the page — because the
    sender had appended a decorative Authentication-Results of its own. That is
    an accusation drawn from a header we were not relying on.
    """
    blob = (
        "Received: from mail.legit-sender.example (mail.legit-sender.example "
        "[198.51.100.30])\n\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
        " Tue, 19 Aug 2026 09:00:00 -0700\n"
        "Authentication-Results: mx.carls-employer.com; dkim=pass "
        "header.d=legit-sender.example; spf=pass; dmarc=pass\n"
        "Authentication-Results: mx.evil.example; dkim=pass; spf=pass; dmarc=pass\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=legit-sender.example; s=k1; b=xx\n"
        "Return-Path: <bounce@legit-sender.example>\n"
        "From: Billing <billing@legit-sender.example>\n"
    )
    findings = judge(parse_headers(blob))
    assert not [f for f in findings if f.severity == "high"]
    assert "dkim_aligned" in keys(findings)


def test_a_planted_results_header_is_still_pointed_out():
    """Not a high finding, but not nothing either — a sender that writes its own
    authentication verdicts is telling you something about itself."""
    blob = (
        "Received: from mail.legit-sender.example (mail.legit-sender.example "
        "[198.51.100.30])\n\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
        " Tue, 19 Aug 2026 09:00:00 -0700\n"
        "Authentication-Results: mx.carls-employer.com; dkim=pass "
        "header.d=legit-sender.example; spf=pass; dmarc=pass\n"
        "Authentication-Results: mx.evil.example; dkim=pass; spf=pass; dmarc=pass\n"
        "From: Billing <billing@legit-sender.example>\n"
    )
    findings = judge(parse_headers(blob))
    finding = next(f for f in findings if f.key == "auth_self_asserted")
    assert finding.severity in {"low", "medium"}
    assert "mx.evil.example" in str(finding.evidence) + finding.detail


def test_the_topmost_results_header_still_decides_when_it_is_the_forged_one():
    """The original case must keep working: if the only results header was
    written outside the boundary, its verdicts are worthless."""
    blob = (
        "Received: from evil.example (evil.example [198.51.100.66])\n"
        "\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
        " Tue, 19 Aug 2026 09:00:00 -0700\n"
        "Authentication-Results: mx.evil.example; dkim=pass "
        "header.d=carls-employer.com; spf=pass; dmarc=pass\n"
        "From: ceo@carls-employer.com\n"
    )
    findings = judge(parse_headers(blob))
    assert "auth_untrusted" in keys(findings)
    assert next(f for f in findings if f.key == "auth_untrusted").severity == "high"


def test_a_chain_that_cannot_be_anchored_says_so():
    blob = ("Received: from a.example by b.example;"
            " Tue, 19 Aug 2026 09:00:00 -0700\n"
            "From: x@a.example\n")
    findings = judge(parse_headers(blob))
    assert "origin_unproven" in keys(findings) or "origin_established" not in keys(findings)


# --- the forged chain ------------------------------------------------------

def test_the_claimed_origin_and_the_real_handoff_are_contrasted(forged):
    """The fixture claims to originate at treasury.gov. Our own relay received
    it from 185.199.108.153, which is not treasury.gov."""
    finding = next(f for f in forged if f.key == "chain_claims_another_origin")
    assert finding.severity in {"high", "medium"}
    assert "treasury.gov" in finding.detail
    assert "185.199.108.153" in finding.detail


def test_a_clean_chain_makes_no_such_claim(good):
    assert "chain_claims_another_origin" not in keys(good)


def test_the_established_origin_is_reported_with_its_basis(good):
    finding = next(f for f in good if f.key == "origin_established")
    assert "209.85.216.172" in finding.detail


def test_an_all_internal_chain_is_not_treated_as_suspicious(internal):
    assert not [f for f in internal if f.severity == "high"]


# --- display name games ----------------------------------------------------

def test_a_display_name_carrying_a_different_address_is_flagged():
    blob = ('From: "security@yourbank.example" <attacker@random-vps.tld>\n'
            "Subject: hi\n")
    assert "display_name_spoof" in keys(judge(parse_headers(blob)))


def test_an_ordinary_display_name_is_not_flagged(good):
    assert "display_name_spoof" not in keys(good)


# --- shape -----------------------------------------------------------------

def test_findings_are_ordered_worst_first(spoofed):
    order = ["high", "medium", "low", "info"]
    seen = [order.index(f.severity) for f in spoofed]
    assert seen == sorted(seen)


def test_every_finding_carries_the_values_it_is_based_on(spoofed):
    """A finding an analyst cannot check is an assertion, not evidence."""
    for finding in spoofed:
        assert finding.evidence != {} or finding.severity == "info"


def test_judging_an_empty_parse_does_not_raise():
    findings = judge(parse_headers(""))
    assert isinstance(findings, list)


def test_judging_junk_does_not_raise():
    for junk in ("\x00\x01", "From:", ":::", "Received: from"):
        judge(parse_headers(junk))
