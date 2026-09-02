"""Reading a header block without inventing an accusation (E1).

Every `Received:` line below the first hop the recipient does not control was
supplied by whoever sent the message, and can be **entirely fabricated**. A
parser that reads the bottom of the chain and calls it "the originating IP"
will confidently name an innocent third party as the source of a phishing
campaign — the `postfix_forged_chain` fixture is exactly that message, and it
claims to come from `treasury.gov`.

This is the same failure mode the rest of the codebase is built against — a
DNSBL error rendered as clean, an unsynced lake rendered as no sanctions —
except here the wrong answer accuses somebody.

So the rule under test: mark every hop, name an origin only when the chain
justifies it, and say which hop anchored that decision.

The four fixtures are four different MTAs on purpose. Google folds with spaces
and puts the IP in `(host [ip])`; Microsoft folds mid-token and writes
`(2603:10b6:...)` with no brackets; Postfix uses tabs and `unknown (HELO x)
(ip)`; Exchange writes link-local IPv6 with a zone index. A parser written
against any one of them breaks on the other three.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.email.parse import Trust, parse_headers  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def google():
    return parse_headers(load("google_aligned.eml"))


@pytest.fixture
def spoofed():
    return parse_headers(load("m365_spoofed.eml"))


@pytest.fixture
def forged():
    return parse_headers(load("postfix_forged_chain.eml"))


@pytest.fixture
def internal():
    return parse_headers(load("exchange_internal.eml"))


# --- the addresses being claimed ------------------------------------------

def test_the_from_address_and_its_domain_are_read(google):
    assert google.from_addr == "noreply@shipping-notices.example.com"
    assert google.from_domain == "shipping-notices.example.com"


def test_the_display_name_is_kept_apart_from_the_address(spoofed):
    """"YourBank Security" is the part a human reads and the part that lies."""
    assert spoofed.display_name == "YourBank Security"
    assert spoofed.from_addr == "security@yourbank.example"


def test_return_path_and_reply_to_are_separate_claims(spoofed):
    assert spoofed.return_path == "bounce@mailer.random-vps.tld"
    assert spoofed.reply_to == "recovery@secure-yourbank-verify.tld"


def test_the_recipient_is_identified_as_such(google):
    """Needed to read the chain, and needed so it can be defaulted off later."""
    assert "carl@carls-employer.com" in google.recipients


def test_an_encoded_subject_is_decoded(spoofed):
    assert "verify your account" in spoofed.subject.lower()


def test_a_quoted_printable_subject_is_decoded(internal):
    assert "Scheduled maintenance" in internal.subject


def test_the_message_id_domain_is_extracted(spoofed):
    """Often the truest thing in the block — the sending host names itself."""
    assert spoofed.message_id_domain == "mailer.random-vps.tld"


def test_the_date_becomes_a_datetime(google):
    assert google.date is not None
    assert google.date.year == 2026


# --- the Received chain ---------------------------------------------------

def test_the_chain_is_read_newest_first(google):
    """MTAs prepend, so hop 0 is the last thing that happened."""
    assert len(google.hops) == 4
    assert google.hops[0].index == 0
    assert google.hops[0].by is None or "carls-employer" in str(google.hops[0].by)


def test_google_style_host_and_ip_are_split(google):
    hop = google.hops[2]
    assert hop.from_host == "mail-pj1-f172.google.com"
    assert hop.from_ip == "209.85.216.172"
    assert hop.by == "mx01.carls-employer.com"


def test_microsoft_style_bare_parenthesised_ip_is_read(spoofed):
    """M365 writes `from host (203.0.113.44) by host (10.13.174.238)` with no
    brackets and folds in the middle of the `by` clause."""
    hop = spoofed.hops[2]
    assert hop.from_host == "mailer.random-vps.tld"
    assert hop.from_ip == "203.0.113.44"
    assert hop.by == "co1nam11ft034.mail.protection.outlook.com"


def test_postfix_unknown_helo_form_is_read(forged):
    """`from unknown (HELO mail.irs-refund.example) (185.199.108.153)` — the
    HELO is a claim, the IP is what the socket said."""
    hop = forged.hops[1]
    assert hop.from_ip == "185.199.108.153"
    assert hop.helo == "mail.irs-refund.example"


def test_a_hop_with_no_from_clause_does_not_crash(google):
    assert google.hops[3].from_host is None or google.hops[3].by is not None


def test_hop_timestamps_are_parsed(forged):
    assert forged.hops[0].when is not None
    assert forged.hops[0].when.year == 2026


def test_hostnames_are_lowercased_so_they_compare(internal):
    """Exchange shouts its hostnames and DNS does not care. Comparing
    `EXCH02...` against `exch02...` would cut the trust boundary in the wrong
    place, so the case is normalised on the way in."""
    assert internal.hops[0].from_host == "exch02.corp.carls-employer.com"


# --- the trust boundary, which is the whole point -------------------------

def test_the_top_of_the_chain_is_trusted(google):
    assert google.hops[0].trust is Trust.TRUSTED


def test_trust_stops_at_the_first_hop_we_do_not_control(google):
    """`mail-pj1-f172.google.com` added hop 3. Google is not our infrastructure,
    so nothing it wrote is evidence."""
    assert google.hops[2].trust is Trust.TRUSTED
    assert google.hops[3].trust is Trust.UNTRUSTED


def test_the_handoff_ip_is_the_one_our_own_server_saw(google):
    assert google.origin_ip == "209.85.216.172"


def test_a_forged_chain_does_not_get_to_name_the_origin(forged):
    """The fixture claims five hops originating at treasury.gov. Only two of
    them were written by machines we control; the rest are the sender's fiction.

    This is the test the whole module exists for."""
    assert forged.origin_ip == "185.199.108.153"
    assert "23.55.161.10" not in (forged.origin_ip or "")
    assert forged.hops[2].trust is Trust.UNTRUSTED
    assert forged.hops[4].trust is Trust.UNTRUSTED


def test_the_forged_hops_are_still_reported(forged):
    """Not naming them as the origin is not the same as hiding them — the
    fabrication is itself the finding."""
    claimed = [h.from_host for h in forged.hops if h.trust is Trust.UNTRUSTED]
    assert "mail.treasury.gov" in claimed


def test_a_provider_that_spans_sibling_domains_stays_trusted(spoofed):
    """M365 hands a message between outlook.com, office365.com and
    protection.outlook.com. Treating each as a different organisation would cut
    the boundary at hop 1 and lose the only IP worth having."""
    assert spoofed.hops[0].trust is Trust.TRUSTED
    assert spoofed.hops[1].trust is Trust.TRUSTED
    assert spoofed.hops[2].trust is Trust.TRUSTED
    assert spoofed.origin_ip == "203.0.113.44"


def test_the_bank_hop_below_microsoft_is_not_trusted(spoofed):
    assert spoofed.hops[3].trust is Trust.UNTRUSTED
    assert spoofed.origin_ip != "192.0.2.10"


def test_the_boundary_says_which_hop_anchored_it(google):
    """An analyst has to be able to check that the anchor really is their own
    server. A trust decision with no stated basis is just an assertion."""
    assert google.boundary_basis
    assert "carls-employer.com" in google.boundary_basis


def test_an_operator_can_declare_their_own_trusted_domains(forged):
    """Inference is a fallback. An operator who knows their perimeter should be
    able to say so."""
    result = parse_headers(load("postfix_forged_chain.eml"),
                           trusted_domains={"carls-employer.com"})
    assert result.origin_ip == "185.199.108.153"


def test_declaring_the_attacker_domain_trusted_changes_the_answer(forged):
    """Not a bug — a demonstration that the boundary is a configured fact, not
    something read off the wire."""
    result = parse_headers(load("postfix_forged_chain.eml"),
                           trusted_domains={"carls-employer.com",
                                            "irs-refund.example"})
    assert result.origin_ip == "23.55.161.10"


def test_a_single_hop_chain_still_names_the_origin():
    """The ordinary shape for a small mail server: one hop, ours, recording who
    connected. There is nothing ambiguous about it — 198.51.100.30 handed the
    message to our own MX.

    This regressed because "the last trusted hop is also the last hop" was being
    read as "the message never left the building", which is only true when the
    address it received from is internal.
    """
    blob = ("Received: from mail.sender.example (mail.sender.example [198.51.100.30])\n"
            "\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
            " Tue, 19 Aug 2026 09:00:00 -0700\n"
            "From: a@sender.example\n")
    parsed = parse_headers(blob)
    assert parsed.origin_ip == "198.51.100.30"


def test_a_fully_trusted_multi_hop_chain_still_names_the_origin():
    """Two internal relays, and the outer one recorded the external sender."""
    blob = ("Received: from relay.carls-employer.com (relay.carls-employer.com [10.0.0.5])\n"
            "\tby mx.carls-employer.com (Postfix) with ESMTP id 2;"
            " Tue, 19 Aug 2026 09:00:01 -0700\n"
            "Received: from mail.sender.example (mail.sender.example [198.51.100.30])\n"
            "\tby relay.carls-employer.com (Postfix) with ESMTP id 1;"
            " Tue, 19 Aug 2026 09:00:00 -0700\n"
            "From: a@sender.example\n")
    parsed = parse_headers(blob)
    assert all(h.trust is Trust.TRUSTED for h in parsed.hops)
    assert parsed.origin_ip == "198.51.100.30"


def test_an_all_internal_chain_names_no_external_origin(internal):
    """Every hop is corp infrastructure. There is no handoff to report, and
    inventing one would be worse than saying nothing."""
    assert all(h.trust is Trust.TRUSTED for h in internal.hops)
    assert internal.origin_ip is None
    assert internal.origin_note


def test_no_received_headers_at_all_is_unknown_not_clean():
    parsed = parse_headers("From: a@b.example\nSubject: hi\n")
    assert parsed.hops == []
    assert parsed.origin_ip is None
    assert parsed.origin_note


# --- authentication headers -----------------------------------------------

def test_authentication_results_are_read(google):
    auth = google.auth[0]
    assert auth.spf == "pass"
    assert auth.dkim == "pass"
    assert auth.dmarc == "pass"


def test_the_authserv_id_is_kept(google):
    """`Authentication-Results` means something only when the receiving domain
    added it, and that is the same trust-boundary question as the chain."""
    assert google.auth[0].authserv_id == "mx01.carls-employer.com"
    assert google.auth[0].trusted is True


def test_a_results_header_from_an_untrusted_authserv_is_marked():
    blob = (
        "Received: from evil.example (evil.example [203.0.113.9])\n"
        "\tby mx.carls-employer.com (Postfix) with ESMTP id 1\n"
        "\tfor <carl@carls-employer.com>; Tue, 19 Aug 2026 09:00:00 -0700\n"
        "Authentication-Results: mx.evil.example; dkim=pass; spf=pass; dmarc=pass\n"
        "From: ceo@carls-employer.com\n"
    )
    parsed = parse_headers(blob)
    assert parsed.auth[0].trusted is False


def test_the_dkim_signing_domain_is_extracted(spoofed):
    assert spoofed.dkim_domains == ["mailer.random-vps.tld"]


def test_the_dkim_selector_is_kept(google):
    assert google.dkim_signatures[0]["s"] == "s1"


def test_a_missing_results_header_is_absent_not_a_failure(forged):
    """"No Authentication-Results" means the receiving server did not check, or
    did not record it. Reporting that as a failed check would be inventing a
    finding — the same mistake as rendering a DNSBL timeout as clean, in the
    other direction."""
    assert forged.auth == []


# --- the low-trust extras -------------------------------------------------

def test_x_originating_ip_is_read_but_flagged(spoofed):
    assert spoofed.x_originating_ip == "198.18.7.99"


def test_list_unsubscribe_urls_are_extracted(spoofed):
    assert any("secure-yourbank-verify.tld" in u for u in spoofed.list_unsubscribe)


def test_the_mailer_is_kept_as_a_weak_signal(spoofed):
    assert "PHPMailer" in (spoofed.x_mailer or "")


# --- hostile and malformed input ------------------------------------------

def test_an_empty_block_does_not_raise():
    parsed = parse_headers("")
    assert parsed.hops == []
    assert parsed.from_addr is None


def test_a_body_after_the_headers_is_ignored():
    blob = load("google_aligned.eml") + "\n\nThis is the body with evil@nope.example\n"
    parsed = parse_headers(blob)
    assert parsed.from_addr == "noreply@shipping-notices.example.com"
    assert "evil@nope.example" not in str(parsed.recipients)


def test_crlf_line_endings_parse_the_same():
    lf = parse_headers(load("google_aligned.eml"))
    crlf = parse_headers(load("google_aligned.eml").replace("\n", "\r\n"))
    assert crlf.origin_ip == lf.origin_ip
    assert len(crlf.hops) == len(lf.hops)


def test_a_hop_count_bomb_is_capped():
    """A message with ten thousand Received headers is not an investigation, it
    is a denial-of-service."""
    from umbra.email.parse import MAX_HOPS

    blob = "".join(
        f"Received: from h{i}.example ([192.0.2.{i % 250}])"
        f" by mx.carls-employer.com; Tue, 19 Aug 2026 09:00:00 -0700\n"
        for i in range(5000)
    ) + "From: a@b.example\n"
    parsed = parse_headers(blob)
    assert len(parsed.hops) <= MAX_HOPS
    assert parsed.notes


def test_absurd_header_lengths_are_truncated_not_stored_whole():
    blob = "Subject: " + ("A" * 200_000) + "\nFrom: a@b.example\n"
    parsed = parse_headers(blob)
    assert len(parsed.subject) < 10_000


def test_junk_bytes_do_not_raise():
    for junk in ("\x00\x01\x02", "Received:", ":::::", "From:", "\n\n\n",
                 "Received: from from from by by by;;;;"):
        parse_headers(junk)


def test_a_malformed_date_is_none_not_a_crash():
    parsed = parse_headers("From: a@b.example\nDate: sometime last tuesday\n")
    assert parsed.date is None


def test_duplicated_from_headers_keep_the_first_and_warn():
    """Two `From:` headers is a known evasion — some clients render the second,
    some the first."""
    blob = ("From: real@carls-employer.com\n"
            "From: fake@evil.example\nSubject: x\n")
    parsed = parse_headers(blob)
    assert parsed.from_addr == "real@carls-employer.com"
    assert any("From" in n for n in parsed.notes)
