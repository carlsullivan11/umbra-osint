"""Headers → IntentPlan, so the analyst picks what runs (E3).

Carl's design: extract the entities, then let the analyst choose which ones go
to the recon workers. That step already exists — `results.html` renders a
checkbox per seed, and `_apply_plan_edits` enforces that edits may only
**narrow**. So the entire job here is emitting an `IntentPlan`; everything
downstream comes free.

Two rules do the real work.

**Everything is shown.** An earlier draft of the plan proposed not extracting
recipient-side identifiers at all, for privacy. That is wrong: an analyst needs
the recipient's own relays visible to find the trust boundary in the chain, and
hiding them breaks the analysis.

**Almost nothing is armed.** Recipient addresses, our own mail relays, and
every hop below the trust boundary are present and unchecked. Ticking one is a
decision; nothing about it should be a default.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.models import EntityType  # noqa: E402
from umbra.email.plan import plan_from_headers  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


@pytest.fixture
def spoofed():
    return plan_from_headers(load("m365_spoofed.eml"))


@pytest.fixture
def forged():
    return plan_from_headers(load("postfix_forged_chain.eml"))


def seed(plan, value):
    return next((s for s in plan.seeds if s.value == value), None)


def included(plan):
    return {s.value for s in plan.seeds if s.include}


def shown(plan):
    return {s.value for s in plan.seeds}


# --- what runs -------------------------------------------------------------

def test_the_claimed_sender_domain_runs(spoofed):
    assert "yourbank.example" in included(spoofed)


def test_the_domain_that_actually_signed_it_runs(spoofed):
    """When the signature is unaligned, the signing domain is the real sender —
    the single most useful thing in the whole block."""
    assert "mailer.random-vps.tld" in included(spoofed)


def test_the_reply_to_domain_runs(spoofed):
    assert "secure-yourbank-verify.tld" in included(spoofed)


def test_the_handoff_ip_runs(spoofed):
    """The one address the chain justifies naming."""
    ip = seed(spoofed, "203.0.113.44")
    assert ip is not None and ip.include
    assert ip.type is EntityType.IP


def test_the_unsubscribe_url_runs(spoofed):
    """Frequently the actual payload domain."""
    assert any(s.type is EntityType.URL and s.include for s in spoofed.seeds)


def test_the_from_address_runs_as_an_email(spoofed):
    entry = seed(spoofed, "security@yourbank.example")
    assert entry is not None and entry.include
    assert entry.type is EntityType.EMAIL


# --- what is shown but not armed ------------------------------------------

def test_the_recipient_is_shown(spoofed):
    """Needed to read the chain."""
    assert "carl@carls-employer.com" in shown(spoofed)


def test_the_recipient_is_not_armed(spoofed):
    """Nobody needs the victim's own address scanned by accident."""
    assert "carl@carls-employer.com" not in included(spoofed)


def test_the_host_that_connected_to_us_is_sender_side_and_runs():
    """On the boundary hop, `by` is our server but `from` is *theirs* — the
    machine that actually connected, and the name it gave for itself.

    Both were being labelled "the recipient's own infrastructure" and left
    unchecked, which is wrong twice: it misdescribes the sender's host, and it
    drops one of the better leads in the whole block, since the connecting
    host's name frequently differs from the From domain.
    """
    blob = ("Received: from mail.sender.example (mail.sender.example [198.51.100.30])\n"
            "\tby mx.carls-employer.com (Postfix) with ESMTP id 1;"
            " Tue, 19 Aug 2026 09:00:00 -0700\n"
            "From: a@sender.example\nTo: carl@carls-employer.com\n")
    plan = plan_from_headers(blob)
    sender_host = seed(plan, "mail.sender.example")
    assert sender_host.include is True
    assert "recipient" not in (sender_host.notes or "").lower()
    # our own MX on the same hop stays off
    assert seed(plan, "mx.carls-employer.com").include is False


def test_a_forged_helo_name_is_offered(forged):
    """`from unknown (HELO mail.irs-refund.example) (185.199.108.153)` — the HELO
    is what the connecting machine called itself to our relay. It is a claim,
    but it is a claim made to a server we control, which is exactly the kind
    worth chasing."""
    helo = seed(forged, "mail.irs-refund.example")
    assert helo is not None and helo.include is True


def test_an_all_internal_chain_arms_no_hop_hosts():
    """With no external handoff, every hop is ours and none of them is a lead."""
    plan = plan_from_headers(load("exchange_internal.eml"))
    # Scoped to hop-derived seeds: the From address in this fixture really is
    # the sender, internal or not, and stays armed.
    assert not [s for s in plan.seeds
                if s.include and "Received" in (s.source_span or "")]


def test_the_recipients_own_relays_are_shown_but_not_armed(forged):
    relay = seed(forged, "relay02.carls-employer.com")
    assert relay is not None
    assert relay.include is False


def test_hops_below_the_boundary_are_shown_but_not_armed(forged):
    """`mail.treasury.gov` is in this message because the sender wrote it there.
    Investigating it means investigating a domain the attacker chose."""
    hop = seed(forged, "mail.treasury.gov")
    assert hop is not None
    assert hop.include is False


def test_the_forged_hop_ip_is_not_armed(forged):
    hop = seed(forged, "23.55.161.10")
    assert hop is not None and hop.include is False


def test_x_originating_ip_is_shown_but_not_armed(spoofed):
    entry = seed(spoofed, "198.18.7.99")
    assert entry is not None and entry.include is False


def test_an_analyst_can_still_tick_the_unarmed_ones(forged):
    """Unchecked is not hidden. Sometimes the forged hop is exactly the thing
    worth looking at — it just takes a decision rather than a default."""
    hop = seed(forged, "mail.treasury.gov")
    hop.include = True
    assert hop in forged.seeds


# --- every seed says where it came from and why ---------------------------

def test_each_seed_names_the_header_it_came_from(spoofed):
    for entry in spoofed.seeds:
        assert entry.source_span, f"{entry.value} has no source header"


def test_unarmed_seeds_explain_themselves(spoofed):
    for entry in spoofed.seeds:
        if not entry.include:
            assert entry.notes, f"{entry.value} is off with no reason given"


def test_the_handoff_ip_outranks_the_vendor_header(spoofed):
    """A trusted Received hop is evidence; X-Originating-IP is a sender-supplied
    claim. The confidence should say so."""
    assert seed(spoofed, "203.0.113.44").confidence > seed(spoofed, "198.18.7.99").confidence


def test_the_signing_domain_note_explains_the_mismatch(spoofed):
    assert "yourbank" in (seed(spoofed, "mailer.random-vps.tld").notes or "").lower()


# --- the plan is runnable --------------------------------------------------

def test_collectors_are_chosen_for_the_included_seeds(spoofed):
    assert "dns_email_auth" in spoofed.collectors
    assert "rdap_domain" in spoofed.collectors


def test_ip_collectors_are_chosen_when_an_ip_is_armed(spoofed):
    assert "rdap_ip" in spoofed.collectors or "asn_cymru" in spoofed.collectors


def test_the_case_is_named_after_the_sender_not_the_subject(spoofed):
    """Subjects carry whatever the attacker wrote, including the recipient's
    name. The sending domain is the durable identifier."""
    assert "yourbank.example" in spoofed.case_name
    assert "verify your account" not in spoofed.case_name.lower()


def test_the_findings_reach_the_warnings(spoofed):
    joined = " ".join(spoofed.warnings).lower()
    assert "dkim" in joined or "sign" in joined


def test_the_plan_records_which_extractor_built_it(spoofed):
    assert "email" in spoofed.extractor


# --- privacy ---------------------------------------------------------------

def test_the_raw_header_block_is_not_carried_in_the_plan(spoofed):
    """The plan is what gets persisted as a case. The header block is the most
    sensitive artifact in this feature and has no investigative value once
    parsed, so it must not ride along inside it."""
    dumped = spoofed.model_dump_json()
    # Header *names* are fine and wanted — `source_span: "DKIM-Signature d="` is
    # how a seed says where it came from. What must not survive is any header
    # *value*: the signature body, the hashes, the routing detail.
    assert "Rv7pQ2sLm4nB8cXe0" not in dumped          # the b= signature
    assert "cKq0Fk3nZ1vTt8mLpQr7wXy2dEsA4hJ6uNb0iOgVc5M=" not in dumped  # bh=
    assert "co1nam11ft034" not in dumped.lower()      # internal M365 routing
    assert "15.20.7918.20" not in dumped              # server version
    assert "Received: from" not in dumped


def test_the_subject_line_is_not_carried_in_the_plan(spoofed):
    """A subject is the recipient's personal data as often as the sender's."""
    assert "verify your account" not in spoofed.model_dump_json().lower()


def test_raw_intent_is_a_description_not_the_block(spoofed):
    assert spoofed.raw_intent
    assert len(spoofed.raw_intent) < 300


# --- shape and hostile input ----------------------------------------------

def test_an_empty_block_produces_a_plan_with_nothing_armed():
    plan = plan_from_headers("")
    assert plan.seeds == [] or not any(s.include for s in plan.seeds)
    assert plan.warnings


def test_junk_does_not_raise():
    for junk in ("\x00\x01", "From:", ":::", "Received: from", "\n\n"):
        plan_from_headers(junk)


def test_seeds_are_unique():
    plan = plan_from_headers(load("google_aligned.eml"))
    values = [(s.type, s.value) for s in plan.seeds]
    assert len(values) == len(set(values))


def test_the_authorization_basis_can_be_set():
    plan = plan_from_headers(load("google_aligned.eml"),
                             authorization_basis="client_engagement")
    assert plan.authorization_basis == "client_engagement"


def test_free_mail_domains_are_not_seeded_as_targets():
    """Investigating gmail.com because the sender used Gmail is not an
    investigation."""
    blob = ("From: someone@gmail.com\nTo: carl@carls-employer.com\n"
            "Subject: hi\n")
    plan = plan_from_headers(blob)
    assert "gmail.com" not in included(plan)
