"""Spamhaus says several different things, and Umbra reported all of them the same.

Two defects found by auditing 692 real listings on production.

**Severity was flattened.** Every Zen listing got a weight of 0.6 whatever came
back. `127.0.0.9` (DROP — a hijacked netblock, the most serious thing Spamhaus
publishes) scored exactly the same as `127.0.0.11`.

**And 127.0.0.11 is not an accusation.** PBL is a *policy* list: "this is an
end-user address that should not be sending mail directly." Essentially every
residential IP on earth is in it. 53 of those 692 listings were PBL-only, and
each one was reported as `listed in zen.spamhaus.org (127.0.0.11)` at weight
0.6, which the verdict layer escalated to **suspicious**. A home broadband
address in Taiwan was flagged as a threat for being a home broadband address.

The codes were also printed raw. `(127.0.0.11)` tells a reader nothing.
"""
from __future__ import annotations

import pytest

from umbra.collectors.reputation import (
    classify_zen_codes,
    dnsbl_hit,
    verdict_from_hits,
)
from umbra.core.dns import DnsblResult


def _zen(codes: list[str]) -> object:
    return dnsbl_hit("spamhaus_zen", 0.6, "zen.spamhaus.org",
                     DnsblResult("listed", codes, f"listed ({', '.join(codes)})"))


# --- codes carry meaning ---------------------------------------------------

@pytest.mark.parametrize("code,word", [
    ("127.0.0.2", "SBL"),
    ("127.0.0.3", "CSS"),
    ("127.0.0.4", "XBL"),
    ("127.0.0.9", "DROP"),
    ("127.0.0.10", "PBL"),
    ("127.0.0.11", "PBL"),
])
def test_each_code_is_named(code, word):
    assert word in classify_zen_codes([code]).label


def test_an_unknown_code_is_not_invented():
    """A code Spamhaus adds later must not be silently described as something
    it is not."""
    c = classify_zen_codes(["127.0.0.42"])
    assert "127.0.0.42" in c.label
    assert c.policy_only is False


# --- severity is graded ----------------------------------------------------

def test_drop_outweighs_xbl_outweighs_css():
    drop = classify_zen_codes(["127.0.0.9"]).weight
    xbl = classify_zen_codes(["127.0.0.4"]).weight
    css = classify_zen_codes(["127.0.0.3"]).weight
    assert drop > xbl >= css > 0


def test_a_hijacked_netblock_no_longer_scores_like_a_home_router():
    assert classify_zen_codes(["127.0.0.9"]).weight > classify_zen_codes(["127.0.0.11"]).weight


def test_the_worst_code_in_a_multi_listing_decides():
    """127.0.0.4 + 127.0.0.11 is a compromised host that is also residential.
    The compromise is the finding."""
    both = classify_zen_codes(["127.0.0.11", "127.0.0.4"])
    assert both.weight == classify_zen_codes(["127.0.0.4"]).weight
    assert both.policy_only is False


# --- PBL is policy, not accusation -----------------------------------------

@pytest.mark.parametrize("code", ["127.0.0.10", "127.0.0.11"])
def test_pbl_alone_is_policy_only(code):
    c = classify_zen_codes([code])
    assert c.policy_only is True
    assert c.weight == 0.0


@pytest.mark.parametrize("code", ["127.0.0.10", "127.0.0.11"])
def test_pbl_alone_does_not_make_an_address_suspicious(code):
    """The production false positive, end to end."""
    verdict, score, sources = verdict_from_hits([_zen([code])])
    assert verdict == "clean"
    assert score == 0
    # Still reported — suppressing it would be its own dishonesty.
    assert "spamhaus_zen" in sources


def test_pbl_explains_itself_to_a_human():
    detail = _zen(["127.0.0.11"]).detail
    assert "127.0.0.11" in detail, "keep the raw code for operators"
    assert "PBL" in detail
    assert "end-user" in detail.lower() or "residential" in detail.lower()


def test_xbl_still_reads_as_a_real_finding():
    hit = _zen(["127.0.0.4"])
    assert hit.listed is True
    assert hit.weight > 0
    verdict, score, _ = verdict_from_hits([hit])
    assert verdict in {"suspicious", "malicious"}
    assert score > 0


def test_drop_reaches_malicious_on_its_own():
    verdict, score, _ = verdict_from_hits([_zen(["127.0.0.9"])])
    assert verdict == "malicious", f"DROP scored only {score}"
