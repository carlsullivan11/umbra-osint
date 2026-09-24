"""Community reports about a Tor exit are reports about its users.

Enabling `UMBRA_ABUSEIPDB_API_KEY` on 2026-09-16 had a side effect nobody asked
for. AbuseIPDB rates `185.220.101.1` at **abuse confidence 100%, 285 reports**,
which is true and expected: it is a busy Tor exit, and every busy exit collects
hundreds of reports as its *baseline*. Traffic from thousands of strangers
leaves through it, and the complaints land on the relay's address.

Measured before and after the key:

    tor + spamhaus_zen           suspicious 60  ->  malicious 99
    tor + abuseipdb (no others)  clean 0        ->  malicious 99

The second line is the problem. Running a relay became `malicious 99/100` on its
own.

`_NON_ACCUSATORY` already exists to stop exactly this, and its comment predicted
the mechanism almost word for word:

    Running a Tor exit is not wrongdoing, and letting it combine would push an
    IP already at spamhaus_zen 0.6 up to 0.70 — turning "suspicious" into
    "malicious" partly because the address is an exit node. Reported, never
    counted.

It guards the `tor_exit` source itself. AbuseIPDB carries the same fact in
laundered form — an aggregate of user reports whose volume is largely explained
by the relay role — and walked straight past the guard.

So the existing rule extends to it, using the mechanism already in
`verdict_from_hits` for platforms: **reported, never allowed to decide alone.**
The precedent is deliberate — a malware URL on GitHub is a fact about a file
somebody uploaded, and 285 complaints about a Tor exit are facts about its
traffic, not about its operator.

What must NOT change: a *specific* listing still condemns a relay. Feodo naming
it as C2, or URLhaus serving malware from it, is an accusation about that host
and is unaffected. Being popular is not a defence; being an aggregate is.
"""
from __future__ import annotations

from umbra.collectors.reputation import ReputationHit, verdict_from_hits

TOR = ReputationHit("tor_exit", True, 0.0, "Tor exit relay 'artikel10ber03'")
ABUSEIPDB = ReputationHit("abuseipdb", True, 1.0, "abuse confidence 100%, 285 reports")
ZEN_XBL = ReputationHit("spamhaus_zen", True, 0.60, "XBL — compromised device")
FEODO = ReputationHit("feodo_tracker", True, 0.95, "known botnet C2")


# --- the regression ---------------------------------------------------------

def test_a_tor_relay_is_not_malicious_for_being_a_tor_relay():
    verdict, score, _ = verdict_from_hits([TOR, ABUSEIPDB])
    assert verdict != "malicious", f"got {verdict} {score}"


def test_aggregate_reports_alone_do_not_condemn_a_relay():
    verdict, score, _ = verdict_from_hits([TOR, ABUSEIPDB])
    assert score == 0, f"community reports set the score to {score}"


def test_the_listing_is_still_reported():
    """Suppressing the verdict must not hide the finding — 285 reports is worth
    knowing, it just is not a verdict about the operator."""
    _v, _s, sources = verdict_from_hits([TOR, ABUSEIPDB])
    assert "abuseipdb" in sources


# --- what must keep working -------------------------------------------------

def test_a_specific_listing_still_condemns_a_relay():
    """Feodo naming it as C2 is an accusation about this host, not about its
    traffic. Being a relay is not a shield."""
    verdict, score, _ = verdict_from_hits([TOR, FEODO])
    assert verdict == "malicious"
    assert score > 0


def test_spamhaus_still_counts_against_a_relay():
    verdict, _s, _ = verdict_from_hits([TOR, ZEN_XBL])
    assert verdict == "suspicious"


def test_abuseipdb_is_unaffected_on_a_non_tor_address():
    """The rule is about relays, not about AbuseIPDB. Everywhere else it decides
    exactly as before."""
    verdict, score, _ = verdict_from_hits([ABUSEIPDB])
    assert verdict == "malicious"
    assert score > 90


def test_abuseipdb_still_adds_to_a_specific_listing_on_a_relay():
    """With Feodo already deciding, the verdict stays malicious — the question is
    only whether AbuseIPDB can get there on its own."""
    verdict, _s, sources = verdict_from_hits([TOR, FEODO, ABUSEIPDB])
    assert verdict == "malicious"
    assert "abuseipdb" in sources


def test_a_middle_relay_gets_the_same_treatment():
    """Exit or not, the reports are about traffic the operator did not send."""
    relay = ReputationHit("tor_relay", True, 0.0, "Tor middle relay")
    assert verdict_from_hits([relay, ABUSEIPDB])[0] != "malicious"
