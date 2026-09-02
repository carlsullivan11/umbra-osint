from __future__ import annotations

from umbra.collectors.base import default_registry
from umbra.collectors.reputation import (
    DomainReputationCollector,
    IpReputationCollector,
    ReputationHit,
    parse_abuseipdb,
    parse_urlhaus_host,
    verdict_from_hits,
    _reverse_ipv4,
)
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _ip_entity(v: str) -> Entity:
    return Entity(id="1", case_id="c", type="ip", value=v,
                  norm_key=entity_key(EntityType.IP, v), props={},
                  confidence=1.0, is_seed=True)


def _domain_entity(v: str) -> Entity:
    return Entity(id="2", case_id="c", type="domain", value=v,
                  norm_key=entity_key(EntityType.DOMAIN, v), props={},
                  confidence=1.0, is_seed=True)


# --- registration + supports ---------------------------------------------

def test_collectors_registered():
    reg = default_registry()
    assert reg.get("ip_reputation") is not None
    assert reg.get("domain_reputation") is not None


def test_supports():
    assert IpReputationCollector().supports(_ip_entity("1.2.3.4"))
    assert not IpReputationCollector().supports(_domain_entity("example.com"))
    assert DomainReputationCollector().supports(_domain_entity("example.com"))
    assert not DomainReputationCollector().supports(_ip_entity("1.2.3.4"))


# --- verdict logic --------------------------------------------------------

def test_verdict_empty_is_unknown():
    assert verdict_from_hits([]) == ("unknown", 0, [])


def test_verdict_all_clean():
    hits = [ReputationHit("a", False, 0.0, ""), ReputationHit("b", False, 0.0, "")]
    v, score, srcs = verdict_from_hits(hits)
    assert v == "clean" and score == 0 and srcs == []


def test_verdict_independent_providers_corroborate():
    """Was `worst_source_wins`, asserting the max weight (95).

    Two *different organisations* — Spamhaus and abuse.ch — reporting the same
    address is stronger evidence than either alone, and max could not say so:
    it returned 95 whether one source fired or both. Combined by noisy-OR
    across providers, 0.6 and 0.95 give 1-(0.4 x 0.05) = 0.98.

    Still not an average, which would have diluted the 0.95 down to 0.775.
    """
    hits = [
        ReputationHit("spamhaus_zen", True, 0.6, "listed"),
        ReputationHit("feodo_tracker", True, 0.95, "C2"),
        ReputationHit("tor_exit", False, 0.0, "no"),
    ]
    v, score, srcs = verdict_from_hits(hits)
    assert v == "malicious"
    assert score == 98
    assert score > 95, "corroboration must add something"
    assert set(srcs) == {"spamhaus_zen", "feodo_tracker"}


def test_a_tor_exit_on_its_own_is_not_an_accusation():
    """Behaviour change, deliberate: this asserted suspicious/25.

    Running a Tor exit is a network role, not wrongdoing, and no blocklist here
    says otherwise — "suspicious" was Umbra's own inference from a fact about
    routing. It also became actively harmful once sources combine: tor_exit
    0.25 alongside spamhaus_zen 0.6 would reach 0.70 and promote an IP to
    malicious partly for being an exit node.

    The fact is still reported in the source list; what it no longer does is
    carry a verdict.
    """
    hits = [ReputationHit("tor_exit", True, 0.25, "exit node")]
    v, score, srcs = verdict_from_hits(hits)
    assert v == "clean" and score == 0
    assert "tor_exit" in srcs


# --- parsers --------------------------------------------------------------

def test_parse_abuseipdb_malicious():
    hit = parse_abuseipdb({"data": {"abuseConfidenceScore": 100, "totalReports": 42,
                                    "ipAddress": "1.2.3.4"}})
    assert hit.listed and hit.weight == 1.0
    assert "42 reports" in hit.detail


def test_parse_abuseipdb_clean():
    hit = parse_abuseipdb({"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    assert not hit.listed and hit.weight == 0.0


def test_parse_urlhaus_no_records():
    hit = parse_urlhaus_host({"query_status": "no_results"})
    assert not hit.listed and hit.weight == 0.0


def test_parse_urlhaus_online_malware():
    data = {
        "query_status": "ok",
        "host": "bad.example",
        "url_count": "3",
        "urls": [
            {"url_status": "online", "blacklists": {"spamhaus_dbl": "abused_legit_malware"}},
            {"url_status": "offline", "blacklists": {}},
        ],
    }
    hit = parse_urlhaus_host(data)
    assert hit.listed and hit.weight == 0.9
    assert "3 malware URL(s), 1 online" in hit.detail
    assert "spamhaus_dbl" in hit.detail


def test_parse_urlhaus_historical_only():
    data = {"query_status": "ok", "host": "x", "url_count": "2",
            "urls": [{"url_status": "offline", "blacklists": {}}]}
    hit = parse_urlhaus_host(data)
    assert hit.listed and hit.weight == 0.6


# --- ipv4 reverse helper --------------------------------------------------

def test_reverse_ipv4():
    assert _reverse_ipv4("1.2.3.4") == "4.3.2.1"
    assert _reverse_ipv4("2606:4700::1") is None   # IPv6 not DNSBL-eligible here
    assert _reverse_ipv4("not-an-ip") is None
