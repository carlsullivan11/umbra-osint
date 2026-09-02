from __future__ import annotations

import dns.resolver
import pytest

import umbra.core.dns as dnsmod
from umbra.core.dns import (
    DnsblResult,
    classify_dnsbl_codes,
    dnsbl_lookup,
    get_resolver,
)
from umbra.collectors.reputation import dnsbl_hit


# --- DNSBL return-code classification (the core of the bug fix) -----------

def test_real_listing_is_listed():
    r = classify_dnsbl_codes(["127.0.0.2", "127.0.0.4"])
    assert r.status == "listed"
    assert r.codes == ["127.0.0.2", "127.0.0.4"]


def test_public_resolver_refusal_is_error_not_listed():
    # 127.255.255.254 = "queried via public resolver" — Spamhaus refusal.
    # The old code did `if answers:` and marked this a LISTING → every IP
    # flagged malicious. It must classify as error.
    r = classify_dnsbl_codes(["127.255.255.254"])
    assert r.status == "error"
    assert "public resolver" in r.detail


def test_dbl_typo_code_is_error():
    assert classify_dnsbl_codes(["127.0.1.255"]).status == "error"


def test_empty_is_not_listed():
    assert classify_dnsbl_codes([]).status == "not_listed"


def test_mixed_real_and_error_prefers_real_listing():
    r = classify_dnsbl_codes(["127.0.0.2", "127.255.255.254"])
    assert r.status == "listed" and r.codes == ["127.0.0.2"]


# --- dnsbl_hit maps status → ReputationHit correctly ----------------------

def test_hit_error_is_not_a_listing():
    hit = dnsbl_hit("spamhaus_zen", 0.6, "zen.spamhaus.org",
                    DnsblResult("error", ["127.255.255.254"], "refused"))
    assert hit.listed is False and hit.weight == 0.0
    assert "check error" in hit.detail


def test_hit_listed_carries_weight():
    hit = dnsbl_hit("spamhaus_zen", 0.6, "zen.spamhaus.org",
                    DnsblResult("listed", ["127.0.0.2"], "listed"))
    assert hit.listed is True and hit.weight == 0.6


def test_hit_not_listed_clean():
    hit = dnsbl_hit("spamhaus_dbl", 0.7, "dbl.spamhaus.org",
                    DnsblResult("not_listed", [], "not listed"))
    assert hit.listed is False and hit.weight == 0.0
    assert "not listed" in hit.detail


# --- resolver construction: never a bare hostname, no bad failover --------

def test_resolver_never_gets_bare_hostname(monkeypatch):
    """UMBRA_DNS_RESOLVER=unbound must not crash: the hostname is resolved to
    an IP (or dropped), never assigned raw. The old code did
    `nameservers.append("unbound")` → ValueError on every lookup."""
    monkeypatch.setattr(dnsmod, "_to_ip", lambda s: "10.9.9.9" if s == "unbound" else s)

    class S:
        primary_dns = "unbound"
    monkeypatch.setattr(dnsmod, "get_settings", lambda: S())

    r = get_resolver(allow_public_failover=True)
    for ns in r.nameservers:
        # every nameserver must be a valid IP literal
        import ipaddress
        ipaddress.ip_address(ns)
    assert "10.9.9.9" in r.nameservers
    assert "1.1.1.1" in r.nameservers  # failover present for general use


def test_unresolvable_hostname_is_dropped(monkeypatch):
    monkeypatch.setattr(dnsmod, "_to_ip", lambda s: None)

    class S:
        primary_dns = "does-not-exist"
    monkeypatch.setattr(dnsmod, "get_settings", lambda: S())
    r = get_resolver(allow_public_failover=True)
    assert r.nameservers == ["1.1.1.1"]


def test_dnsbl_resolver_has_no_public_failover(monkeypatch):
    """DNSBL queries must NOT fall back to 1.1.1.1 — that's what produced the
    bogus refusal codes. With no primary configured, no public resolver is
    injected."""
    class S:
        primary_dns = None
    monkeypatch.setattr(dnsmod, "get_settings", lambda: S())
    r = get_resolver(allow_public_failover=False)
    assert "1.1.1.1" not in r.nameservers


def test_dnsbl_lookup_resolver_error_is_error_state(monkeypatch):
    """A resolver failure must yield status 'error' — never silently 'clean'."""
    class BoomResolver:
        nameservers: list = []
        timeout = lifetime = 1.0
        def resolve(self, *a, **k):
            raise dns.resolver.NoNameservers("boom")
    monkeypatch.setattr(dnsmod, "get_resolver", lambda **k: BoomResolver())
    res = dnsbl_lookup("2.0.0.127.zen.spamhaus.org")
    assert res.status == "error"


# --- public system resolvers must never serve DNSBL (found in prod) -------

def test_public_system_resolvers_are_stripped_for_dnsbl(monkeypatch):
    """Regression, caught by the containerized deploy gate: inside Docker the
    system resolvers are typically 1.1.1.1/8.8.4.4. With no primary configured,
    get_resolver(allow_public_failover=False) previously inherited them, so
    DNSBL queries would egress via a public resolver and every address would
    look listed (127.255.255.x)."""
    class S:
        primary_dns = None
    monkeypatch.setattr(dnsmod, "get_settings", lambda: S())

    real = dns.resolver.Resolver
    class FakeResolver(real):
        def __init__(self, *a, **k):
            super().__init__(configure=False)
            self.nameservers = ["1.1.1.1", "8.8.4.4"]
    monkeypatch.setattr(dnsmod.dns.resolver, "Resolver", FakeResolver)

    r = dnsmod.get_resolver(allow_public_failover=False)
    assert r.nameservers == [], "public resolvers must be stripped for DNSBL"


def test_local_system_resolver_is_kept_for_dnsbl(monkeypatch):
    """A genuinely local recursive resolver in resolv.conf is fine to use."""
    class S:
        primary_dns = None
    monkeypatch.setattr(dnsmod, "get_settings", lambda: S())

    real = dns.resolver.Resolver
    class FakeResolver(real):
        def __init__(self, *a, **k):
            super().__init__(configure=False)
            self.nameservers = ["127.0.0.1", "1.1.1.1"]
    monkeypatch.setattr(dnsmod.dns.resolver, "Resolver", FakeResolver)

    r = dnsmod.get_resolver(allow_public_failover=False)
    assert r.nameservers == ["127.0.0.1"]


def test_dnsbl_lookup_refuses_when_only_public_resolvers(monkeypatch):
    """Must report an actionable error — never 'clean', never 'listed'."""
    class FakeR:
        nameservers: list = []
    monkeypatch.setattr(dnsmod, "get_resolver", lambda **k: FakeR())
    res = dnsmod.dnsbl_lookup("2.0.0.127.zen.spamhaus.org")
    assert res.status == "error"
    assert "UMBRA_DNS_RESOLVER" in res.detail
