"""Collectors that exist, are registered, and never run on the path people use.

The registry, the playbook and COLLECTOR_TRUST all agree there are 40
collectors. That count says nothing about whether a given collector is ever
*reached*. Three were not, on a default domain plan:

    sslbl_cert           the abuse.ch SSL Blacklist lake, joined on the SHA-1
                         that tls_cert and ct_lake already write
    domain_reputation    ran on /reputation but not on a domain intent
    ransomware_exposure  playbook-only; no IntentFlags bit selects it

Production, 2026-09-01, before this change:

    tls_cert            190 evidence rows
    cert entities      2195
    sslbl_cert            0 evidence rows — ever

Two thousand certificates collected and the blacklist never looked at one of
them. Adding the name to the plan is not sufficient to fix that, which is what
`test_a_cert_entity_is_reachable_at_all` is for.
"""
from __future__ import annotations

from umbra.core.models import EntityType
from umbra.intent.plan import _DOMAIN_CORE, analyze_intent, select_collectors
from umbra.intent.schema import AnalyzeRequest, IntentFlags, IntentSeed


def domain_seed(value: str = "example.com") -> IntentSeed:
    return IntentSeed(type=EntityType.DOMAIN, value=value, confidence=0.9, include=True)


def plan_for(value: str = "example.com") -> list[str]:
    return select_collectors([domain_seed(value)], IntentFlags())


# --- the three that were never reached -------------------------------------

def test_a_domain_plan_reads_the_sslbl_lake():
    """tls_cert writes fingerprint_sha1 specifically so this can join on it."""
    assert "sslbl_cert" in _DOMAIN_CORE
    assert "sslbl_cert" in plan_for()


def test_sslbl_runs_after_the_collector_that_produces_the_cert():
    """Ordering is not cosmetic — sslbl_cert consumes what tls_cert emits."""
    assert _DOMAIN_CORE.index("tls_cert") < _DOMAIN_CORE.index("sslbl_cert")


def test_a_domain_plan_checks_reputation():
    """/reputation ran this for a stranger; the full investigation did not."""
    assert "domain_reputation" in _DOMAIN_CORE
    assert "domain_reputation" in plan_for()


def test_a_domain_plan_checks_ransomware_exposure():
    assert "ransomware_exposure" in _DOMAIN_CORE
    assert "ransomware_exposure" in plan_for()


def test_ransomware_is_last_so_a_slow_feed_cannot_starve_dns_or_tls():
    """It is a cached ransomware.live GET. DNS and TLS are the reason the run
    exists; they must not queue behind a third-party feed having a bad day."""
    assert _DOMAIN_CORE[-1] == "ransomware_exposure"
    for essential in ("dns_resolve", "tls_cert", "rdap_domain"):
        assert _DOMAIN_CORE.index(essential) < _DOMAIN_CORE.index("ransomware_exposure")


# --- the part that makes the above real ------------------------------------

def test_a_cert_entity_is_reachable_at_all():
    """Naming a collector in the plan does not mean it can ever run.

    The orchestrator walks entities breadth-first and refuses to expand any
    entity whose type is not in `_PIVOT_TYPES`. `cert` was not in that set, so
    every certificate `tls_cert` produced was a dead end and `sslbl_cert` — the
    only collector that accepts a cert — could never be handed one. That is
    exactly the shape of prod: 2,195 certs, zero sslbl_cert evidence.
    """
    from types import SimpleNamespace

    from umbra.core.orchestrator import _PIVOT_TYPES, Orchestrator

    assert "cert" in _PIVOT_TYPES

    orch = Orchestrator.__new__(Orchestrator)
    seed = SimpleNamespace(id="s", type="domain", value="example.com", is_seed=True)
    cert = SimpleNamespace(id="c", type="cert", value="a" * 64, is_seed=False)
    assert orch._should_pivot(cert, [seed], {"example.com"}) is True


def test_the_only_cert_consumer_is_still_offline():
    """Making certs pivotable is cheap because sslbl_cert reads a local lake.
    If this ever becomes a network call, the cost of the pivot changes."""
    from umbra.collectors.base import default_registry

    col = next(c for c in default_registry().list() if c.name == "sslbl_cert")
    assert {t.value for t in col.inputs} == {"cert"}


# --- nothing else moved ----------------------------------------------------

def test_the_lake_is_still_queried_before_crtsh():
    assert _DOMAIN_CORE.index("ct_lake") < _DOMAIN_CORE.index("crtsh")


def test_the_collector_count_is_unchanged():
    """This slice reaches collectors that already existed. It adds none."""
    from umbra.collectors.base import default_registry

    assert len(default_registry().list()) == 40


def test_a_full_domain_intent_plans_all_three():
    plan = analyze_intent(AnalyzeRequest(text="look into example.com", use_llm=False))
    chosen = set(plan.collectors)
    assert {"sslbl_cert", "domain_reputation", "ransomware_exposure"} <= chosen
