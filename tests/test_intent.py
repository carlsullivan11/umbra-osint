from __future__ import annotations

import json

from umbra.core.models import EntityType
from umbra.intent.extract import extract_flags, extract_hits
from umbra.intent.plan import analyze_intent, select_collectors
from umbra.intent.schema import AnalyzeRequest, IntentFlags


def test_extract_email_domain_github():
    text = (
        "Brand example-brand.com and GH example-user; "
        "email hello@example-brand.com. Check lookalikes and breaches."
    )
    hits = extract_hits(text)
    types = {(h.type, h.value) for h in hits}
    assert (EntityType.DOMAIN, "example-brand.com") in types
    assert (EntityType.EMAIL, "hello@example-brand.com") in types
    assert any(h.type == EntityType.USERNAME and "example-user" in h.value for h in hits)
    flags = extract_flags(text)
    assert flags.want_lookalikes
    assert flags.want_breaches


def test_extract_urls_and_ip():
    text = "See https://example.com/path and host 8.8.8.8 plus github.com/octocat"
    hits = extract_hits(text)
    vals = {(h.type.value, h.value) for h in hits}
    assert ("domain", "example.com") in vals
    assert ("ip", "8.8.8.8") in vals
    assert ("username", "github:octocat") in vals


def test_analyze_plan_collectors():
    text = (
        "domain example.com, email security@example.com, "
        "github:octocat — need typosquat watch and breach check"
    )
    plan = analyze_intent(
        AnalyzeRequest(text=text, authorization_basis="own_asset", authorization_note="lab")
    )
    assert plan.refuse is False
    assert plan.plan_id.startswith("plan_")
    included = {s.value for s in plan.seeds if s.include}
    assert "example.com" in included
    assert "security@example.com" in included
    assert "lookalike_domains" in plan.collectors
    assert "hibp_breach" in plan.collectors
    assert "dns_resolve" in plan.collectors
    assert plan.flags.want_lookalikes
    assert plan.playbook in {"domain_dossier", "person_footprint", "custom"}


def test_low_confidence_person_excluded():
    text = "Contact John Smith about example.com"
    plan = analyze_intent(AnalyzeRequest(text=text, authorization_basis="training_lab"))
    people = [s for s in plan.seeds if s.type == EntityType.PERSON]
    # may or may not extract; if so, default exclude
    for p in people:
        if p.confidence < 0.8:
            assert p.include is False


def test_refuse_pattern_training_lab():
    text = "find my ex and her home address in Bentonville"
    plan = analyze_intent(AnalyzeRequest(text=text, authorization_basis="training_lab"))
    assert plan.refuse is True
    assert plan.refuse_reason


def test_select_collectors_registered_only():
    from umbra.intent.schema import IntentSeed

    seeds = [
        IntentSeed(type=EntityType.DOMAIN, value="example.com", confidence=0.9, include=True)
    ]
    cols = select_collectors(seeds, IntentFlags(want_lookalikes=True), registered={"dns_resolve", "lookalike_domains", "nope"})
    assert cols == ["dns_resolve", "lookalike_domains"]


def test_plan_json_roundtrip():
    plan = analyze_intent(
        AnalyzeRequest(
            text="example.org and user@example.org",
            authorization_basis="own_asset",
        )
    )
    data = json.loads(plan.model_dump_json())
    assert data["schema_version"] == 1
    assert "seeds" in data


def test_extract_phone_from_notes():
    hits = extract_hits("Robocall from (415) 555-2671 last night")
    phones = [h for h in hits if h.type == EntityType.PHONE]
    assert any(h.value == "+14155552671" for h in phones)


def test_phone_only_plan_uses_phone_validate_not_ddg():
    plan = analyze_intent(
        AnalyzeRequest(
            text="+1 415-555-2671",
            authorization_basis="own_asset",
            authorization_note="lab",
            use_llm=False,
        )
    )
    assert plan.refuse is False
    included = [s for s in plan.seeds if s.include and s.type == EntityType.PHONE]
    assert included
    assert included[0].value == "+14155552671"
    assert "phone_validate" in plan.collectors
    assert "ddg_search" not in plan.collectors
    assert plan.playbook == "phone_reputation"


def test_ip_only_plan_includes_geo_and_reputation():
    plan = analyze_intent(
        AnalyzeRequest(
            text="8.8.8.8",
            authorization_basis="public_cti",
            authorization_note="lab",
            use_llm=False,
        )
    )
    assert plan.refuse is False
    assert "ip_geo" in plan.collectors
    assert "rdap_ip" in plan.collectors
    assert "asn_cymru" in plan.collectors
    assert "ip_reputation" in plan.collectors
    assert "malware_infra" in plan.collectors


def test_domain_plan_includes_passive_ip_set_for_pivots():
    plan = analyze_intent(
        AnalyzeRequest(
            text="example.com",
            authorization_basis="public_cti",
            authorization_note="lab",
            use_llm=False,
        )
    )
    assert plan.refuse is False
    assert "dns_resolve" in plan.collectors
    for name in ("rdap_ip", "asn_cymru", "ip_geo", "ip_reputation", "malware_infra"):
        assert name in plan.collectors, name


def test_person_prefix_is_included():
    plan = analyze_intent(
        AnalyzeRequest(
            text="person: Jane Doe",
            authorization_basis="training_lab",
            authorization_note="lab",
            use_llm=False,
        )
    )
    people = [s for s in plan.seeds if s.type == EntityType.PERSON and s.include]
    assert people
    assert people[0].value == "jane doe"
    assert "obituary_search" in plan.collectors
    assert "county_records" in plan.collectors
    assert "sex_offender_registry" in plan.collectors
    assert plan.playbook == "person_footprint"


def test_crypto_address_plan_does_not_ddg():
    addr = "0x" + ("11" * 20)
    plan = analyze_intent(
        AnalyzeRequest(
            text=addr,
            authorization_basis="public_cti",
            authorization_note="lab",
            use_llm=False,
        )
    )
    crypto = [s for s in plan.seeds if s.include and s.type == EntityType.CRYPTO_ADDRESS]
    assert crypto
    assert crypto[0].value.startswith("eth:")
    assert "ddg_search" not in plan.collectors
    assert "crypto_screen" in plan.collectors
    assert plan.playbook == "crypto_screen"
