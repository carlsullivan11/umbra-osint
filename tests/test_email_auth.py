from __future__ import annotations

from umbra.collectors.base import default_registry
from umbra.collectors.dns_email_auth import (
    DnsEmailAuthCollector,
    _report_addresses,
    assess_email_posture,
    parse_bimi,
    parse_dmarc,
    parse_spf,
)
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _domain(v: str) -> Entity:
    return Entity(id="1", case_id="c", type="domain", value=v,
                  norm_key=entity_key(EntityType.DOMAIN, v), props={},
                  confidence=1.0, is_seed=True)


def test_registered_and_supports():
    assert default_registry().get("dns_email_auth") is not None
    c = DnsEmailAuthCollector()
    assert c.supports(_domain("example.com"))


# --- SPF ------------------------------------------------------------------

def test_parse_spf_basic():
    r = parse_spf("v=spf1 include:_spf.google.com ip4:192.0.2.1 -all")
    assert r["all"] == "-"
    assert r["includes"] == ["_spf.google.com"]
    assert r["ip4"] == ["192.0.2.1"]
    assert r["dns_lookups"] == 1
    assert r["exceeds_lookup_limit"] is False


def test_parse_spf_dangerous_plus_all():
    assert parse_spf("v=spf1 +all")["all"] == "+"


def test_parse_spf_lookup_limit():
    rec = "v=spf1 " + " ".join(f"include:x{i}.example" for i in range(11)) + " ~all"
    r = parse_spf(rec)
    assert r["dns_lookups"] == 11 and r["exceeds_lookup_limit"] is True


def test_parse_spf_counts_a_mx_redirect():
    r = parse_spf("v=spf1 a mx include:foo.com redirect=bar.com")
    # a + mx + include + redirect = 4 lookups
    assert r["dns_lookups"] == 4 and r["redirect"] == "bar.com"


# --- DMARC ----------------------------------------------------------------

def test_parse_dmarc_full():
    rec = ("v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=r; "
           "rua=mailto:agg@dmarc.example.com,mailto:x@dmarcian.com; "
           "ruf=mailto:forensic@example.com")
    d = parse_dmarc(rec)
    assert d["policy"] == "reject"
    assert d["subdomain_policy"] == "quarantine"
    assert d["pct"] == "100" and d["adkim"] == "s"
    assert "agg@dmarc.example.com" in d["rua"] and "x@dmarcian.com" in d["rua"]
    assert d["ruf"] == ["forensic@example.com"]


def test_report_addresses_strips_mailto_and_size():
    assert _report_addresses("mailto:a@b.com!10m, mailto:c@d.com") == ["a@b.com", "c@d.com"]


def test_parse_bimi():
    b = parse_bimi("v=BIMI1; l=https://ex.com/logo.svg; a=https://ex.com/vmc.pem")
    assert b["logo_url"].endswith("logo.svg") and b["vmc_url"].endswith("vmc.pem")


# --- posture / spoofability ----------------------------------------------

def test_posture_no_records_is_spoofable():
    p = assess_email_posture(None, None, False, None, False)
    assert p["grade"] == "none" and p["spoofable"] is True
    assert any("no DMARC" in r for r in p["reasons"])


def test_posture_reject_hardline_is_strong_not_spoofable():
    spf = parse_spf("v=spf1 include:_spf.google.com -all")
    dmarc = parse_dmarc("v=DMARC1; p=reject")
    p = assess_email_posture(spf, dmarc, True, "enforce", True)
    assert p["grade"] == "strong" and p["spoofable"] is False


def test_posture_p_none_is_spoofable_weak():
    spf = parse_spf("v=spf1 ~all")
    dmarc = parse_dmarc("v=DMARC1; p=none")
    p = assess_email_posture(spf, dmarc, False, None, False)
    assert p["spoofable"] is True and p["grade"] == "weak"


def test_posture_quarantine_is_moderate_not_spoofable():
    dmarc = parse_dmarc("v=DMARC1; p=quarantine")
    p = assess_email_posture(parse_spf("v=spf1 -all"), dmarc, True, None, False)
    assert p["grade"] == "moderate" and p["spoofable"] is False
