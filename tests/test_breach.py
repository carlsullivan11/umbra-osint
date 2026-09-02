from __future__ import annotations

from umbra.collectors.hibp_breach import remediation_for_data_classes, severity_for_breach
from umbra.cli.breach import check_password_pwned, format_password_advice


def test_remediation_includes_password_steps():
    steps = remediation_for_data_classes(["Passwords", "Email addresses"])
    assert any("password" in s.lower() for s in steps)
    assert any("phish" in s.lower() for s in steps)


def test_severity_high_for_passwords():
    assert severity_for_breach({"DataClasses": ["Passwords"]}) == "high"
    assert severity_for_breach({"DataClasses": ["Email addresses"]}) == "medium"
    assert severity_for_breach({"DataClasses": ["Names"]}) == "low"


def test_password_advice_exposed():
    tips = format_password_advice(True, 1000)
    assert any("1000" in t or "1,000" in t for t in tips)


def test_password_pwned_known_bad():
    # "password" is famously pwned; uses live HIBP range API
    result = check_password_pwned("password", "Umbra-Test/0.1")
    assert result["pwned"] is True
    assert result["count"] > 0
    assert len(result["prefix"]) == 5
