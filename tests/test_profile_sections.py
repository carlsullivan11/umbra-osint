"""Profile-export sections for the signals surfaced in P2:
reputation verdicts and email-authentication posture.

These are the "so what" of the reputation and dns_email_auth collectors —
if a domain is spoofable or an IP is malicious, the profile is where an
operator actually sees it.
"""
from __future__ import annotations

from pathlib import Path

from umbra.core.config import Settings
from umbra.core.models import EntityIn, EntityType
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.export.profile import render_profile_markdown


def _case_with(tmp_path: Path, entities: list[EntityIn]):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)
    case = repo.create_case("profile-sections", "training_lab", "t")
    for ent in entities:
        repo.seed(case.id, ent)
    session.commit()
    return repo, case.id


# --- email authentication posture ----------------------------------------

def test_spoofable_domain_is_flagged_red_with_remediation(tmp_path: Path):
    repo, case_id = _case_with(tmp_path, [
        EntityIn(type=EntityType.DOMAIN, value="spoofme.example", confidence=0.9, props={
            "email_posture_grade": "none",
            "spoofable": True,
            "dmarc_policy": None,
            "spf_parsed": None,
            "dkim_selectors": [],
            "email_posture_reasons": ["no SPF record", "no DMARC record — domain is spoofable"],
        }),
    ])
    md = render_profile_markdown(repo, case_id)
    assert "## Email authentication posture" in md
    assert "**1** spoofable" in md
    assert "🔴" in md
    assert "spoofme.example" in md
    # remediation guidance must appear when something is spoofable
    assert "p=quarantine" in md and "p=reject" in md


def test_protected_domain_is_green_and_no_remediation_block(tmp_path: Path):
    repo, case_id = _case_with(tmp_path, [
        EntityIn(type=EntityType.DOMAIN, value="locked.example", confidence=0.9, props={
            "email_posture_grade": "strong",
            "spoofable": False,
            "dmarc_policy": "reject",
            "spf_parsed": {"all": "-"},
            "dkim_selectors": ["s1", "s2"],
            "mta_sts": {"mode": "enforce"},
            "bimi": {"logo_url": "x"},
            "dnssec": True,
            "email_posture_reasons": ["DMARC p=reject (strongest)"],
        }),
    ])
    md = render_profile_markdown(repo, case_id)
    assert "**0** spoofable" in md
    assert "🟢" in md
    assert "MTA-STS=enforce" in md and "BIMI" in md and "DNSSEC" in md
    assert "Fix: publish SPF" not in md  # no remediation block when nothing is spoofable


def test_spoofable_sorts_before_protected(tmp_path: Path):
    repo, case_id = _case_with(tmp_path, [
        EntityIn(type=EntityType.DOMAIN, value="safe.example", confidence=0.9, props={
            "email_posture_grade": "strong", "spoofable": False,
            "dmarc_policy": "reject", "dkim_selectors": ["s1"],
        }),
        EntityIn(type=EntityType.DOMAIN, value="risky.example", confidence=0.9, props={
            "email_posture_grade": "none", "spoofable": True,
            "dmarc_policy": None, "dkim_selectors": [],
        }),
    ])
    md = render_profile_markdown(repo, case_id)
    section = md.split("## Email authentication posture", 1)[1]
    assert section.index("risky.example") < section.index("safe.example")


def test_no_section_when_no_email_data(tmp_path: Path):
    repo, case_id = _case_with(tmp_path, [
        EntityIn(type=EntityType.DOMAIN, value="plain.example", confidence=0.9),
    ])
    assert "## Email authentication posture" not in render_profile_markdown(repo, case_id)


# --- reputation verdicts --------------------------------------------------

def test_malicious_sorts_before_suspicious_and_clean_is_omitted(tmp_path: Path):
    repo, case_id = _case_with(tmp_path, [
        EntityIn(type=EntityType.IP, value="9.9.9.9", confidence=0.9, props={
            "reputation_verdict": "suspicious", "reputation_score": 60,
            "reputation_sources": ["tor_exit"],
        }),
        EntityIn(type=EntityType.IP, value="8.8.8.8", confidence=0.9, props={
            "reputation_verdict": "malicious", "reputation_score": 95,
            "reputation_sources": ["feodo_tracker"],
        }),
        EntityIn(type=EntityType.IP, value="1.1.1.1", confidence=0.9, props={
            "reputation_verdict": "clean", "reputation_score": 0, "reputation_sources": [],
        }),
    ])
    md = render_profile_markdown(repo, case_id)
    assert "## Reputation flags" in md
    section = md.split("## Reputation flags", 1)[1]
    assert section.index("8.8.8.8") < section.index("9.9.9.9")  # malicious first
    # a clean entity must not be listed as a flag
    flags_block = section.split("_Verdicts aggregate", 1)[0]
    assert "1.1.1.1" not in flags_block


# --- C5: unchecked is not clean, and ransomware exposure is called out ------

def _case_from_props(tmp_path: Path, entities):
    """Build a case from (type, value, props) tuples.

    Separate from `_case_with` above, which takes EntityIn objects — shadowing
    it broke every earlier test in this file.
    """
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    repo = Repository(get_session(), settings.raw_dir)
    case = repo.create_case("profile c5", "other")
    for etype, value, props in entities:
        repo.seed(case.id, EntityIn(type=EntityType(etype), value=value,
                                    confidence=0.9, props=props))
    return repo, case.id


def test_reputation_lookup_errors_are_reported_not_omitted(tmp_path: Path):
    """The section only listed malicious/suspicious entities, so an address the
    lookup could not check simply vanished from the profile — reading as though
    it had been checked and found fine. That is the DNSBL failure mode in an
    audit artifact (docs/DNS-SERVICE.md)."""
    repo, case_id = _case_from_props(tmp_path, [
        ("ip", "203.0.113.5", {"reputation_verdict": "error", "reputation_score": 0,
                               "reputation_sources": [], "reputation_checked": 0}),
    ])
    md = render_profile_markdown(repo, case_id)
    assert "could not be checked" in md.lower() or "not checked" in md.lower()
    assert "203.0.113.5" in md


def test_a_clean_entity_does_not_produce_an_error_note(tmp_path: Path):
    repo, case_id = _case_from_props(tmp_path, [
        ("ip", "203.0.113.6", {"reputation_verdict": "clean", "reputation_score": 0,
                               "reputation_sources": [], "reputation_checked": 4}),
    ])
    md = render_profile_markdown(repo, case_id).lower()
    assert "could not be checked" not in md


def test_ransomware_exposure_gets_its_own_section(tmp_path: Path):
    """A leak-site hit is the single most actionable thing a profile can carry;
    it must not be buried in the evidence list."""
    repo, case_id = _case_from_props(tmp_path, [
        ("domain", "victim.example", {"kind": "ransomware_leak", "group": "examplegang",
                                      "source": "ransomware.live", "published": "2026-08-01"}),
    ])
    md = render_profile_markdown(repo, case_id)
    assert "Ransomware" in md
    assert "examplegang" in md
