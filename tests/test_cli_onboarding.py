"""Stage S8 — `umbra init` and `umbra doctor`.

The onboarding path a new user hits before reading any docs. Two properties
matter most: `init` must be safe to re-run, and the ethics acknowledgement must
be a real, recorded decision rather than a banner nobody reads.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from umbra.cli.onboarding import (
    DoctorCheck,
    ETHICS_ACK_FILE,
    doctor_checks,
    ethics_ack_path,
    initialize,
    read_ack,
    write_ack,
)
from umbra.core.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data")


# --- init -----------------------------------------------------------------

def test_init_creates_the_data_layout(settings):
    result = initialize(settings, accept_ethics=True)
    for sub in ("raw", "exports", "cache"):
        assert (settings.data_dir / sub).is_dir(), f"missing {sub}/"
    assert result["data_dir"] == str(settings.data_dir)


def test_init_is_idempotent(settings):
    """Re-running must never clobber an existing install."""
    first = initialize(settings, accept_ethics=True)
    (settings.data_dir / "raw" / "keepme.txt").write_text("important")

    second = initialize(settings, accept_ethics=True)
    assert (settings.data_dir / "raw" / "keepme.txt").read_text() == "important"
    assert second["data_dir"] == first["data_dir"]
    assert second["created"] == [], "second run should create nothing new"


def test_init_records_the_ethics_acknowledgement(settings):
    """An acknowledgement nobody can point to later is not an acknowledgement.
    It is written to disk with a timestamp and the version acknowledged."""
    initialize(settings, accept_ethics=True)
    ack = read_ack(settings)
    assert ack is not None
    assert ack["accepted"] is True
    assert ack["acknowledged_at"], "must record when"
    assert "authorized" in ack["statement"].lower()


def test_init_without_acceptance_does_not_fabricate_consent(settings):
    """Declining must leave no acceptance record — the tool must not claim the
    operator agreed to something they did not."""
    initialize(settings, accept_ethics=False)
    ack = read_ack(settings)
    assert ack is None or ack.get("accepted") is not True


def test_ack_file_lives_in_the_data_dir(settings):
    assert ethics_ack_path(settings) == settings.data_dir / ETHICS_ACK_FILE


def test_write_ack_is_readable_json(settings):
    settings.ensure_dirs()
    write_ack(settings)
    raw = ethics_ack_path(settings).read_text(encoding="utf-8")
    assert json.loads(raw)["accepted"] is True


# --- doctor ---------------------------------------------------------------

def test_doctor_returns_structured_checks(settings):
    checks = doctor_checks(settings)
    assert checks and all(isinstance(c, DoctorCheck) for c in checks)
    names = {c.name for c in checks}
    for expected in ("python", "data directory", "database", "wiki corpus",
                     "dns resolver", "ethics acknowledgement"):
        assert expected in names, f"doctor should check {expected}"


def test_doctor_flags_missing_ethics_ack(settings):
    settings.ensure_dirs()
    ack = next(c for c in doctor_checks(settings) if c.name == "ethics acknowledgement")
    assert ack.ok is False
    assert "umbra init" in ack.detail, "must tell the user how to fix it"


def test_doctor_passes_ethics_after_init(settings):
    initialize(settings, accept_ethics=True)
    ack = next(c for c in doctor_checks(settings) if c.name == "ethics acknowledgement")
    assert ack.ok is True


def test_doctor_warns_when_dnsbl_resolver_is_public(settings, monkeypatch):
    """DNSBL through a public resolver silently marks every address listed —
    doctor must catch that misconfiguration, since it fails loudly nowhere else."""
    import umbra.cli.onboarding as ob

    monkeypatch.setattr(ob, "_resolver_nameservers", lambda: ["1.1.1.1"])
    dns = next(c for c in doctor_checks(settings) if c.name == "dns resolver")
    assert dns.ok is False
    assert "public" in dns.detail.lower()


def test_doctor_ok_with_local_resolver(settings, monkeypatch):
    import umbra.cli.onboarding as ob

    monkeypatch.setattr(ob, "_resolver_nameservers", lambda: ["127.0.0.1"])
    dns = next(c for c in doctor_checks(settings) if c.name == "dns resolver")
    assert dns.ok is True


def test_doctor_never_raises_on_a_broken_install(tmp_path):
    """doctor is what you run when things are broken; it must report, not crash."""
    s = Settings(data_dir=tmp_path / "does-not-exist")
    checks = doctor_checks(s)
    assert checks
    assert any(c.ok is False for c in checks)


def test_doctor_reports_wiki_corpus_absence_as_optional(settings):
    """No wiki corpus is a normal state, not a failure — it must not read as
    'your install is broken'."""
    settings.ensure_dirs()
    wiki = next(c for c in doctor_checks(settings) if c.name == "wiki corpus")
    assert wiki.optional is True


# --- CLI registration -----------------------------------------------------

def test_commands_are_registered():
    from umbra.cli.main import app

    names = {c.name for c in app.registered_commands}
    assert "init" in names and "doctor" in names


def test_first_run_reports_what_it_created(tmp_path):
    """A brand-new install must say what it created. get_settings() calls
    ensure_dirs() as a side effect, so using it here made the very first run
    misreport 'already present'."""
    s = Settings(data_dir=tmp_path / "fresh")
    assert not s.data_dir.exists()
    result = initialize(s, accept_ethics=True)
    assert result["created"], "first run must report created directories"
    assert any("fresh" in c for c in result["created"])
