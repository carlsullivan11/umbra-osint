"""One source of truth for "what is in each lake right now".

`umbra doctor` and the lake-health analytics both need the same six readings.
Two independent readers is how they start disagreeing — and a monitor that
disagrees with the diagnostic is worse than no monitor, because the operator
now has to work out which one is lying.

So `lake_inventory()` produces structured readings and `doctor` renders them.
The invariant worth protecting is the one about absence: a lake that could not
be read reports an error, never a row count of zero.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.core.config import Settings
from umbra.lake.inventory import lake_inventory


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = Settings(data_dir=tmp_path)
    s.ensure_dirs()
    return s


def test_every_known_lake_is_reported(settings):
    names = {r.lake for r in lake_inventory(settings)}
    assert {"abuse.ch", "certificate transparency", "geoip", "epss",
            "public suffix", "people"} <= names


def test_a_fresh_install_reports_lakes_rather_than_raising(settings):
    """Nothing is synced yet. That is a normal state, not a crash."""
    readings = lake_inventory(settings)
    assert readings


def test_an_unreadable_lake_reports_an_error_not_zero_rows(monkeypatch, settings):
    """Zero rows is a measurement; "could not look" is not. Recording the
    second as the first makes an unreadable lake indistinguishable from one
    that lost everything."""
    import umbra.lake.inventory as inv

    def boom(*_a, **_k):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(inv, "_geoip_reading", boom)
    row = {r.lake: r for r in lake_inventory(settings)}["geoip"]
    assert row.error is not None
    assert row.rows is None
    assert row.readable is False


def test_one_broken_lake_does_not_hide_the_others(monkeypatch, settings):
    import umbra.lake.inventory as inv

    monkeypatch.setattr(inv, "_geoip_reading",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("x")))
    names = {r.lake for r in lake_inventory(settings)}
    assert "epss" in names and "people" in names


def test_readings_carry_a_sync_time_field_even_when_unknown(settings):
    for r in lake_inventory(settings):
        assert hasattr(r, "synced_at")


# --- doctor keeps rendering from the same readings -------------------------

def test_doctor_still_reports_every_lake(settings):
    from umbra.cli.onboarding import lake_checks

    names = {c.name for c in lake_checks(settings)}
    assert {"abuse.ch lake", "geoip lake", "epss lake",
            "public suffix lake", "people lake"} <= names


def test_doctor_marks_lake_checks_optional(settings):
    """Umbra runs without any lake; a cold one must not read as a broken install."""
    from umbra.cli.onboarding import lake_checks

    assert all(c.optional for c in lake_checks(settings))


def test_an_unreadable_lake_says_unreadable_in_doctor(monkeypatch, settings):
    from umbra.cli.onboarding import lake_checks
    import umbra.lake.inventory as inv

    monkeypatch.setattr(inv, "_epss_reading",
                        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("locked")))
    row = {c.name: c for c in lake_checks(settings)}["epss lake"]
    assert "unreadable" in row.detail
    assert row.ok is False
