"""`umbra faa` — status / lookup / import-zip.

`sync` is not exercised against the network here (no live egress in the unit
suite); the parts that can be wrong offline are what these cover.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.main import app

from faa_fixtures import _acftref_row, _master_row, build_zip

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("UMBRA_FAA_DB", str(tmp_path / "lake" / "faa.sqlite"))
    monkeypatch.delenv("UMBRA_DATABASE_URL", raising=False)
    return tmp_path


@pytest.fixture
def zip_path(tmp_path: Path) -> Path:
    return build_zip(
        tmp_path / "ReleasableAircraft.zip",
        [_master_row(n_number="737KL", name="ACME AVIATION LLC",
                     mfr_code="0020901", type_reg="7")],
        [_acftref_row(code="0020901", mfr="AAR AIRLIFT GROUP INC", model="UH-60A")],
    )


def test_status_on_an_empty_lake_says_how_to_fill_it(env):
    out = runner.invoke(app, ["faa", "status"])
    assert out.exit_code == 0
    assert "umbra faa sync" in out.stdout


def test_import_zip_then_status_reports_rows(env, zip_path):
    assert runner.invoke(app, ["faa", "import-zip", str(zip_path)]).exit_code == 0
    out = runner.invoke(app, ["faa", "status"])
    assert "1" in out.stdout
    assert "umbra faa sync" not in out.stdout


def test_lookup_finds_the_registrant(env, zip_path):
    runner.invoke(app, ["faa", "import-zip", str(zip_path)])
    out = runner.invoke(app, ["faa", "lookup", "N737KL"])
    assert out.exit_code == 0
    assert "ACME AVIATION LLC" in out.stdout


def test_lookup_warns_that_registrant_is_not_operator(env, zip_path):
    runner.invoke(app, ["faa", "import-zip", str(zip_path)])
    out = runner.invoke(app, ["faa", "lookup", "N737KL"])
    assert "not necessarily the operator" in out.stdout


def test_a_miss_never_claims_the_aircraft_is_unregistered(env, zip_path):
    runner.invoke(app, ["faa", "import-zip", str(zip_path)])
    out = runner.invoke(app, ["faa", "lookup", "N99999"])
    assert out.exit_code == 1
    assert "44114" in out.stdout
    assert "unchecked" in out.stdout


def test_lookup_before_any_sync_tells_you_to_sync(env):
    out = runner.invoke(app, ["faa", "lookup", "N737KL"])
    assert out.exit_code == 2
    assert "umbra faa sync" in out.stdout


def test_importing_something_that_is_not_the_archive_fails_loudly(env, tmp_path):
    import zipfile

    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(bad, "w") as z:
        z.writestr("index.html", "<html>Access Denied</html>")
    out = runner.invoke(app, ["faa", "import-zip", str(bad)])
    assert out.exit_code != 0
