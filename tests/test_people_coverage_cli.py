"""`umbra people coverage` prints lake emptiness/import status.

Same rollup as `/people/coverage`, reusing `lake_coverage.py`: a lake with
no rows must read "not imported", never an identity claim about the person
being searched. Fixture only — every lake is a fresh SQLite file under a
temp `UMBRA_DATA_DIR`; no live download, no network call.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.main import app
from umbra.lake.fec import FecLake

runner = CliRunner()


@pytest.fixture()
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    return tmp_path


class TestAllEmpty:
    def test_text_output_says_not_imported(self, isolated_data_dir):
        result = runner.invoke(app, ["people", "coverage"])
        assert result.exit_code == 0, result.output
        assert "not imported" in result.output
        assert "not a clinician" not in result.output
        assert "not an officer" not in result.output
        assert "not a licensee" not in result.output
        for name in ("people", "FEC", "parcels", "NPPES", "IRS 990", "ULS"):
            assert name in result.output

    def test_json_output_includes_lakes(self, isolated_data_dir):
        result = runner.invoke(app, ["people", "coverage", "--json"])
        assert result.exit_code == 0, result.output
        import json

        body = json.loads(result.output)
        names = {lk["name"] for lk in body["lakes"]}
        assert names == {"people", "FEC", "parcels", "NPPES", "IRS 990", "ULS", "inmate_facts"}
        for lk in body["lakes"]:
            assert lk["count"] == 0
            assert lk["available"] is False
            assert lk["note"] == "not imported"


class TestSeededLake:
    def test_row_count_and_import_time_shown(self, isolated_data_dir):
        fec = FecLake()
        fec._conn.execute(
            "INSERT INTO contributor(key, name_raw, name_canonical, city, state, "
            "zip5, contributions, total_amount) VALUES "
            "('k1','JENNINGS, EMILY','emily jennings','SOMERVILLE','MA','02143',1,100)"
        )
        fec._conn.execute(
            "INSERT INTO imported(crc, filename, rows, imported_at) VALUES "
            "('c1','indiv24.zip',1,'2026-01-01T00:00:00+00:00')"
        )
        fec._conn.commit()
        fec.close()

        result = runner.invoke(app, ["people", "coverage"])
        assert result.exit_code == 0, result.output
        assert "FEC" in result.output
        assert "1" in result.output
        assert "2026-01-01T00:00:00+00:00" in result.output
