"""`umbra people find NAME --json` must print `UnifiedResult.as_dict()` and
skip the rich tables entirely. Table output must stay unchanged without
`--json`.

Issue: carlsullivan11/umbra#30.

Fixture only: an FEC contributor lake seeded with one row is enough to
populate `unified_search`'s `contributors` group without any live download.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.main import app
from umbra.lake.fec import FecLake

FEC_ROW = (
    "C00878454|N|12P|P2024|20240829967531|15E|IND|JENNINGS, EMILY|"
    "SOMERVILLE|MA|021432389|SKADDEN ARPS|ATTORNEY|08052024|250|"
    "C00401224|4187316|1813451|||4083020242017155126"
)


@pytest.fixture
def fec_lake(tmp_path: Path, monkeypatch) -> Path:
    fec_path = tmp_path / "fec.sqlite"
    monkeypatch.setenv("UMBRA_FEC_DB", str(fec_path))
    z = tmp_path / "indiv.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("itcont.txt", FEC_ROW + "\n")
    lake = FecLake(fec_path)
    lake.import_zip(z)
    lake.close()
    return fec_path


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("UMBRA_DATA_DIR", str(d))
    return d


def test_json_prints_as_dict_and_skips_tables(fec_lake, data_dir):
    result = CliRunner().invoke(app, ["people", "find", "Emily Jennings", "--json"])
    assert result.exit_code == 0, result.output

    payload = json.loads(result.output)
    assert payload["query"] == "Emily Jennings"
    assert payload["contributors"]
    assert payload["contributors"][0]["name_raw"] == "JENNINGS, EMILY"

    assert "FEC contributors" not in result.output
    assert "people lake" not in result.output


def test_table_output_unchanged_without_json(fec_lake, data_dir):
    result = CliRunner().invoke(app, ["people", "find", "Emily Jennings"])
    assert result.exit_code == 0, result.output

    assert "FEC contributors" in result.output
    assert "JENNINGS, EMILY" in result.output
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.output)
