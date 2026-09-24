"""`umbra analytics collectors` / `umbra analytics lakes`.

Both live in the open core: the numbers are about how Umbra behaves, so a pip
user auditing the tool should be able to ask the same questions the hosted
operator can. The private web dashboard renders these same functions.

What the output has to keep saying, because it is the whole point of the
feature: where the time went, and what the numbers are drawn from.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umbra.cli.main import app
from umbra.core.config import Settings
from umbra.core.models import utcnow
from umbra.db.repository import Repository
from umbra.db.schema import LakeSnapshot, get_session, init_db

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("UMBRA_DATABASE_URL", raising=False)
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    return settings


def _run_with(seconds, notes=None):
    repo = Repository(get_session(), Path("/tmp"))
    case = repo.create_case("acme", "own_asset")
    run = repo.create_run(case.id, depth=1, max_entities=5,
                          collectors=list(seconds))
    run.finished_at = utcnow()
    stats = dict(run.stats or {})
    stats["collector_seconds"] = seconds
    stats["notes"] = notes or []
    run.stats = stats
    repo.session.commit()
    repo.session.close()


# --- collectors ------------------------------------------------------------

def test_the_scorecard_names_the_slow_collector(env):
    _run_with({"rdap_ip": 6.5, "ip_geo": 0.1})
    out = runner.invoke(app, ["analytics", "collectors"])
    assert out.exit_code == 0
    assert "rdap_ip" in out.stdout


def test_the_scorecard_states_what_it_measured(env):
    _run_with({"rdap_ip": 6.5})
    out = runner.invoke(app, ["analytics", "collectors"])
    assert "run" in out.stdout.lower()


def test_the_scorecard_on_a_fresh_install_explains_itself(env):
    """No runs yet is normal. It must not print an empty table."""
    out = runner.invoke(app, ["analytics", "collectors"])
    assert out.exit_code == 0
    assert "no runs" in out.stdout.lower()


def test_the_scorecard_speaks_json(env):
    _run_with({"rdap_ip": 6.5})
    out = runner.invoke(app, ["analytics", "collectors", "--json"])
    assert out.exit_code == 0
    import json

    payload = json.loads(out.stdout)
    assert payload["rows"][0]["collector"] == "rdap_ip"
    assert "runs_with_timing" in payload


def test_the_json_does_not_offer_a_per_call_average(env):
    """The orchestrator never measured one — see umbra.analytics.collectors."""
    _run_with({"rdap_ip": 6.5})
    import json

    payload = json.loads(runner.invoke(app, ["analytics", "collectors", "--json"]).stdout)
    assert "mean_seconds_per_run" in payload["rows"][0]
    assert not any("per_call" in k for k in payload["rows"][0])


# --- lakes -----------------------------------------------------------------

def test_lake_health_with_no_snapshots_says_how_to_get_some(env):
    out = runner.invoke(app, ["analytics", "lakes"])
    assert out.exit_code == 0
    assert "--record" in out.stdout


def test_recording_writes_a_snapshot(env):
    out = runner.invoke(app, ["analytics", "lakes", "--record"])
    assert out.exit_code == 0
    session = get_session()
    try:
        assert session.query(LakeSnapshot).count() >= 1
    finally:
        session.close()


def test_a_shrinking_lake_is_surfaced(env):
    session = get_session()
    for i, rows in ((2, 9000), (0, 45)):
        session.add(LakeSnapshot(id=f"t{i}", ts=utcnow() - timedelta(days=i),
                                 lake="tor", rows=rows, synced_at=utcnow()))
    session.commit()
    session.close()
    out = runner.invoke(app, ["analytics", "lakes"])
    assert "tor" in out.stdout
    assert "shrank" in out.stdout.lower()


def test_lake_health_speaks_json(env):
    runner.invoke(app, ["analytics", "lakes", "--record"])
    import json

    out = runner.invoke(app, ["analytics", "lakes", "--json"])
    payload = json.loads(out.stdout)
    assert isinstance(payload["rows"], list)
    assert "note" in payload


def test_recording_is_not_implied_by_a_plain_read(env):
    """`umbra analytics lakes` must not silently mutate the series — a report
    that writes every time it is read makes its own history."""
    runner.invoke(app, ["analytics", "lakes"])
    session = get_session()
    try:
        assert session.query(LakeSnapshot).count() == 0
    finally:
        session.close()
