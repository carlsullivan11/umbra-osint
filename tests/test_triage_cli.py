"""`umbra triage` — bring your own key, exit codes, nothing private printed or sent."""
from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from jev_fake import FakeJev, choice
from umbra.cli.main import app
from test_triage_alert import ECS_OUTBOUND, PRIVATE_BITS

runner = CliRunner()
IP = "185.231.154.75"
KEY_VARS = ("UMBRA_OPENROUTER_API_KEY", "UMBRA_TYPESAFE_API_KEY", "UMBRA_JEV_PROVIDER",
            "UMBRA_JEV_ENABLED")


@pytest.fixture
def env(tmp_path, monkeypatch):
    for k in KEY_VARS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def use_fake(monkeypatch, tmp_path, fake):
    monkeypatch.setenv("UMBRA_OPENROUTER_API_KEY", "sk-or-v1-test")
    monkeypatch.setattr("umbra.cli.triage_cmd._client", lambda s: fake.client(tmp_path))


def enriched_as(monkeypatch, props):
    monkeypatch.setattr("umbra.cli.triage_cmd.enrich",
                        lambda alerts, repo, **kw: ("c_test", {("ip", IP): props}))


def run(*args):
    return runner.invoke(app, ["triage", *args], env={"COLUMNS": "200"})


def test_without_a_key_it_runs_deterministically_and_says_how_to_bring_one(env):
    out = run(IP, "--no-collect")
    assert out.exit_code == 0
    assert "NEEDS ANALYST" in out.stdout
    assert "bring your own key" in out.stdout
    assert "UMBRA_OPENROUTER_API_KEY" in out.stdout


def test_the_key_alone_is_the_opt_in(env, monkeypatch):
    fake = FakeJev(noul_rules={"malware_or_c2": [("", 0.8)]})
    use_fake(monkeypatch, env, fake)
    out = run(IP, "--no-collect", "--json")
    assert out.exit_code == 0, out.stdout
    data = json.loads(out.stdout)
    assert data["jev"]["used"] and fake.calls
    assert data["disposition"] == "escalate"


def test_exit_codes(env, monkeypatch):
    benign = FakeJev(role_rules=[("", choice("clean", {"clean": 0.95}, 0.95))],
                     noul_rules={"malware_or_c2": [("", 0.03)]})
    use_fake(monkeypatch, env, benign)
    enriched_as(monkeypatch, {"reputation_verdict": "clean", "as_name": "GOOGLE, US"})
    assert run(IP, "--exit-code").exit_code == 0          # suggest close
    assert run(IP, "--exit-code", "--asset", "critical").exit_code == 10
    enriched_as(monkeypatch, {"reputation_verdict": "malicious", "reputation_sources": ["feodo"]})
    assert run(IP, "--exit-code").exit_code == 20


def test_suggest_close_is_worded_as_a_suggestion(env, monkeypatch):
    use_fake(monkeypatch, env, FakeJev(role_rules=[("", choice("clean", {"clean": 0.95}, 0.95))],
                                       noul_rules={"malware_or_c2": [("", 0.03)]}))
    enriched_as(monkeypatch, {"reputation_verdict": "clean"})
    out = run(IP)
    assert "SUGGEST CLOSE" in out.stdout
    assert "never closes an alert" in out.stdout


def test_an_alert_file_never_prints_or_sends_private_fields(env, monkeypatch):
    fake = FakeJev()
    use_fake(monkeypatch, env, fake)
    (env / "alert.json").write_text(json.dumps(ECS_OUTBOUND))
    out = run("alert.json", "--no-collect", "--json")
    sent = json.dumps([c["body"] for c in fake.calls])
    for bit in PRIVATE_BITS:
        assert bit not in out.stdout and bit not in sent
    assert "host.name" in out.stdout  # listed as kept local, by field name only


def test_dry_run_prints_the_state_and_asks_nothing(env, monkeypatch):
    fake = FakeJev()
    use_fake(monkeypatch, env, fake)
    out = run(IP, "--no-collect", "--dry-run")
    assert out.exit_code == 0
    assert "Facts established by Umbra" in out.stdout
    assert not fake.calls


def test_stdin_and_nothing_external(env):
    out = runner.invoke(app, ["triage", "-", "--no-collect"], input="10.0.0.1\n")
    assert out.exit_code == 2
    assert "Nothing external" in out.stdout


def test_bad_options_are_rejected(env):
    assert run(IP, "--asset", "mainframe").exit_code != 0
    assert run(IP, "--basis", "because").exit_code != 0


def test_an_unsynced_local_lake_is_called_out(env, monkeypatch):
    use_fake(monkeypatch, env, FakeJev())
    enriched_as(monkeypatch, {"reputation_verdict": "clean"})
    out = run(IP)
    assert "umbra abuse sync" in out.stdout
