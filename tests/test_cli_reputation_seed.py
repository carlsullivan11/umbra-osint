"""`umbra reputation-seed` — a command that had never once been run.

It was wired into the app and asserted to exist, and that was the whole of its
coverage. `get_session` had been dropped from its imports at some point and the
call left behind under a `# type: ignore[name-defined]`, so every invocation
raised `NameError` on line 42. A wiring test proves a command is reachable; it
proves nothing about whether it works.

So these tests actually run it.
"""
from __future__ import annotations

import warnings

import pytest
from typer.testing import CliRunner

warnings.filterwarnings("ignore")

from umbra.cli.main import app  # noqa: E402

runner = CliRunner()


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Isolate the database, and keep the collectors offline.

    `ip_reputation` does DNSBL lookups. A unit test for a CLI command must not
    depend on a resolver being reachable — and per AGENTS.md the DNSBL path must
    never fall back to a public resolver, so a test that quietly went to the
    network would be testing the wrong thing anyway.
    """
    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.chdir(tmp_path)

    from umbra.core.orchestrator import Orchestrator

    monkeypatch.setattr(
        Orchestrator, "run",
        lambda self, case_id, **kw: {"collectors": kw.get("collectors"),
                                     "entities": 0, "offline_stub": True})
    return tmp_path


def write(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(body)
    return str(path)


def run(*args):
    return runner.invoke(app, list(args), env={"COLUMNS": "200"})


def test_it_runs_at_all(workdir):
    """The regression. `get_session` was undefined and this raised NameError."""
    path = write(workdir, "ips.txt", "185.199.108.153\n198.51.100.30\n")
    result = run("reputation-seed", "--file", path, "--type", "ip",
                 "--basis", "own_asset")
    assert result.exit_code == 0, result.stdout + str(result.exception)


def test_it_creates_a_case(workdir):
    path = write(workdir, "ips.txt", "185.199.108.153\n")
    result = run("reputation-seed", "--file", path, "--type", "ip")
    assert "Created case" in result.stdout


def test_comments_and_blank_lines_are_skipped(workdir):
    path = write(workdir, "ips.txt",
                 "# a comment\n\n185.199.108.153\n\n# another\n")
    result = run("reputation-seed", "--file", path, "--type", "ip")
    assert result.exit_code == 0
    assert "1 assets" in result.stdout


def test_an_empty_file_is_refused_clearly(workdir):
    path = write(workdir, "empty.txt", "# nothing but comments\n")
    result = run("reputation-seed", "--file", path, "--type", "ip")
    assert result.exit_code == 1
    assert "No assets" in result.stdout


def test_domains_work_too(workdir):
    path = write(workdir, "domains.txt", "example.com\n")
    result = run("reputation-seed", "--file", path, "--type", "domain")
    assert result.exit_code == 0


def test_a_missing_file_is_a_clean_error(workdir):
    result = run("reputation-seed", "--file", "nope.txt", "--type", "ip")
    assert result.exit_code != 0


def test_unparseable_lines_are_reported_not_swallowed(workdir):
    """It used to `except Exception: pass` around every seed, so a file of junk
    reported a happy "Created case with 3 assets" having stored none of them."""
    path = write(workdir, "ips.txt",
                 "185.199.108.153\nnot-an-ip-at-all\n999.999.999.999\n")
    result = run("reputation-seed", "--file", path, "--type", "ip")
    assert result.exit_code == 0
    assert "skipped" in result.stdout.lower()


def test_the_valid_entries_still_seed_when_others_fail(workdir):
    path = write(workdir, "ips.txt", "nonsense\n185.199.108.153\n")
    result = run("reputation-seed", "--file", path, "--type", "ip")
    assert result.exit_code == 0
    assert "Created case" in result.stdout


def test_the_basis_has_a_long_form(workdir):
    """`-b` was the only spelling, so `--basis` — what every other command in
    this CLI accepts — was a usage error."""
    path = write(workdir, "ips.txt", "185.199.108.153\n")
    assert run("reputation-seed", "--file", path, "--type", "ip",
               "--basis", "client_engagement").exit_code == 0


def test_a_bogus_basis_is_refused(workdir):
    """The basis is the ethics gate for the whole case (AGENTS.md #1). It was
    taken verbatim, so a typo became the recorded justification."""
    path = write(workdir, "ips.txt", "185.199.108.153\n")
    assert run("reputation-seed", "--file", path, "--type", "ip",
               "--basis", "whatever").exit_code != 0


def test_a_bogus_type_is_refused(workdir):
    """`--type ipv4` silently meant "domain", because anything that was not
    exactly "ip" fell through to the domain branch."""
    path = write(workdir, "ips.txt", "185.199.108.153\n")
    assert run("reputation-seed", "--file", path, "--type", "ipv4").exit_code != 0


def test_junk_never_reaches_the_graph_as_an_ip(workdir):
    """`normalize_value` does not validate IPs, so without a check here the
    string went into the graph and collectors were sent to resolve it."""
    path = write(workdir, "ips.txt", "not-an-ip-at-all\n999.999.999.999\n")
    result = run("reputation-seed", "--file", path, "--type", "ip")
    assert "with 0 of 2 assets" in result.stdout
