"""`umbra example.email` and friends.

Carl asked for the bare form specifically — a path where a subcommand normally
goes. That is a Click group that checks, when a word is not a command, whether
it is a file on disk. The risk of doing that is shadowing: a file called
`doctor` in the working directory must not take over `umbra doctor`, and an
unknown word that is not a file must still produce Click's ordinary error
rather than a confusing one about a missing path. Both are tested below.

The rest is the same contract the confirm page has: reading a file runs
nothing. `--confirm` is the terminal's version of ticking the boxes.
"""
from __future__ import annotations

import json
import shutil
import warnings
from pathlib import Path

import pytest
from typer.testing import CliRunner

warnings.filterwarnings("ignore")

from umbra.cli.main import app  # noqa: E402

FIXTURES = Path(__file__).parent / "email" / "fixtures"
runner = CliRunner()


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    shutil.copy(FIXTURES / "m365_spoofed.eml", tmp_path / "example.email")
    shutil.copy(FIXTURES / "postfix_forged_chain.eml", tmp_path / "forged.eml")
    (tmp_path / "iocs.txt").write_text(
        "185.199.108.153\nevil-domain.example\nphish@evil-domain.example\n")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def run(*args):
    return runner.invoke(app, list(args), env={"COLUMNS": "200"})


def text(result) -> str:
    """stdout plus stderr — Click 8.2 keeps them apart, and usage errors go to
    stderr while the reports go to stdout."""
    try:
        err = result.stderr
    except ValueError:  # not captured separately on this Click version
        err = ""
    return (result.stdout or "") + (err or "")


# --- the command Carl asked for -------------------------------------------

def test_a_bare_path_is_read(workdir):
    result = run("example.email")
    assert result.exit_code == 0
    assert "yourbank.example" in result.stdout


def test_a_bare_path_reaches_the_verdict(workdir):
    result = run("example.email")
    assert "signed by a domain that is not the sender" in result.stdout


def test_an_absolute_path_works(workdir):
    result = run(str(workdir / "example.email"))
    assert result.exit_code == 0
    assert "yourbank.example" in result.stdout


def test_a_real_command_is_not_shadowed_by_a_file_of_the_same_name(workdir):
    """The failure mode of routing bare paths: `umbra collectors` breaking
    because somebody left a file called `collectors` in the directory."""
    (workdir / "collectors").write_text("185.199.108.153\n")
    result = run("collectors")
    assert result.exit_code == 0
    assert "Collectors" in result.stdout
    assert "185.199.108.153" not in result.stdout


def test_an_unknown_word_still_gets_the_normal_error(workdir):
    result = run("definitely-not-a-command")
    assert result.exit_code != 0
    assert "no such command" in text(result).lower()


def test_an_option_is_not_treated_as_a_path(workdir):
    result = run("--help")
    assert result.exit_code == 0


# --- umbra email -----------------------------------------------------------

def test_the_email_command_reads_a_file(workdir):
    result = run("email", "example.email")
    assert result.exit_code == 0
    assert "203.0.113.44" in result.stdout


def test_the_chain_is_printed_with_its_trust(workdir):
    result = run("email", "example.email")
    assert "trusted" in result.stdout
    assert "untrusted" in result.stdout


def test_the_origin_is_stated_with_its_reasoning(workdir):
    result = run("email", "forged.eml")
    assert "185.199.108.153" in result.stdout


def test_the_forged_origin_is_not_presented_as_the_source(workdir):
    """The chain claims treasury.gov. It must not be named as the origin."""
    result = run("email", "forged.eml")
    origin_line = next(line for line in result.stdout.splitlines()
                       if line.startswith("Origin:"))
    assert "23.55.161.10" not in origin_line


def test_stdin_works(workdir):
    blob = (FIXTURES / "m365_spoofed.eml").read_text()
    result = runner.invoke(app, ["email"], input=blob, env={"COLUMNS": "200"})
    assert result.exit_code == 0
    assert "yourbank.example" in result.stdout


def test_an_operator_can_declare_their_trusted_domains(workdir):
    result = run("email", "forged.eml", "--trusted-domain", "carls-employer.com")
    assert result.exit_code == 0
    assert "185.199.108.153" in result.stdout


def test_input_that_is_not_mail_says_so_rather_than_looking_clean(workdir):
    """An empty parse rendered as a tidy report is the worst possible output —
    it reads as "this message is fine"."""
    result = run("email", "iocs.txt")
    assert result.exit_code == 0
    assert "parse failure" in result.stdout or "not a clean message" in result.stdout


# --- umbra file ------------------------------------------------------------

def test_the_file_command_reads_an_indicator_list(workdir):
    result = run("file", "iocs.txt")
    assert result.exit_code == 0
    assert "185.199.108.153" in result.stdout


def test_a_missing_file_is_a_clean_error(workdir):
    result = run("file", "nope.txt")
    assert result.exit_code != 0
    assert "no such file" in text(result).lower()


def test_a_directory_is_a_clean_error(workdir):
    result = run("file", str(workdir))
    assert result.exit_code != 0
    assert "directory" in text(result).lower()


# --- nothing runs without a decision --------------------------------------

def test_reading_a_file_collects_nothing(workdir):
    result = run("example.email")
    assert "Nothing has been collected" in result.stdout


def test_the_json_form_carries_the_plan_and_the_findings(workdir):
    result = run("email", "example.email", "--json")
    payload = json.loads(result.stdout)
    assert payload["plan"]["extractor"] == "email_headers_v1"
    assert any(f["key"] == "dkim_unaligned" for f in payload["findings"])


def test_json_values_are_not_truncated_by_the_table(workdir):
    """The tables abbreviate long values to stay readable. `--json` is what an
    analyst copies from, so it must carry them whole."""
    result = run("email", "example.email", "--json")
    payload = json.loads(result.stdout)
    urls = [s["value"] for s in payload["plan"]["seeds"] if s["type"] == "url"]
    assert any(u.endswith("9f2a1c") for u in urls)


# --- the selection, from the terminal --------------------------------------

def test_only_narrows_the_selection(workdir):
    result = run("email", "example.email", "--only", "yourbank.example", "--json")
    payload = json.loads(result.stdout)
    armed = [s["value"] for s in payload["plan"]["seeds"] if s["include"]]
    assert armed == ["yourbank.example"]


def test_drop_removes_one(workdir):
    result = run("email", "example.email", "--drop", "yourbank.example", "--json")
    payload = json.loads(result.stdout)
    armed = [s["value"] for s in payload["plan"]["seeds"] if s["include"]]
    assert "yourbank.example" not in armed
    assert "mailer.random-vps.tld" in armed


def test_the_recipient_stays_off_unless_named(workdir):
    result = run("email", "example.email", "--json")
    payload = json.loads(result.stdout)
    armed = [s["value"] for s in payload["plan"]["seeds"] if s["include"]]
    assert "carl@carls-employer.com" not in armed


def test_an_analyst_can_deliberately_arm_the_recipient_side(workdir):
    """Unchecked is not forbidden — it is a decision the analyst gets to make."""
    result = run("email", "example.email", "--only", "carls-employer.com", "--json")
    payload = json.loads(result.stdout)
    armed = [s["value"] for s in payload["plan"]["seeds"] if s["include"]]
    assert armed == ["carls-employer.com"]


def test_a_bad_basis_is_rejected(workdir):
    result = run("email", "example.email", "--basis", "whatever")
    assert result.exit_code != 0
