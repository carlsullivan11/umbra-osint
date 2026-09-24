"""`umbra urlscan lookup` — and the absence of `umbra urlscan submit`.

The command reads an archive. It does not ask urlscan to go and fetch anything,
so there is no subcommand that could.
"""
from __future__ import annotations

import httpx
import respx
from typer.testing import CliRunner

from umbra.cli.main import app
from umbra.collectors.urlscan_io import API_SEARCH

runner = CliRunner()


def _payload(n=1, malicious=None):
    rows = []
    for i in range(n):
        row = {
            "_id": f"uuid-{i}",
            "task": {"url": f"http://evil.test/{i}", "time": "2026-08-01T10:00:00.000Z"},
            "page": {"domain": "evil.test"},
        }
        if malicious is not None:
            row["verdicts"] = {"overall": {"malicious": malicious, "score": 100}}
        rows.append(row)
    return {"results": rows, "total": n}


@respx.mock
def test_lookup_shows_a_permalink():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_payload()))
    out = runner.invoke(app, ["urlscan", "lookup", "evil.test"])
    assert out.exit_code == 0
    assert "uuid-0" in out.stdout


@respx.mock
def test_lookup_accepts_a_full_url():
    route = respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_payload()))
    out = runner.invoke(app, ["urlscan", "lookup", "http://evil.test/login"])
    assert out.exit_code == 0
    assert "page.url" in route.calls[0].request.url.params["q"]


@respx.mock
def test_a_missing_verdict_renders_as_unknown_not_benign():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_payload()))
    out = runner.invoke(app, ["urlscan", "lookup", "evil.test"])
    assert "benign" not in out.stdout.lower()


@respx.mock
def test_a_malicious_verdict_is_shown():
    respx.get(API_SEARCH).mock(
        return_value=httpx.Response(200, json=_payload(malicious=True)))
    out = runner.invoke(app, ["urlscan", "lookup", "evil.test"])
    assert "malicious" in out.stdout


@respx.mock
def test_no_scans_never_reports_the_url_as_clean():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(200, json=_payload(0)))
    out = runner.invoke(app, ["urlscan", "lookup", "evil.test"])
    assert out.exit_code == 1
    assert "clean" not in out.stdout.lower()
    assert "not a URL that has been cleared" in out.stdout or "unknown" in out.stdout.lower()


@respx.mock
def test_rate_limited_says_unchecked():
    respx.get(API_SEARCH).mock(return_value=httpx.Response(429))
    out = runner.invoke(app, ["urlscan", "lookup", "evil.test"])
    assert out.exit_code == 1
    assert "unchecked" in out.stdout.lower()


def test_there_is_no_submit_subcommand():
    """Submitting is a live fetch of someone else's host, published. Reading an
    archive is not, and this slice only does the second.

    Asserted against the registered command names rather than the help text:
    the help says "never submits a scan", and a substring search would forbid
    the sentence that documents the guarantee.
    """
    from umbra.cli.urlscan_cmd import urlscan_app

    names = {c.name or c.callback.__name__ for c in urlscan_app.registered_commands}
    assert "lookup" in names
    assert not {n for n in names if "submit" in n or "scan" == n}


def test_submit_is_not_silently_accepted():
    out = runner.invoke(app, ["urlscan", "submit", "http://evil.test/"])
    assert out.exit_code != 0
