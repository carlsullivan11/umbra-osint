"""`umbra internetdb lookup` — and no scan subcommand."""
from __future__ import annotations

import httpx
import respx
from typer.testing import CliRunner

from umbra.cli.main import app
from umbra.collectors.internetdb import INTERNETDB_URL

runner = CliRunner()
IP = "93.184.216.34"
URL = INTERNETDB_URL.format(ip=IP)


@respx.mock
def test_lookup_shows_ports():
    respx.get(URL).mock(return_value=httpx.Response(
        200, json={"ip": IP, "ports": [22, 443], "hostnames": [], "cpes": [],
                   "tags": [], "vulns": []}))
    out = runner.invoke(app, ["internetdb", "lookup", IP])
    assert out.exit_code == 0
    assert "22" in out.stdout and "443" in out.stdout


@respx.mock
def test_lookup_says_whose_scan_it_was():
    respx.get(URL).mock(return_value=httpx.Response(
        200, json={"ip": IP, "ports": [22], "vulns": []}))
    out = runner.invoke(app, ["internetdb", "lookup", IP])
    assert "not our scan" in out.stdout.lower()


@respx.mock
def test_a_404_exits_nonzero_without_claiming_nothing_is_open():
    respx.get(URL).mock(return_value=httpx.Response(404))
    out = runner.invoke(app, ["internetdb", "lookup", IP])
    assert out.exit_code == 1
    assert "no open ports" not in out.stdout.lower()
    assert "unchecked" in out.stdout.lower()


@respx.mock
def test_a_private_address_is_refused_without_a_request():
    route = respx.get(INTERNETDB_URL.format(ip="10.0.0.5")).mock(
        return_value=httpx.Response(200, json={}))
    out = runner.invoke(app, ["internetdb", "lookup", "10.0.0.5"])
    assert not route.called
    assert out.exit_code == 1


def test_there_is_no_scan_subcommand():
    """Reading an index is not scanning, and this command offers no way to."""
    from umbra.cli.internetdb_cmd import internetdb_app

    names = {c.name or c.callback.__name__ for c in internetdb_app.registered_commands}
    assert names == {"lookup"}
