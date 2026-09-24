"""Shodan InternetDB — read the index, scan nobody.

`umbra scan ports` sends packets, and `docs/PORT-SCAN.md` is mostly about when
it refuses: `public_cti` and `other` are denied outright, because finding an
address in a malware feed gives you no authority over it. That refusal is the
reason this collector exists in the shape it does.

InternetDB answers the same question — what is exposed on this address — from
Shodan's *existing* index, with no key and no packet from Umbra to the target.
It is available on every basis precisely because it is not a scan, and nothing
here may become a way to get scan results without the gate.

The honesty burden is heavier than usual for the same reason. "Shodan has no
record of this address" is not "this address has nothing open": Shodan scans on
its own schedule, misses hosts, and a 404 is the *normal* answer for a host it
has never indexed. Reporting that as "no open ports" would hand back a scan
result that nobody was authorised to produce and that nobody actually produced.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from umbra.collectors.base import CollectorContext, default_registry
from umbra.collectors.internetdb import INTERNETDB_URL, MAX_VULNS, InternetDbCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

IP = "93.184.216.34"  # plain public unicast
URL = INTERNETDB_URL.format(ip=IP)


def _entity(value: str = IP) -> Entity:
    return Entity(id="e1", case_id="c1", type=EntityType.IP.value, value=value,
                  norm_key=entity_key(EntityType.IP, value), props={},
                  confidence=1.0, is_seed=True)


def _ctx() -> CollectorContext:
    return CollectorContext(settings=Settings(), case_id="c", run_id="r",
                            http=httpx.Client(timeout=5))


def _payload(**over) -> dict:
    body = {
        "ip": IP,
        "ports": [22, 80, 443],
        "hostnames": ["host.example.com"],
        "cpes": ["cpe:/a:nginx:nginx:1.18.0"],
        "tags": ["cdn"],
        "vulns": ["CVE-2021-44228"],
    }
    body.update(over)
    return body


def run(entity=None):
    return InternetDbCollector().collect(entity or _entity(), _ctx())


def _props(res) -> dict:
    assert res.entities, "expected the IP entity to be re-emitted with props"
    return res.entities[0].props


# --- it reads an index; it does not scan -----------------------------------

@respx.mock
def test_it_queries_internetdb():
    route = respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    run()
    assert route.called


@respx.mock
def test_it_opens_no_connection_to_the_investigated_address():
    """The whole point. A packet to the target would make this a scan, and a
    scan needs the authorization_basis gate this collector does not have."""
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    for port in (80, 443, 22):
        respx.get(f"http://{IP}:{port}/").mock(return_value=httpx.Response(200))
    respx.get(f"http://{IP}/").mock(return_value=httpx.Response(200))
    respx.get(f"https://{IP}/").mock(return_value=httpx.Response(200))
    run()
    for call in respx.calls:
        assert IP not in call.request.url.host, (
            f"connected to the investigated address: {call.request.url}")


def test_the_module_never_imports_the_scanner():
    """tests/test_port_scan.py enforces this across all collectors; asserted
    here too because this is the one collector where someone would be tempted."""
    import inspect

    import umbra.collectors.internetdb as mod

    assert "umbra.scan" not in inspect.getsource(mod)


@respx.mock
def test_the_only_host_it_ever_contacts_is_internetdb():
    """Was a substring check on module names, which flagged `urlscan_io` for
    containing "scan" — a false constraint on a legitimate name, and a weak
    proxy for something tests/test_port_scan.py already enforces properly
    (no collector may import the scanner).

    The invariant that is genuinely specific to this collector is narrower and
    stronger: exactly one host is ever contacted, and it is Shodan's index.
    """
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    run()
    hosts = {c.request.url.host for c in respx.calls}
    assert hosts == {"internetdb.shodan.io"}


# --- parsing ---------------------------------------------------------------

@respx.mock
def test_ports_land_on_the_entity():
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    assert _props(run())["internetdb_ports"] == [22, 80, 443]


@respx.mock
def test_hostnames_cpes_and_tags_land_on_the_entity():
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    p = _props(run())
    assert p["internetdb_hostnames"] == ["host.example.com"]
    assert p["internetdb_cpes"] == ["cpe:/a:nginx:nginx:1.18.0"]
    assert p["internetdb_tags"] == ["cdn"]


@respx.mock
def test_the_fetch_time_is_stored():
    """A Shodan record is a snapshot of whenever Shodan last looked. Without a
    fetch stamp there is no way to tell a fresh answer from a year-old one."""
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    assert _props(run())["internetdb_fetched_at"]


@respx.mock
def test_vulns_are_capped():
    many = [f"CVE-2021-{i:05d}" for i in range(40)]
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload(vulns=many)))
    assert len(_props(run())["internetdb_vulns"]) == MAX_VULNS


@respx.mock
def test_the_vuln_cap_is_stated_rather_than_silent():
    """40 CVEs is a fact about the host; showing 15 without saying so is not."""
    many = [f"CVE-2021-{i:05d}" for i in range(40)]
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload(vulns=many)))
    notes = " ".join(run().notes)
    assert "40" in notes and str(MAX_VULNS) in notes


@respx.mock
def test_empty_arrays_do_not_become_props():
    """An empty `ports` list from Shodan means Shodan saw none, which is not
    the same as Umbra having checked. Absent beats a confident empty list."""
    respx.get(URL).mock(return_value=httpx.Response(
        200, json=_payload(ports=[], hostnames=[], cpes=[], tags=[], vulns=[])))
    p = _props(run())
    assert "internetdb_ports" not in p


# --- evidence --------------------------------------------------------------

@respx.mock
def test_evidence_points_at_the_internetdb_url():
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    assert run().evidence[0].source_url == URL


@respx.mock
def test_evidence_says_it_is_shodans_scan_not_ours():
    """The copy matters: an operator reading "3 open ports" on a case they
    never scanned must not think Umbra scanned it."""
    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    ev = run().evidence[0]
    blob = f"{ev.source_name} {ev.summary}"
    assert "Shodan InternetDB" in blob
    assert "not our scan" in blob.lower() or "not a scan" in blob.lower()


@respx.mock
def test_the_trust_matches_the_declared_score():
    from umbra.core.scoring import COLLECTOR_TRUST

    respx.get(URL).mock(return_value=httpx.Response(200, json=_payload()))
    assert run().evidence[0].confidence == pytest.approx(COLLECTOR_TRUST["internetdb"])


# --- absence is unchecked, never "nothing open" ----------------------------

@respx.mock
def test_a_404_produces_a_note_and_no_evidence():
    """404 is the normal answer for a host Shodan has never indexed."""
    respx.get(URL).mock(return_value=httpx.Response(404, json={"detail": "No information"}))
    res = run()
    assert not res.evidence
    assert not res.entities
    assert res.notes


@respx.mock
def test_a_404_never_says_no_open_ports():
    respx.get(URL).mock(return_value=httpx.Response(404))
    notes = " ".join(run().notes).lower()
    assert "no open ports" not in notes
    assert "no record" in notes or "not indexed" in notes or "no information" in notes


@respx.mock
def test_a_404_says_umbra_did_not_scan():
    respx.get(URL).mock(return_value=httpx.Response(404))
    notes = " ".join(run().notes).lower()
    assert "scan" in notes


@respx.mock
def test_a_429_is_unchecked_and_reads_differently_from_a_404():
    respx.get(URL).mock(return_value=httpx.Response(429))
    limited = " ".join(run().notes)
    respx.get(URL).mock(return_value=httpx.Response(404))
    missing = " ".join(run().notes)
    assert limited != missing
    assert "429" in limited or "rate" in limited.lower()


@respx.mock
def test_a_server_error_is_a_source_failure_not_an_empty_host():
    respx.get(URL).mock(return_value=httpx.Response(503))
    res = run()
    assert not res.evidence
    assert res.notes


@respx.mock
def test_malformed_json_does_not_take_the_run_down():
    respx.get(URL).mock(return_value=httpx.Response(200, text="not json"))
    res = run()
    assert not res.evidence
    assert res.notes


@respx.mock
def test_a_transport_error_is_reported():
    respx.get(URL).mock(side_effect=httpx.ConnectError("boom"))
    res = run()
    assert not res.evidence
    assert res.notes


# --- addresses it refuses to look up ---------------------------------------

@pytest.mark.parametrize("value", [
    "10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1",
    "100.64.0.1",     # CGNAT — the carrier's address, shared between subscribers
    "203.0.113.10",   # TEST-NET-3 documentation space, not a real host
    "198.51.100.7",   # TEST-NET-2
])
@respx.mock
def test_non_public_addresses_are_skipped_without_a_request(value):
    route = respx.get(INTERNETDB_URL.format(ip=value)).mock(
        return_value=httpx.Response(200, json=_payload()))
    res = run(_entity(value))
    assert not route.called
    assert not res.evidence
    assert res.notes


@respx.mock
def test_ipv6_is_skipped_because_internetdb_is_ipv4_only():
    v6 = "2001:db8::1"
    route = respx.get(INTERNETDB_URL.format(ip=v6)).mock(
        return_value=httpx.Response(200, json=_payload()))
    res = run(_entity(v6))
    assert not route.called
    assert "IPv6" in " ".join(res.notes)


@respx.mock
def test_a_skipped_address_never_reads_as_nothing_open():
    res = run(_entity("10.0.0.5"))
    assert "no open ports" not in " ".join(res.notes).lower()


@respx.mock
def test_garbage_is_skipped():
    res = run(_entity("not-an-ip"))
    assert not res.evidence
    assert res.notes


# --- wiring ----------------------------------------------------------------

def test_it_is_registered():
    assert "internetdb" in {c.name for c in default_registry().list()}


def test_it_takes_ip_only():
    reg = {c.name: c for c in default_registry().list()}
    assert reg["internetdb"].inputs == {EntityType.IP}


def test_it_has_a_trust_score():
    from umbra.core.scoring import COLLECTOR_TRUST

    assert 0.6 <= COLLECTOR_TRUST["internetdb"] <= 0.7


def test_the_playbook_still_matches_the_registry():
    from umbra.cli.playbook_cmd import _PLAYBOOK_COLLECTORS

    assert set(_PLAYBOOK_COLLECTORS) == {c.name for c in default_registry().list()}
