"""Parsing what an analyst pastes — and what never leaves the machine (docs/TRIAGE.md)."""
from __future__ import annotations

import json

from umbra.core.models import EntityType
from umbra.triage.alert import MAX_ALERTS, alert_from_json, classify_indicator, parse_input

PRIVATE_BITS = ("10.0.0.5", "WS-042", "carl.s", "s3cr3t-token", "C:\\Users")

ECS_OUTBOUND = {
    "@timestamp": "2026-09-24T03:02:00Z",
    "source": {"ip": "10.0.0.5", "port": 51234},
    "destination": {"ip": "185.231.154.75", "port": 5555},
    "host": {"name": "WS-042"},
    "user": {"name": "carl.s"},
    "process": {"command_line": "agent.exe --token s3cr3t-token", "executable": "C:\\Users\\x.exe"},
    "rule": {"name": "Outbound connection to rare port"},
    "event": {"count": 14},
}


def test_single_tokens():
    assert classify_indicator("185.220.101.1").type is EntityType.IP
    assert classify_indicator("evil-domain.example.com").type is EntityType.DOMAIN
    assert classify_indicator("http://176.65.134.121:8080/x.mips64").type is EntityType.URL
    assert classify_indicator("10.0.0.5") is None
    assert classify_indicator("printer.corp") is None
    assert classify_indicator("http://192.168.1.1/admin") is None


def test_ecs_outbound_takes_only_the_remote_side():
    a = alert_from_json(ECS_OUTBOUND)
    assert a.kind == "outbound_conn"
    assert [(i.type, i.value) for i in a.indicators] == [(EntityType.IP, "185.231.154.75")]
    assert a.context == {"remote port": "5555", "detection rule": "Outbound connection to rare port"}
    assert a.events == 14
    assert {"host.name", "user.name", "process.command_line", "internal address"} <= set(a.kept_local)


def test_nothing_private_is_carried_on_the_alert():
    blob = json.dumps(alert_from_json(ECS_OUTBOUND).to_dict())
    for bit in PRIVATE_BITS:
        assert bit not in blob


def test_inbound_eve_uses_the_source_not_our_own_hostname():
    a = alert_from_json({
        "src_ip": "167.172.83.145", "dest_ip": "10.1.1.1", "dest_port": 443,
        "http": {"hostname": "umbra.example.com", "url": "/wp-admin/setup.php",
                 "http_user_agent": "Mozilla/5.0 zgrab/0.x"},
        "alert": {"signature": "ET SCAN WordPress probe"},
    })
    assert a.kind == "inbound_conn"
    assert [i.value for i in a.indicators] == ["167.172.83.145"]
    assert a.untrusted == {"user agent": "Mozilla/5.0 zgrab/0.x", "requested path": "/wp-admin/setup.php"}
    assert a.context["our port"] == "443"


def test_dns_query():
    a = alert_from_json({"dns": {"question": {"name": "pdbxq1z3.eng-us-puraboost.us."}},
                         "source": {"ip": "10.0.0.8"}})
    assert a.kind == "dns_query"
    assert [(i.type, i.value) for i in a.indicators] == [(EntityType.DOMAIN, "pdbxq1z3.eng-us-puraboost.us")]


def test_proxy_download_keeps_the_url_and_fences_the_user_agent():
    a = alert_from_json({"url": {"full": "http://176.65.134.121:8080/x.mips64"},
                         "user_agent": {"original": "Wget/1.21"}, "source": {"ip": "10.0.0.9"}})
    assert a.kind == "web_request"
    assert [(i.type, i.value) for i in a.indicators] == [
        (EntityType.URL, "http://176.65.134.121:8080/x.mips64"), (EntityType.IP, "176.65.134.121")]
    assert a.untrusted["user agent"] == "Wget/1.21"


def test_a_pasted_url_also_checks_its_host():
    alerts, _ = parse_input("https://login-paypa1.example.com/verify")
    assert [(i.type, i.value) for i in alerts[0].indicators] == [
        (EntityType.URL, "https://login-paypa1.example.com/verify"),
        (EntityType.DOMAIN, "login-paypa1.example.com")]


def test_flat_zeek_names():
    a = alert_from_json({"id.orig_h": "10.0.0.3", "id.resp_h": "45.9.148.108", "id.resp_p": 4444})
    assert [i.value for i in a.indicators] == ["45.9.148.108"]
    assert a.context["remote port"] == "4444"


def test_ioc_text_dedupes_and_drops_internal():
    alerts, notes = parse_input("185.220.101.1\n185.220.101.1\n10.0.0.1\nevil-domain.example.com\n")
    vals = [a.indicators[0].value for a in alerts]
    assert vals.count("185.220.101.1") == 1
    assert "evil-domain.example.com" in vals
    assert "10.0.0.1" not in vals


def test_ndjson_and_elastic_hits_wrappers():
    nd = "\n".join(json.dumps({"destination": {"ip": ip}}) for ip in ("8.8.8.8", "1.1.1.1"))
    assert len(parse_input(nd)[0]) == 2
    wrapped = json.dumps({"hits": {"hits": [{"_source": {"destination": {"ip": "9.9.9.9"}}}]}})
    alerts, _ = parse_input(wrapped)
    assert alerts[0].indicators[0].value == "9.9.9.9"


def test_batch_is_capped_and_says_so():
    many = json.dumps([{"destination": {"ip": "8.8.8.8"}}] * (MAX_ALERTS + 5))
    alerts, notes = parse_input(many)
    assert len(alerts) == MAX_ALERTS
    assert any("first" in n for n in notes)


def test_an_all_internal_alert_has_nothing_to_assess():
    alerts, notes = parse_input(json.dumps({"source": {"ip": "10.0.0.1"}, "destination": {"ip": "10.0.0.2"}}))
    assert alerts and not alerts[0].indicators
    assert any("no public" in n for n in notes)
