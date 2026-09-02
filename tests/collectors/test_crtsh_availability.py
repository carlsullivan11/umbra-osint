"""crt.sh being down is not the same as a domain having no certificates.

crt.sh 502s often — it did so seconds after a direct request for the same
domain succeeded. The collector reported that as *"crt.sh empty for
cloudflare.com"*, which reads as "this domain has no certificates". Cloudflare
obviously has certificates. Same failure class as a DNSBL error rendering as
"clean": an unavailable source must not look like a negative result.

It also burned all three query variants on a server error — six requests at a
service that is already struggling.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from umbra.core.models import EntityType
from umbra.core.normalize import entity_key


def _ctx(responses):
    """responses: list of (status, payload) consumed in order."""
    calls = {"n": 0}
    import json as _json

    class _Resp:
        def __init__(self, status, payload):
            self.status_code = status
            self.content = _json.dumps(payload).encode() if payload is not None else b""
            self.text = self.content.decode()
            self._payload = payload

        def json(self):
            return self._payload

    class _Http:
        def get(self, *a, **k):
            i = min(calls["n"], len(responses) - 1)
            calls["n"] += 1
            status, payload = responses[i]
            return _Resp(status, payload)

    ctx = SimpleNamespace(settings=SimpleNamespace(user_agent="t", request_timeout_s=5),
                          case_id="c", run_id="r", http=_Http())
    ctx.calls = calls
    return ctx


def _run(ctx):
    from umbra.collectors.crtsh import CrtshCollector

    ent = SimpleNamespace(type="domain", value="cloudflare.com", confidence=0.9,
                          norm_key=entity_key(EntityType.DOMAIN, "cloudflare.com"), props={})
    return CrtshCollector().collect(ent, ctx)


ROW = [{"issuer_name": "C=US, O=Let's Encrypt, CN=R3", "common_name": "cloudflare.com",
        "name_value": "cloudflare.com", "id": 1, "not_before": "2026-01-01",
        "not_after": "2026-04-01", "serial_number": "0abc"}]


# --- unavailable is not empty --------------------------------------------

def test_a_server_error_is_reported_as_unavailable_not_empty(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    res = _run(_ctx([(502, None)]))
    note = " ".join(res.notes).lower()
    assert "unavailable" in note or "could not" in note
    assert "empty" not in note, "a 502 does not mean the domain has no certificates"


def test_the_evidence_says_the_source_was_unreachable(monkeypatch):
    """A run that recorded nothing must be distinguishable later from a run that
    checked and found nothing."""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    res = _run(_ctx([(502, None)]))
    ev = res.evidence[0]
    assert ev.raw.get("available") is False
    assert ev.raw.get("status") == 502


def test_a_genuine_empty_result_still_says_empty(monkeypatch):
    """200 with an empty list is a real answer: no certificates on record."""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    res = _run(_ctx([(200, [])]))
    note = " ".join(res.notes).lower()
    assert "no certificates" in note or "empty" in note
    assert "unavailable" not in note
    assert res.evidence[0].raw.get("available") is True


# --- do not hammer a struggling service ----------------------------------

def test_a_server_error_stops_early_instead_of_trying_every_query(monkeypatch):
    """Three query variants x two attempts is six requests at a service that is
    already returning 502."""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    ctx = _ctx([(502, None)])
    _run(ctx)
    assert ctx.calls["n"] <= 3, f"made {ctx.calls['n']} requests against a failing service"


def test_it_still_falls_through_query_variants_on_a_real_empty(monkeypatch):
    """An empty result for the wildcard is worth retrying as an exact match —
    that is a data question, not an availability one."""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    ctx = _ctx([(200, []), (200, ROW)])
    res = _run(ctx)
    assert ctx.calls["n"] >= 2
    assert any(e.type == EntityType.CERT for e in res.entities)


def test_a_recovered_request_is_used(monkeypatch):
    """crt.sh flaps; the second attempt often works."""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    res = _run(_ctx([(502, None), (200, ROW)]))
    assert any(e.type == EntityType.CERT for e in res.entities)


def test_certificates_are_keyed_on_the_serial_from_the_real_field(monkeypatch):
    """Verified against the live API: crt.sh returns serial_number and no
    sha256."""
    monkeypatch.setattr("time.sleep", lambda *_: None)
    res = _run(_ctx([(200, ROW)]))
    cert = next(e for e in res.entities if e.type == EntityType.CERT)
    assert cert.value == "0abc"
