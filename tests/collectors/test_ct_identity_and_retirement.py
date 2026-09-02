"""Two clean-ups: one collector retired, one identity bug closed.

**`wikidata_search` is retired.** `wikidata` covers the same inputs with real
per-claim provenance, so keeping both meant every org and person run queried
Wikidata twice for overlapping data. Retiring it is only honest if nothing is
lost, so the one field it extracted and the new collector did not — the Legal
Entity Identifier — moves across first.

**crtsh keyed certificates on the wrong thing.** It used
`row.get("sha256") or row.get("id")`, and crt.sh's JSON has no `sha256` field —
so in practice the certificate entity was named after a **crt.sh row id** while
`ct_lake` names the same certificate after its serial. Two collectors, two
identities, no way to tell from the value which kind it was.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from umbra.core.models import EntityType
from umbra.core.normalize import entity_key


# --- the retirement -------------------------------------------------------

def test_wikidata_search_is_gone_from_the_registry():
    from umbra.collectors.base import default_registry

    names = {c.name for c in default_registry().list()}
    assert "wikidata_search" not in names
    assert "wikidata" in names, "the replacement must still be there"


def test_the_replacement_covers_what_it_replaced():
    from umbra.collectors.base import default_registry

    col = default_registry().get("wikidata")
    assert {EntityType.ORG, EntityType.PERSON} <= col.inputs


def test_the_planner_no_longer_asks_for_it():
    from umbra.intent.plan import _ORG, _PERSON

    assert "wikidata_search" not in _ORG + _PERSON
    assert "wikidata" in _ORG


def test_no_stale_trust_weight_is_left_behind():
    from umbra.collectors.base import default_registry
    from umbra.core.scoring import COLLECTOR_TRUST

    assert set(COLLECTOR_TRUST) <= {c.name for c in default_registry().list()}


def test_the_legal_entity_identifier_survived_the_retirement():
    """P1278 was the one thing the old collector extracted that the new one did
    not. Retiring without porting it would have quietly dropped a field that
    matters for corporate work."""
    from umbra.collectors.wikidata import VALUE_PROPS

    assert "P1278" in VALUE_PROPS
    assert "lei" in VALUE_PROPS["P1278"].lower()


def test_the_module_is_actually_deleted():
    from pathlib import Path

    src = Path(__file__).resolve().parents[2] / "src/umbra/collectors/wikidata_search.py"
    assert not src.exists(), "a retired collector left on disk gets re-registered by accident"


# --- certificate identity -------------------------------------------------

CRTSH_ROWS = [
    # Exactly the fields crt.sh returns — note the absence of any fingerprint.
    {"issuer_ca_id": 183267, "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
     "common_name": "example.com", "name_value": "example.com\nwww.example.com",
     "id": 9876543210, "entry_timestamp": "2026-01-01T00:00:00",
     "not_before": "2026-01-01T00:00:00", "not_after": "2026-04-01T00:00:00",
     "serial_number": "04a1b2c3d4e5f6"},
]


def _ctx():
    import json as _json

    class _Resp:
        """Mirrors what the collector actually reads: status, content, json."""
        status_code = 200
        content = _json.dumps(CRTSH_ROWS).encode()
        text = content.decode()

        @staticmethod
        def json():
            return CRTSH_ROWS

    class _Http:
        def get(self, *a, **k):   # the collector passes timeout=
            return _Resp()

    return SimpleNamespace(settings=SimpleNamespace(user_agent="t", request_timeout_s=5),
                           case_id="c", run_id="r", http=_Http())


def _run():
    from umbra.collectors.crtsh import CrtshCollector

    ent = SimpleNamespace(type="domain", value="example.com", confidence=0.9,
                          norm_key=entity_key(EntityType.DOMAIN, "example.com"), props={})
    return CrtshCollector().collect(ent, _ctx())


def test_a_certificate_is_named_by_its_serial_not_a_crtsh_row_id():
    """So the same certificate seen through crtsh and through the owned lake is
    the same node, instead of two unrelated ones."""
    res = _run()
    certs = [e for e in res.entities if e.type == EntityType.CERT]
    assert certs, "crtsh should still record certificates"
    assert certs[0].value == "04a1b2c3d4e5f6"
    assert "9876543210" not in [str(c.value) for c in certs]


def test_the_crtsh_row_id_is_kept_but_labelled():
    """It is still useful — crt.sh/?id= resolves it — it just is not identity."""
    res = _run()
    cert = next(e for e in res.entities if e.type == EntityType.CERT)
    assert str(cert.props.get("crtsh_id")) == "9876543210"


def test_no_fingerprint_is_claimed_when_none_was_returned():
    """crt.sh does not return one. Recording the row id under a fingerprint key
    would make a lookup by fingerprint silently wrong."""
    res = _run()
    cert = next(e for e in res.entities if e.type == EntityType.CERT)
    assert not cert.props.get("fingerprint_sha256")


def test_the_useful_fields_crtsh_already_returns_are_kept():
    """subject/serial/validity were in the spec's field list and in the response
    all along — no extra request needed."""
    res = _run()
    cert = next(e for e in res.entities if e.type == EntityType.CERT)
    for field in ("cn", "serial_number", "not_before", "not_after", "issuer"):
        assert cert.props.get(field), f"missing {field}"


def test_the_issuing_ca_becomes_an_organization():
    """Same relationship ct_lake now emits, so the two CT paths agree."""
    res = _run()
    assert any(e.type == EntityType.ORG and "let's encrypt" in e.value.lower()
               for e in res.entities)
