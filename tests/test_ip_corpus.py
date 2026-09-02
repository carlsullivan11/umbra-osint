"""Phase A IP backfill — passive only, public IPs, enrichment markers."""

from __future__ import annotations

from datetime import timedelta

import pytest

from umbra.core.models import utcnow
from umbra.ip_corpus import (
    ACTIVE_FORBIDDEN,
    PASSIVE_COLLECTORS,
    assert_passive_only,
    is_enriched,
    is_public_ip,
)


def test_passive_allowlist_has_no_active():
    assert not (set(PASSIVE_COLLECTORS) & ACTIVE_FORBIDDEN)
    assert "http_probe" not in PASSIVE_COLLECTORS
    assert "rdap_ip" in PASSIVE_COLLECTORS
    assert "ip_geo" in PASSIVE_COLLECTORS


def test_assert_passive_rejects_http_probe():
    with pytest.raises(ValueError, match="forbidden"):
        assert_passive_only(["rdap_ip", "http_probe"])


def test_is_public_ip():
    assert is_public_ip("8.8.8.8")
    assert is_public_ip("1.1.1.1")
    assert not is_public_ip("10.0.0.1")
    assert not is_public_ip("127.0.0.1")
    assert not is_public_ip("not-an-ip")
    assert not is_public_ip("100.64.1.1")  # CGNAT


def test_is_enriched_markers():
    assert not is_enriched({})
    assert not is_enriched({"noise": 1})
    assert is_enriched({"geo_country": "US"})
    assert is_enriched({"asn": "AS15169"})
    assert is_enriched({"cymru_asn": "15169"})
    assert is_enriched({"cymru": [{"asn": "15169"}]})


def test_has_asn_signal():
    from umbra.ip_corpus import _has_asn_signal

    assert not _has_asn_signal({})
    assert _has_asn_signal({"cymru": [{"asn": "15169", "cc": "US"}]})
    assert _has_asn_signal({"asn": "AS15169"})


def test_is_enriched_cooldown_stamp():
    now = utcnow()
    recent = (now - timedelta(days=1)).isoformat()
    stale = (now - timedelta(days=30)).isoformat()
    assert is_enriched({"passive_enriched_at": recent}, now=now)
    assert not is_enriched({"passive_enriched_at": stale}, now=now)
