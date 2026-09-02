"""`ct_lake` collector — subdomain discovery from the OWNED CT corpus.

The offline counterpart to `crtsh`: proves the owned-lake data actually
reaches the case graph with no external API.
"""
from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from umbra.collectors.base import CollectorContext, default_registry
from umbra.collectors.ct_lake import CtLakeCollector
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity
from umbra.lake.ct import CertRecord
from umbra.lake.store import LakeStore


def _domain_entity(v: str) -> Entity:
    return Entity(id="1", case_id="c", type="domain", value=v,
                  norm_key=entity_key(EntityType.DOMAIN, v), props={},
                  confidence=1.0, is_seed=True)


def _ctx(tmp_path: Path) -> CollectorContext:
    settings = Settings(data_dir=tmp_path)
    return CollectorContext(settings=settings, case_id="c", run_id="r",
                            http=httpx.Client(timeout=5))


def _seed_corpus(tmp_path: Path, records: list[CertRecord]) -> None:
    """Populate the lake the collector will read (same path resolution)."""
    settings = Settings(data_dir=tmp_path)
    store = LakeStore.from_settings(settings)
    store.add_records("testlog", 0, records)


def _rec(domains: list[str], serial: str, ts: int = 1000) -> CertRecord:
    return CertRecord(0, ts, sorted(domains), domains[0], "Test CA", serial,
                      "2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def test_registered_and_supports():
    assert default_registry().get("ct_lake") is not None
    c = CtLakeCollector()
    assert c.supports(_domain_entity("example.com"))
    ip = Entity(id="2", case_id="c", type="ip", value="1.2.3.4",
                norm_key=entity_key(EntityType.IP, "1.2.3.4"), props={},
                confidence=1.0, is_seed=True)
    assert not c.supports(ip)


def test_finds_subdomains_from_owned_corpus(tmp_path: Path):
    _seed_corpus(tmp_path, [
        _rec(["example.com", "www.example.com"], "aa"),
        _rec(["api.example.com"], "bb"),
        _rec(["unrelated.org"], "cc"),
    ])
    result = CtLakeCollector().collect(_domain_entity("example.com"), _ctx(tmp_path))
    domains = {e.value for e in result.entities if e.type == EntityType.DOMAIN}
    assert "www.example.com" in domains
    assert "api.example.com" in domains
    assert "unrelated.org" not in domains
    # cert entities + issued_for/subdomain_of edges
    assert any(e.type == EntityType.CERT for e in result.entities)
    assert result.edges
    assert result.evidence and result.evidence[0].source_name == "Umbra CT corpus (owned)"
    assert result.evidence[0].source_url is None  # no external API was consulted


def test_empty_corpus_is_honest_not_silent(tmp_path: Path):
    """A tail-forward corpus with no data must say so (and how to fix it),
    never imply the domain simply has no certificates."""
    _seed_corpus(tmp_path, [_rec(["other.example"], "zz")])
    result = CtLakeCollector().collect(_domain_entity("example.com"), _ctx(tmp_path))
    assert result.entities == []
    assert result.notes and "no certs" in result.notes[0]
    assert "umbra ct ingest" in result.notes[0]  # actionable


def test_missing_corpus_fails_soft(tmp_path: Path):
    """No lake at all → a note, never an exception that fails the whole run."""
    result = CtLakeCollector().collect(_domain_entity("example.com"), _ctx(tmp_path / "nothing"))
    assert result.notes
    assert result.entities == []
