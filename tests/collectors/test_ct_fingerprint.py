"""Certificate identity: SHA-256 fingerprints, and issuers as organizations.

Reconciling `references/ct-logs-collector.md` against what already exists —
`crtsh` (fetch), `ct_lake` (owned corpus), `tls_cert` (live), and the 15-minute
ingest timer from PHASES C3 — the spec's field list was already covered except
for one thing, and one relationship:

**`fingerprint_sha256` was stored nowhere.** It is the only globally unique
identifier a certificate has: a serial number is unique *per issuer*, so two
certificates from different CAs can share one. Without a fingerprint you cannot
say "the certificate this host is serving is the certificate we saw in CT" —
which is the question CT data exists to answer.

**`Certificate → Organization`** was in the spec's graph relationships and
implemented by neither collector, though the issuer organisation is already
parsed out of the DER.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from umbra.core.models import EntityType
from umbra.core.normalize import entity_key


def _self_signed(cn: str = "example.com"):
    """A real certificate, so the fingerprint is a real fingerprint."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Issuing CA"),
    ])
    now = datetime.now(tz=timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, cert.public_bytes(serialization.Encoding.DER)


# --- the fingerprint ------------------------------------------------------

def test_the_fingerprint_is_the_sha256_of_the_der():
    """Not of the PEM, not of the text — the DER bytes, which is what every
    other tool means by a certificate fingerprint."""
    from umbra.lake.ct import cert_fingerprint

    cert, der = _self_signed()
    assert cert_fingerprint(cert) == hashlib.sha256(der).hexdigest()
    assert len(cert_fingerprint(cert)) == 64


def test_the_fingerprint_matches_what_openssl_would_print():
    from umbra.lake.ct import cert_fingerprint

    cert, _ = _self_signed()
    assert cert_fingerprint(cert) == cert.fingerprint(__import__(
        "cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()).hex()


def test_two_different_certificates_do_not_share_a_fingerprint():
    from umbra.lake.ct import cert_fingerprint

    a, _ = _self_signed("a.example")
    b, _ = _self_signed("b.example")
    assert cert_fingerprint(a) != cert_fingerprint(b)


def test_a_parsed_record_carries_it():
    from umbra.lake.ct import CertRecord

    assert "fingerprint_sha256" in CertRecord.__dataclass_fields__


# --- the lake stores and returns it ---------------------------------------

def test_the_lake_column_exists():
    from umbra.lake.store import CtCert

    assert hasattr(CtCert, "fingerprint_sha256")


def test_an_existing_lake_gains_the_column_without_losing_data(tmp_path: Path):
    """Production already holds 2,000 certificates and the lake had no migration
    path at all — `create_all` does not alter an existing table, so a new column
    would simply never appear there."""
    import sqlalchemy as sa

    db = tmp_path / "lake.sqlite"
    # A lake created before the column existed.
    with sa.create_engine(f"sqlite:///{db}").begin() as conn:
        conn.execute(sa.text(
            "CREATE TABLE ct_cert (id INTEGER PRIMARY KEY, log TEXT, entry_index INTEGER,"
            " entry_type INTEGER, timestamp_ms INTEGER, cn TEXT, issuer TEXT,"
            " serial TEXT, not_before TEXT, not_after TEXT, seen_at TEXT)"))
        conn.execute(sa.text("INSERT INTO ct_cert (log, entry_index, entry_type,"
            " timestamp_ms, cn, seen_at) VALUES ('t', 1, 0, 0, 'old.example', 'x')"))

    from umbra.lake.store import LakeStore

    LakeStore(f"sqlite:///{db}")  # opening it must migrate, not wipe

    with sa.create_engine(f"sqlite:///{db}").begin() as conn:
        cols = {r[1] for r in conn.execute(sa.text("PRAGMA table_info(ct_cert)"))}
        rows = conn.execute(sa.text("SELECT cn FROM ct_cert")).fetchall()
    assert "fingerprint_sha256" in cols
    assert [r[0] for r in rows] == ["old.example"], "existing rows must survive"


def test_search_results_include_the_fingerprint(tmp_path: Path):
    from umbra.lake.ct import CertRecord
    from umbra.lake.store import LakeStore

    store = LakeStore(f"sqlite:///{tmp_path/'l.sqlite'}")
    store.add_records("test", 0, [CertRecord(
        entry_type=0, timestamp_ms=0, domains=["example.com"], cn="example.com",
        issuer="Example Issuing CA", serial="ab12", not_before="2026-01-01",
        not_after="2026-06-01", fingerprint_sha256="f" * 64)])
    hits = store.search("example.com", exact=False, limit=10)
    assert hits
    assert hits[0].get("fingerprint_sha256") == "f" * 64


# --- the collector surfaces it -------------------------------------------

def _ctx(tmp_path):
    return SimpleNamespace(
        settings=SimpleNamespace(cache_dir=tmp_path, lake_url=None, user_agent="t"),
        case_id="c", run_id="r", http=None)


def test_the_cert_entity_carries_its_fingerprint(tmp_path, monkeypatch):
    """A certificate entity identified only by serial cannot be matched against
    the same certificate seen anywhere else."""
    import umbra.collectors.ct_lake as ctl

    monkeypatch.setattr(ctl, "_lake_rows", lambda *a, **k: ([{
        "cn": "example.com", "issuer": "Example Issuing CA", "serial": "ab12",
        "not_before": "2026-01-01", "not_after": "2026-06-01",
        "fingerprint_sha256": "a" * 64, "domains": ["example.com"]}], {"certs": 1}))

    ent = SimpleNamespace(type="domain", value="example.com", confidence=0.9,
                          norm_key=entity_key(EntityType.DOMAIN, "example.com"), props={})
    res = ctl.CtLakeCollector().collect(ent, _ctx(tmp_path))
    cert = next(e for e in res.entities if e.type == EntityType.CERT)
    assert cert.props.get("fingerprint_sha256") == "a" * 64


def test_the_issuer_becomes_an_organization_with_an_edge(tmp_path, monkeypatch):
    """The spec's Certificate -> Organization relationship. The issuer org is
    already parsed out of the DER and was being dropped on the floor."""
    import umbra.collectors.ct_lake as ctl

    monkeypatch.setattr(ctl, "_lake_rows", lambda *a, **k: ([{
        "cn": "example.com", "issuer": "Example Issuing CA", "serial": "ab12",
        "not_before": "2026-01-01", "not_after": "2026-06-01",
        "fingerprint_sha256": "a" * 64, "domains": ["example.com"]}], {"certs": 1}))

    ent = SimpleNamespace(type="domain", value="example.com", confidence=0.9,
                          norm_key=entity_key(EntityType.DOMAIN, "example.com"), props={})
    res = ctl.CtLakeCollector().collect(ent, _ctx(tmp_path))
    assert any(e.type == EntityType.ORG and "example issuing ca" in e.value.lower()
               for e in res.entities)
    assert any(edge.rel.value == "issued_for" or edge.rel.value == "owns"
               for edge in res.edges)


def test_a_missing_issuer_does_not_invent_an_organization(tmp_path, monkeypatch):
    import umbra.collectors.ct_lake as ctl

    monkeypatch.setattr(ctl, "_lake_rows", lambda *a, **k: ([{
        "cn": "example.com", "issuer": None, "serial": "ab12",
        "domains": ["example.com"]}], {"certs": 1}))
    ent = SimpleNamespace(type="domain", value="example.com", confidence=0.9,
                          norm_key=entity_key(EntityType.DOMAIN, "example.com"), props={})
    res = ctl.CtLakeCollector().collect(ent, _ctx(tmp_path))
    assert not any(e.type == EntityType.ORG for e in res.entities)
