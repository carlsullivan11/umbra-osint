"""Certificate Transparency ingestion — parse CT log entries into certs+domains.

This is the *producer* side of Umbra: instead of asking crt.sh "what certs
exist for X?", we read the CT logs directly (RFC 6962 ``get-sth`` /
``get-entries``), parse each entry's certificate, and store the issued domains
in our own corpus (``umbra.lake.store``). Over time that corpus *becomes* the
searchable index crt.sh provides — but owned, offline-queryable, and not a
single point of failure.

The parsing is the fiddly part and lives here as a pure function
(``parse_ct_entry``) so it is unit-testable without network:

- ``leaf_input`` is a base64 ``MerkleTreeLeaf`` (RFC 6962 §3.4):
  version(1) │ leaf_type(1) │ timestamp(8) │ entry_type(2) │ entry │ extensions
- entry_type 0 (x509_entry): the DER cert is inline — 3-byte length + cert.
- entry_type 1 (precert_entry): the leaf holds only the TBS; the full
  precertificate is the first opaque in ``extra_data`` (PrecertChainEntry) —
  3-byte length + DER.

Domain extraction is Subject Alternative Name dNSNames ∪ Subject CN.
"""
from __future__ import annotations

import base64
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

# Curated CT logs (temporal — CT logs are sharded by year and retire; refresh
# yearly). All verified reachable against /ct/v1/get-sth on 2026-09-13.
#
# "Refresh yearly" was written here from the start and nothing enforced it. The
# 2025 shards sat in this dict through 2026, the corpus froze at 2,000 certs,
# and `ct stats` reported "100.0000% of log" — which reads as finished and meant
# dead. `tests/test_ct_log_freshness.py` now fails when this list goes stale, so
# the next January is a red test rather than a silent nine-month gap.
KNOWN_LOGS: dict[str, str] = {
    "cloudflare_nimbus2026": "https://ct.cloudflare.com/logs/nimbus2026",
    "google_argon2026h1": "https://ct.googleapis.com/logs/us1/argon2026h1",
    "google_argon2026h2": "https://ct.googleapis.com/logs/us1/argon2026h2",
    "google_xenon2026h1": "https://ct.googleapis.com/logs/eu1/xenon2026h1",
    "google_xenon2026h2": "https://ct.googleapis.com/logs/eu1/xenon2026h2",
}

# Shards that have closed to new submissions. Kept rather than deleted: ingest
# checkpoints outlive the config, and a checkpoint whose log is simply *absent*
# renders as "unknown" — which says less about a stalled corpus than "retired"
# does. Certificates already ingested from these stay valid and searchable.
RETIRED_LOGS: dict[str, str] = {
    "cloudflare_nimbus2025": "https://ct.cloudflare.com/logs/nimbus2025",
    "google_argon2025h1": "https://ct.googleapis.com/logs/us1/argon2025h1",
    "google_argon2025h2": "https://ct.googleapis.com/logs/us1/argon2025h2",
    "google_xenon2025h2": "https://ct.googleapis.com/logs/eu1/xenon2025h2",
}


def default_log() -> str:
    """The log to ingest when nobody names one.

    A literal default is how this rotted: `cloudflare_nimbus2025` was written
    into the CLI and into `deploy/scripts/ct_ingest.sh`, and the ingest timer
    spent nine months faithfully tailing a shard that had stopped accepting
    certificates. Deriving it from `KNOWN_LOGS` means refreshing the shard list
    is the only edit a new year needs.
    """
    return next(iter(KNOWN_LOGS))


def log_status(name: str) -> str:
    """``active`` | ``retired`` | ``unknown`` for a log name."""
    if name in KNOWN_LOGS:
        return "active"
    if name in RETIRED_LOGS:
        return "retired"
    return "unknown"


def describe_checkpoint(name: str, last_index: int, tree_size: int) -> str:
    """One human line for an ingest checkpoint.

    A percentage is only meaningful for a log that can still grow. On a retired
    shard "100.0000% of log" is true and useless — it describes a finished read
    of a source that will never have anything new, and it is indistinguishable
    from a healthy, caught-up ingest. Say which one it is.
    """
    status = log_status(name)
    if status == "retired":
        return (f"at {last_index:,} / {tree_size:,} — retired shard, "
                f"no new certificates (kept for search)")
    pct = (last_index / tree_size * 100) if tree_size else 0.0
    line = f"at {last_index:,} / {tree_size:,} ({pct:.4f}% of log)"
    if status == "unknown":
        line += " — log not in the configured set"
    return line


@dataclass
class CertRecord:
    """One parsed CT entry: a certificate and the domains it was issued for."""
    entry_type: int
    timestamp_ms: int
    domains: list[str]
    cn: str | None
    issuer: str | None
    serial: str | None
    not_before: str | None
    not_after: str | None
    # SHA-256 of the DER. The only globally unique identifier a certificate
    # has: a serial number is unique per *issuer*, so two CAs can issue certs
    # sharing one. Without this you cannot say "the cert this host is serving
    # is the cert we saw in CT", which is what CT data is for.
    fingerprint_sha256: str | None = None
    # SHA-1 of DER for SSLBL joins only — not the preferred identity.
    fingerprint_sha1: str | None = None
    error: str | None = None
    raw_fields: dict[str, Any] = field(default_factory=dict)

    @property
    def issued_at(self) -> str:
        try:
            return datetime.fromtimestamp(self.timestamp_ms / 1000, tz=timezone.utc).isoformat()
        except Exception:
            return ""


def reverse_domain(name: str) -> str:
    """``www.example.com`` → ``com.example.www`` for prefix/subtree indexing.

    Reversed-label form lets a single indexed prefix query fetch an entire
    domain subtree (``com.example`` and ``com.example.%``) without a leading
    LIKE wildcard, which no B-tree index can use. Leading ``*`` is preserved.
    """
    n = (name or "").strip().strip(".").lower()
    if not n:
        return ""
    return ".".join(reversed(n.split(".")))


def cert_fingerprint(cert: x509.Certificate) -> str | None:
    """SHA-256 over the DER encoding — what every other tool calls *the*
    certificate fingerprint. Not the PEM, not the text."""
    try:
        return cert.fingerprint(hashes.SHA256()).hex()
    except Exception:  # noqa: BLE001 - a missing fingerprint must not drop the cert
        return None


def cert_fingerprint_sha1(cert: x509.Certificate) -> str | None:
    """SHA-1 over the DER — what abuse.ch SSLBL indexes. Not an identity we
    prefer; carried so `sslbl_cert` can join without re-fetching the cert."""
    try:
        return cert.fingerprint(hashes.SHA1()).hex()
    except Exception:  # noqa: BLE001
        return None


def _cert_domains(cert: x509.Certificate) -> tuple[list[str], str | None]:
    names: set[str] = set()
    cn: str | None = None
    try:
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            cn = str(cns[0].value)
            if cn:
                names.add(cn.strip(".").lower())
    except Exception:  # noqa: BLE001
        pass
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for d in san.value.get_values_for_type(x509.DNSName):
            if d:
                names.add(d.strip(".").lower())
    except x509.ExtensionNotFound:
        pass
    except Exception:  # noqa: BLE001
        pass
    return sorted(names), cn


def _issuer_org(cert: x509.Certificate) -> str | None:
    for oid in (NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME):
        try:
            vals = cert.issuer.get_attributes_for_oid(oid)
            if vals:
                return str(vals[0].value)
        except Exception:  # noqa: BLE001
            continue
    return None


def _cert_from_entry(leaf: bytes, extra_data_b64: str, entry_type: int) -> x509.Certificate:
    if entry_type == 0:  # x509_entry — DER inline in leaf
        clen = int.from_bytes(leaf[12:15], "big")
        der = leaf[15:15 + clen]
        return x509.load_der_x509_certificate(der)
    # precert_entry — full precertificate is first opaque in extra_data
    extra = base64.b64decode(extra_data_b64)
    clen = int.from_bytes(extra[0:3], "big")
    der = extra[3:3 + clen]
    return x509.load_der_x509_certificate(der)


def parse_ct_entry(leaf_input_b64: str, extra_data_b64: str) -> CertRecord | None:
    """Parse a CT ``get-entries`` item into a CertRecord.

    Returns None for unknown entry types; returns a CertRecord with ``error``
    set (and no domains) if the certificate itself fails to parse — so a single
    malformed entry can never crash a bulk ingest.
    """
    try:
        leaf = base64.b64decode(leaf_input_b64)
    except Exception as exc:  # noqa: BLE001
        return CertRecord(-1, 0, [], None, None, None, None, None, error=f"b64: {exc}")
    if len(leaf) < 12:
        return None
    timestamp_ms = struct.unpack(">Q", leaf[2:10])[0]
    entry_type = struct.unpack(">H", leaf[10:12])[0]
    if entry_type not in (0, 1):
        return None
    try:
        cert = _cert_from_entry(leaf, extra_data_b64, entry_type)
    except Exception as exc:  # noqa: BLE001
        return CertRecord(entry_type, timestamp_ms, [], None, None, None, None, None,
                          error=f"cert-parse: {exc}")
    domains, cn = _cert_domains(cert)
    try:
        serial = format(cert.serial_number, "x")
    except Exception:  # noqa: BLE001
        serial = None
    try:
        nb = cert.not_valid_before_utc.isoformat()
        na = cert.not_valid_after_utc.isoformat()
    except AttributeError:  # cryptography < 42 fallback
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
        na = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()
    return CertRecord(
        entry_type=entry_type,
        timestamp_ms=timestamp_ms,
        domains=domains,
        cn=cn,
        issuer=_issuer_org(cert),
        serial=serial,
        fingerprint_sha256=cert_fingerprint(cert),
        fingerprint_sha1=cert_fingerprint_sha1(cert),
        not_before=nb,
        not_after=na,
    )


# --- log client (thin; the CLI/ingester injects the httpx client) ----------

def get_sth(http, log_url: str) -> dict[str, Any]:
    resp = http.get(f"{log_url.rstrip('/')}/ct/v1/get-sth")
    resp.raise_for_status()
    return resp.json()


def get_entries(http, log_url: str, start: int, end: int) -> list[dict[str, Any]]:
    """Fetch entries [start, end]. Logs cap the count and may return a prefix;
    the caller advances by ``len(returned)`` and loops."""
    resp = http.get(
        f"{log_url.rstrip('/')}/ct/v1/get-entries",
        params={"start": start, "end": end},
    )
    resp.raise_for_status()
    return resp.json().get("entries", [])
