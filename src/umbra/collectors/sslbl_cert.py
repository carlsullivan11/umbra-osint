"""Certificate → known malware C2, via abuse.ch SSLBL in the owned lake.

The join Umbra is uniquely placed to make. SSLBL publishes the SHA1 fingerprints
of certificates observed on malware command-and-control servers; Umbra already
collects certificates from live TLS (`tls_cert`) and owns a Certificate
Transparency corpus (`ct_lake`). Once both sides are local, "is this host's
certificate a known controller certificate" is a primary-key lookup — no API, no
key, no rate limit.

**The fingerprint has to line up.** SSLBL is SHA1-only; Umbra keys certificates
on SHA256, because that is what CT and modern tooling use. Rather than weaken
the identity, the SHA1 rides along in the certificate's props — see
`tls_cert` and `umbra.lake.ct.cert_fingerprint_sha1`.

**A certificate with no fingerprint was not checked.** `crtsh` identifies
certificates by serial number, so those entities cannot be looked up here. That
is reported as unchecked, never as not-listed: a cert that was never compared to
the blacklist is not a cert that passed it.
"""
from __future__ import annotations

import logging

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import (
    CollectorResult,
    EdgeIn,
    EdgeType,
    EntityIn,
    EntityType,
    EvidenceIn,
)
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

logger = logging.getLogger(__name__)

SOURCE_URL = "https://sslbl.abuse.ch/blacklist/"


def _lake(ctx: CollectorContext):
    """Seam for tests; lazy so a missing lake cannot break registration."""
    from umbra.lake.store import LakeStore

    return LakeStore.from_settings(ctx.settings)


def _sha1_of(entity: Entity) -> str:
    """The SHA1 fingerprint, wherever the producing collector put it."""
    props = getattr(entity, "props", None) or {}
    for key in ("sha1", "fingerprint_sha1", "sha1_fingerprint"):
        value = str(props.get(key) or "").strip().replace(":", "").lower()
        if len(value) == 40 and all(c in "0123456789abcdef" for c in value):
            return value
    # A cert entity keyed on its own SHA1 (some importers do this) is still a
    # valid lookup.
    value = str(getattr(entity, "value", "") or "").strip().replace(":", "").lower()
    if len(value) == 40 and all(c in "0123456789abcdef" for c in value):
        return value
    return ""


class SslblCertCollector(BaseCollector):
    name = "sslbl_cert"
    timeout_s = 10
    version = "0.1.0"
    inputs = {EntityType.CERT}
    description = ("Certificate against the abuse.ch SSL Blacklist of malware C2 "
                   "certificates, from the owned lake — no API key, no network")

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        sha1 = _sha1_of(entity)

        try:
            lake = _lake(ctx)
            synced = lake.abuse_feed_synced_at("sslbl")
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"sslbl_cert: abuse.ch lake unavailable ({exc})")
            return result

        if not sha1:
            result.notes.append(
                "sslbl_cert: not checked — this certificate has no SHA1 "
                "fingerprint (crt.sh identifies certificates by serial number; "
                "run `tls_cert` against the host to fetch the certificate itself)")
            return result
        if not synced:
            result.notes.append(
                "sslbl_cert: not checked — SSLBL has never been synced into this "
                "lake (run `umbra abuse sync`)")
            return result

        try:
            hit = lake.abuse_cert(sha1)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"sslbl_cert: lookup failed ({exc})")
            return result

        if not hit:
            result.notes.append(
                f"sslbl_cert: not listed — {sha1[:12]}… is not on the abuse.ch "
                f"SSL Blacklist (checked {synced[:10]})")
            return result

        family = (hit.get("malware") or "").strip()
        reason = hit.get("reason") or "malware C2"
        src_key = entity.norm_key

        if family:
            result.entities.append(EntityIn(
                type=EntityType.MALWARE, value=family, confidence=0.9,
                props={"source": "sslbl", "role": reason},
            ))
            result.edges.append(EdgeIn(
                source_key=src_key,
                target_key=entity_key(EntityType.MALWARE, family),
                rel=EdgeType.INDICATOR_OF, confidence=0.9,
                props={"source": "sslbl", "reason": reason},
            ))
        result.evidence.append(EvidenceIn(
            collector=self.name,
            source_name="abuse.ch SSLBL (owned lake)",
            source_url=SOURCE_URL,
            summary=f"certificate {sha1[:12]}… is blacklisted: {reason}",
            confidence=0.9,
            raw={"sha1": sha1, "reason": reason, "malware": family,
                 "listed_at": hit.get("listed_at"), "feed": "sslbl"},
            entity_key=src_key,
        ))
        result.notes.append(
            f"sslbl_cert: this certificate is on the abuse.ch SSL Blacklist "
            f"({reason}, listed {hit.get('listed_at') or 'unknown date'}) — "
            f"a strong indicator the host is malware infrastructure")
        return result
