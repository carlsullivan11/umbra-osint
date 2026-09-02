"""Subdomain discovery from Umbra's **owned** Certificate Transparency corpus.

The offline counterpart to `crtsh`: same output shape (subdomain DOMAIN
entities + CERT entities + `subdomain_of`/`issued_for` edges), but sourced from
the local CT lake (`umbra ct ingest`) instead of crt.sh — no external API, no
rate limits, no third-party availability dependency. This is the "producer, not
consumer" thesis reaching the case graph.

Honest limitation, surfaced in the collector's own notes: the corpus is
**tail-forward** — it only knows certificates ingested so far, so on a small
corpus it returns less than crt.sh. It is *additive* to `crtsh`, not yet a drop-in
replacement; run both and the graph dedupes by entity key. As the corpus grows
this becomes the primary source and crt.sh the fallback.
"""
from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key, normalize_value, parent_domain
from umbra.db.schema import Entity

_MAX_HOSTS = 200
_MAX_CERTS = 100


def _lake_rows(ctx: CollectorContext, domain: str) -> tuple[list[dict], dict]:
    """Query the owned corpus. Imported lazily so a missing or locked lake never
    breaks collector *registration*, and kept as a seam so the collector can be
    tested without a lake on disk."""
    from umbra.lake.store import LakeStore

    store = LakeStore.from_settings(ctx.settings)
    return store.search(domain, exact=False, limit=1000), store.stats()


class CtLakeCollector(BaseCollector):
    name = "ct_lake"
    timeout_s = 10
    inputs = {EntityType.DOMAIN}
    description = "Subdomains from the owned CT corpus (`umbra ct` — no external API)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        domain = entity.value.strip().lower().rstrip(".")
        result = CollectorResult()
        src_key = entity.norm_key

        try:
            rows, stats = _lake_rows(ctx, domain)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"ct_lake: corpus unavailable ({exc})")
            return result

        corpus_certs = stats.get("certs", 0)
        if not rows:
            result.notes.append(
                f"ct_lake: no certs for {domain} in the owned corpus "
                f"({corpus_certs:,} certs ingested — corpus is tail-forward; "
                f"run `umbra ct ingest` to grow it)"
            )
            return result

        apex = normalize_value(EntityType.DOMAIN, domain)
        names: set[str] = set()
        seen_certs: set[str] = set()

        for row in rows:
            host = (row.get("domain") or "").strip().lower().lstrip("*.")
            if host and " " not in host and (host == domain or host.endswith("." + domain)):
                names.add(host)

            serial = row.get("serial")
            if serial and str(serial) not in seen_certs and len(seen_certs) < _MAX_CERTS:
                seen_certs.add(str(serial))
                issuer = (row.get("issuer") or "").strip()
                if issuer:
                    # The spec's Certificate -> Organization relationship. The
                    # issuing CA is already parsed out of the DER at ingest and
                    # was being dropped on the floor.
                    result.entities.append(EntityIn(
                        type=EntityType.ORG, value=issuer, confidence=0.75,
                        props={"role": "certificate_issuer", "source": "ct_lake"}))
                    result.edges.append(EdgeIn(
                        source_key=entity_key(EntityType.CERT, str(serial)),
                        target_key=entity_key(EntityType.ORG, issuer),
                        rel=EdgeType.ISSUED_FOR, confidence=0.75,
                        props={"role": "issuer", "source": "ct_lake"}))
                result.entities.append(EntityIn(
                    type=EntityType.CERT,
                    value=str(serial),
                    confidence=0.8,
                    props={
                        "issuer": row.get("issuer"),
                        "cn": row.get("cn"),
                        # The certificate's only globally unique id — a serial
                        # is unique per issuer, so it cannot match this cert
                        # against the same cert seen anywhere else.
                        "fingerprint_sha256": row.get("fingerprint_sha256"),
                        # SHA-1 for SSLBL join only (sslbl_cert collector).
                        "fingerprint_sha1": row.get("fingerprint_sha1"),
                        "sha1": row.get("fingerprint_sha1"),
                        "not_before": row.get("not_before"),
                        "not_after": row.get("not_after"),
                        "source": "umbra_ct_lake",
                        "ct_log": row.get("log"),
                        "ct_entry_index": row.get("entry_index"),
                    },
                ))
                result.edges.append(EdgeIn(
                    source_key=entity_key(EntityType.CERT, str(serial)),
                    target_key=src_key,
                    rel=EdgeType.ISSUED_FOR,
                    confidence=0.8,
                ))

        for host in sorted(names)[:_MAX_HOSTS]:
            result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.85))
            hkey = entity_key(EntityType.DOMAIN, host)
            if host != apex:
                result.edges.append(EdgeIn(
                    source_key=hkey, target_key=src_key,
                    rel=EdgeType.SUBDOMAIN_OF, confidence=0.9,
                ))
            parent = parent_domain(host)
            if parent and parent != host:
                result.entities.append(EntityIn(type=EntityType.DOMAIN, value=parent, confidence=0.7))
                result.edges.append(EdgeIn(
                    source_key=hkey, target_key=entity_key(EntityType.DOMAIN, parent),
                    rel=EdgeType.PARENT_DOMAIN, confidence=0.7,
                ))

        result.evidence.append(EvidenceIn(
            collector=self.name,
            source_name="Umbra CT corpus (owned)",
            source_url=None,
            summary=(
                f"{len(names)} name(s) and {len(seen_certs)} cert(s) for {domain} "
                f"from the owned CT corpus ({corpus_certs:,} certs ingested)"
            ),
            confidence=0.9,  # exact index match on locally-verified CT data
            raw={"names": sorted(names)[:50], "certs": len(seen_certs),
                 "corpus_certs": corpus_certs},
            entity_key=src_key,
        ))
        result.notes.append(
            f"ct_lake: {len(names)} name(s) from owned corpus (no external API)"
        )
        return result
