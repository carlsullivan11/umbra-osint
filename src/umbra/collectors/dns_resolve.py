from __future__ import annotations

import dns.exception
import dns.resolver

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.dns import get_resolver
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


class DnsResolveCollector(BaseCollector):
    name = "dns_resolve"
    timeout_s = 15
    inputs = {EntityType.DOMAIN}
    description = "Resolve A/AAAA/MX/NS/TXT/CNAME for a domain"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        domain = entity.value
        result = CollectorResult()
        records: dict[str, list[str]] = {}

        resolver = get_resolver()
        resolver.lifetime = min(10.0, ctx.settings.request_timeout_s)

        def _query(rtype: str) -> list[str]:
            try:
                ans = resolver.resolve(domain, rtype)
                return sorted({rr.to_text().strip('"') for rr in ans})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return []
            except dns.exception.DNSException:
                return []

        for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
            vals = _query(rtype)
            if vals:
                records[rtype] = vals

        src_key = entity.norm_key

        for ip in records.get("A", []) + records.get("AAAA", []):
            result.entities.append(EntityIn(type=EntityType.IP, value=ip, confidence=0.9))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.IP, ip),
                    rel=EdgeType.RESOLVES_TO,
                    confidence=0.9,
                    props={"rr": "A/AAAA"},
                )
            )

        for cname in records.get("CNAME", []):
            cname_n = cname.rstrip(".")
            result.entities.append(EntityIn(type=EntityType.DOMAIN, value=cname_n, confidence=0.85))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.DOMAIN, cname_n),
                    rel=EdgeType.RESOLVES_TO,
                    confidence=0.85,
                    props={"rr": "CNAME"},
                )
            )

        for mx in records.get("MX", []):
            # format: "10 mail.example.com."
            parts = mx.split()
            host = parts[-1].rstrip(".") if parts else mx
            host = host.strip().rstrip(".")
            if not host or host == ".":
                continue
            result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.8, props={"role": "mx"}))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.DOMAIN, host),
                    rel=EdgeType.HAS_MX,
                    confidence=0.8,
                )
            )

        for ns in records.get("NS", []):
            host = ns.rstrip(".").strip()
            if not host or host == ".":
                continue
            result.entities.append(
                EntityIn(type=EntityType.NAMESERVER, value=host, confidence=0.85)
            )
            # Do NOT also emit DOMAIN for NS — prevents root-server graph blowups
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.NAMESERVER, host),
                    rel=EdgeType.HAS_NS,
                    confidence=0.85,
                )
            )

        if records.get("TXT"):
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=src_key,
                    rel=EdgeType.HAS_TXT,
                    confidence=0.5,
                    props={"count": len(records["TXT"])},
                )
            )
            # self-edge filtered later; store TXT on entity via evidence instead

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="DNS",
                source_url=None,
                summary=f"DNS records for {domain}: {', '.join(records.keys()) or 'none'}",
                confidence=0.9,
                raw=records,
                entity_key=src_key,
            )
        )
        # attach txt into props via entity update
        if records.get("TXT"):
            result.entities.append(
                EntityIn(
                    type=EntityType.DOMAIN,
                    value=domain,
                    confidence=0.9,
                    props={"txt": records["TXT"][:20]},
                )
            )
        return result
