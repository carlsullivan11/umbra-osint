"""ASN / BGP origin via Team Cymru DNS interface — no REST API key."""

from __future__ import annotations

import dns.exception
import dns.resolver

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.dns import get_resolver
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _cymru_query_ipv4(ip: str, resolver: dns.resolver.Resolver) -> list[str]:
    # 1.2.3.4 -> 4.3.2.1.origin.asn.cymru.com TXT
    parts = ip.split(".")
    if len(parts) != 4:
        return []
    qname = ".".join(reversed(parts)) + ".origin.asn.cymru.com"
    try:
        ans = resolver.resolve(qname, "TXT")
        out = []
        for rr in ans:
            if hasattr(rr, "strings"):
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            else:
                out.append(rr.to_text().strip('"'))
        return out
    except Exception:
        return []


def _cymru_query_ipv6(ip: str, resolver: dns.resolver.Resolver) -> list[str]:
    # Expand and nibble-reverse into origin6.asn.cymru.com
    try:
        import ipaddress

        addr = ipaddress.IPv6Address(ip)
        exploded = addr.exploded.replace(":", "")
        nibbles = ".".join(reversed(exploded))
        qname = f"{nibbles}.origin6.asn.cymru.com"
        ans = resolver.resolve(qname, "TXT")
        out = []
        for rr in ans:
            if hasattr(rr, "strings"):
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            else:
                out.append(rr.to_text().strip('"'))
        return out
    except Exception:
        return []


def _asn_peer(asn: str, resolver: dns.resolver.Resolver) -> list[str]:
    # AS15169.asn.cymru.com TXT -> ASN | CC | Registry | Allocated | AS Name
    num = asn.upper().replace("AS", "").strip()
    qname = f"AS{num}.asn.cymru.com"
    try:
        ans = resolver.resolve(qname, "TXT")
        out = []
        for rr in ans:
            if hasattr(rr, "strings"):
                out.append(b"".join(rr.strings).decode("utf-8", "replace"))
            else:
                out.append(rr.to_text().strip('"'))
        return out
    except Exception:
        return []


class AsnCymruCollector(BaseCollector):
    name = "asn_cymru"
    timeout_s = 15
    inputs = {EntityType.IP}
    description = "ASN/BGP origin via Team Cymru DNS (no API key)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        ip = entity.value
        src = entity.norm_key
        resolver = get_resolver()
        resolver.lifetime = min(8.0, ctx.settings.request_timeout_s)

        if ":" in ip:
            rows = _cymru_query_ipv6(ip, resolver)
        else:
            rows = _cymru_query_ipv4(ip, resolver)

        if not rows:
            result.notes.append(f"Cymru: no origin for {ip}")
            return result

        # Format: "15169 | 8.8.8.0/24 | US | arin |"
        parsed = []
        for row in rows:
            parts = [p.strip() for p in row.split("|")]
            asn = parts[0] if parts else ""
            prefix = parts[1] if len(parts) > 1 else ""
            cc = parts[2] if len(parts) > 2 else ""
            registry = parts[3] if len(parts) > 3 else ""
            parsed.append(
                {"asn": asn, "prefix": prefix, "cc": cc, "registry": registry, "raw": row}
            )
            if asn and asn.isdigit():
                as_id = f"AS{asn}"
                # AS name
                name_rows = _asn_peer(asn, resolver)
                as_name = None
                if name_rows:
                    # "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
                    np = [p.strip() for p in name_rows[0].split("|")]
                    if len(np) >= 5:
                        as_name = np[4]
                result.entities.append(
                    EntityIn(
                        type=EntityType.ASN,
                        value=as_id,
                        display_name=as_name or as_id,
                        confidence=0.9,
                        props={"as_name": as_name, "cc": cc, "registry": registry, "prefix": prefix},
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.ASN, as_id),
                        rel=EdgeType.MEMBER_OF,
                        confidence=0.9,
                        props={"prefix": prefix},
                    )
                )
                if as_name:
                    # org-ish
                    org = as_name.split(",")[0].strip()
                    # strip trailing " - Google LLC" patterns
                    if " - " in org:
                        org = org.split(" - ", 1)[-1].strip()
                    if org and len(org) > 2:
                        result.entities.append(EntityIn(type=EntityType.ORG, value=org, confidence=0.55))
                        result.edges.append(
                            EdgeIn(
                                source_key=entity_key(EntityType.ASN, as_id),
                                target_key=entity_key(EntityType.ORG, org),
                                rel=EdgeType.OWNS,
                                confidence=0.5,
                            )
                        )

        result.entities.append(
            EntityIn(
                type=EntityType.IP,
                value=ip,
                confidence=0.9,
                props={"cymru": parsed},
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="Team Cymru DNS",
                source_url="https://www.team-cymru.com/ip-asn-mapping",
                summary=f"Cymru origin for {ip}: {parsed}",
                confidence=0.9,
                raw={"rows": rows, "parsed": parsed},
                entity_key=src,
            )
        )
        return result
