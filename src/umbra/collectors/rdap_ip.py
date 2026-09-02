from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


class RdapIpCollector(BaseCollector):
    name = "rdap_ip"
    timeout_s = 20
    inputs = {EntityType.IP}
    description = "RDAP/IP network registration (ASN, org)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        ip = entity.value
        result = CollectorResult()
        url = f"https://rdap.org/ip/{ip}"
        try:
            resp = ctx.http.get(url, follow_redirects=True)
            if resp.status_code == 404:
                result.notes.append(f"RDAP IP not found for {ip}")
                return result
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"RDAP IP error: {exc}")
            return result

        src_key = entity.norm_key
        name = data.get("name") or data.get("handle")
        if name:
            result.entities.append(EntityIn(type=EntityType.ORG, value=str(name), confidence=0.65))
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.ORG, str(name)),
                    target_key=src_key,
                    rel=EdgeType.HOSTS,
                    confidence=0.6,
                )
            )

        for cidr in data.get("cidr0_cidrs") or []:
            # informational props
            pass

        # entities with roles
        for ent in data.get("entities") or []:
            vcard = ent.get("vcardArray")
            org_name = None
            if isinstance(vcard, list) and len(vcard) >= 2:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        org_name = str(item[3])
            if org_name:
                if org_name.strip().lower() not in {"admin", "abuse", "registrant", "technical", "billing", "noc"}:
                    result.entities.append(EntityIn(type=EntityType.ORG, value=org_name, confidence=0.6))
                    result.edges.append(
                        EdgeIn(
                            source_key=entity_key(EntityType.ORG, org_name),
                            target_key=src_key,
                            rel=EdgeType.OWNS,
                            confidence=0.55,
                        )
                    )

        # ASN links sometimes in "links" or remarks — best effort from "network" type entities
        for ent in data.get("entities") or []:
            handle = ent.get("handle") or ""
            if handle.upper().startswith("AS") and handle[2:].isdigit():
                result.entities.append(EntityIn(type=EntityType.ASN, value=handle, confidence=0.7))
                result.edges.append(
                    EdgeIn(
                        source_key=src_key,
                        target_key=entity_key(EntityType.ASN, handle),
                        rel=EdgeType.MEMBER_OF,
                        confidence=0.7,
                    )
                )

        result.entities.append(
            EntityIn(
                type=EntityType.IP,
                value=ip,
                confidence=0.9,
                props={
                    "rdap_name": data.get("name"),
                    "rdap_type": data.get("type"),
                    "rdap_country": data.get("country"),
                    "startAddress": data.get("startAddress"),
                    "endAddress": data.get("endAddress"),
                },
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="RDAP-IP",
                source_url=url,
                summary=f"RDAP network data for {ip}",
                confidence=0.8,
                raw=data,
                entity_key=src_key,
            )
        )
        return result
