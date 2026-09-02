from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key, is_email
from umbra.db.schema import Entity


class RdapDomainCollector(BaseCollector):
    name = "rdap_domain"
    timeout_s = 20
    inputs = {EntityType.DOMAIN}
    description = "RDAP lookup for domain registration data"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        domain = entity.value
        result = CollectorResult()
        url = f"https://rdap.org/domain/{domain}"
        try:
            resp = ctx.http.get(url, follow_redirects=True)
            if resp.status_code == 404:
                result.notes.append(f"RDAP not found for {domain}")
                return result
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 — collector boundary
            result.notes.append(f"RDAP error: {exc}")
            return result

        src_key = entity.norm_key
        # registrar
        for entity_obj in data.get("entities") or []:
            roles = entity_obj.get("roles") or []
            vcard = entity_obj.get("vcardArray")
            name = None
            emails: list[str] = []
            if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if not isinstance(item, list) or len(item) < 4:
                        continue
                    label = item[0]
                    val = item[3]
                    if label == "fn":
                        name = str(val)
                    if label == "email" and isinstance(val, str):
                        emails.append(val)
            if "registrar" in roles and name:
                result.entities.append(EntityIn(type=EntityType.REGISTRAR, value=name, confidence=0.85))
                result.edges.append(
                    EdgeIn(
                        source_key=src_key,
                        target_key=entity_key(EntityType.REGISTRAR, name),
                        rel=EdgeType.REGISTERED_BY,
                        confidence=0.85,
                    )
                )
            if "registrant" in roles and name:
                # skip role-looking labels
                if name.strip().lower() not in {"admin", "abuse", "registrant", "technical", "billing", "noc"}:
                    result.entities.append(EntityIn(type=EntityType.ORG, value=name, confidence=0.6))
                    result.edges.append(
                        EdgeIn(
                            source_key=entity_key(EntityType.ORG, name),
                            target_key=src_key,
                            rel=EdgeType.OWNS,
                            confidence=0.55,
                        )
                    )
            for em in emails:
                if is_email(em):
                    result.entities.append(EntityIn(type=EntityType.EMAIL, value=em, confidence=0.7))
                    result.edges.append(
                        EdgeIn(
                            source_key=src_key,
                            target_key=entity_key(EntityType.EMAIL, em),
                            rel=EdgeType.USES_EMAIL,
                            confidence=0.7,
                        )
                    )

        for ns in data.get("nameservers") or []:
            host = (ns.get("ldhName") or ns.get("unicodeName") or "").rstrip(".").strip()
            if not host:
                continue
            result.entities.append(EntityIn(type=EntityType.NAMESERVER, value=host.lower(), confidence=0.8))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.NAMESERVER, host.lower()),
                    rel=EdgeType.HAS_NS,
                    confidence=0.8,
                )
            )

        events = data.get("events") or []
        result.entities.append(
            EntityIn(
                type=EntityType.DOMAIN,
                value=domain,
                confidence=0.9,
                props={"rdap_events": events[:10], "rdap_status": data.get("status")},
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="RDAP",
                source_url=url,
                summary=f"RDAP registration data for {domain}",
                confidence=0.85,
                raw=data,
                entity_key=src_key,
            )
        )
        return result
