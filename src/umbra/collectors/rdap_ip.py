from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _abuse_email(data: dict) -> str | None:
    """The abuse contact from an RDAP entity vcard, if the registry published one.

    This is the single most actionable field in an RDAP record — it is who you
    tell about the address — and it was being parsed out of the vcard array and
    then dropped.
    """
    for ent in data.get("entities") or []:
        roles = [str(r).lower() for r in (ent.get("roles") or [])]
        if "abuse" not in roles:
            continue
        vcard = ent.get("vcardArray") or []
        if len(vcard) < 2:
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "email":
                text = str(item[3]).strip()
                if text:
                    return text
    return None


def summarize_network(ip: str, data: dict) -> str:
    """One line describing the network an address belongs to.

    Replaces `f"RDAP network data for {ip}"`, which was true of every RDAP
    response ever returned and therefore told a reader nothing. Everything here
    was already fetched and stored in `raw`; only the summary was empty.
    """
    name = (data.get("name") or data.get("handle") or "").strip()
    parts: list[str] = []

    if name:
        parts.append(str(name))
    start, end = data.get("startAddress"), data.get("endAddress")
    if start and end:
        parts.append(f"{start}–{end}")
    country = (data.get("country") or "").strip()
    if country:
        parts.append(str(country))
    net_type = (data.get("type") or "").strip()
    if net_type:
        parts.append(str(net_type))

    head = f"{ip} is in " + ", ".join(parts) if parts else f"{ip}: registry returned no network detail"

    abuse = _abuse_email(data)
    if abuse:
        head += f" — abuse contact {abuse}"
    return head


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
                summary=summarize_network(ip, data),
                confidence=0.8,
                raw=data,
                entity_key=src_key,
            )
        )
        return result
