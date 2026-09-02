from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


class EmailSplitCollector(BaseCollector):
    name = "email_split"
    timeout_s = 5
    inputs = {EntityType.EMAIL}
    description = "Split email into domain + local username entities"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        email = entity.value
        if "@" not in email:
            return result
        local, domain = email.rsplit("@", 1)
        src = entity.norm_key
        result.entities.append(EntityIn(type=EntityType.DOMAIN, value=domain, confidence=0.95))
        result.entities.append(
            EntityIn(
                type=EntityType.USERNAME,
                value=f"email:{local}",
                confidence=0.7,
                display_name=local,
            )
        )
        result.edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.DOMAIN, domain),
                rel=EdgeType.LINKED_FROM,
                confidence=0.95,
                props={"via": "email_domain"},
            )
        )
        result.edges.append(
            EdgeIn(
                source_key=src,
                target_key=entity_key(EntityType.USERNAME, f"email:{local}"),
                rel=EdgeType.SAME_AS,
                confidence=0.5,
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="local:email_split",
                summary=f"Split {email} → domain={domain}, local={local}",
                confidence=1.0,
                raw={"local": local, "domain": domain},
                entity_key=src,
            )
        )
        return result
