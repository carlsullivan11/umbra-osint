"""Offline facts about an address — U6.

`EMAIL` had three collectors: `email_split`, `gravatar`, and `hibp_breach`
behind a key that is not set. A production search of a yahoo.com address came
back with 55 rows, 51 of them about Yahoo's hosting infrastructure.

Scoping the pivot (`Orchestrator._seed_apexes`) removed those 51. This puts
something in their place that is actually about the address: whether it names a
person or a function, whether the provider is a throwaway, and what form it
delivers to.

Offline, like `mac_oui` and `iana_port`. No request, no key, no rate limit —
the answers were always derivable from the string.
"""
from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EntityIn, EntityType, EvidenceIn
from umbra.db.schema import Entity
from umbra.email.profile import profile_email


class EmailProfileCollector(BaseCollector):
    name = "email_profile"
    timeout_s = 5
    inputs = {EntityType.EMAIL}
    description = "Offline address facts: role account, disposable, provider class, delivery form"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        address = (entity.value or "").strip()
        if "@" not in address:
            result.notes.append(f"email_profile: {address!r} is not an address")
            return result

        p = profile_email(address)
        bits = [f"provider={p['provider_class']}"]
        if p["role_account"]:
            bits.append("role account")
        # `provider=disposable` already says it; repeating it reads like two
        # findings where there is one.
        if p["disposable"] and p["provider_class"] != "disposable":
            bits.append("disposable")
        if p["canonical"] != p["address"]:
            bits.append(f"delivers to {p['canonical']}")

        # Confidence is high because none of this is inferred from a third
        # party — it is the address, read carefully.
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="local:email_profile",
                summary=f"{p['address']}: " + ", ".join(bits),
                confidence=0.95,
                raw=p,
                entity_key=entity.norm_key,
            )
        )
        if p["note"]:
            result.notes.append(f"email_profile: {p['note']}")

        # The delivery form as its own entity, so two spellings of one mailbox
        # converge in the graph instead of sitting beside each other unlinked.
        if p["canonical"] and p["canonical"] != p["address"]:
            result.entities.append(
                EntityIn(type=EntityType.EMAIL, value=p["canonical"], confidence=0.9)
            )

        return result
