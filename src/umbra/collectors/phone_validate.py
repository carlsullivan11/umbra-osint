"""Offline phone validation collector (Phase A).

libphonenumber only: E.164, validity, numbering-plan type, display formats.
No network, no CNAM, no carrier API, no owner identity.
"""
from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity
from umbra.phone.normalize import phone_facts

_SCOPE_NOTE = (
    "Offline numbering-plan validation only. Not a live line check, not caller ID, "
    "and not a person or spam verdict."
)


class PhoneValidateCollector(BaseCollector):
    name = "phone_validate"
    timeout_s = 5
    version = "0.1.0"
    inputs = {EntityType.PHONE}
    description = (
        "Validate and format a phone number with libphonenumber (offline, no key)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        result.notes.append(_SCOPE_NOTE)

        facts = phone_facts(entity.value)
        if not facts.get("possible") or not facts.get("e164"):
            result.notes.append(
                facts.get("notes") and facts["notes"][0]
                or "Not a possible phone number under the default numbering plan."
            )
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="libphonenumber (Google)",
                    source_url="https://github.com/google/libphonenumber",
                    summary=f"Could not validate phone input {entity.value!r}",
                    confidence=0.2,
                    raw=facts,
                    entity_key=entity.norm_key,
                )
            )
            return result

        e164 = facts["e164"]
        src_key = entity_key(EntityType.PHONE, e164)
        result.notes.extend(facts.get("notes") or [])

        # Merge facts onto the seed (same pattern as reputation collectors).
        result.entities.append(
            EntityIn(
                type=EntityType.PHONE,
                value=e164,
                confidence=0.95 if facts.get("valid") else 0.7,
                props={
                    "phone_e164": e164,
                    "phone_possible": bool(facts.get("possible")),
                    "phone_valid": bool(facts.get("valid")),
                    "phone_country_code": facts.get("country_code"),
                    "phone_region": facts.get("region"),
                    "phone_type": facts.get("number_type"),
                    "phone_national": facts.get("national_format"),
                    "phone_international": facts.get("international_format"),
                    # Reputation page reads these for a one-glance answer.
                    "reputation_verdict": "valid" if facts.get("valid") else "possible",
                    "reputation_score": 0,
                    "reputation_checked": 1,
                    "reputation_sources": ["libphonenumber"],
                    "phone_layer": "validate",
                },
            )
        )

        summary = (
            f"{facts.get('international_format') or e164}: "
            f"{'valid' if facts.get('valid') else 'possible'} "
            f"{facts.get('number_type') or 'unknown'} "
            f"({facts.get('region') or '??'})"
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="libphonenumber (Google)",
                source_url="https://github.com/google/libphonenumber",
                summary=summary,
                confidence=0.9 if facts.get("valid") else 0.65,
                raw=facts,
                entity_key=src_key,
            )
        )
        return result
