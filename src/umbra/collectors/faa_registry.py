"""N-number → registrant of record, from the owned FAA lake (offline).

Reads a local table. No network call, no API key, and deliberately no live
flight data: this answers "who holds the registration", which is a records
question, not a where-is-it-now question.

What it will not do, and why each one matters:

- **Claim an operator or a pilot.** The MASTER file records the holder of the
  certificate of registration. Trusts, LLCs and management companies are
  ordinary registrants for airframes flown by other people entirely, so
  "registered to X" is not "X was flying it" and is not "X was aboard".
- **Report a miss as "not registered".** Besides the usual stale-lake reasons,
  the FAA runs a PII-withholding programme under 49 U.S.C. § 44114(b) — an
  owner may ask that their name and address be withheld from public
  dissemination. Absence here can be a live registration whose owner opted
  out, so absence is *unchecked*.
- **Turn an individual's name into a graph node.** When `TYPE REGISTRANT` says
  the holder is a person rather than an organisation, the name is reported in
  the evidence but no PERSON entity is created — minting one invites a pivot
  into person collectors off a record that says nothing about conduct.
"""
from __future__ import annotations

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
from umbra.lake.faa import (
    DOCUMENTATION_URL,
    SOURCE_PAGE,
    FaaLake,
    default_lake,
    normalize_n_number,
)

_ROLE_NOTE = (
    "The FAA registry names the holder of the certificate of registration. That "
    "is not necessarily the operator, the lessee, or whoever was flying — "
    "trusts, LLCs and management companies routinely register aircraft flown by "
    "someone else."
)

_WITHHELD_NOTE = (
    "Absence here means unchecked, not an absence of registration: under "
    "49 U.S.C. § 44114(b) an owner may ask the FAA to withhold their name and "
    "address from public dissemination, so a registration that is current can "
    "still be missing from this file."
)


class FaaRegistryCollector(BaseCollector):
    name = "faa_registry"
    timeout_s = 5
    version = "0.1.0"
    inputs = {EntityType.AIRCRAFT}
    description = (
        "Resolve a US N-number to its registrant of record and airframe from "
        "the owned FAA registry lake (offline)"
    )

    def __init__(self, lake: FaaLake | None = None) -> None:
        self._lake = lake

    @property
    def lake(self) -> FaaLake:
        return self._lake if self._lake is not None else default_lake()

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()

        n_number = normalize_n_number(entity.value)
        if not n_number:
            result.notes.append(f"Not a US N-number: {entity.value!r}")
            return result

        lake = self.lake
        status = lake.status()
        if not status.get("available"):
            # Distinguished from a miss on purpose: an empty lake tells you
            # nothing about the aircraft, and saying so is the difference
            # between "unchecked" and a false all-clear.
            result.notes.append(
                "FAA registry lake is empty — run `umbra faa sync` to enable "
                "N-number lookups. Nothing was checked, so this is unknown "
                "rather than unregistered."
            )
            return result

        hit = lake.lookup(n_number)
        if hit is None:
            result.notes.append(
                f"{n_number} is not in the FAA registry lake "
                f"(imported {status.get('imported_at') or 'unknown date'})."
            )
            result.notes.append(_WITHHELD_NOTE)
            return result

        result.notes.append(_ROLE_NOTE)
        src_key = entity.norm_key

        # The registrant becomes an ORG node only when the file says the holder
        # *is* an organisation, and even then as a candidate: the name is a
        # string in a government file, not a verified corporate identity, so it
        # is a lead to confirm against a corporate registry rather than a fact.
        if hit.registrant_name and hit.registrant_is_org:
            result.entities.append(
                EntityIn(type=EntityType.ORG, value=hit.registrant_name, confidence=0.6)
            )
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.ORG, hit.registrant_name),
                    rel=EdgeType.REGISTERED_BY,
                    confidence=0.6,
                    props={
                        "registrant_type": hit.registrant_type,
                        "candidate": True,
                        "note": "registrant of record; confirm against a corporate registry",
                    },
                )
            )
            result.notes.append(
                f"{hit.registrant_name} is recorded as the registrant "
                f"({hit.registrant_type}). Added as a candidate organisation to "
                "confirm against a corporate registry — the FAA file is a name "
                "string, not a verified corporate identity."
            )
        elif hit.registrant_name:
            result.notes.append(
                f"Registrant of record is an individual or co-owner "
                f"({hit.registrant_type or 'type not stated'}). The name is in "
                "the evidence below; no person entity is created from a "
                "registration record."
            )

        summary_bits = [f"{hit.n_number} is registered to {hit.registrant_name or 'an unnamed holder'}"]
        if hit.manufacturer or hit.model:
            summary_bits.append(f"on a {hit.airframe_label()}")
        if hit.year_manufactured:
            summary_bits.append(f"({hit.year_manufactured})")

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name=(
                    f"FAA Releasable Aircraft Database "
                    f"({status.get('edition') or 'ReleasableAircraft.zip'}, "
                    f"imported {status.get('imported_at') or 'unknown'})"
                ),
                source_url=SOURCE_PAGE,
                summary=" ".join(summary_bits),
                confidence=0.85,
                raw={
                    **hit.as_dict(),
                    "lake_edition": status.get("edition"),
                    "lake_imported_at": status.get("imported_at"),
                    "documentation": DOCUMENTATION_URL,
                },
                entity_key=src_key,
            )
        )

        if hit.status_code and hit.status_code != "V":
            result.notes.append(
                f"Registration status code is {hit.status_code!r}, not 'V' "
                "(valid) — the registration may be expired, cancelled or in "
                "process. See the FAA documentation for the code list."
            )
        return result
