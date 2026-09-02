"""MAC → registrant lookup against the owned OUI lake (stage S13 / M3).

Offline: this reads a local table, makes no network calls, and needs no key.

What it deliberately does **not** do:

- Guess a vendor. A miss is reported as a miss.
- Resolve a locally administered address to a manufacturer. Those have no IEEE
  registrant by construction, so any vendor string would be invented.
- Imply location. A MAC is a layer-2 identifier: it does not appear on the
  public Internet and cannot be geolocated. That note goes on every result,
  because a confident vendor name is exactly what invites the question.
"""
from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.mac import mac_facts
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
from umbra.lake.oui import OuiTable, default_table

_L2_NOTE = (
    "A MAC address is a layer 2 (link-local) identifier: it is not routable on "
    "the public Internet and cannot be geolocated from the address alone."
)


class MacOuiCollector(BaseCollector):
    name = "mac_oui"
    timeout_s = 5
    version = "0.1.0"
    inputs = {EntityType.MAC}
    description = "Resolve a MAC address to its IEEE registrant from the owned OUI lake (offline)"

    def __init__(self, table: OuiTable | None = None) -> None:
        self._table = table

    @property
    def table(self) -> OuiTable:
        return self._table if self._table is not None else default_table()

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        try:
            facts = mac_facts(entity.value)
        except ValueError as exc:
            result.notes.append(f"Not a MAC address: {exc}")
            return result

        result.notes.append(_L2_NOTE)
        result.notes.extend(facts["notes"])

        if facts["is_probably_randomized"]:
            # No registrant exists. Stop before the vendor claim.
            return result

        table = self.table
        if not table.available:
            result.notes.append(
                "OUI corpus not available — clone umbra-wiki or set UMBRA_OUI_CSV "
                "to enable vendor resolution (see docs/OSS.md)."
            )
            return result

        hit = table.lookup(facts["mac"])
        if not hit:
            result.notes.append(
                f"No registration found for {facts['oui']} — unknown or unassigned prefix."
            )
            return result

        vendors = hit.get("vendors") or [hit["vendor"]]
        src_key = entity.norm_key

        for vendor in vendors:
            result.entities.append(
                EntityIn(type=EntityType.ORG, value=vendor, confidence=0.9)
            )
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.ORG, vendor),
                    rel=EdgeType.REGISTERED_BY,
                    confidence=0.9,
                    props={"prefix": hit["prefix"], "registry": hit["registry"]},
                )
            )

        if len(vendors) > 1:
            result.notes.append(
                f"IEEE lists {len(vendors)} organisations for {hit['prefix']} "
                "(a legacy shared registration) — all are recorded."
            )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="IEEE MAC address registries (via umbra-wiki OUI lake)",
                source_url="https://standards-oui.ieee.org/",
                summary=(
                    f"{facts['mac']} is registered to {hit['vendor']} "
                    f"({hit['registry']}, /{hit['bits']} prefix {hit['prefix']})"
                ),
                confidence=0.9,
                raw={
                    "mac": facts["mac"],
                    "prefix": hit["prefix"],
                    "bits": hit["bits"],
                    "registry": hit["registry"],
                    "vendors": vendors,
                    "is_multicast": facts["is_multicast"],
                    "is_local": facts["is_local"],
                },
                entity_key=src_key,
            )
        )

        if hit["bits"] > 24:
            result.notes.append(
                f"Matched a /{hit['bits']} {hit['registry']} block, not the 24-bit "
                "parent — the parent block is registered to a different holder."
            )
        return result
