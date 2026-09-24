"""Person name → publishable animal-abuse registry findings (offline).

Reads the owned registry lake; no network. Every hit is a **finding** — a
conviction, plea, registry listing or civil order — with the record it came
from, because that is the only kind of row the lake stores.

What it will not do:

- **Treat a name as an identity.** Hits are reported as evidence on the person
  already in the case, never as new PERSON nodes, and only exact or
  first+last matches count. Initial-only and surname matches are counted in a
  note, not reported: on a registry of offences, a weak name match is an
  accusation against a stranger.
- **Report a miss as a clean record.** The lake holds the sources someone
  imported, not every court in the country; charges, sealed and expunged
  cases are deliberately absent.
- **Read around the publication rules.** Removed, expired, suppressed and
  disputed rows are invisible here exactly as they are on any public surface.
"""
from __future__ import annotations

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EntityType, EvidenceIn
from umbra.db.schema import Entity
from umbra.lake.animal_registry import AnimalRegistryLake

_STRONG = {"exact": 0.7, "partial": 0.55}

_IDENTITY_NOTE = (
    "A registry hit is a name on an official finding, not an identification. "
    "Confirm identity against the linked record (location, date, case number) "
    "before relying on it. Consumer-reporting uses are subject to the FCRA."
)

_ABSENCE_NOTE = (
    "No registry finding is not a clean record: the lake covers only the sources "
    "imported into it, and never holds charges, sealed or expunged cases."
)


def _state_of(entity: Entity) -> str | None:
    props = entity.props or {}
    for key in ("state", "region"):
        value = str(props.get(key) or "").strip().upper()
        if len(value) == 2 and value.isalpha():
            return value
    return None


class AnimalRegistryCollector(BaseCollector):
    name = "animal_registry"
    timeout_s = 5
    version = "0.1.0"
    inputs = {EntityType.PERSON}
    description = (
        "Offline lookup of cited animal-abuse findings (convictions, pleas, "
        "government registry listings) in the owned registry lake; candidate, "
        "not identity"
    )

    def __init__(self, lake: AnimalRegistryLake | None = None) -> None:
        self._lake = lake

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        name = (entity.value or entity.display_name or "").strip()
        if len(name.replace(",", " ").split()) < 2:
            result.notes.append("animal_registry needs a first and last name")
            return result

        lake = self._lake or AnimalRegistryLake.from_settings(ctx.settings)
        try:
            status = lake.status()
            if not status["available"]:
                result.notes.append(
                    "Animal-abuse registry lake has no publishable findings — "
                    "import a source with `umbra animal-registry import-csv`. "
                    "Nothing was checked, so this is unknown, not clean.")
                return result

            state = _state_of(entity)
            hits = lake.search(name, state=state, limit=50)
            strong = [h for h in hits if h["match"] in _STRONG]
            weak = len(hits) - len(strong)

            for h in strong[:10]:
                where = ", ".join(p for p in (h["city"], h["county"], h["state"]) if p)
                summary = (
                    f"{h['name_raw']}: {h['disposition'].replace('_', ' ')} — "
                    f"{h['offense']}"
                    + (f" ({h['finding_date']})" if h["finding_date"] else "")
                    + (f", {where}" if where else "")
                )
                result.evidence.append(
                    EvidenceIn(
                        collector=self.name,
                        source_name=h["source_name"],
                        source_url=h["source_url"],
                        entity_key=entity.norm_key,
                        summary=summary[:240],
                        confidence=_STRONG[h["match"]],
                        raw={
                            "entry_id": h["entry_id"],
                            "match": h["match"],
                            "disposition": h["disposition"],
                            "offense": h["offense"],
                            "statute": h["statute"],
                            "finding_date": h["finding_date"],
                            "citation": h["citation"],
                            "state": h["state"],
                            "identity_confirmed": False,
                        },
                    )
                )

            scope = f" in {state}" if state else ""
            result.notes.append(
                f"{len(strong)} registry finding(s){scope} matched on first+last name")
            if weak:
                result.notes.append(
                    f"{weak} weaker match(es) (initial or surname only) not reported")
            result.notes.append(_IDENTITY_NOTE if strong else _ABSENCE_NOTE)
            return result
        finally:
            if self._lake is None:
                lake.close()
