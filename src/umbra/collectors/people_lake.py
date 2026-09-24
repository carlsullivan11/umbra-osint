"""The owned person corpora, reachable from a case at last (H3 / S1a).

**No collector imported `FecLake`.** 2,250,469 contributor records — name, city,
state, employer, occupation, contribution counts, all public FEC filings — were
reachable only from the `/people` web page. The largest corpus Umbra owns could
not be reached from an investigation. `PeopleLake`'s 14,663 people were barely
better: three collectors touch it and the planner selected them for one case out
of a thousand.

So a person search in a case returned this:

    public_records_portals  Linked 18 free portals for manual search
    edgar_search            browse_hits=0 efts_total=0
    opencorporates          captcha wall or block — not scraped

Eighteen links to go and do it yourself, a miss from a corporate-filings
database, and a permanent error.

Offline, like `mac_oui` and `email_profile`: no request, no key, nothing to
rate-limit. The search itself is `umbra.people.search.unified_search`, reused
rather than reimplemented — there must be one place that decides how the two
lakes are read together, and it already has tests.

**Evidence, and no entities.** An FEC row says *somebody with this name, in this
city, gave money and listed this employer*. Promoting that to an ORG entity
joined to a PERSON asserts that a particular person works somewhere, which the
filing does not establish. `umbra.people.search` refuses to merge the two lakes
for the same reason. The record belongs in evidence; the claim belongs nowhere.

**Ambiguity is the finding.** At 2.25M rows a common name matches people in many
states, and saying how many is what makes a result usable instead of misleading.
Returning the first few quietly implies the search found *someone*; it found
many.
"""
from __future__ import annotations

import logging

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EntityType, EvidenceIn
from umbra.db.schema import Entity

logger = logging.getLogger(__name__)

#: Named at module level so tests can substitute them without a lake on disk.
def _lake(ctx: CollectorContext):
    from umbra.lake.people import PeopleLake

    return PeopleLake.from_settings(ctx.settings)


def _search(lake, query: str, **kwargs):
    from umbra.people.search import unified_search

    return unified_search(lake, query, **kwargs)


def _states(rows: list[dict]) -> list[str]:
    out: list[str] = []
    for r in rows or []:
        s = (r.get("state") or "").strip().upper()
        if s and s not in out:
            out.append(s)
    return sorted(out)


def summarize(query: str, result) -> str:
    """One line a human can act on, including how much the name narrows.

    The count and the state list are the substance. "Found 12 records" reads as
    a hit; "12 records across 4 states — this is a name match" reads as what it
    is, and the difference is whether the reader goes on to identify the wrong
    person.
    """
    people = list(getattr(result, "people", None) or [])
    contributors = list(getattr(result, "contributors", None) or [])
    total = len(people) + len(contributors)

    if not total:
        return (f"No record naming {query} in the owned corpora (people lake, "
                f"FEC contributors). Coverage is partial — that is unchecked, "
                f"not an absence of the person.")

    parts: list[str] = []
    if people:
        parts.append(f"{len(people)} in the people lake")
    if contributors:
        states = _states(contributors)
        where = f" across {len(states)} state(s) ({', '.join(states)})" if states else ""
        parts.append(f"{len(contributors)} FEC contributor record(s){where}")

    line = f"{query}: " + "; ".join(parts) + "."
    if getattr(result, "ambiguous", False):
        line += (" These are name matches across more than one state — a shared "
                 "name is not one person, and this data cannot tell them apart.")
    else:
        line += " A name match is not an identification."
    return line


class PeopleLakeCollector(BaseCollector):
    name = "people_lake"
    timeout_s = 15
    inputs = {EntityType.PERSON}
    description = "Owned person corpora: obituary/kinship people lake + 2.25M FEC contributors (offline)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        query = (entity.value or "").strip()
        if not query:
            return result

        try:
            lake = _lake(ctx)
        except Exception as exc:  # noqa: BLE001
            # An optional multi-GB lake failing to open is not an absence of the
            # person, and must never read as one.
            result.notes.append(
                f"people_lake: corpora unavailable ({exc}) — unchecked, not a "
                "statement about {query}".format(query=query))
            return result

        try:
            found = _search(lake, query, limit=20)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"people_lake: search failed ({exc}) — unchecked")
            return result
        finally:
            try:
                lake.close()
            except Exception:  # noqa: BLE001
                pass

        summary = summarize(query, found)
        people = list(getattr(found, "people", None) or [])
        contributors = list(getattr(found, "contributors", None) or [])

        if not (people or contributors):
            result.notes.append(f"people_lake: {summary}")
            return result

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                # No URL: this is Umbra's own corpus and there is no third-party
                # page to cite. Inventing one would be worse than citing none.
                source_name="local:owned person corpora (people lake + FEC)",
                summary=summary,
                # High: the rows are public filings read from an owned copy.
                # What is *uncertain* is whether they are the same person, and
                # that is what the summary says rather than what the number does.
                confidence=0.85,
                raw={
                    "people": people[:10],
                    "contributors": contributors[:10],
                    "people_total": len(people),
                    "contributor_total": len(contributors),
                    "states": _states(contributors),
                    "ambiguous": bool(getattr(found, "ambiguous", False)),
                },
                entity_key=entity.norm_key,
            )
        )

        note = getattr(found, "note", "") or ""
        if note:
            result.notes.append(f"people_lake: {note}")
        return result
