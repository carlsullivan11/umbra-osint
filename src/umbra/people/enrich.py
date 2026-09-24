"""Records → people lake.

`county_sources`, `land_facts` and `sor_sources` have had tables and indexes
since the lake was built, and have held zero rows the whole time. Meanwhile
`umbra.records.search` already unifies court opinions, parcel owner-name hits
and portal pointers across 100 verified sources, and the lake already has a
writer for each kind. Nothing was missing except the wire between them.

Two rules this bridge exists to hold:

**A portal is not a record.** `RecordHit.is_record` is False for portals — they
point at a place to look, not at a finding about anybody. Writing one into the
lake would convert "here is the county's search page" into "this person appears
in county records", which is the single most misleading thing a people search
can do.

**A name hit is not an identification.** A parcel whose owner field contains
"John Smith" belongs to *a* John Smith. `name_hit` stays a flag on the row
rather than being promoted into a claim, and nothing here raises a person's
confidence on the strength of a string match.
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

#: Assessor detail strings put the parcel number in a handful of shapes:
#: "APN 123-45-678", "Parcel: 12345", "PIN 00-11-22".
_APN_RE = re.compile(
    r"\b(?:apn|parcel(?:\s*(?:id|no|number|#))?|pin)\b\s*[:#]?\s*([A-Za-z0-9][A-Za-z0-9\-./]{2,})",
    re.I,
)

#: Court hits land in `county_sources` — it is the lake's table for
#: "a public record naming this person", and a court opinion is one. A separate
#: court table would duplicate its shape for no gain.
_COURT_KINDS = {"court_opinion", "court_docket"}


def extract_apn(detail: str | None) -> str | None:
    """Parcel number from an assessor detail string, or None."""
    if not detail:
        return None
    m = _APN_RE.search(detail)
    if not m:
        return None
    apn = m.group(1).strip(" .,;")
    return apn or None


def enrich_from_records(lake, name: str, search: Any) -> dict:
    """Write a RecordSearch into the people lake under `name`.

    Idempotent: the lake's writers key on the source URL, so re-running a search
    updates rows rather than duplicating them.

    Returns counts per kind plus `portals_skipped`, so a caller can say what was
    deliberately not written instead of leaving the difference unexplained.
    """
    stats = {
        "land": 0, "court": 0, "county": 0, "portals_skipped": 0,
        "errors": 0, "note": "",
    }
    person = (name or "").strip()
    if not person:
        stats["note"] = "no name given; nothing was searched"
        return stats

    # The person row first, so records always have something to hang from even
    # when every source came back empty.
    lake.upsert_person_from_parse(
        decedent_name=person,
        parse={},
        source_url=f"umbra:records:{person}",
        title=person,
        source_host="umbra-records",
        confidence=0.3,
    )

    for hit in list(getattr(search, "parcels", []) or []):
        if not getattr(hit, "is_record", True):
            stats["portals_skipped"] += 1
            continue
        apn = extract_apn(getattr(hit, "detail", ""))
        situs = (getattr(hit, "title", "") or "").strip() or None
        if not (apn or situs):
            continue
        try:
            lake.upsert_land_fact(
                source_url=hit.url,
                person_name=person,
                apn=apn,
                situs=situs,
                region=getattr(hit, "region", "") or None,
                excerpt=getattr(hit, "detail", "") or None,
            )
            stats["land"] += 1
        except Exception as exc:  # noqa: BLE001 - one bad row must not lose the rest
            logger.warning("land fact for %s failed: %s", person, exc)
            stats["errors"] += 1

    for hit in list(getattr(search, "court", []) or []):
        if not getattr(hit, "is_record", True):
            stats["portals_skipped"] += 1
            continue
        try:
            lake.upsert_county_source(
                url=hit.url,
                person_name=person,
                region=getattr(hit, "region", "") or None,
                kind=getattr(hit, "kind", "court_opinion"),
                title=getattr(hit, "title", "") or None,
                excerpt=getattr(hit, "detail", "") or None,
                # The source matched a name string. It did not confirm a person,
                # and the flag is the whole of what is being claimed.
                name_hit=True,
            )
            stats["court"] += 1
            stats["county"] += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("county source for %s failed: %s", person, exc)
            stats["errors"] += 1

    # Portals are counted, never written.
    stats["portals_skipped"] += sum(
        1 for _ in (getattr(search, "portals", []) or [])
    )

    written = stats["land"] + stats["county"]
    if written:
        stats["note"] = (
            f"{written} record(s) written for {person}. A name match is not an "
            "identification: these records name someone with this name."
        )
    else:
        # Deliberately not "no records": the sources that were searched had
        # nothing, which is a statement about coverage, not about the person.
        stats["note"] = (
            f"The sources searched returned nothing for {person}. Coverage is "
            "partial — that is unchecked, not an absence of records."
        )
    return stats
