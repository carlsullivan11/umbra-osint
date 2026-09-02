"""One search across court, county and property records.

The pieces existed and none of them were reachable by typing a name. Court
records lived inside the investigation path, county portals were link lists a
collector walked during a case, property facts were a lake table with no query
in front of it. "Umbra has a court records collector" and "you can search court
records in Umbra" turned out to be very different statements.

This is the second one. `search(name)` returns three sections, and each says
plainly what kind of thing it is, because they are not equally strong:

    court     live from CourtListener — actual records, national coverage
    property  live from statewide parcel layers — real assessor rows, 5 states
    lake      what Umbra already holds about the name (obits, kinship, land, corp)
    portals   where to look for county and property records in a given region

**The portals section is links, not records, and says so.** It is the fallback
for the counties nothing else reaches: 3,143 counties run 3,143 systems, and 40
of the 288 portals behind our packs actively refuse automation. A link to the
right assessor search page beats a scraped fragment that breaks next month —
but calling it a "record" would be a lie.

Property used to be portals only. `umbra.records.parcels` changed that for the
five states that publish a statewide ArcGIS parcel layer, which is a real
answer rather than a link — and stays loudly five states rather than implying
national coverage.

**A name match is never an identity.** Same rule as `court_records`, and it
applies to every row here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_NAME_OK = re.compile(r"^[\w .,'\-]{3,80}$", re.U)


@dataclass
class RecordHit:
    """One row. `kind` decides how much weight a reader should give it."""

    kind: str            # court_opinion | court_docket | obituary | land | corp | portal
    title: str
    url: str
    detail: str = ""
    region: str = ""
    source: str = ""
    #: portals are pointers, not findings. Kept explicit so the UI cannot blur it.
    is_record: bool = True
    reachable: str = ""  # portals only: fetchable | link_only | blocked_by_guard | broken


@dataclass
class RecordSearch:
    query: str
    court: list[RecordHit] = field(default_factory=list)
    #: NOT named `property` — that shadows the @property decorator below.
    parcels: list[RecordHit] = field(default_factory=list)
    lake: list[RecordHit] = field(default_factory=list)
    portals: list[RecordHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def record_count(self) -> int:
        """Actual records — portals deliberately excluded."""
        return len(self.court) + len(self.parcels) + len(self.lake)

    def as_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "record_count": self.record_count,
            "court": [h.__dict__ for h in self.court],
            "property": [h.__dict__ for h in self.parcels],
            "lake": [h.__dict__ for h in self.lake],
            "portals": [h.__dict__ for h in self.portals],
            "notes": self.notes,
        }


def _court(name: str, http, limit: int = 10) -> tuple[list[RecordHit], list[str]]:
    from umbra.collectors.court_records import API, FCRA_NOTE, SEARCH_TYPES, SITE

    hits: list[RecordHit] = []
    notes: list[str] = []
    found_any = False

    for code, label in SEARCH_TYPES:
        try:
            resp = http.get(API, params={"q": f'"{name}"', "type": code},
                            headers={"Accept": "application/json"}, timeout=20)
            resp.raise_for_status()
            payload = resp.json()
        except Exception as exc:  # noqa: BLE001
            from umbra.core.notes import describe_http_failure
            notes.append(describe_http_failure(f"courtlistener_{label}", exc, API))
            continue

        count = int(payload.get("count") or 0)
        rows = (payload.get("results") or [])[:limit]
        if count:
            found_any = True
        if count > len(rows):
            notes.append(
                f"{count:,} {label} result(s); showing {len(rows)}. A large count "
                f"usually means a common name, not a prolific litigant."
            )
        for row in rows:
            case = (row.get("caseName") or row.get("case_name_full") or "").strip()
            if not case:
                continue
            path = (row.get("absolute_url") or "").strip()
            court = (row.get("court") or "").strip()
            filed = (row.get("dateFiled") or "").strip()
            hits.append(RecordHit(
                kind=f"court_{label}",
                title=case,
                url=f"{SITE}{path}" if path.startswith("/") else (path or SITE),
                detail=" · ".join(x for x in (court, filed) if x),
                source="CourtListener (Free Law Project)",
            ))

    if found_any:
        notes.append(FCRA_NOTE)
    else:
        notes.append(
            "No CourtListener match. That covers federal courts and the state "
            "courts CourtListener has ingested — not every court, and not sealed "
            "or expunged matters. Absence is not a clean record."
        )
    return hits, notes


def _lake(name: str, settings) -> tuple[list[RecordHit], list[str]]:
    """Obituaries, land and corporate facts Umbra already holds."""
    hits: list[RecordHit] = []
    notes: list[str] = []
    try:
        from umbra.lake.people import PeopleLake

        lake = PeopleLake.from_settings(settings)
    except Exception as exc:  # noqa: BLE001
        return [], [f"people lake unreadable: {exc}"]

    try:
        for row in lake.land_for_name(name)[:20]:
            hits.append(RecordHit(
                kind="land", title=row.get("situs") or row.get("apn") or "parcel",
                url=row.get("source_url") or "",
                detail=" · ".join(x for x in (row.get("apn"), row.get("region")) if x),
                region=row.get("region") or "", source="county assessor (owned lake)"))
        for row in lake.corps_for_name(name)[:20]:
            hits.append(RecordHit(
                kind="corp", title=row.get("org_name") or "entity",
                url=row.get("source_url") or "",
                detail=" · ".join(x for x in (row.get("file_number"), row.get("region")) if x),
                region=row.get("region") or "", source="state registry (owned lake)"))
        for person in lake.lookup_name(name, limit=3):
            for obit in lake.obituaries_for_person(person["id"])[:5]:
                hits.append(RecordHit(
                    kind="obituary", title=person.get("name") or name,
                    url=obit.get("url", ""), detail=obit.get("source") or "",
                    source="obituary (owned lake)"))
        status = lake.status()
        if not status.land_facts and not status.corp_facts:
            # The tables are empty because the county collector has only ever run
            # inside an investigation. Saying so beats an empty section.
            notes.append(
                "The land and corporate tables are empty in this lake — they fill "
                "from `county_records` during an investigation, not from this "
                "search. Empty here means not yet collected, not none exist."
            )
    except Exception as exc:  # noqa: BLE001
        notes.append(f"people lake query failed: {exc}")
    finally:
        lake.close()
    return hits, notes


def _portals(region: str | None, settings) -> tuple[list[RecordHit], list[str]]:
    """Where to look for county and property records. Pointers, not findings."""
    from umbra.collectors.public_records_portals import _PORTALS

    if not region:
        return [], []

    key = region.strip().lower()
    packs = _PORTALS.get(key)
    notes: list[str] = []
    if not packs:
        # Same *state*, not same country. Splitting on "us" matched every
        # us-* pack and took the first six alphabetically, so a New York miss
        # helpfully offered Alaska, Alabama and Arkansas.
        parts = key.split("-")
        prefix = "-".join(parts[:2]) if len(parts) >= 2 else key
        near = sorted(k for k in _PORTALS if k.startswith(prefix) and k != key)[:6]
        notes.append(
            f"No portal pack for {key!r}. "
            + (f"Related packs: {', '.join(near)}." if near else
               "L2 county packs cover 75 of 3,143 counties; the rest inherit "
               "state and federal sources only.")
        )
        return [], notes

    health: dict[str, str] = {}
    try:
        from umbra.people.portal_health import PortalHealth

        ph = PortalHealth.from_settings(settings)
        try:
            for row in ph.for_region(key):
                health[row["url"]] = row["status"]
        finally:
            ph.close()
    except Exception:  # noqa: BLE001
        pass

    hits = [
        RecordHit(
            kind="portal", title=p.get("name", ""), url=p["url"],
            detail=p.get("kind", ""), region=key, source="record portal",
            is_record=False, reachable=health.get(p["url"], ""),
        )
        for p in packs
    ]
    blocked = [h for h in hits if h.reachable in ("link_only", "broken", "blocked_by_guard")]
    if blocked:
        notes.append(
            f"{len(blocked)} of {len(hits)} portal(s) here cannot be read "
            f"automatically — open them yourself. Umbra records the link because "
            f"that is what it can honestly offer for these."
        )
    return hits, notes


def state_of(region: str | None) -> str | None:
    """`us-ar-benton` -> `AR`. The region string already carries the state."""
    parts = (region or "").strip().lower().split("-")
    if len(parts) >= 2 and parts[0] == "us" and len(parts[1]) == 2:
        return parts[1].upper()
    return None


def _property(name: str, http, region: str | None, settings=None) -> tuple[list[RecordHit], list[str]]:
    """Live parcel rows from statewide assessor layers."""
    from umbra.records.parcels import COVERED_STATES, search as search_parcels

    state = state_of(region)
    # With no region, ask every covered state — a name search should not require
    # knowing which of five states to guess.
    found = search_parcels(name, http=http, states=[state] if state else None,
                           settings=settings)

    hits = [
        RecordHit(
            kind="parcel",
            title=p.owner,
            url=p.url,
            detail=" · ".join(x for x in (p.address, p.city,
                                          f"assessed {p.value}" if p.value else "") if x),
            region=" ".join(x for x in (p.county, p.state) if x).strip(),
            source=p.source,
        )
        for p in found.hits
    ]
    notes = list(found.notes)
    county = "-".join((region or "").strip().lower().split("-")[2:])
    statewide = bool(state and state in COVERED_STATES)

    if county and hits:
        # Neither tier filters to the named county, but for different reasons,
        # and saying the wrong one would be worse than saying nothing.
        if statewide:
            # One layer covers the state and is queried that way on purpose:
            # people own land across county lines, and hiding the parcel one
            # county over would be wrong in the direction that matters.
            notes.append(
                f"The region names {county} county, but the {state} statewide "
                f"layer was searched in full — owners hold property across "
                f"county lines. The county column shows where each parcel is."
            )
        else:
            notes.append(
                f"The region names {county} county. {state} has no statewide "
                f"layer, so every verified {state} county layer was searched — "
                f"the county column shows where each parcel actually is."
            )

    # Only a genuine absence of coverage. Printing "no parcel layer for NY"
    # above 75 New York parcels — which is what this did before registry
    # layers existed — is the exact dishonesty this module exists to avoid.
    if state and not statewide and not hits:
        notes.append(
            f"No parcel layer for {state}. Umbra queries "
            f"{', '.join(COVERED_STATES)} statewide, plus whatever county "
            f"layers it has verified into its own registry; elsewhere the "
            f"county portal links below are the honest answer."
        )
    return hits, notes


def search(name: str, *, http, settings, region: str | None = None,
           limit: int = 10) -> RecordSearch:
    """Court + lake + portals for one name."""
    query = (name or "").strip()
    out = RecordSearch(query=query)

    if not _NAME_OK.match(query):
        out.notes.append(
            f"{query!r} is not a name-shaped query, so nothing was sent to any "
            "public source."
        )
        return out

    out.court, court_notes = _court(query, http, limit=limit)
    out.parcels, prop_notes = _property(query, http, region, settings)
    out.lake, lake_notes = _lake(query, settings)
    out.portals, portal_notes = _portals(region, settings)
    out.notes = court_notes + prop_notes + lake_notes + portal_notes

    out.notes.append(
        "Every row is a name match, not a confirmed identity. Court records name "
        "defendants who were acquitted and people who merely share a name."
    )
    return out
