"""Parcel coverage against all 3,143 counties, and targeted discovery to close it.

Discovery ran five generic catalog queries — `title:parcels AND type:"Feature
Service"` and four like it. The ArcGIS catalog returns what it likes for a
generic term, which is why 3,143 counties yielded one or two verified layers per
state. And nothing anywhere said *which* counties were missing, so "expand
coverage" had no target and no finish line.

Two pieces here.

**Targeted queries.** A state name and a county name are the discriminating
terms. 51 state queries plus one query per still-uncovered county is a plan;
five generic queries is a lottery.

**A ledger.** Coverage is counted against the real county list, so an absent
owner reads as "Orange County, TX is not ingested" and never as an answer about
a person. "Every county" is only a meaningful goal if the gap is countable, and
this is what makes it countable.

A caveat that belongs in the code rather than in an optimistic README: **not
every county publishes an open layer.** Many use proprietary assessor portals
with no API at all. The ceiling on this approach is the set of counties that
publish, and the ledger's job is to say where that ceiling actually is instead
of leaving the shortfall implied.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Iterable

logger = logging.getLogger(__name__)

STATE_NAMES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware",
    "DC": "District of Columbia", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana",
    "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
    "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan",
    "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri", "MT": "Montana",
    "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
    "NM": "New Mexico", "NY": "New York", "NC": "North Carolina",
    "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma", "OR": "Oregon",
    "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah",
    "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
}

_SUFFIX_RE = re.compile(
    r"\s+(county|parish|borough|census area|city and borough|municipality|"
    r"city|district)\s*$",
    re.I,
)

_BASE = 'type:"Feature Service" AND access:public'


def _bare(county: str | None) -> str:
    """County name without its type suffix.

    "Orange County County parcels" finds nothing, and registries write both
    "Orange" and "Orange County" for the same place.
    """
    return _SUFFIX_RE.sub("", (county or "").strip()).strip()


def _key(state: str | None, county: str | None) -> str:
    return f"{(state or '').upper()}|{_bare(county).lower()}"


def _all_counties() -> list[dict[str, str]]:
    """Every county-equivalent, flattened."""
    from umbra.geo.us_counties import counties_for_state

    out: list[dict[str, str]] = []
    for abbr in STATE_NAMES:
        for row in counties_for_state(abbr) or []:
            name = row.get("n") or row.get("name") or ""
            if name:
                out.append({"state": abbr, "county": name,
                            "fips": row.get("f") or row.get("fips") or ""})
    return out


def state_queries() -> list[str]:
    """One catalog query per state. A statewide layer covers every county in it,
    so these are the highest-leverage searches available."""
    return [
        f'{_BASE} AND title:parcels AND "{name}"'
        for name in STATE_NAMES.values()
    ]


def county_queries(counties: Iterable[dict[str, Any]], *,
                   limit: int | None = None) -> list[str]:
    """One query per county. Bounded, because 3,143 counties is 3,143 requests
    and a sweep needs to take a slice rather than the whole list each run."""
    out: list[str] = []
    for row in counties or []:
        if limit is not None and len(out) >= limit:
            break
        bare = _bare(row.get("county"))
        state = (row.get("state") or "").upper()
        if not bare:
            continue
        name = STATE_NAMES.get(state, state)
        out.append(f'{_BASE} AND title:parcels AND "{bare}" AND "{name}"')
    return out


def _covered_keys(lake) -> set[str]:
    """County keys with at least one ingested row.

    A layer probed to zero rows has covered nobody, and a statewide layer covers
    every county in its state — counting that as one would understate NC by 99.
    """
    covered: set[str] = set()
    try:
        rows = lake.coverage() or []
    except Exception:  # noqa: BLE001
        return covered

    from umbra.geo.us_counties import counties_for_state

    for row in rows:
        if not int(row.get("rows") or 0):
            continue
        state = (row.get("state") or "").upper()
        county = row.get("county")
        if row.get("statewide") and state:
            for c in counties_for_state(state) or []:
                covered.add(_key(state, c.get("n") or c.get("name")))
            continue
        if not state or not county:
            # A layer whose region never resolved is not a claim about a state.
            continue
        covered.add(_key(state, county))
    return covered


def coverage_report(lake) -> dict[str, Any]:
    """How much of the country the parcel lake actually holds."""
    everything = _all_counties()
    covered = _covered_keys(lake)
    hit = sum(1 for c in everything if _key(c["state"], c["county"]) in covered)
    total = len(everything)
    missing = total - hit

    # `count()`, not the sum of `ingested.rows`. That column records what each
    # run *wrote*; rows whose storage key collided were never stored, so the sum
    # overstated the lake. On 2026-09-16 the two figures were printed a second
    # apart and disagreed by 77,675 — "881,971 owner records" from the ingest and
    # "959,646 owner records" from this report, for the same lake.
    parcels = 0
    try:
        parcels = int(lake.count())
    except Exception:  # noqa: BLE001
        parcels = 0

    note = (
        f"{hit:,} of {total:,} counties ingested; {missing:,} not covered. "
        "A name absent from this lake means its county is not ingested — that "
        "is unchecked, never an absence of property. Not every county "
        "publishes an open parcel layer, so some of the gap is a ceiling "
        "rather than a backlog."
    )
    return {
        "counties_total": total,
        "counties_covered": hit,
        "counties_missing": missing,
        "percent": round(100.0 * hit / total, 2) if total else 0.0,
        "parcels": parcels,
        "note": note,
    }


def uncovered_counties(lake, *, limit: int | None = None) -> list[dict[str, str]]:
    """The counties still missing, named. "Expand coverage" needs a target
    list, not a percentage."""
    covered = _covered_keys(lake)
    out = [c for c in _all_counties()
           if _key(c["state"], c["county"]) not in covered]
    return out[:limit] if limit is not None else out
