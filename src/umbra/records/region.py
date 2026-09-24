"""Work out which county a parcel layer belongs to, or admit you cannot.

352,679 rows were stored with NULL state and county — in the lake, unsearchable
by location, and counting for nothing in the coverage ledger. That is why it read
`0 of 3,143` while 408,935 records sat in the table: the ledger was honest and
the rows were anonymous.

The source registry is no help. All eight affected layers have NULL region there
too, so this was never captured rather than lost. What a layer does carry is its
URL and, usually, ArcGIS service metadata. Probed live on 2026-09-16:

    Florida_Statewide_Cadastral  "…provided by each of Florida's 67 county
                                  property appraisers"
    RussellCountyGIS             "Russell County, KS"
    Chowan_Feature_Service       "Chowan_Feature_Service"

The middle one is the case that earns this module. Russell County exists in AL,
KS, KY and VA; the metadata is the only thing on hand that says which.

**Nothing is invented.** Every candidate is resolved against the real county
list, and a name that does not match one stays unknown. A NULL is visibly
unknown; a wrong county is not, and a parcel search filtered to the wrong county
is worse than one that admits it has no filter.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from umbra.records.coverage import STATE_NAMES

#: `…sheboygancounty.com` — a county that runs its own GIS names itself in the
#: hostname, which is the most reliable signal available short of metadata.
_HOST_COUNTY = re.compile(r"([a-z]+?)county\.(?:com|org|net|gov|us)", re.I)

#: "Russell County, KS" / "Chowan County, North Carolina"
_COUNTY_STATE = re.compile(
    r"\b([A-Z][A-Za-z.'\-]+(?:\s+[A-Z][A-Za-z.'\-]+)?)\s+County\s*,\s*"
    r"([A-Za-z]{2}|[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b")

#: `Florida_Statewide_Cadastral`, `North Carolina Statewide Parcels`. Matched by
#: finding the keyword and reading *backwards*, because a forward regex with an
#: optional second word is greedy and swallows the token before the state —
#: `.../rest/services/Florida_Statewide/...` captured "services Florida".
_STATEWIDE_WORD = re.compile(r"\bstatewide\b", re.I)

_NAME_TO_ABBR = {name.lower(): abbr for abbr, name in STATE_NAMES.items()}


@dataclass(frozen=True, slots=True)
class Region:
    state: str | None = None
    county: str | None = None
    #: One layer covering a whole state. Not a county, and not one of them —
    #: Florida's cadastral layer is 67 counties in a single FeatureServer.
    statewide: bool = False
    #: Where the answer came from, so a wrong one can be traced and corrected.
    basis: str = "unresolved"


def _abbr(token: str) -> str | None:
    t = (token or "").strip()
    if not t:
        return None
    if len(t) == 2 and t.upper() in STATE_NAMES:
        return t.upper()
    return _NAME_TO_ABBR.get(t.lower())


#: Words that are part of a county's *type*, not its name. `lookup_county`
#: matches on substring, so the bare token "City" resolved to "Juneau City and
#: Borough, AK" — and 23,471 rows of a Homestead, Florida layer were about to be
#: labelled Alaskan. A confidently wrong county is worse than a NULL, because a
#: NULL is visibly unknown.
_GENERIC_PLACE = {"city", "town", "village", "borough", "parish", "county",
                  "municipality", "district", "area", "park", "of", "and", "the"}


def _confirm(county: str, state: str | None, *, exact: bool = False) -> Region | None:
    """Accept a county only if it exists, and only if the state is settled.

    `exact` is for the weakest signal — a bare token lifted out of a service
    name. There the token has to *be* the county's name rather than appear
    inside it, because "City" appears inside a great many of them.
    """
    from umbra.geo.us_counties import lookup_county

    name = (county or "").strip()
    if not name or name.lower() in _GENERIC_PLACE:
        return None

    hit = lookup_county(f"{name} County", state)
    if not hit:
        hit = lookup_county(name, state)
    if not hit or not hit.get("state"):
        return None

    resolved = hit.get("name") or name
    if exact:
        bare = re.sub(r"\s+(county|parish|borough|city and borough|municipality|"
                      r"census area|city|district)\s*$", "", resolved, flags=re.I).strip()
        if bare.lower() != name.lower():
            return None
    return Region(state=hit["state"], county=resolved)


def region_from_layer(layer_url: str, metadata: str = "") -> Region:
    """Resolve a layer's region from its URL and service metadata.

    Order is by how much the signal can be trusted: an explicit "X County, ST"
    in the metadata beats a hostname, which beats a service name. Anything that
    does not confirm against the real county list is discarded rather than
    downgraded — a half-confident county is still a county on a search filter.
    """
    url = (layer_url or "").strip()
    meta = (metadata or "").strip()
    blob = f"{meta} {url}"

    # 1. Statewide. Checked first: a statewide layer often also mentions
    #    counties ("each of Florida's 67 county property appraisers"), and
    #    matching one of those would turn 67 counties into one.
    for text in (meta, url.replace("/", " ").replace("_", " ").replace("-", " ")):
        m = _STATEWIDE_WORD.search(text or "")
        if not m:
            continue
        before = (text[: m.start()]).split()
        # Two words first: "North Carolina Statewide" must not resolve on
        # "Carolina" alone.
        for take in (2, 1):
            if len(before) >= take:
                abbr = _abbr(" ".join(before[-take:]))
                if abbr:
                    return Region(state=abbr, statewide=True,
                                  basis=f"statewide layer named for {STATE_NAMES[abbr]}")

    # 2. "X County, ST" in the metadata — the only thing that disambiguates a
    #    county name shared by several states.
    m = _COUNTY_STATE.search(meta)
    if m:
        abbr = _abbr(m.group(2))
        if abbr:
            got = _confirm(m.group(1), abbr)
            if got:
                return Region(state=got.state, county=got.county,
                              basis=f"service metadata named {got.county}, {got.state}")

    # 3. A county that hosts its own GIS names itself in the hostname.
    host = (urlsplit(url).hostname or "")
    m = _HOST_COUNTY.search(host)
    if m:
        got = _confirm(m.group(1), None)
        if got:
            return Region(state=got.state, county=got.county,
                          basis=f"hostname {host}")

    # 4. A service name like `Chowan_Feature_Service`. Weakest: it carries no
    #    state, so it only resolves when the name is unique across all of them.
    for token in re.split(r"[/_\-\s]+", url.rsplit("/FeatureServer", 1)[0].rsplit("/", 1)[-1]):
        # "county" itself must be in the stop list. Without it,
        # `Nowhereville_County_Parcels` fed the bare word "County" to
        # `lookup_county`, which matched the first county in the list and
        # confidently labelled 0 rows as Autauga County, Alabama.
        if len(token) < 4 or token.lower() in {"feature", "service", "layers",
                                               "parcels", "parcel", "map", "gis",
                                               "rest", "services", "data",
                                               "public", "county", "counties",
                                               "boundaries", "cadastral", "tax",
                                               "land", "property", "integration"}:
            continue
        got = _confirm(token, None, exact=True)
        if got:
            return Region(state=got.state, county=got.county,
                          basis=f"service name {token!r}")

    return Region(basis="no state or county derivable from the layer")
