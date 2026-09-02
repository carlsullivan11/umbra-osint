"""Property records by owner name — from statewide assessor layers, not scrapers.

The open question in `umbra.records` was whether property could ever be more
than a link. Portals are honest but weak: 3,143 counties, 3,143 systems, 40 of
our 288 portal URLs actively refusing automation. Writing 3,143 scrapers is not
a plan, it is a hobby that fails quietly one clerk's-office redesign at a time.

The answer turned out to be the same shape as CourtListener, one level up:
**ArcGIS REST is a protocol, and states already publish parcels on it.** A
state aggregates its counties' CAMA rolls into one layer with a documented
`/query` endpoint, and that endpoint speaks the same dialect everywhere. One
client covers every state that publishes one — no key, no scraping, no HTML.

Each source here was probed before it was added. Not assumed — probed:

    AR  gis.arkansas.gov          ownername   200/req    county CAMA rolls
    CT  services3.arcgis.com      Owner       2000/req   parcels + CAMA 2023
    NC  services.nconemap.gov     ownname     5000/req   NC OneMap
    VT  services1.arcgis.com      OWNER1      2000/req   VCGI standardized
    WI  services3.arcgis.com      OWNERNME1   —          statewide initiative

Five states name the owner field five different ways, which is exactly why the
field map is per-source data rather than a clever guess.

**Coverage is stated, never implied.** Five states is five states. A search for
a Texas name returns *no rows* here, and that must read as "Umbra does not cover
Texas" and never as "this person owns no property". `unchecked != clean` is the
whole reason `covered_states` is reported alongside the hits.

**These are homes.** A name query returns a real person's residential address
and what their county thinks it is worth. It is public record — states publish
it deliberately, and that is what makes using it lawful — but "lawful" is not
"harmless", so the caution rides along with the results rather than living in a
policy page. And as everywhere else in this module: a name match is not an
identity. `SMITH, JAMES` is thousands of people.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

#: Only these survive into a SQL `where`. Everything else is dropped before the
#: string is built, so the escaping below is a second line of defence rather
#: than the only one.
_SAFE = re.compile(r"[^A-Za-z0-9 '\-.&]")

#: A single token this short matches most of the state. Requiring two useful
#: tokens is what keeps "Jo" from returning a quarter of Connecticut.
_MIN_TOKEN = 3


@dataclass(frozen=True)
class ParcelSource:
    """One statewide parcel layer, with the field names it actually uses."""

    state: str
    label: str
    url: str
    owner: str
    #: Field names vary wildly; any of these may be absent from a given row.
    address: str = ""
    city: str = ""
    parcel_id: str = ""
    value: str = ""
    county: str = ""
    attribution: str = ""
    #: Some layers cap harder than others. Ask for no more than they will give.
    page: int = 200
    #: How this layer is named in notes. Statewide sources are their state;
    #: a county layer says which county, so several in one state stay distinct.
    note_label: str = ""

    def where_label(self) -> str:
        """Short label for notes. Three identical "NY: showing 25" lines are
        worse than useless — the reader cannot tell which layer capped."""
        return self.note_label or self.state

    def out_fields(self) -> str:
        wanted = [self.owner, self.address, self.city, self.parcel_id,
                  self.value, self.county]
        return ",".join(f for f in wanted if f)


SOURCES: tuple[ParcelSource, ...] = (
    ParcelSource(
        state="AR", label="Arkansas GIS Office — statewide parcels",
        url="https://gis.arkansas.gov/arcgis/rest/services/FEATURESERVICES/Planning_Cadastre/MapServer/0",
        owner="ownername", address="adrlabel", city="adrcity",
        parcel_id="parcelid", value="totalvalue", county="county",
        attribution="Arkansas GIS Office (county CAMA rolls)", page=200,
    ),
    ParcelSource(
        state="CT", label="Connecticut statewide parcel + CAMA layer",
        url="https://services3.arcgis.com/3FL1kr7L4LvwA2Kb/arcgis/rest/services/Connecticut_State_Parcel_Layer_2023/FeatureServer/0",
        owner="Owner", address="Location", city="Town_Name",
        attribution="CT Office of Policy and Management", page=200,
    ),
    ParcelSource(
        state="NC", label="NC OneMap — statewide parcels",
        url="https://services.nconemap.gov/secure/rest/services/NC1Map_Parcels/MapServer/0",
        owner="ownname", address="siteadd", city="scity",
        parcel_id="parno", value="parval", county="cntyname",
        attribution="NC OneMap (NC Center for Geographic Information)", page=200,
    ),
    ParcelSource(
        state="VT", label="Vermont standardized parcels (VCGI)",
        url="https://services1.arcgis.com/BkFxaEFNwHqX3tAw/arcgis/rest/services/FS_VCGI_VTPARCELS_WM_NOCACHE_v2/FeatureServer/1",
        owner="OWNER1", address="E911ADDR", city="TOWN",
        attribution="Vermont Center for Geographic Information", page=200,
    ),
    ParcelSource(
        state="WI", label="Wisconsin Statewide Parcel Map Initiative",
        url="https://services3.arcgis.com/n6uYoouQZW75n5WI/arcgis/rest/services/Wisconsin_Statewide_Parcels_DB/FeatureServer/0",
        owner="OWNERNME1", address="PSTLADRESS", city="CNTYNAME",
        parcel_id="PARCELID", value="CNTYASSDVALUE",
        attribution="WI Dept. of Administration / SCO", page=200,
    ),
)

COVERED_STATES: tuple[str, ...] = tuple(s.state for s in SOURCES)


@dataclass
class ParcelHit:
    owner: str
    address: str = ""
    city: str = ""
    parcel_id: str = ""
    value: str = ""
    county: str = ""
    state: str = ""
    source: str = ""
    url: str = ""


@dataclass
class ParcelSearch:
    query: str
    hits: list[ParcelHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Which states were actually asked. The caller needs this to say what a
    #: zero-row answer does and does not mean.
    searched: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"query": self.query, "count": len(self.hits),
                "searched": self.searched,
                "hits": [h.__dict__ for h in self.hits], "notes": self.notes}


def _tokens(name: str) -> list[str]:
    """Useful name tokens, cleaned of anything that could reach the SQL.

    Hyphens survive because `Wal-Mart` and `Smith-Jones` are real owner names.
    A *doubled* hyphen is not — it is the SQL comment token — so runs collapse
    to one. Quote doubling already keeps it inside a string literal where it is
    inert; this removes the sequence outright rather than relying on that.
    """
    cleaned = _SAFE.sub(" ", name or "")
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    return [t for t in cleaned.split() if len(t) >= _MIN_TOKEN]


def where_clause(field_name: str, name: str) -> str:
    """AND of LIKE terms, one per token — order-independent by construction.

    Assessor rolls write the same person as `DOE, JANE`, `DOE JANE A` and
    `JANE DOE` depending on the county that supplied the row. Matching the
    literal string would miss most of them, so each token is required
    separately and the order stops mattering.

    Single quotes are doubled, per SQL-92, on top of `_SAFE` having already
    dropped every character that is not name-shaped.
    """
    terms = []
    for tok in _tokens(name):
        safe = tok.upper().replace("'", "''")
        terms.append(f"UPPER({field_name}) LIKE '%{safe}%'")
    return " AND ".join(terms)


def _query(http, source: ParcelSource, name: str, limit: int) -> tuple[list[ParcelHit], list[str]]:
    clause = where_clause(source.owner, name)
    if not clause:
        return [], []

    notes: list[str] = []
    params = {
        "where": clause, "f": "json", "outFields": source.out_fields(),
        "returnGeometry": "false",
        "resultRecordCount": min(limit, source.page),
    }
    try:
        resp = http.get(f"{source.url}/query", params=params, timeout=30)
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        from umbra.core.notes import describe_http_failure

        return [], [describe_http_failure(f"parcels_{source.state}", exc, source.url)]

    # ArcGIS answers 200 with an error body. Treating that as "no parcels"
    # would turn a broken query into a clean bill of health.
    if isinstance(payload, dict) and payload.get("error"):
        msg = str(payload["error"].get("message") or "unknown")
        return [], [f"{source.state} parcel layer refused the query ({msg}) — "
                    f"that is a source failure, not an absence of records."]

    rows = payload.get("features") or []
    hits: list[ParcelHit] = []
    for row in rows[:limit]:
        attrs = row.get("attributes") or {}

        def pick(key: str) -> str:
            if not key:
                return ""
            val = attrs.get(key)
            return "" if val is None else str(val).strip()

        owner = pick(source.owner)
        if not owner:
            continue
        hits.append(ParcelHit(
            owner=owner, address=pick(source.address), city=pick(source.city),
            parcel_id=pick(source.parcel_id), value=pick(source.value),
            county=pick(source.county), state=source.state,
            source=source.attribution or source.label, url=source.url,
        ))

    asked = min(limit, source.page)
    if len(rows) >= asked:
        # Never a silent cap — and name the *right* cap. Saying "the layer
        # returns at most 25" when 25 is our own limit and the layer's is 200
        # blames the source for our choice, which is the same class of error
        # this module exists to avoid.
        whose = ("Umbra's page size" if limit <= source.page
                 else f"the {source.state} layer's own cap")
        notes.append(
            f"{source.where_label()}: showing {len(hits)}, which is {whose} "
            f"({asked}) — there are probably more."
        )
    return hits, notes


def from_registry(row: dict[str, Any]) -> ParcelSource:
    """A verified county layer from the owned registry, as a searchable source.

    Discovered layers are ordinary sources — same query path, same escaping,
    same truncation note. The only difference is provenance, and `attribution`
    carries it so a hit can always be traced back to whose data it is.
    """
    where = " ".join(x for x in (row.get("county") or "", row.get("state") or "") if x)
    # The registry stores the publishing ArcGIS account for traceability, but it
    # is often a named individual at the county ("janetcourson"). Surfacing a
    # private person's username as the attribution on someone else's property
    # record helps no reader and exposes them for no reason. The county is the
    # meaningful attributor; the account stays in the lake.
    return ParcelSource(
        state=(row.get("state") or "??").upper(),
        label=row.get("title") or "county parcel layer",
        url=row["layer_url"],
        owner=row["owner_field"],
        address=row.get("address_field") or "",
        city=row.get("city_field") or "",
        parcel_id=row.get("parcel_field") or "",
        value=row.get("value_field") or "",
        attribution=(f"{where} county GIS parcel layer" if where
                     else "county GIS parcel layer (coverage unresolved)"),
        note_label=where or (row.get("title") or "county layer"),
        page=int(row.get("page") or 200),
    )


def registry_sources(settings, states: Iterable[str] | None = None,
                     limit: int = 40) -> tuple[list[ParcelSource], list[str]]:
    """Verified county layers Umbra found and probed itself."""
    try:
        from umbra.lake.parcel_sources import ParcelSourceLake

        lake = ParcelSourceLake.from_settings(settings)
    except Exception:  # noqa: BLE001
        return [], []
    try:
        if not lake.available:
            return [], []
        wanted = {s.strip().upper() for s in states} if states else None
        rows: list[dict[str, Any]] = []
        if wanted:
            for st in sorted(wanted):
                rows.extend(lake.verified(state=st, limit=limit))
        else:
            rows = lake.verified(limit=limit)
        return [from_registry(r) for r in rows[:limit]], []
    except Exception as exc:  # noqa: BLE001
        return [], [f"parcel source registry unreadable: {exc}"]
    finally:
        lake.close()


def search(name: str, *, http, states: Iterable[str] | None = None,
           limit: int = 25, settings=None) -> ParcelSearch:
    """Parcels whose owner name matches, across every layer Umbra can query.

    Two tiers, and they are not equal: the five curated statewide layers cover
    a whole state each, while registry entries are single counties Umbra
    discovered and verified. Both are real records; only the breadth differs.
    """
    query = (name or "").strip()
    out = ParcelSearch(query=query)

    if not _tokens(query):
        out.notes.append(
            f"{query!r} has no name token of {_MIN_TOKEN}+ characters, so no "
            "parcel layer was queried."
        )
        return out

    wanted = {s.strip().upper() for s in states} if states else None
    chosen = [s for s in SOURCES if wanted is None or s.state in wanted]

    discovered: list[ParcelSource] = []
    if settings is not None:
        if wanted:
            discovered, reg_notes = registry_sources(settings, states)
            out.notes.extend(reg_notes)
            # Never query the same layer twice because it is both curated and found.
            known = {s.url for s in chosen}
            discovered = [s for s in discovered if s.url not in known]
            chosen = chosen + discovered
        else:
            # Every county layer is a separate HTTP round trip. Firing all of
            # them at an unscoped search would make one query dozens of requests
            # to dozens of county servers — slow for the reader and rude to
            # them. Rather than truncate to an arbitrary handful and pretend
            # that was the whole registry, say what naming a region would add.
            available, reg_notes = registry_sources(settings, None, limit=500)
            out.notes.extend(reg_notes)
            if available:
                where = sorted({s.state for s in available if s.state != "??"})
                out.notes.append(
                    f"{len(available)} verified county layer(s) in "
                    f"{', '.join(where)} were NOT searched — an unscoped name "
                    f"search would mean one request per county. Add a region "
                    f"(e.g. --region us-pa) to include them."
                )

    if wanted and not chosen:
        out.notes.append(
            f"No parcel layer for {', '.join(sorted(wanted))}. Umbra has "
            f"statewide layers for {', '.join(COVERED_STATES)} and whatever "
            f"county layers `umbra records sources sync` has verified — for "
            f"anywhere else the county portal links are the honest answer."
        )
        return out

    # Deduped and sorted: `searched` is quoted back to the reader in the
    # zero-rows note, and "AR, AR, NC, ??" would read as a bug.
    out.searched = sorted({s.state for s in chosen if s.state != "??"})
    for source in chosen:
        hits, notes = _query(http, source, query, limit)
        out.hits.extend(hits)
        out.notes.extend(notes)

    if discovered:
        curated = len(chosen) - len(discovered)
        alongside = (" alongside the statewide layer(s)" if curated else
                     " — there is no statewide layer here")
        out.notes.append(
            f"{len(discovered)} county layer(s) Umbra discovered and verified "
            f"were searched{alongside}. Each covers a single county, so this is "
            f"deeper coverage in a few places, not wider coverage everywhere."
        )

    # The single most misreadable result in this module: zero rows.
    if not out.hits:
        scope = ", ".join(out.searched) or "no layers"
        out.notes.append(
            f"No parcel match in {scope}. That is the extent of what Umbra "
            f"queries — statewide layers for {len(COVERED_STATES)} states plus "
            f"{len(discovered)} verified county layer(s) — and it is not "
            f"evidence that the name owns no property anywhere."
        )
    else:
        out.notes.append(
            "Parcel rows are public assessor records and include home "
            "addresses. A name match is not an identity — common names collide "
            "constantly in these rolls."
        )
    return out
