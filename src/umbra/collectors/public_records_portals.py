from __future__ import annotations

"""Free public-record *portals* for person/org mapping (not paywalled scrapers).

Design:
- Attach jurisdiction-aware URL entities so operators (or later assisted flows)
  can complete county / vital / court / property / obituary searches.
- Prefer official clerk/assessor/court and well-known public memorial indexes.
- Never claim automated hit rates; confidence stays moderate (manual_search).

Region packs use stable keys like ``us-ar-benton``, ``us-ca-alameda``,
``us-obituary``, ``us-federal``. Person props ``location``, ``state``,
``county``, ``city``, ``regions`` drive which packs attach.
"""

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.collectors.us_state_portals import detect_state_keys, state_packs
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

Portal = dict[str, str]


def _p(name: str, url: str, kind: str) -> Portal:
    return {"name": name, "url": url, "kind": kind}


# --- National / multi-jurisdiction packs ---------------------------------

_US_OBITUARY: list[Portal] = [
    _p("Legacy.com Obituary Search", "https://www.legacy.com/obituaries/search", "obituary"),
    _p("Find a Grave Memorial Search", "https://www.findagrave.com/memorial/search", "obituary"),
    _p(
        "USGenWeb Obituaries Project (gateway)",
        "https://www.usgenweb.org/",
        "obituary",
    ),
    _p(
        "Library of Congress Chronicling America (historical newspapers)",
        "https://chroniclingamerica.loc.gov/",
        "obituary",
    ),
    _p(
        "Newspapers.com (subscription index — manual)",
        "https://www.newspapers.com/",
        "obituary",
    ),
    _p(
        "GenealogyBank Obits (subscription — manual)",
        "https://www.genealogybank.com/explore/obituaries/all",
        "obituary",
    ),
    _p("Tribute Archive Search", "https://www.tributearchive.com/", "obituary"),
    _p("Echovita Obituary Search", "https://www.echovita.com/us", "obituary"),
]

_US_FEDERAL: list[Portal] = [
    _p("SEC EDGAR", "https://www.sec.gov/edgar/search/", "business"),
    _p("USPTO Assignment Search", "https://assignment.uspto.gov/", "ip"),
    _p("SAM.gov Entity Information", "https://sam.gov/content/entity-information", "government_contracting"),
    _p(
        "FEC Individual Contributions",
        "https://www.fec.gov/data/receipts/individual-contributions/",
        "campaign_finance",
    ),
    _p("CourtListener / RECAP", "https://www.courtlistener.com/", "courts"),
    _p("PACER (CM/ECF gateway — account often required)", "https://pacer.uscourts.gov/", "courts"),
    _p("FOIA.gov", "https://www.foia.gov/", "foia"),
    _p(
        "National Archives Catalog",
        "https://www.archives.gov/research/catalog",
        "vital",
    ),
    _p(
        "Social Security Death Index research guide (NARA)",
        "https://www.archives.gov/research/census/ssdi",
        "vital",
    ),
    _p(
        "Unclaimed property — NAUPA multistate search",
        "https://unclaimed.org/",
        "property",
    ),
]

_US_AR_STATE: list[Portal] = [
    _p("Arkansas Judiciary Case Search", "https://caseinfo.arcourts.gov/", "courts"),
    _p(
        "Arkansas Secretary of State Business Entity Search",
        "https://www.sos.arkansas.gov/business-commercial-services-bcs/business-entity-search",
        "business",
    ),
    _p(
        "Arkansas Department of Health — vital records info",
        "https://www.healthy.arkansas.gov/programs-services/topics/vital-records",
        "vital",
    ),
    _p(
        "Arkansas professional / health license info hub",
        "https://www.healthy.arkansas.gov/",
        "license",
    ),
]


# County deep packs (L2) live in data — see umbra.geo.deep_packs / county_deep_packs.json
from umbra.geo.deep_packs import deep_city_hints, deep_portal_lists  # noqa: E402

_US_CA_STATE: list[Portal] = [
    _p(
        "California Courts — find your court",
        "https://www.courts.ca.gov/find-my-court.htm",
        "courts"),
    _p(
        "California Secretary of State Business Search",
        "https://bizfileonline.sos.ca.gov/search/business",
        "business",
    ),
    _p(
        "CDPH Vital Records (order portal / info)",
        "https://www.cdph.ca.gov/Programs/CHSI/Pages/Vital-Records.aspx",
        "vital",
    ),
    _p(
        "California unclaimed property (SCO)",
        "https://ucpi.sco.ca.gov/UCP/",
        "property",
    ),
]


_PORTALS: dict[str, list[Portal]] = {}
_PORTALS.update(state_packs())
_PORTALS.update({
    "us-obituary": _US_OBITUARY,
    "us-federal": _US_FEDERAL,
    "us-ar": _US_AR_STATE,
    "us-ca": _US_CA_STATE,
})
_PORTALS.update(deep_portal_lists())



def _blob(props: dict) -> str:
    parts: list[str] = []
    for key in ("location", "state", "county", "city", "region", "address"):
        v = props.get(key)
        if v:
            parts.append(str(v))
    regions = props.get("regions") or []
    if isinstance(regions, (list, tuple, set)):
        parts.extend(str(x) for x in regions)
    elif regions:
        parts.append(str(regions))
    return " ".join(parts).lower()


def resolve_regions(props: dict | None) -> list[str]:
    """Map free-text person/org location props → portal pack keys."""
    props = props or {}
    regions: set[str] = set()
    explicit = props.get("regions") or []
    if isinstance(explicit, str):
        explicit = [explicit]
    for r in explicit:
        key = str(r).strip().lower().replace(" ", "-")
        if key in _PORTALS:
            regions.add(key)

    blob = _blob(props)

    # Always attach national memorial + federal when doing person mapping.
    regions.add("us-obituary")
    regions.add("us-federal")

    # Coarse state tokens still useful before comma-state detect
    if any(x in blob for x in ("arkansas", " ar", " ar,", "ar ", "bentonville", "rogers", "nwa")):
        regions.add("us-ar")
    if any(x in blob for x in ("california", " ca", " ca,", "bay area", "sf bay")):
        regions.add("us-ca")

    # L2 deep packs — city/county hints from county_deep_packs.json
    for pack_key, cities in deep_city_hints():
        if any(c in blob for c in cities):
            regions.add(pack_key)
            # parent state from pack key us-xx-...
            parts = pack_key.split("-")
            if len(parts) >= 2:
                regions.add(f"us-{parts[1]}")

    for key in detect_state_keys(blob, props):
        regions.add(key)

    # Census county name → deep pack / state (tracker)
    try:
        from umbra.geo.us_counties import lookup_county

        hit = lookup_county(blob, str(props.get("state") or "") or None)
        if hit:
            st = (hit.get("state") or "").lower()
            if st:
                regions.add(f"us-{st}")
            pack = hit.get("pack")
            if pack:
                regions.add(pack)
    except Exception:
        pass

    return sorted(regions)



def name_query_urls(person_name: str) -> list[Portal]:
    """Deep-link helpers for common name-based public indexes (still manual)."""
    parts = [p for p in person_name.replace(",", " ").split() if p]
    if len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    from urllib.parse import quote_plus

    f, l = quote_plus(first), quote_plus(last)
    full = quote_plus(person_name.strip())
    return [
        _p(
            f"Legacy.com search: {person_name}",
            f"https://www.legacy.com/obituaries/search?firstName={f}&lastName={l}",
            "obituary",
        ),
        _p(
            f"Find a Grave search: {person_name}",
            f"https://www.findagrave.com/memorial/search?firstname={f}&lastname={l}",
            "obituary",
        ),
        _p(
            f"CourtListener people search: {person_name}",
            f"https://www.courtlistener.com/?type=r&q={full}",
            "courts",
        ),
        _p(
            f"Chronicling America search: {person_name}",
            f"https://chroniclingamerica.loc.gov/search/pages/results/?proxtext={full}",
            "obituary",
        ),
        _p(
            f"OpenCorporates search: {person_name}",
            f"https://opencorporates.com/companies?q={full}",
            "business",
        ),
        _p(
            f"SEC EDGAR company search: {person_name}",
            f"https://www.sec.gov/cgi-bin/browse-edgar?company={full}&action=getcompany",
            "business",
        ),
        _p(
            f"CourtListener API search: {person_name}",
            f"https://www.courtlistener.com/api/rest/v4/search/?type=r&q={full}",
            "courts",
        ),
        _p(
            f"FEC name index: {person_name}",
            f"https://api.open.fec.gov/v1/names/?q={l}&api_key=DEMO_KEY",
            "campaign_finance",
        ),
        _p(
            f"Echovita search: {person_name}",
            f"https://www.echovita.com/us/obituaries?q={full}",
            "obituary",
        ),
        _p(
            f"NWA Online obituaries: {person_name}",
            f"https://www.nwaonline.com/obituaries/?q={full}",
            "obituary",
        ),
    ]


class PublicRecordsPortalsCollector(BaseCollector):
    name = "public_records_portals"
    timeout_s = 60
    inputs = {EntityType.PERSON, EntityType.ORG}
    description = (
        "Attach free county/state/federal + obituary portal URLs by jurisdiction "
        "(manual-search trail; not automated people-search)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        src = entity.norm_key
        props = entity.props or {}
        region_keys = resolve_regions(props)

        portals: list[dict] = []
        seen_urls: set[str] = set()

        def add_portal(p: Portal, reg: str) -> None:
            url = p["url"]
            if url in seen_urls:
                return
            seen_urls.add(url)
            item = {**p, "region": reg}
            portals.append(item)
            result.entities.append(
                EntityIn(
                    type=EntityType.URL,
                    value=url,
                    display_name=p["name"],
                    confidence=0.9,
                    props={
                        "portal_kind": p["kind"],
                        "region": reg,
                        "manual_search": True,
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, url),
                    rel=EdgeType.ASSOCIATED_WITH,
                    confidence=0.5,
                    props={"portal": True, "kind": p["kind"], "region": reg},
                )
            )

        for reg in region_keys:
            for p in _PORTALS.get(reg, []):
                add_portal(p, reg)

        # Name deep-links for persons (obituary + court indexes)
        if entity.type == EntityType.PERSON.value:
            for p in name_query_urls(entity.value or ""):
                add_portal(p, "us-name-query")

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="public_records_portals",
                summary=(
                    f"Linked {len(portals)} free public-record / obituary portals for "
                    f"manual search (name={entity.value!r}, regions={region_keys}). "
                    f"Not automated scraping."
                ),
                confidence=0.9,
                raw={
                    "portals": portals,
                    "query_hint": entity.value,
                    "regions": region_keys,
                },
                entity_key=src,
            )
        )
        return result
