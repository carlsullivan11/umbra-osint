"""Allowlisted GET of curated county/state/federal public-record portals.

Not PACER, not login, not captcha bypass, not paid assessor APIs.
Fetches landing pages and public name-index URLs already listed in
``public_records_portals`` packs. Stores every source link. A name token on
the page is a *candidate hit*, not identity.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.collectors.public_records_portals import (
    _PORTALS,
    name_query_urls,
    resolve_regions,
)
from umbra.collectors.us_state_portals import region_places
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.core.scrape import crawl_allowlisted
from umbra.db.schema import Entity
from umbra.geo.deep_packs import region_place_labels
from umbra.people.obituary_parse import strip_html
from umbra.people.records_parse import parse_index_json, parse_public_records_text

_MAX_FETCH = 10
_MAX_BODY = 80_000
_SKIP_PATH = ("login", "signin", "efile", "e-file", "checkout", "captcha", "recaptcha", "cart")
_PHONE_RE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

_REGION_PLACE = {
    "us-federal": "United States",
}
_REGION_PLACE.update(region_places())
_REGION_PLACE.update(region_place_labels())


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def _pack_hosts() -> set[str]:
    hosts: set[str] = set()
    for pack in _PORTALS.values():
        for p in pack:
            h = _host(p["url"])
            if h:
                hosts.add(h)
    hosts.update(
        {
            "www.courtlistener.com",
            "courtlistener.com",
            "chroniclingamerica.loc.gov",
            "opencorporates.com",
            "www.opencorporates.com",
            "www.sec.gov",
            "efts.sec.gov",
            "api.open.fec.gov",
            "www.fec.gov",
            "www.nwaonline.com",
            "nwaonline.com",
            "www.echovita.com",
        }
    )
    return hosts


_PACK_HOSTS = _pack_hosts()


def scrape_allowed(url: str) -> bool:
    host = _host(url)
    if not host:
        return False
    path = (urlsplit(url).path or "").lower()
    if any(tok in path for tok in _SKIP_PATH):
        return False
    if host in _PACK_HOSTS:
        return True
    if host.endswith(".gov") or host.endswith(".mil"):
        return True
    return False


def _name_hit(text: str, person: str) -> bool:
    last = (person.replace(",", " ").split() or [""])[-1].lower()
    if len(last) < 3:
        return False
    tokens = re.findall(r"[a-z0-9']+", text.lower())
    return last in tokens


class CountyRecordsCollector(BaseCollector):
    name = "county_records"
    timeout_s = 120
    inputs = {EntityType.PERSON, EntityType.ORG}
    description = (
        "GET curated public county/state/federal record portals; store links; "
        "candidate name hits only (no login/PACER)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        src = entity.norm_key
        name = (entity.value or "").strip()
        props = entity.props or {}
        regions = resolve_regions(props)

        targets: list[tuple[str, str, str]] = []  # url, kind, region
        seen: set[str] = set()

        def add(url: str, kind: str, region: str) -> None:
            if not url or url in seen or not scrape_allowed(url):
                return
            seen.add(url)
            targets.append((url, kind, region))

        for reg in regions:
            for p in _PORTALS.get(reg, []):
                add(p["url"], p["kind"], reg)
        if entity.type == EntityType.PERSON.value:
            for p in name_query_urls(name):
                add(p["url"], p["kind"], "us-name-query")

        _kind_rank = {"property": 0, "business": 1, "courts": 2, "vital": 3}
        targets.sort(key=lambda t: _kind_rank.get(t[1], 9))
        to_fetch = targets[:_MAX_FETCH]
        meta = {u: (k, r) for u, k, r in to_fetch}
        fetched = 0
        hits = 0
        lake = None
        try:
            from umbra.lake.people import PeopleLake

            lake = PeopleLake.from_settings(ctx.settings)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"county_records lake: {exc}")

        ua = getattr(ctx.settings, "user_agent", None) or "UmbraOSINT/0.2"
        timeout = getattr(ctx.settings, "request_timeout_s", 20) or 20

        crawl = crawl_allowlisted(
            ctx.http,
            [u for u, _, _ in to_fetch],
            allow=scrape_allowed,
            needle=name,
            max_pages=_MAX_FETCH + 6,
            follow_per_page=3,
            user_agent=ua,
            timeout=timeout,
            pause_s=getattr(ctx.settings, "scrape_pause_s", 0.35),
        )
        result.notes.extend(crawl.notes)

        def _meta_for(url: str) -> tuple[str, str]:
            if url in meta:
                return meta[url]
            host = _host(url)
            for seed, kr in meta.items():
                if _host(seed) == host:
                    return kr
            return ("property", regions[0] if regions else "")

        for page in crawl.pages:
            url = page.url
            kind, region = _meta_for(url)
            result.entities.append(
                EntityIn(
                    type=EntityType.URL,
                    value=url,
                    confidence=0.55,
                    props={"portal_kind": kind, "region": region, "county_record": True},
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, url),
                    rel=EdgeType.ASSOCIATED_WITH,
                    confidence=0.45,
                    props={"kind": kind, "region": region, "source": "county_records"},
                )
            )
            place = _REGION_PLACE.get(region)
            if place:
                result.entities.append(
                    EntityIn(
                        type=EntityType.LOCATION,
                        value=place,
                        confidence=0.5,
                        props={"kind": "jurisdiction", "region": region},
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.LOCATION, place),
                        rel=EdgeType.LOCATED_IN,
                        confidence=0.4,
                        props={"kind": "jurisdiction", "region": region},
                    )
                )

            title = page.title
            excerpt = ""
            status = page.status
            hit = False
            try:
                if status is not None:
                    fetched += 1
                html = (page.html or "")[:_MAX_BODY]
                if html.strip().startswith("{") or html.strip().startswith("["):
                    indexed = parse_index_json(html, person_name=name, source_url=url)
                    if indexed.get("name_hit"):
                        hit = True
                        hits += 1
                    for extra in indexed.get("urls") or []:
                        result.entities.append(
                            EntityIn(
                                type=EntityType.URL,
                                value=extra,
                                confidence=0.45,
                                props={"kind": "index_hit", "source": "county_records", "manual_confirm": True},
                            )
                        )
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(EntityType.URL, extra),
                                rel=EdgeType.ASSOCIATED_WITH,
                                confidence=0.4,
                                props={"kind": "index_hit", "manual_confirm": True},
                            )
                        )
                    excerpt = " ".join(indexed.get("names") or [])[:1500]
                elif html:
                    text = strip_html(html)
                    excerpt = text[:1500]
                    hit = bool(name and _name_hit(text, name))
                    if hit:
                        hits += 1
                    phones = _PHONE_RE.findall(text[:4000])[:3]
                    if phones:
                        result.notes.append(f"public phones on {url}: {phones}")
                    parsed = parse_public_records_text(
                        text,
                        person_name=name,
                        kind=kind,
                        source_url=url,
                        region=region,
                    )
                    for fact in parsed.get("land") or []:
                        situs = fact.get("situs")
                        apn = fact.get("apn")
                        loc = situs or (f"APN {apn}" if apn else None)
                        if loc:
                            result.entities.append(
                                EntityIn(
                                    type=EntityType.LOCATION,
                                    value=loc,
                                    confidence=0.4,
                                    props={
                                        "kind": "parcel",
                                        "apn": apn,
                                        "source": "county_records",
                                        "source_url": url,
                                        "manual_confirm": True,
                                    },
                                )
                            )
                            result.edges.append(
                                EdgeIn(
                                    source_key=src,
                                    target_key=entity_key(EntityType.LOCATION, loc),
                                    rel=EdgeType.ASSOCIATED_WITH,
                                    confidence=0.35,
                                    props={
                                        "kind": "land_candidate",
                                        "apn": apn,
                                        "source_url": url,
                                        "manual_confirm": True,
                                    },
                                )
                            )
                        if lake is not None:
                            try:
                                lake.upsert_land_fact(
                                    source_url=url,
                                    person_name=name or None,
                                    apn=apn,
                                    situs=situs,
                                    region=region,
                                    excerpt=excerpt[:400],
                                )
                            except Exception as exc:  # noqa: BLE001
                                result.notes.append(f"land upsert: {exc}")
                    for fact in parsed.get("corps") or []:
                        org = fact.get("org_name")
                        if not org:
                            continue
                        result.entities.append(
                            EntityIn(
                                type=EntityType.ORG,
                                value=org,
                                confidence=0.4,
                                props={
                                    "kind": "sos_candidate",
                                    "file_number": fact.get("file_number"),
                                    "source_url": url,
                                    "manual_confirm": True,
                                },
                            )
                        )
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(EntityType.ORG, org),
                                rel=EdgeType.ASSOCIATED_WITH,
                                confidence=0.35,
                                props={
                                    "kind": "corp_officer_candidate",
                                    "file_number": fact.get("file_number"),
                                    "source_url": url,
                                    "manual_confirm": True,
                                },
                            )
                        )
                        if lake is not None:
                            try:
                                lake.upsert_corp_fact(
                                    source_url=url,
                                    org_name=org,
                                    person_name=name or None,
                                    file_number=fact.get("file_number"),
                                    region=region,
                                    excerpt=excerpt[:400],
                                )
                            except Exception as exc:  # noqa: BLE001
                                result.notes.append(f"corp upsert: {exc}")
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"county_records fetch {url!r}: {exc}")

            if lake is not None:
                try:
                    lake.upsert_county_source(
                        url=url,
                        person_name=name or None,
                        region=region,
                        kind=kind,
                        title=title,
                        excerpt=excerpt or None,
                        name_hit=hit,
                        http_status=status,
                    )
                except Exception as exc:  # noqa: BLE001
                    result.notes.append(f"county_records upsert: {exc}")

        if lake is not None:
            try:
                lake.close()
            except Exception:
                pass

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="county_records",
                summary=(
                    f"County/state/federal public portals for {name!r}: "
                    f"{len(to_fetch)} seed URLs, crawled {fetched} pages "
                    f"name-token hits={hits}. Not identity. No login/PACER."
                ),
                confidence=0.55 if hits else 0.4,
                raw={
                    "regions": regions,
                    "urls": [u for u, _, _ in to_fetch],
                    "fetched": fetched,
                    "name_hits": hits,
                },
                entity_key=src,
            )
        )
        return result
