"""Public sex-offender *registry portals* — NSOPW + state Megan's Law sites.

High-signal when first **and** last name appear on a public page. Still a
candidate, not identity. No captcha, no NSOPW map scrape, no photo dump.
"""

from __future__ import annotations

from urllib.parse import quote_plus, urlsplit

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.collectors.us_state_portals import detect_state_keys, sor_portals
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.core.scrape import crawl_allowlisted
from umbra.db.schema import Entity
from umbra.people.sor_parse import parse_sor_html

_MAX_FETCH = 8
_SKIP_PATH = ("login", "signin", "captcha", "recaptcha", "checkout")

_PORTALS: list[tuple[str, str, str]] = sor_portals()
_HOSTS = frozenset(
    (urlsplit(url).netloc or "").lower() for _r, _t, url in _PORTALS if url
)


def _regions_for(entity: Entity) -> list[str]:
    props = entity.props or {}
    loc = " ".join(
        str(props.get(k) or "")
        for k in ("location", "city", "state", "county", "regions")
    ).lower()
    out = ["us-federal"]
    out.extend(detect_state_keys(loc, props))
    seen: list[str] = []
    for r in out:
        if r not in seen:
            seen.append(r)
    return seen


class SexOffenderRegistryCollector(BaseCollector):
    name = "sex_offender_registry"
    timeout_s = 60
    version = "0.1.0"
    inputs = {EntityType.PERSON}
    description = (
        "Allowlisted GET of NSOPW / Megan's Law / AR offender portals; "
        "first+last name on page = candidate, not identity"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        name = (entity.value or entity.display_name or "").strip()
        parts = [p for p in name.replace(",", " ").split() if p]
        if len(parts) < 2:
            result.notes.append("sex_offender_registry needs first and last name")
            return result
        src = entity_key(EntityType.PERSON, name)
        regions = _regions_for(entity)
        first, last = parts[0], parts[-1]
        seeds: list[str] = []
        for region, _title, url in _PORTALS:
            if region in regions:
                seeds.append(url)
        q_last, q_first = quote_plus(last), quote_plus(first)
        if "us-federal" in regions:
            seeds.append(
                f"https://www.nsopw.gov/en/Search/Results?firstname={q_first}&lastname={q_last}"
            )
        seeds = list(dict.fromkeys(seeds))[:_MAX_FETCH]

        def allow(url: str) -> bool:
            host = urlsplit(url).netloc.lower()
            path = urlsplit(url).path.lower()
            if any(s in path for s in _SKIP_PATH):
                return False
            return host in _HOSTS

        lake = None
        try:
            from umbra.lake.people import PeopleLake

            lake = PeopleLake.from_settings(ctx.settings)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"sor lake: {exc}")

        ua = getattr(ctx.settings, "user_agent", None) or "UmbraOSINT/0.2"
        timeout = getattr(ctx.settings, "request_timeout_s", 20) or 20
        crawl = crawl_allowlisted(
            ctx.http,
            seeds,
            allow=allow,
            needle=name,
            max_pages=_MAX_FETCH,
            follow_per_page=2,
            user_agent=ua,
            timeout=timeout,
            pause_s=getattr(ctx.settings, "scrape_pause_s", 0.4),
        )
        result.notes.extend(crawl.notes)

        fetched = 0
        hits = 0
        try:
            for page in crawl.pages:
                url = page.url
                title = page.title
                status = page.status
                html = page.html or ""
                parsed = parse_sor_html(
                    html,
                    person_name=name,
                    source_url=url,
                    region=",".join(regions),
                )
                if status is not None:
                    fetched += 1
                result.entities.append(
                    EntityIn(
                        type=EntityType.URL,
                        value=url,
                        display_name=title or url,
                        confidence=0.55 if parsed["name_hit"] else 0.4,
                        props={
                            "kind": "sex_offender_registry",
                            "http_status": status,
                            "name_hit": parsed["name_hit"],
                            "manual_confirm": True,
                        },
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.URL, url),
                        rel=EdgeType.ASSOCIATED_WITH,
                        confidence=0.5 if parsed["name_hit"] else 0.35,
                        props={"kind": "sor_source", "manual_confirm": True},
                    )
                )
                if parsed["name_hit"]:
                    hits += 1
                    for addr in parsed["addresses"]:
                        result.entities.append(
                            EntityIn(
                                type=EntityType.LOCATION,
                                value=addr,
                                confidence=0.5,
                                props={
                                    "kind": "sor_listed_address",
                                    "source_url": url,
                                    "manual_confirm": True,
                                },
                            )
                        )
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(EntityType.LOCATION, addr),
                                rel=EdgeType.LOCATED_IN,
                                confidence=0.4,
                                props={"kind": "sor_candidate", "manual_confirm": True},
                            )
                        )
                    for alias in parsed["aliases"]:
                        result.entities.append(
                            EntityIn(
                                type=EntityType.PERSON,
                                value=alias,
                                display_name=alias,
                                confidence=0.45,
                                props={"kind": "sor_aka", "related_to": name, "manual_confirm": True},
                            )
                        )
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(EntityType.PERSON, alias),
                                rel=EdgeType.SAME_AS,
                                confidence=0.4,
                                props={"kind": "sor_aka", "manual_confirm": True},
                            )
                        )
                    result.evidence.append(
                        EvidenceIn(
                            collector=self.name,
                            source_name="sex_offender_registry",
                            source_url=url,
                            entity_key=src,
                            summary=(
                                f"SOR candidate {name}: "
                                + ", ".join(parsed["offenses"][:3] or ["name on public registry page"])
                            )[:240],
                            raw={
                                "url": url,
                                "dob": parsed["dob"],
                                "registry_id": parsed["registry_id"],
                                "tier": parsed["tier"],
                            },
                            confidence=0.5,
                        )
                    )
                if lake is not None:
                    try:
                        lake.upsert_sor_source(
                            url=url,
                            person_name=name,
                            region=",".join(regions),
                            title=title,
                            name_hit=parsed["name_hit"],
                            excerpt=parsed["excerpt"],
                            parsed=parsed,
                        )
                        if parsed["name_hit"]:
                            lake.upsert_sor_fact(
                                source_url=url,
                                person_name=name,
                                registry_id=parsed["registry_id"],
                                dob=parsed["dob"],
                                address=(parsed["addresses"] or [None])[0],
                                aliases=parsed["aliases"],
                                offenses=parsed["offenses"],
                                tier=parsed["tier"],
                                excerpt=parsed["excerpt"],
                            )
                    except Exception as exc:  # noqa: BLE001
                        result.notes.append(f"sor upsert: {exc}")
        finally:
            if lake is not None:
                try:
                    lake.close()
                except Exception:
                    pass

        result.notes.append(
            f"{len(seeds)} SOR seeds, crawled {fetched} pages, name hits {hits} "
            f"(first+last token; not identity)"
        )
        return result
