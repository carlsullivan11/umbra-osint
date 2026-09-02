from __future__ import annotations

"""Obituary search + public page scrape + people-lake upsert.

Pipeline
--------
1. DDG discovery (obituary-biased) with wiki/Find a Grave fallbacks
2. Attach URL candidates + store every allowlisted fetch **link**
3. Parse body with ``people.obituary_parse`` (survivors, dates, places, …)
4. Upsert into owned **people lake** (``data/lake/people.sqlite``)
5. Emit PERSON + RELATED_TO graph edges for the case

Lawful public sources only; paywalled hosts are link-only.
"""


import re
from urllib.parse import quote_plus, unquote, urlsplit

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity
from umbra.people.obituary_parse import parse_obituary_text, strip_html
from umbra.people.graph import enrichment_from_lakes, graph_from_lake, graph_from_parse

_HREF_RE = re.compile(r'class="result__a"[^>]*href="(https?://[^"]+)"', re.I)
_TITLE_BLOCK_RE = re.compile(
    r'class="result__a"[^>]*href="(https?://[^"]+)"[^>]*>(.*?)</a>',
    re.I | re.S,
)
_SNIPPET_RE = re.compile(r'class="result__snippet"[^>]*>(.*?)</(?:a|td|div)', re.I | re.S)

_OBIT_HOST_HINTS = (
    "legacy.com", "findagrave.com", "echovita.com", "tributearchive.com",
    "obituary", "funeral", "memorial", "dignitymemorial.com",
    "newspapers.com", "genealogybank.com", "chroniclingamerica.loc.gov", "loc.gov",
    "nwaonline.com", "arkansasonline.com", "nwahomepage.com",
)

_FETCH_ALLOW_SUFFIXES = (
    "legacy.com", "findagrave.com", "echovita.com", "tributearchive.com",
    "dignitymemorial.com", "loc.gov", "wikipedia.org",
    "nwaonline.com", "arkansasonline.com",
)

_MAX_PAGE_FETCH = 5
_MAX_BODY_CHARS = 200_000


def _looks_obituary(url: str) -> bool:
    u = url.lower()
    return any(h in u for h in _OBIT_HOST_HINTS)


def _host_fetch_allowed(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    return any(host == sfx or host.endswith("." + sfx) for sfx in _FETCH_ALLOW_SUFFIXES)


def _queries(name: str, loc: str | None) -> list[str]:
    qname = f'"{name.strip()}"'
    base = [
        f"{qname} obituary",
        f'{qname} "survived by"',
        f'{qname} "passed away"',
        f"{qname} site:legacy.com",
        f"{qname} site:findagrave.com",
        f"{qname} site:en.wikipedia.org",
        f"{qname} site:nwaonline.com",
        f"{qname} site:echovita.com",
    ]
    if loc:
        base.insert(1, f"{qname} obituary {loc}")
        base.insert(2, f'{qname} "survived by" {loc}')
    return base


def _fallback_seed_urls(name: str) -> list[str]:
    parts = [x for x in name.replace(",", " ").split() if x]
    if len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    from urllib.parse import quote, quote_plus

    # Preserve capitalization for Wikipedia
    display = " ".join(w[:1].upper() + w[1:] if w else w for w in name.strip().split())
    slug = quote(display.replace(" ", "_"), safe="_")
    return [
        f"https://en.wikipedia.org/wiki/{slug}",
        f"https://www.findagrave.com/memorial/search?firstname={quote_plus(first)}&lastname={quote_plus(last)}",
        f"https://www.legacy.com/obituaries/search?firstName={quote_plus(first)}&lastName={quote_plus(last)}",
        f"https://www.nwaonline.com/obituaries/",
        f"https://www.echovita.com/us",
    ]


def _people_lake(ctx: CollectorContext):
    try:
        from umbra.lake.people import PeopleLake

        return PeopleLake.from_settings(ctx.settings)
    except Exception:  # noqa: BLE001
        return None


class ObituarySearchCollector(BaseCollector):
    name = "obituary_search"
    timeout_s = 90
    inputs = {EntityType.PERSON}
    description = (
        "Search/scrape public obituaries; parse survivors+metadata; store links in people lake"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        src = entity.norm_key
        name = (entity.value or "").strip()
        if not name or " " not in name:
            result.notes.append(
                "obituary_search: need a full person name (given + family) for useful queries"
            )
            return result

        props = entity.props or {}
        loc = props.get("location") or props.get("city") or props.get("state")
        loc_s = str(loc).strip() if loc else None

        lake = _people_lake(ctx)
        lake_hits = 0
        if lake is not None:
            try:
                hits = lake.lookup_name(name, limit=3)
                for h in hits:
                    obits = lake.obituaries_for_person(h["id"])
                    kin = lake.kinship_for_person(h["id"])
                    extra = enrichment_from_lakes(lake, name, dict(h), ctx.settings)
                    ents, eds = graph_from_lake(
                        name, dict(h), obits, kin, src_key=src, **extra
                    )
                    result.entities.extend(ents)
                    result.edges.extend(eds)
                    lake_hits += sum(1 for o in obits if o.get("url"))
                    # decedent field evidence
                    fields = {
                        kk: h.get(kk)
                        for kk in (
                            "age",
                            "birth_date",
                            "death_date",
                            "residence",
                            "death_place",
                            "funeral_home",
                            "cemetery",
                            "occupation",
                            "military",
                        )
                        if h.get(kk)
                    }
                    if fields or lake_hits:
                        result.evidence.append(
                            EvidenceIn(
                                collector=self.name,
                                source_name="people_lake",
                                summary=(
                                    f"People lake hit for {name!r}: "
                                    f"{lake_hits} stored obit link(s); fields={fields}."
                                ),
                                confidence=0.85,
                                raw={"person": dict(h), "fields": fields},
                                entity_key=src,
                            )
                        )
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"people lake read: {exc}")

        all_links: list[str] = []
        text_blobs: list[str] = []
        per_query: dict[str, list[str]] = {}

        for q in _queries(name, loc_s):
            links, blob = self._ddg(q, ctx, result)
            per_query[q] = links
            if blob:
                text_blobs.append(blob)
            for link in links:
                if link not in all_links:
                    all_links.append(link)

        if not all_links:
            result.notes.append(
                "obituary_search: DDG returned no links; using public wiki/memorial fallbacks"
            )
            all_links.extend(_fallback_seed_urls(name))

        ranked = sorted(
            all_links,
            key=lambda u: (
                0 if _host_fetch_allowed(u) else 1,
                0 if _looks_obituary(u) else 1,
                u,
            ),
        )[:20]

        for link in ranked:
            conf = 0.55 if _looks_obituary(link) else 0.4
            result.entities.append(
                EntityIn(
                    type=EntityType.URL,
                    value=link,
                    confidence=conf,
                    props={
                        "obituary_candidate": _looks_obituary(link),
                        "manual_confirm": True,
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, link),
                    rel=EdgeType.MENTIONS,
                    confidence=conf,
                    props={"kind": "obituary_candidate", "obituary_host": _looks_obituary(link)},
                )
            )
            try:
                host = link.split("://", 1)[1].split("/", 1)[0].lower()
                if host.startswith("www."):
                    host = host[4:]
                if host and "." in host:
                    result.entities.append(
                        EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.35)
                    )
                    result.edges.append(
                        EdgeIn(
                            source_key=src,
                            target_key=entity_key(EntityType.DOMAIN, host),
                            rel=EdgeType.MENTIONS,
                            confidence=0.35,
                            props={"kind": "obituary_source_host"},
                        )
                    )
            except Exception:
                pass

        # lake already opened above for hydrate (may be None)
        fetched: list[dict] = []
        parses: list[dict] = []
        to_fetch = [u for u in ranked if _host_fetch_allowed(u)][:_MAX_PAGE_FETCH]
        extra_fetch: list[str] = []

        def _ingest_page(page_url: str, *, via: str | None = None) -> None:
            body_text, meta = self._fetch_public_obit(page_url, ctx, result)
            rec = {"url": page_url, **{k: v for k, v in meta.items() if k != "html"}}
            if via:
                rec["via"] = via
            fetched.append(rec)
            html = meta.get("html") or ""
            title = meta.get("title_guess")
            if body_text:
                text_blobs.append(body_text)
                if "findagrave.com/memorial/search" in page_url and html:
                    last = name.strip().split()[-1].lower().replace("'", "")

                    def _fg_match(u: str) -> bool:
                        slug = u.lower().rstrip("/").rsplit("/", 1)[-1]
                        parts = slug.replace("_", "-").split("-")
                        return last in parts

                    for m in re.findall(
                        r'href="(https://www\.findagrave\.com/memorial/\d+/[^"?#]+)"',
                        html,
                    ):
                        if _fg_match(m) and m not in extra_fetch and m not in to_fetch:
                            extra_fetch.append(m)
                    for m in re.findall(r'href="(/memorial/\d+/[^"?#]+)"', html):
                        full = "https://www.findagrave.com" + m
                        if _fg_match(full) and full not in extra_fetch and full not in to_fetch:
                            extra_fetch.append(full)

                parsed = parse_obituary_text(
                    body_text, decedent_name=name, title=title
                )
                pdata = parsed.to_dict()
                parses.append({"url": page_url, "parse": pdata})

                # Always store the link + parse in people lake
                if lake is not None and meta.get("status") == 200:
                    try:
                        lake.upsert_person_from_parse(
                            decedent_name=name,
                            parse=pdata,
                            source_url=page_url,
                            title=title,
                            http_status=meta.get("status"),
                            excerpt=body_text[:1500],
                            confidence=0.55,
                        )
                    except Exception as exc:  # noqa: BLE001
                        result.notes.append(f"people lake upsert: {exc}")

                # Rich URL entity props for the case graph
                result.entities.append(
                    EntityIn(
                        type=EntityType.URL,
                        value=page_url,
                        display_name=title or page_url,
                        confidence=0.7,
                        props={
                            "obituary_candidate": True,
                            "scraped": True,
                            "obituary": {
                                "age": pdata.get("age"),
                                "birth_date": pdata.get("birth_date"),
                                "death_date": pdata.get("death_date"),
                                "residence": pdata.get("residence"),
                                "death_place": pdata.get("death_place"),
                                "funeral_home": pdata.get("funeral_home"),
                                "cemetery": pdata.get("cemetery"),
                                "occupation": pdata.get("occupation"),
                                "military": pdata.get("military"),
                                "survivor_count": len(pdata.get("survivors") or []),
                            },
                            "manual_confirm": True,
                        },
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.URL, page_url),
                        rel=EdgeType.MENTIONS,
                        confidence=0.7,
                        props={"kind": "obituary_scraped", "link": page_url},
                    )
                )
                result.evidence.append(
                    EvidenceIn(
                        collector=self.name,
                        source_name="public_obituary_page",
                        source_url=page_url,
                        summary=(
                            f"Scraped {page_url} ({meta.get('status')}, "
                            f"{meta.get('chars', 0)} chars). "
                            f"age={pdata.get('age')} death={pdata.get('death_date')} "
                            f"survivors={len(pdata.get('survivors') or [])} "
                            f"preceded={len(pdata.get('preceded') or [])}."
                        ),
                        confidence=0.7,
                        raw={
                            "url": page_url,
                            "status": meta.get("status"),
                            "chars": meta.get("chars"),
                            "title_guess": title,
                            "parse": pdata,
                        },
                        entity_key=src,
                    )
                )

        for page_url in to_fetch:
            _ingest_page(page_url)
        for page_url in extra_fetch[:3]:
            _ingest_page(page_url, via="findagrave_search_follow")

        # Also parse combined snippet text (when bodies thin)
        combined = "\n".join(text_blobs)
        combined_parse = parse_obituary_text(combined, decedent_name=name)
        # Merge survivors from page parses + combined
        survivor_map: dict[str, dict] = {}
        for block in parses:
            for s in block["parse"].get("survivors") or []:
                survivor_map[s["name"].lower()] = s
        for s in combined_parse.to_dict().get("survivors") or []:
            survivor_map.setdefault(s["name"].lower(), s)
        for block in parses:
            for s in block["parse"].get("preceded") or []:
                key = s["name"].lower()
                if key not in survivor_map:
                    s = dict(s)
                    s["living"] = False
                    survivor_map[key] = s

        family_added = 0
        merged_parse = combined_parse.to_dict()
        merged_parse["survivors"] = list(survivor_map.values())
        # Prefer page-parse facts over combined snippets
        for block in parses:
            for k, v in block["parse"].items():
                if k in {"survivors", "preceded", "raw_survivor_clauses"}:
                    continue
                if v and not merged_parse.get(k):
                    merged_parse[k] = v
        src_url = None
        if parses:
            src_url = parses[0].get("url")
        g_ents, g_edges = graph_from_parse(
            name, merged_parse, source_url=src_url, source="obituary", src_key=src
        )
        result.entities.extend(g_ents)
        result.edges.extend(g_edges)
        family_added = sum(1 for e in g_edges if e.rel == EdgeType.RELATED_TO)

        # Enrich seed person props on evidence (orchestrator may not mutate seed)
        seed_fields = {
            k: combined_parse.to_dict().get(k)
            for k in (
                "age", "birth_date", "death_date", "residence", "death_place",
                "funeral_home", "cemetery", "occupation", "military",
            )
            if combined_parse.to_dict().get(k)
        }
        # Prefer non-null from page parses
        for block in parses:
            for k, v in block["parse"].items():
                if k in seed_fields or k in {
                    "age", "birth_date", "death_date", "residence", "death_place",
                    "funeral_home", "cemetery", "occupation", "military",
                }:
                    if v and not seed_fields.get(k):
                        seed_fields[k] = v

        fetched_ok = sum(1 for f in fetched if f.get("status") == 200 and f.get("chars", 0) > 0)
        lake_status = None
        if lake is not None:
            try:
                lake_status = lake.status().as_dict()
            except Exception:
                pass

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="obituary_search (discover + scrape + people lake)",
                source_url=f"https://duckduckgo.com/?q={quote_plus(_queries(name, loc_s)[0])}",
                summary=(
                    f"Obituary pipeline for {name!r}: {len(ranked)} links, "
                    f"fetched {fetched_ok} pages, {family_added} kin candidates. "
                    f"Fields: {seed_fields or '{}'}. "
                    f"People lake: {lake_status}."
                ),
                confidence=0.6 if fetched_ok else 0.45,
                raw={
                    "name": name,
                    "location": loc_s,
                    "queries": per_query,
                    "links": ranked,
                    "fetched_pages": fetched,
                    "parses": parses,
                    "survivors": list(survivor_map.values()),
                    "decedent_fields": seed_fields,
                    "people_lake": lake_status,
                },
                entity_key=src,
            )
        )
        if lake is not None:
            try:
                lake.close()
            except Exception:
                pass
        return result

    def _fetch_public_obit(
        self, url: str, ctx: CollectorContext, result: CollectorResult
    ) -> tuple[str, dict]:
        meta: dict = {"status": None, "chars": 0, "title_guess": None, "error": None}
        if not _host_fetch_allowed(url):
            meta["error"] = "host_not_allowlisted"
            return "", meta
        try:
            resp = ctx.http.get(
                url,
                headers={"User-Agent": ctx.settings.user_agent, "Accept": "text/html"},
                follow_redirects=True,
                timeout=getattr(ctx.settings, "request_timeout_s", 20) or 20,
            )
            meta["status"] = resp.status_code
            if resp.status_code >= 400:
                result.notes.append(f"obituary_search fetch {url!r}: HTTP {resp.status_code}")
                return "", meta
            html = (resp.text or "")[:_MAX_BODY_CHARS]
            meta["html"] = html
            tm = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            if tm:
                meta["title_guess"] = strip_html(tm.group(1))[:200]
            text = strip_html(html)
            meta["chars"] = len(text)
            return text[:50_000], meta
        except Exception as exc:  # noqa: BLE001
            meta["error"] = str(exc)[:200]
            result.notes.append(f"obituary_search fetch {url!r}: {exc}")
            return "", meta

    def _ddg(
        self, q: str, ctx: CollectorContext, result: CollectorResult
    ) -> tuple[list[str], str]:
        url = "https://html.duckduckgo.com/html/"
        try:
            resp = ctx.http.post(
                url,
                data={"q": q, "b": ""},
                headers={
                    "User-Agent": ctx.settings.user_agent,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                follow_redirects=True,
            )
            resp.raise_for_status()
            html = resp.text
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"obituary_search ddg {q!r}: {exc}")
            return [], ""

        links: list[str] = []
        for m in _HREF_RE.findall(html):
            if m not in links:
                links.append(m)
        for m in re.findall(r"uddg=([^&\"']+)", html):
            try:
                u = unquote(m)
            except Exception:
                continue
            if u.startswith("http") and u not in links:
                links.append(u)

        parts: list[str] = []
        for href, title_html in _TITLE_BLOCK_RE.findall(html):
            parts.append(strip_html(title_html))
            parts.append(href)
        for sn in _SNIPPET_RE.findall(html):
            parts.append(strip_html(sn))
        blob = " | ".join(parts)[:8000]
        return links[:12], blob
