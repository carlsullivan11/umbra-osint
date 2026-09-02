from __future__ import annotations

import re
from urllib.parse import quote_plus, unquote

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

_RESULT_RE = re.compile(
    r'uddg=([^&"]+)|href="//duckduckgo\.com/l/\?uddg=([^&"]+)"|class="result__a"[^>]*href="(https?://[^"]+)"',
    re.I,
)
_HREF_RE = re.compile(r'class="result__a"[^>]*href="(https?://[^"]+)"', re.I)


class DdgSearchCollector(BaseCollector):
    name = "ddg_search"
    timeout_s = 45
    inputs = {EntityType.PERSON, EntityType.ORG, EntityType.DOMAIN, EntityType.USERNAME}
    description = "DuckDuckGo HTML search (free substitute for paid web intel APIs)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        src = entity.norm_key
        if entity.type == EntityType.PERSON.value:
            q = f'"{entity.value}"'
            # light disambiguation from props
            loc = (entity.props or {}).get("location")
            org = (entity.props or {}).get("org")
            if loc:
                q += f" {loc}"
            if org:
                q += f" {org}"
        elif entity.type == EntityType.USERNAME.value:
            handle = entity.value.split(":")[-1]
            q = f'"{handle}"'
        elif entity.type == EntityType.DOMAIN.value:
            q = f"site:{entity.value} OR \"{entity.value}\""
        else:
            q = f'"{entity.value}"'

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
            result.notes.append(f"ddg_search: {exc}")
            return result

        links: list[str] = []
        for m in _HREF_RE.findall(html):
            if m not in links:
                links.append(m)
        # fallback uddg
        for m in re.findall(r"uddg=([^&\"']+)", html):
            try:
                u = unquote(m)
            except Exception:
                continue
            if u.startswith("http") and u not in links:
                links.append(u)

        links = links[:15]
        for link in links:
            result.entities.append(EntityIn(type=EntityType.URL, value=link, confidence=0.45))
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, link),
                    rel=EdgeType.MENTIONS,
                    confidence=0.45,
                    props={"query": q},
                )
            )
            # domain extract
            try:
                host = link.split("://", 1)[1].split("/", 1)[0].lower()
                if host.startswith("www."):
                    host = host[4:]
                if host and "." in host:
                    result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host, confidence=0.4))
                    result.edges.append(
                        EdgeIn(
                            source_key=src,
                            target_key=entity_key(EntityType.DOMAIN, host),
                            rel=EdgeType.MENTIONS,
                            confidence=0.4,
                        )
                    )
            except Exception:
                pass

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="DuckDuckGo HTML",
                source_url=f"https://duckduckgo.com/?q={quote_plus(q)}",
                summary=f"DDG search {q!r}: {len(links)} result link(s)",
                confidence=0.5,
                raw={"query": q, "links": links},
                entity_key=src,
            )
        )
        return result
