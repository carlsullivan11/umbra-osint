"""OpenCorporates company search via public HTML — no API key.

Note: OC often returns an hCaptcha wall to datacenter IPs. When that happens we
record evidence and recommend `wikidata` instead of fighting captchas.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus, urljoin

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

_COMPANY_HREF = re.compile(
    r'href="(https://opencorporates\.com/companies/[^"]+)"[^>]*>([^<]+)</a>',
    re.I,
)
_COMPANY_HREF2 = re.compile(r'href="(/companies/[a-z]{2,}/[^"]+)"[^>]*>\s*([^<]+)', re.I)


class OpenCorporatesCollector(BaseCollector):
    name = "opencorporates"
    timeout_s = 45
    inputs = {EntityType.ORG, EntityType.PERSON}
    description = "OpenCorporates HTML company search (captcha-aware; prefer `wikidata`)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        q = entity.value.strip()
        src = entity.norm_key
        url = f"https://opencorporates.com/companies?q={quote_plus(q)}&utf8=%E2%9C%93"
        try:
            resp = ctx.http.get(url, follow_redirects=True)
            html = resp.text or ""
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"opencorporates: {exc}")
            return result

        if (
            resp.status_code != 200
            or "captcha" in html.lower()
            or "hcaptcha" in html.lower()
            or "HAProxy Challenge" in html
        ):
            # A note, not evidence. This used to write an evidence row saying
            # "captcha wall — not scraped" at confidence 0.3, and on production
            # that was *every* row the collector ever produced: 31 of 31, in
            # every person and org result, sitting beside real findings and
            # saying nothing. A source that refused to answer has not found
            # anything, and the run-notes UI is where a source failure belongs.
            result.notes.append(
                f"opencorporates: captcha wall or block (HTTP {resp.status_code}) "
                "— unchecked, not an absence of companies by that name. "
                "OpenCorporates serves a challenge to datacenter IPs; "
                "`wikidata` is the free substitute."
            )
            return result

        hits: list[tuple[str, str]] = []
        for m in _COMPANY_HREF.finditer(html):
            hits.append((m.group(1), re.sub(r"\s+", " ", m.group(2)).strip()))
        if not hits:
            for m in _COMPANY_HREF2.finditer(html):
                full = urljoin("https://opencorporates.com", m.group(1))
                hits.append((full, re.sub(r"\s+", " ", m.group(2)).strip()))

        seen: set[str] = set()
        uniq: list[tuple[str, str]] = []
        for link, name in hits:
            if link in seen or not name or name.lower() in {"companies", "search"}:
                continue
            seen.add(link)
            uniq.append((link, name))
        hits = uniq[:20]

        for link, name in hits:
            parts = link.rstrip("/").split("/")
            jur = parts[-2] if len(parts) >= 2 else None
            result.entities.append(
                EntityIn(
                    type=EntityType.ORG,
                    value=name,
                    confidence=0.55,
                    props={"opencorporates": link, "jurisdiction": jur},
                )
            )
            result.entities.append(EntityIn(type=EntityType.URL, value=link, confidence=0.8))
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.ORG, name),
                    rel=EdgeType.MENTIONS if entity.type == EntityType.PERSON.value else EdgeType.SAME_AS,
                    confidence=0.45,
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.ORG, name),
                    target_key=entity_key(EntityType.URL, link),
                    rel=EdgeType.HAS_PROFILE,
                    confidence=0.75,
                )
            )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="OpenCorporates HTML",
                source_url=url,
                summary=f"OpenCorporates {q!r}: {len(hits)} company hit(s)",
                confidence=0.65,
                raw={"hits": [{"url": u, "name": n} for u, n in hits]},
                entity_key=src,
            )
        )
        return result
