"""SEC EDGAR search via public HTTP endpoints — no API key (SEC fair-access UA)."""

from __future__ import annotations

import re
from urllib.parse import quote_plus

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

_CIK_RE = re.compile(r"/CIK=(\d+)", re.I)
_COMPANY_RE = re.compile(
    r'<span class="companyName">([^<]+)<.*?CIK=<?(\d+)',
    re.I | re.S,
)
# browse-edgar company hit
_HREF_CIK = re.compile(r"browse-edgar\?action=getcompany&CIK=(\d+)[^\"']*\"[^>]*>([^<]+)", re.I)


class EdgarSearchCollector(BaseCollector):
    name = "edgar_search"
    timeout_s = 45
    inputs = {EntityType.ORG, EntityType.PERSON}
    description = "SEC EDGAR company/person search via public browse pages (no key)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        q = entity.value.strip()
        src = entity.norm_key
        # SEC requires descriptive User-Agent with contact
        headers = {
            "User-Agent": "Umbra/0.1 (authorized research; local lab; contact: umbra@localhost)",
            "Accept": "text/html,application/json",
            "Accept-Encoding": "gzip, deflate",
        }
        url = (
            "https://www.sec.gov/cgi-bin/browse-edgar"
            f"?company={quote_plus(q)}&owner=include&action=getcompany"
        )
        try:
            resp = ctx.http.get(url, headers=headers, follow_redirects=True)
            if resp.status_code != 200:
                result.notes.append(f"EDGAR HTTP {resp.status_code}")
                return result
            html = resp.text
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"EDGAR: {exc}")
            return result

        hits: list[dict] = []
        # company name line pattern
        for m in re.finditer(
            r'class="companyName">\s*([^<\n]+)\s*<small>.*?CIK=<?(\d+)',
            html,
            re.I | re.S,
        ):
            name = re.sub(r"\s+", " ", m.group(1)).strip()
            cik = m.group(2).lstrip("0") or m.group(2)
            hits.append({"name": name, "cik": cik})

        if not hits:
            for m in _HREF_CIK.finditer(html):
                cik, name = m.group(1), re.sub(r"\s+", " ", m.group(2)).strip()
                hits.append({"name": name, "cik": cik.lstrip("0") or cik})

        # unique by cik
        seen = set()
        uniq = []
        for h in hits:
            if h["cik"] in seen:
                continue
            seen.add(h["cik"])
            uniq.append(h)
        hits = uniq[:15]

        for h in hits:
            cik = h["cik"]
            name = h["name"]
            cik_url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}&owner=include&count=40"
            result.entities.append(
                EntityIn(
                    type=EntityType.ORG,
                    value=name,
                    confidence=0.65,
                    props={"cik": cik, "source": "edgar"},
                )
            )
            result.entities.append(EntityIn(type=EntityType.URL, value=cik_url, confidence=0.8))
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.ORG, name),
                    rel=EdgeType.MENTIONS if entity.type == EntityType.PERSON.value else EdgeType.SAME_AS,
                    confidence=0.5,
                    props={"cik": cik},
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.ORG, name),
                    target_key=entity_key(EntityType.URL, cik_url),
                    rel=EdgeType.HAS_PROFILE,
                    confidence=0.8,
                )
            )

        # Also try EDGAR full-text search JSON-ish endpoint (public)
        efts = f"https://efts.sec.gov/LATEST/search-index?q=%22{quote_plus(q)}%22&dateRange=custom&startdt=2018-01-01&enddt=2030-01-01&forms=10-K,10-Q,8-K"
        try:
            er = ctx.http.get(
                "https://efts.sec.gov/LATEST/search-index",
                params={
                    "q": f'"{q}"',
                    "dateRange": "all",
                    "forms": "10-K,8-K,10-Q",
                },
                headers=headers,
            )
            efts_count = None
            if er.status_code == 200:
                try:
                    data = er.json()
                    hits_meta = data.get("hits") or {}
                    efts_count = hits_meta.get("total", {}).get("value")
                    for item in (hits_meta.get("hits") or [])[:10]:
                        src_doc = item.get("_source") or {}
                        display = src_doc.get("display_names") or src_doc.get("entity_name")
                        if isinstance(display, list):
                            display = display[0] if display else None
                        file_url = None
                        adsh = src_doc.get("adsh") or (item.get("_id") or "")
                        if display:
                            result.entities.append(
                                EntityIn(
                                    type=EntityType.ORG,
                                    value=str(display).split("(")[0].strip()[:120],
                                    confidence=0.45,
                                    props={"edgar_efts": True},
                                )
                            )
                except Exception:
                    efts_count = None
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="SEC EDGAR",
                    source_url=url,
                    summary=f"EDGAR search {q!r}: browse_hits={len(hits)} efts_total={efts_count}",
                    confidence=0.7,
                    raw={"browse_hits": hits, "efts_total": efts_count},
                    entity_key=src,
                )
            )
        except Exception as exc:  # noqa: BLE001
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="SEC EDGAR",
                    source_url=url,
                    summary=f"EDGAR browse {q!r}: {len(hits)} hit(s); efts error {exc}",
                    confidence=0.65,
                    raw={"browse_hits": hits},
                    entity_key=src,
                )
            )

        return result
