"""Technology → known-exploited CVEs, from the owned corpus.

Rank 3 of `references/open-knowledge-sources.md`. The plan
(`references/nvd-cve-collector.md`) specifies an `nvd_cve` collector querying
the NVD REST API. This deviates on the data source, deliberately, and keeps the
plan's entity and edge model.

**Why a `vulnerability` entity type here, when `event` was refused.** A CVE is
globally identified, stable, and authoritative — and it is a *join node*. "Which
of my assets are affected by Log4Shell" is a graph traversal through the CVE, so
the CVE has to be a node for the question to be answerable at all. It is also
already the primary key of 1,665 pages in the wiki corpus, so the entity value
and its page slug are the same string. None of that was true of `event`.

**Why the owned corpus instead of the NVD API.** Asking NVD "what affects nginx"
returns hundreds of CVEs, most of them old, unexploited, and irrelevant to a
running case — the graph explosion that deep-scan budgets exist to prevent. The
corpus holds **CISA KEV**: vulnerabilities *known to be exploited in the wild*,
which is the actionable subset and is bounded by construction (1,665 total, a
handful per product). It needs no API key, no rate limit, and works offline, and
CI refreshes it daily. Same "own the data" pattern as `ct_lake` and the OUI lake.

**The honesty requirement.** No KEV entry does **not** mean no vulnerabilities —
nginx has plenty of CVEs and zero KEV entries. Saying "no known exploited
vulnerabilities" is true; saying "no vulnerabilities" would be false and is the
same unchecked-versus-clean failure this project keeps designing against.
"""
from __future__ import annotations

import logging
import re

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import (
    CollectorResult,
    EdgeIn,
    EdgeType,
    EntityIn,
    EntityType,
    EvidenceIn,
)
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

logger = logging.getLogger(__name__)

# A product with more matches than this is almost certainly a loose text match
# rather than a real affected-product list.
MAX_CVES = 15
# Below this, a corpus hit is more likely to be prose mentioning the word than a
# KEV entry for the product.
MIN_QUERY_LEN = 3

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
_FIELD_RE = {
    "vendor": re.compile(r"\|\s*Vendor / project\s*\|\s*([^|\n]+)", re.I),
    "product": re.compile(r"\|\s*Product\s*\|\s*([^|\n]+)", re.I),
    "date_added": re.compile(r"\|\s*Date added\s*\|\s*([^|\n]+)", re.I),
    "ransomware": re.compile(r"\|\s*Ransomware campaign use\s*\|\s*([^|\n]+)", re.I),
}


def _corpus_hits(query: str, limit: int) -> list[dict]:
    """CVE pages from the owned corpus. Seam for tests; never raises."""
    try:
        from umbra.wiki.service import WikiService

        svc = WikiService()
        return [h for h in svc.lookup(query, limit=limit)
                if (h.get("page_type") or "") == "cve"]
    except Exception as exc:  # noqa: BLE001 - a missing corpus is not an error
        logger.warning("cve corpus unavailable: %s", exc)
        return []


def _field(body: str, name: str) -> str | None:
    m = _FIELD_RE[name].search(body or "")
    return m.group(1).strip() if m else None


def _mentions_product(page: dict, query: str) -> bool:
    """Only count a page whose Vendor/Product actually names the query.

    Full-text search will happily return a page that mentions the word in
    passing; the metadata table is the affected-product list.
    """
    body = page.get("body") or ""
    q = query.strip().lower()
    for key in ("vendor", "product"):
        value = (_field(body, key) or "").lower()
        if value and (q in value or value in q):
            return True
    return False


class CveLookupCollector(BaseCollector):
    name = "cve_lookup"
    timeout_s = 10
    version = "0.1.0"
    inputs = {EntityType.TECHNOLOGY}
    description = ("Known-exploited CVEs (CISA KEV) affecting a technology, from the "
                   "owned corpus — no external API")


    def _epss_lake(self, ctx, result):
        """The EPSS lake, or None with a note saying why there is no score.

        Never a silent absence: a CVE rendered without a score should be
        explained by something the reader can act on.
        """
        try:
            from umbra.lake.epss import EpssLake

            lake = EpssLake.from_settings(ctx.settings)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"epss lake unreadable: {exc}")
            return None
        if not lake.row_count():
            result.notes.append(
                "EPSS lake empty — run `umbra epss sync`. CVEs below carry no "
                "exploitation probability; that is unscored, not low."
            )
            lake.close()
            return None
        return lake

    @staticmethod
    def _epss_props(lake, cve_id: str) -> dict:
        """EPSS fields for a CVE, or nothing at all.

        Deliberately omits the keys rather than writing `epss: None`. A null in
        a props dict reads as "we looked and it is zero" to anything rendering
        it, and unscored is not zero.
        """
        if lake is None:
            return {}
        hit = lake.score(cve_id)
        if not hit:
            return {"epss_scored": False}
        return {
            "epss_scored": True,
            "epss": hit["score"],
            "epss_percentile": hit["percentile"],
            "epss_band": hit["band"],
            # The model that produced the number travels with it.
            "epss_model_version": hit["model_version"],
            "epss_score_date": hit["score_date"],
        }

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        product = (entity.value or "").strip()
        if len(product) < MIN_QUERY_LEN:
            return result

        pages = [p for p in _corpus_hits(product, MAX_CVES * 3)
                 if _mentions_product(p, product)][:MAX_CVES]

        if not pages:
            # The distinction that matters: KEV is the *exploited* subset.
            result.notes.append(
                f"no known-exploited (CISA KEV) vulnerabilities recorded for "
                f"{product!r}. This is not 'no vulnerabilities' — the corpus "
                f"covers KEV plus imported NVD entries, not all of NVD."
            )
            return result

        src_key = entity.norm_key

        # EPSS annotates each KEV hit with the modelled probability of
        # exploitation. KEV already tells you it *is* exploited, so the score
        # adds nothing to that judgement — what it adds is ordering. A product
        # with nine KEV entries needs a "look at this one first", and severity
        # alone does not give one.
        epss = self._epss_lake(ctx, result)

        for page in pages:
            slug = page.get("slug") or ""
            match = _CVE_RE.search(slug) or _CVE_RE.search(page.get("title") or "")
            if not match:
                continue
            cve_id = match.group(0).upper()
            body = page.get("body") or ""
            vendor = _field(body, "vendor")
            ransomware = (_field(body, "ransomware") or "").lower()

            result.entities.append(EntityIn(
                type=EntityType.VULNERABILITY,
                value=cve_id,
                confidence=0.9,
                props={
                    "source": "cisa_kev",
                    "wiki_slug": slug,
                    "vendor": vendor,
                    "product": _field(body, "product"),
                    "kev_date_added": _field(body, "date_added"),
                    "known_ransomware_use": ransomware.startswith("known"),
                    **self._epss_props(epss, cve_id),
                },
            ))
            result.edges.append(EdgeIn(
                source_key=src_key,
                target_key=entity_key(EntityType.VULNERABILITY, cve_id),
                rel=EdgeType.AFFECTED_BY,
                confidence=0.9,
                props={"source": "cisa_kev"},
            ))
            result.evidence.append(EvidenceIn(
                collector=self.name,
                source_name="CISA Known Exploited Vulnerabilities (owned corpus)",
                source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                summary=(f"{product} is affected by {cve_id}"
                         + (" — known ransomware campaign use" if ransomware.startswith("known") else "")),
                confidence=0.9,
                raw={
                    "cve_id": cve_id,
                    "wiki_slug": slug,
                    "vendor": vendor,
                    "product": _field(body, "product"),
                    "kev_date_added": _field(body, "date_added"),
                    "known_ransomware_use": ransomware.startswith("known"),
                    "source": "cisa_kev",
                },
                entity_key=src_key,
            ))

        if result.entities:
            result.notes.append(
                f"{len(result.entities)} known-exploited CVE(s) for {product} — "
                f"KEV membership means exploited in the wild, so these are "
                f"prioritised over CVSS score."
            )
        return result
