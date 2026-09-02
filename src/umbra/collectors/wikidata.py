"""Wikidata claim collector — structured context with per-claim provenance.

Phase 2 of `references/wikidata-integration.md`, using the property mappings in
`references/wikidata-schema.md` (verified against the live API in Phase 1).

Replaces `wikidata_search` (retired 2026-08-16), which resolved a label to a
handful of hits and recorded them as one blob. This takes a QID or a label and
walks the mapped claims, recording **each claim as its own evidence** with the
property it came from, the QID it belongs to, its reference URLs, and when it
was retrieved — which is what makes a single fact citable, contestable, and
ageable later. Keeping both meant every org and person run queried Wikidata
twice for overlapping data.

Three rules, each of which is a correctness property rather than a style choice:

- **Deprecated claims are skipped.** A deprecated rank is Wikidata recording a
  statement as *known wrong*. Ingesting one imports an error as a fact — the
  same failure as importing revoked ATT&CK techniques.
- **An unsourced claim is recorded as unsourced**, and scored lower. Most claims
  carry no reference at all; presenting them as sourced would be exactly the
  provenance theatre this project exists to avoid.
- **Referenced items are resolved to labels in one batched request.** `Q62` in a
  case graph is unreadable, and one request per QID is a burst of small calls
  against a free public endpoint.

Ethics: Wikidata content is CC0 and public. This reads it; it never writes.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

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

API = "https://www.wikidata.org/w/api.php"
ENTITY_URL = "https://www.wikidata.org/wiki/{qid}"

# Wikidata's user-agent policy asks for something identifying and contactable;
# anonymous bulk clients get blocked.
USER_AGENT = "umbra-osint/0.1 (https://github.com/carlsullivan11/umbra)"

_QID_RE = re.compile(r"^Q\d+$", re.I)
# wbgetentities accepts up to 50 ids per call.
_BATCH = 50
_CACHE_TTL_S = 24 * 3600

# Property -> (human label, how to treat the value). Straight from the schema
# doc; anything not listed here is deliberately not ingested.
ITEM_PROPS = {
    "P31": "instance of",
    "P17": "country",
    "P159": "headquarters location",
    "P112": "founder",
    "P27": "country of citizenship",
}
VALUE_PROPS = {
    "P3587": "CVE ID",
    # Ported from wikidata_search when it was retired — the one field it
    # extracted that this collector did not, and it matters for corporate work.
    "P1278": "LEI (Legal Entity Identifier)",
    "P856": "official website",
    "P1324": "source code repository",
    "P569": "date of birth",
    "P570": "date of death",
}

# Which claims become graph edges, and as what.
EDGE_FOR = {
    "P159": (EdgeType.HEADQUARTERED_IN, EntityType.LOCATION),
    "P17": (EdgeType.LOCATED_IN, EntityType.LOCATION),
    "P112": (EdgeType.FOUNDED_BY, EntityType.PERSON),
    "P27": (EdgeType.CITIZEN_OF, EntityType.LOCATION),
}

# Incident classes, resolved after Phase 1 research.
#
# Wikidata does not model incidents as events: `cyberattack` is a *method*
# (cyberattack -> cyber adversary technique -> tactic -> method) and `data
# breach` is a *process* whose parent `occurrent` is the parent of `occurrence`
# too — making them siblings, not descendants. So no "event" root class catches
# them, and an `event` entity type would have matched nothing while duplicating
# `breach`, which Umbra already has, HIBP already populates, and the watch
# module already monitors.
#
# Instead, incident items land on types that already exist and already have
# features built on them.
BREACH_CLASSES = {
    "Q1172486",   # data breach
    "Q2143665",   # security breach / data leak
}
VULNERABILITY_CLASSES = {
    "Q631425",    # vulnerability
    "Q110464538", # named vulnerability
}

# Reference snak properties, in the order we prefer them.
REF_URL_PROP = "P854"          # reference URL
REF_ITEM_PROPS = ("P248", "P143")  # stated in / imported from


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _cache_path(cache_dir, key: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", key)[:80]
    return Path(cache_dir) / f"wikidata_{safe}.json"


def _cache_get(cache_dir, key: str):
    path = _cache_path(cache_dir, key)
    try:
        if not path.is_file():
            return None
        age = datetime.now(tz=timezone.utc).timestamp() - path.stat().st_mtime
        if age > _CACHE_TTL_S:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _cache_put(cache_dir, key: str, value) -> None:
    try:
        path = _cache_path(cache_dir, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")
    except (OSError, TypeError):
        logger.debug("wikidata cache write failed for %s", key)


def _api(ctx: CollectorContext, cache_key: str, **params):
    """One GET against the API, cached. Returns None on any failure."""
    cache_dir = getattr(ctx.settings, "cache_dir", None)
    if cache_dir:
        hit = _cache_get(cache_dir, cache_key)
        if hit is not None:
            return hit
    try:
        resp = ctx.http.get(API, params={**params, "format": "json"},
                            headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            logger.warning("wikidata %s -> HTTP %s", cache_key, resp.status_code)
            return None
        data = resp.json()
    except Exception as exc:  # noqa: BLE001 - collectors fail soft
        logger.warning("wikidata request failed (%s): %s", cache_key, exc)
        return None
    if cache_dir:
        _cache_put(cache_dir, cache_key, data)
    return data


def _search_qid(ctx: CollectorContext, label: str) -> str | None:
    data = _api(ctx, f"search_{label.lower()}", action="wbsearchentities",
                search=label, language="en", type="item", limit=1)
    hits = (data or {}).get("search") or []
    return hits[0].get("id") if hits else None


def _get_entities(ctx: CollectorContext, qids: list[str]) -> dict:
    """Fetch entities in batches; wbgetentities takes up to 50 ids."""
    out: dict = {}
    for i in range(0, len(qids), _BATCH):
        chunk = qids[i:i + _BATCH]
        data = _api(ctx, "ents_" + "_".join(chunk), action="wbgetentities",
                    ids="|".join(chunk), props="labels|descriptions|claims",
                    languages="en")
        out.update((data or {}).get("entities") or {})
    return out


def _label_of(entity: dict, fallback: str) -> str:
    return ((entity.get("labels") or {}).get("en") or {}).get("value") or fallback


def _reference_urls(claim: dict) -> tuple[list[str], list[str]]:
    """(reference URLs, item-valued sources) for one claim."""
    urls: list[str] = []
    items: list[str] = []
    for ref in claim.get("references") or []:
        snaks = ref.get("snaks") or {}
        for snak in snaks.get(REF_URL_PROP, []):
            value = (snak.get("datavalue") or {}).get("value")
            if isinstance(value, str):
                urls.append(value)
        for prop in REF_ITEM_PROPS:
            for snak in snaks.get(prop, []):
                value = (snak.get("datavalue") or {}).get("value")
                if isinstance(value, dict) and value.get("id"):
                    items.append(value["id"])
    return urls, items


def _claim_value(claim: dict):
    return ((claim.get("mainsnak") or {}).get("datavalue") or {}).get("value")


def _readable(value) -> str:
    """A claim value as text, without pretending a date is a string."""
    if isinstance(value, dict):
        if "time" in value:
            return str(value["time"]).lstrip("+")[:10]
        if "id" in value:
            return str(value["id"])
        return json.dumps(value, sort_keys=True)[:120]
    return str(value)


class WikidataCollector(BaseCollector):
    name = "wikidata"
    timeout_s = 30
    version = "0.1.0"
    inputs = {EntityType.ORG, EntityType.PERSON, EntityType.LOCATION}
    description = "Wikidata claims with per-claim provenance (QID or label; CC0 public data)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        value = (entity.value or "").strip()
        if not value:
            return result

        # A QID is unambiguous — searching for it by label would waste a request
        # and risk matching a different item.
        qid = value.upper() if _QID_RE.match(value) else _search_qid(ctx, value)
        if not qid:
            result.notes.append(f"no wikidata match for {value!r}")
            return result

        entities = _get_entities(ctx, [qid])
        item = entities.get(qid)
        if not item:
            result.notes.append(f"wikidata lookup failed for {qid}")
            return result

        claims = item.get("claims") or {}
        label = _label_of(item, value)
        retrieved_at = _now()
        src_key = entity.norm_key

        # Record the QID on the seed so a later run can skip the search. When
        # the seed *was* a QID, the entity is named by its label instead: a
        # graph node called "Q4778915" is unreadable, and the label is already
        # in hand.
        seeded_as_qid = bool(_QID_RE.match(value))
        result.entities.append(
            EntityIn(type=EntityType(entity.type),
                     value=label if seeded_as_qid else value,
                     confidence=max(0.85, float(entity.confidence or 0.5)),
                     props={"wikidata_qid": qid, "wikidata_label": label})
        )
        if seeded_as_qid:
            # Keep the QID reachable in the graph rather than dropping the link.
            result.edges.append(
                EdgeIn(source_key=src_key,
                       target_key=entity_key(EntityType(entity.type), label),
                       rel=EdgeType.SAME_AS, confidence=0.95,
                       props={"wikidata_qid": qid, "source": "wikidata"})
            )

        # Referenced items are resolved together rather than one call each.
        wanted: list[str] = []
        for prop in ITEM_PROPS:
            for claim in claims.get(prop, []):
                if claim.get("rank") == "deprecated":
                    continue
                value_obj = _claim_value(claim)
                if isinstance(value_obj, dict) and value_obj.get("id"):
                    wanted.append(value_obj["id"])
        related = _get_entities(ctx, sorted(set(wanted))) if wanted else {}

        for prop, prop_label in {**ITEM_PROPS, **VALUE_PROPS}.items():
            for claim in claims.get(prop, []):
                # Wikidata marks a claim deprecated when it is known wrong.
                if claim.get("rank") == "deprecated":
                    continue
                raw_value = _claim_value(claim)
                if raw_value is None:
                    continue

                ref_urls, ref_items = _reference_urls(claim)
                if isinstance(raw_value, dict) and raw_value.get("id"):
                    target_qid = raw_value["id"]
                    shown = _label_of(related.get(target_qid, {}), target_qid)
                else:
                    shown = _readable(raw_value)

                # A sourced claim is worth more than an unsourced one, and the
                # difference has to be visible rather than assumed.
                confidence = 0.8 if ref_urls else 0.6

                extra: dict = {}
                if prop == "P3587" and isinstance(raw_value, str):
                    # The bridge to the CVE corpus: the wiki already has a page
                    # per CVE, KEV/NVD import into it daily, and the news feed's
                    # planned entity chips key on the same id.
                    extra = {"cve_id": raw_value, "wiki_slug": f"cve/{raw_value}"}

                result.evidence.append(EvidenceIn(
                    collector=self.name,
                    source_name=f"Wikidata {qid} · {prop} ({prop_label})",
                    source_url=ENTITY_URL.format(qid=qid),
                    summary=f"{label} — {prop_label}: {shown}",
                    confidence=confidence,
                    raw={
                        "source": "wikidata",
                        "wikidata_qid": qid,
                        "property_id": prop,
                        "property_label": prop_label,
                        "value": shown,
                        "value_qid": raw_value.get("id") if isinstance(raw_value, dict) else None,
                        "rank": claim.get("rank"),
                        "reference_urls": ref_urls,
                        "reference_items": ref_items,
                        "retrieved_at": retrieved_at,
                        **extra,
                    },
                    entity_key=src_key,
                ))

                self._graph(result, prop, raw_value, shown, src_key, related, confidence)

        self._incident(result, claims, label, src_key)

        if not result.evidence:
            result.notes.append(f"{qid} has no mapped claims")
        return result

    def _incident(self, result: CollectorResult, claims: dict, label: str,
                  src_key: str) -> None:
        """Map incident items onto the types Umbra already has.

        Deliberately not an `event` entity type — see BREACH_CLASSES above for
        why no Wikidata class hierarchy supports one.
        """
        instance_of = {
            (_claim_value(c) or {}).get("id")
            for c in claims.get("P31", [])
            if c.get("rank") != "deprecated" and isinstance(_claim_value(c), dict)
        }
        if instance_of & BREACH_CLASSES:
            result.entities.append(EntityIn(
                type=EntityType.BREACH, value=label, confidence=0.75,
                props={"source": "wikidata", "kind": "data_breach"}))
            result.edges.append(EdgeIn(
                source_key=src_key,
                target_key=entity_key(EntityType.BREACH, label),
                rel=EdgeType.ASSOCIATED_WITH, confidence=0.75,
                props={"source": "wikidata"}))

    def _graph(self, result: CollectorResult, prop: str, raw_value, shown: str,
               src_key: str, related: dict, confidence: float) -> None:
        """Turn the mapped claims into entities and edges."""
        if prop in EDGE_FOR and isinstance(raw_value, dict) and raw_value.get("id"):
            rel, etype = EDGE_FOR[prop]
            # Never leave a bare QID in the graph — it is unreadable.
            if shown.startswith("Q") and shown[1:].isdigit():
                return
            result.entities.append(
                EntityIn(type=etype, value=shown, confidence=confidence,
                         props={"wikidata_qid": raw_value["id"]})
            )
            result.edges.append(
                EdgeIn(source_key=src_key, target_key=entity_key(etype, shown),
                       rel=rel, confidence=confidence,
                       props={"property_id": prop, "source": "wikidata"})
            )
            return

        if prop in ("P856", "P1324") and isinstance(raw_value, str):
            result.entities.append(
                EntityIn(type=EntityType.URL, value=raw_value, confidence=confidence,
                         props={"source": "wikidata", "property_id": prop})
            )
            result.edges.append(
                EdgeIn(source_key=src_key,
                       target_key=entity_key(EntityType.URL, raw_value),
                       rel=EdgeType.OWNS, confidence=confidence,
                       props={"property_id": prop, "source": "wikidata"})
            )
            host = re.sub(r"^https?://", "", raw_value).split("/")[0].split(":")[0]
            host = host.removeprefix("www.")
            if host and "." in host:
                result.entities.append(
                    EntityIn(type=EntityType.DOMAIN, value=host, confidence=confidence - 0.05,
                             props={"source": "wikidata", "property_id": prop})
                )
