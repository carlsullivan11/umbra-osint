from __future__ import annotations

from urllib.parse import urlparse

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


class WaybackCdxCollector(BaseCollector):
    name = "wayback_cdx"
    timeout_s = 45
    inputs = {EntityType.DOMAIN, EntityType.URL}
    description = "Internet Archive CDX snapshots (historical web presence)"

    def supports(self, entity: Entity) -> bool:
        if not super().supports(entity):
            return False
        # Avoid CDX storms on every on-site path; domains + apex URLs only
        if entity.type == EntityType.URL.value:
            p = urlparse(entity.value if "://" in entity.value else f"https://{entity.value}")
            path = (p.path or "/").rstrip("/")
            return path == ""
        return True

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        if entity.type == EntityType.URL.value:
            target = entity.value
        else:
            target = f"{entity.value}/*"
        src = entity.norm_key
        api = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": target,
            "output": "json",
            "limit": "25",
            "fl": "timestamp,original,statuscode,mimetype",
            "filter": "statuscode:200",
            "collapse": "urlkey",
        }
        try:
            resp = ctx.http.get(api, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"wayback: {exc}")
            return result

        if not isinstance(data, list) or len(data) < 2:
            result.notes.append("wayback: no snapshots")
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="Wayback CDX",
                    source_url=str(getattr(resp, "url", api)),
                    summary=f"No Wayback snapshots for {target}",
                    confidence=0.5,
                    raw={"snapshots": [], "target": target},
                    entity_key=src,
                )
            )
            return result

        rows = data[1:26]
        snaps = []
        for row in rows:
            if len(row) < 2:
                continue
            ts, original = row[0], row[1]
            wb = f"https://web.archive.org/web/{ts}/{original}"
            snaps.append({"ts": ts, "original": original, "wayback": wb})
            result.entities.append(
                EntityIn(type=EntityType.URL, value=wb, confidence=0.7, props={"wayback": True})
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, wb),
                    rel=EdgeType.OBSERVED_AT,
                    confidence=0.7,
                    props={"timestamp": ts},
                )
            )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="Wayback CDX",
                source_url=str(resp.url),
                summary=f"Wayback: {len(snaps)} snapshot(s) for {target}",
                confidence=0.8,
                raw={"snapshots": snaps},
                entity_key=src,
            )
        )
        return result
