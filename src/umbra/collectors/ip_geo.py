"""IP → city/country from the owned geoip lake (DB-IP City Lite, offline).

No network at collect time. Fill the lake with ``umbra geoip sync``.

What this deliberately does **not** claim:
- Precise street-level location (database is city-grade and often wrong for
  CGNAT, VPN, mobile, corporate, and anycast).
- That a missing lake means the IP has no location — that is *unchecked*.
- That country of registration (RDAP) equals country of use (this collector).
"""

from __future__ import annotations

import ipaddress

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
from umbra.lake.geoip import GeoIpStore, default_store

_CAVEAT = (
    "IP geolocation is approximate. CGNAT, VPN, mobile carriers, hosting "
    "anycast, and corporate egress often place the IP far from the end user."
)


class IpGeoCollector(BaseCollector):
    name = "ip_geo"
    timeout_s = 15
    version = "0.1.0"
    inputs = {EntityType.IP}
    description = (
        "City/country geolocation from the owned DB-IP City Lite lake (offline, free CC-BY)"
    )

    def __init__(self, store: GeoIpStore | None = None) -> None:
        self._store = store

    @property
    def store(self) -> GeoIpStore:
        return self._store if self._store is not None else default_store()

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        ip_s = entity.value
        try:
            ip = ipaddress.ip_address(ip_s.split("%")[0].strip())
        except ValueError:
            result.notes.append(f"Not an IP address: {ip_s!r}")
            return result

        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            result.notes.append(
                f"{ip_s} is private/reserved — public IP geolocation does not apply."
            )
            return result

        store = self.store
        if not store.available:
            result.notes.append(
                "GeoIP lake not loaded — run `umbra geoip sync` "
                "(free DB-IP City Lite). Location is unchecked, not empty."
            )
            return result

        hit = store.lookup(str(ip))
        if hit is None:
            result.notes.append(
                f"No geolocation row for {ip_s} in the owned lake "
                f"(edition={store.get_meta('edition') or 'unknown'})."
            )
            result.notes.append(_CAVEAT)
            return result

        result.notes.append(_CAVEAT)
        src_key = entity.norm_key
        label = hit.location_label()
        props = {
            "geo_country": hit.country,
            "geo_region": hit.region,
            "geo_city": hit.city,
            "geo_latitude": hit.latitude,
            "geo_longitude": hit.longitude,
            "geo_source": hit.source,
            "geo_network_start": hit.network_start,
            "geo_network_end": hit.network_end,
        }

        # Enrich the IP entity props (merge-friendly)
        result.entities.append(
            EntityIn(
                type=EntityType.IP,
                value=str(ip),
                confidence=0.75,
                props=props,
            )
        )

        if label and label != "unknown":
            result.entities.append(
                EntityIn(
                    type=EntityType.LOCATION,
                    value=label,
                    confidence=0.7,
                    props={
                        "country": hit.country,
                        "region": hit.region,
                        "city": hit.city,
                        "latitude": hit.latitude,
                        "longitude": hit.longitude,
                        "source": hit.source,
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.LOCATION, label),
                    rel=EdgeType.LOCATED_IN,
                    confidence=0.7,
                    props={"source": hit.source},
                )
            )

        # Country-only location for graph pivots / wikidata
        if hit.country and (not hit.city or label != hit.country):
            result.entities.append(
                EntityIn(
                    type=EntityType.LOCATION,
                    value=hit.country,
                    confidence=0.75,
                    props={"country": hit.country, "source": hit.source, "kind": "country"},
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.LOCATION, hit.country),
                    rel=EdgeType.LOCATED_IN,
                    confidence=0.75,
                    props={"source": hit.source, "granularity": "country"},
                )
            )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="DB-IP City Lite (owned lake)",
                source_url="https://db-ip.com/db/download/ip-to-city-lite",
                summary=f"{ip_s} ≈ {label}"
                + (
                    f" ({hit.latitude},{hit.longitude})"
                    if hit.latitude is not None and hit.longitude is not None
                    else ""
                ),
                confidence=0.7,
                raw=hit.as_dict(),
                entity_key=src_key,
            )
        )
        return result
