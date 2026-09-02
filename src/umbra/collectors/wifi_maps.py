"""RF / wireless map context — WiGLE, OpenWifiMap, Deflock, WaveDigger.

Do **not** scrape those map UIs (JS, ToS). Recreate the *useful graph* from
public APIs and operator-owned survey files:

- Portal URLs (always)
- WiGLE API BSSID lookup if UMBRA_WIGLE_API_NAME + TOKEN (optional)
- OSM Overpass for ALPR/surveillance nodes (Deflock's public data source)
- Network Survey / WaveDigger JSON the operator collected (own_asset)

Crowdsourced last-seen ≠ home address. Randomized MACs stay un-geolocated.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import quote_plus

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.mac import mac_facts, normalize_mac
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

_OVERPASS = "https://overpass-api.de/api/interpreter"
_NOMINATIM = "https://nominatim.openstreetmap.org/search"
_WIGLE_SEARCH = "https://api.wigle.net/api/v2/network/search"

_PORTALS = [
    ("WiGLE", "https://wigle.net/", "wifi"),
    ("OpenWifiMap", "https://openwifimap.net/", "wifi"),
    ("Deflock (ALPR / surveillance map)", "https://deflock.me/", "surveillance"),
    ("Network Survey / WaveDigger", "https://networksurvey.app/wavedigger/", "survey"),
]


def parse_network_survey(payload: Any) -> list[dict[str, Any]]:
    """Normalize Network Survey / generic wardrive JSON into AP rows."""
    rows: list[dict[str, Any]] = []
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError:
            return []
    records = payload
    if isinstance(payload, dict):
        records = payload.get("wifiAccessPoints") or payload.get("records") or payload.get("networks") or []
    if not isinstance(records, list):
        return []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        bssid = rec.get("bssid") or rec.get("BSSID") or rec.get("mac")
        ssid = rec.get("ssid") or rec.get("SSID") or rec.get("ssidName")
        lat = rec.get("latitude") or rec.get("lat")
        lon = rec.get("longitude") or rec.get("lon") or rec.get("lng")
        if not bssid and not ssid:
            continue
        rows.append(
            {
                "bssid": str(bssid).strip() if bssid else None,
                "ssid": str(ssid).strip() if ssid else None,
                "lat": lat,
                "lon": lon,
            }
        )
        if len(rows) >= 50:
            break
    return rows


def _portal_url(name: str, kind: str, query: str) -> str:
    q = quote_plus(query)
    if kind == "wifi" and "wigle" in name.lower():
        if re.fullmatch(r"[0-9A-Fa-f:.-]{11,}", query):
            return f"https://wigle.net/search?netid={q}"
        return f"https://wigle.net/search?ssid={q}"
    if "openwifi" in name.lower() and query:
        return f"https://openwifimap.net/#map?q={q}"
    if "deflock" in name.lower() and query:
        return f"https://deflock.me/?q={q}"
    return {
        "WiGLE": "https://wigle.net/",
        "OpenWifiMap": "https://openwifimap.net/",
        "Deflock (ALPR / surveillance map)": "https://deflock.me/",
        "Network Survey / WaveDigger": "https://networksurvey.app/wavedigger/",
    }.get(name, "https://wigle.net/")


class WifiMapsCollector(BaseCollector):
    name = "wifi_maps"
    timeout_s = 60
    inputs = {EntityType.MAC, EntityType.LOCATION, EntityType.PERSON, EntityType.ORG}
    description = (
        "WiGLE/OpenWifiMap/Deflock portals; optional WiGLE BSSID API; OSM ALPR "
        "nodes; operator Network Survey ingest (no map-UI scrape)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        src = entity.norm_key
        value = (entity.value or "").strip()
        props = entity.props or {}
        loc = (
            props.get("location")
            or props.get("city")
            or (value if entity.type == EntityType.LOCATION.value else "")
            or ""
        )
        loc = str(loc).strip()
        query = value or loc or "map"

        for pname, _url, kind in _PORTALS:
            url = _portal_url(pname, kind, query if entity.type == EntityType.MAC.value else loc or query)
            result.entities.append(
                EntityIn(
                    type=EntityType.URL,
                    value=url,
                    display_name=pname,
                    confidence=0.85,
                    props={"portal_kind": kind, "rf_map": True, "manual_search": True},
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.URL, url),
                    rel=EdgeType.ASSOCIATED_WITH,
                    confidence=0.4,
                    props={"kind": kind, "source": "wifi_maps"},
                )
            )

        ua = getattr(ctx.settings, "user_agent", None) or "UmbraOSINT/0.2"
        timeout = min(getattr(ctx.settings, "request_timeout_s", 20) or 20, 25)

        if entity.type == EntityType.MAC.value:
            self._wigle_bssid(entity, ctx, result, ua, timeout)

        survey = props.get("rf_survey") or props.get("network_survey")
        if survey:
            self._ingest_survey(src, survey, result)

        hydrated = False
        if loc:
            try:
                from umbra.lake.rf import RfLake

                rf = RfLake.from_settings(ctx.settings)
                try:
                    rf.backfill_geocode_from_cameras()
                except Exception:
                    pass
                rows = rf.cameras_for_region(loc)
                if not rows:
                    coords = rf.geocode_get(loc)
                    if coords:
                        rows = rf.cameras_near(coords[0], coords[1], km=6.0)
                rf.close()
            except Exception:
                rows = []
            for row in rows[:25]:
                place = (
                    f"camera {row.get('label') or 'surveillance'} "
                    f"({float(row['lat']):.5f},{float(row['lon']):.5f})"
                )
                result.entities.append(
                    EntityIn(
                        type=EntityType.LOCATION,
                        value=place,
                        confidence=0.5,
                        props={
                            "kind": "osm_surveillance",
                            "osm_id": row.get("osm_id"),
                            "source": "rf_lake",
                            "deflock_equivalent": True,
                        },
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.LOCATION, place),
                        rel=EdgeType.ASSOCIATED_WITH,
                        confidence=0.4,
                        props={"kind": "surveillance", "source": "rf_lake"},
                    )
                )
                hydrated = True
            if hydrated:
                result.notes.append(f"RF lake cameras near {loc!r}: {len(rows)}")

        if loc and not hydrated:
            self._osm_surveillance(src, loc, ctx, result, ua, timeout)

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="wifi_maps",
                summary=(
                    f"RF map context for {value!r}: portals attached. "
                    "WiGLE last-seen is crowdsourced, not a residence. "
                    "OSM cameras are Deflock's public source (Overpass), not a scrape of deflock.me."
                ),
                confidence=0.45,
                raw={"location": loc or None, "type": entity.type},
                entity_key=src,
            )
        )
        result.notes.append(
            "SSID/BSSID geolocation is a last-seen observation from volunteers, "
            "not proof someone lives there. Randomized MACs are not geolocated."
        )
        return result

    def _wigle_bssid(
        self,
        entity: Entity,
        ctx: CollectorContext,
        result: CollectorResult,
        ua: str,
        timeout: float,
    ) -> None:
        try:
            facts = mac_facts(entity.value)
        except ValueError:
            return
        if facts.get("is_probably_randomized"):
            result.notes.append("Randomized/local MAC — skip WiGLE geolocation.")
            return
        name = getattr(ctx.settings, "wigle_api_name", None)
        token = getattr(ctx.settings, "wigle_api_token", None)
        if not name or not token:
            result.notes.append("WiGLE API unset (UMBRA_WIGLE_API_NAME / UMBRA_WIGLE_API_TOKEN) — portal only.")
            return
        netid = ":".join(normalize_mac(entity.value)[i : i + 2] for i in range(0, 12, 2))
        raw = f"{name}:{token}".encode()
        auth = base64.b64encode(raw).decode()
        try:
            resp = ctx.http.get(
                _WIGLE_SEARCH,
                params={"netid": netid, "resultsPerPage": 1},
                headers={
                    "User-Agent": ua,
                    "Authorization": f"Basic {auth}",
                    "Accept": "application/json",
                },
                timeout=timeout,
            )
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"WiGLE: {exc}")
            return
        if resp.status_code == 401:
            result.notes.append("WiGLE API unauthorized.")
            return
        if resp.status_code >= 400:
            result.notes.append(f"WiGLE HTTP {resp.status_code}")
            return
        try:
            body = resp.json()
        except Exception:
            result.notes.append("WiGLE: non-JSON body")
            return
        results = (body or {}).get("results") or []
        if not results:
            result.notes.append("WiGLE: no network match (unchecked, not clean).")
            return
        hit = results[0]
        lat, lon = hit.get("trilat"), hit.get("trilong")
        ssid = hit.get("ssid")
        if lat is not None and lon is not None:
            place = f"{float(lat):.5f},{float(lon):.5f}"
            result.entities.append(
                EntityIn(
                    type=EntityType.LOCATION,
                    value=place,
                    confidence=0.4,
                    props={
                        "kind": "wigle_last_seen",
                        "ssid": ssid,
                        "source": "wigle",
                        "manual_confirm": True,
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity.norm_key,
                    target_key=entity_key(EntityType.LOCATION, place),
                    rel=EdgeType.OBSERVED_AT,
                    confidence=0.35,
                    props={"source": "wigle", "ssid": ssid, "manual_confirm": True},
                )
            )

    def _osm_surveillance(
        self,
        src: str,
        loc: str,
        ctx: CollectorContext,
        result: CollectorResult,
        ua: str,
        timeout: float,
    ) -> None:
        headers = {"User-Agent": ua, "Accept": "application/json"}
        try:
            geo = ctx.http.get(
                _NOMINATIM,
                params={"q": loc, "format": "json", "limit": 1},
                headers=headers,
                timeout=min(timeout, 15),
            )
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"Nominatim: {exc}")
            return
        if geo.status_code >= 400:
            result.notes.append(f"Nominatim HTTP {geo.status_code}")
            return
        try:
            hits = geo.json() or []
        except Exception:
            return
        if not hits:
            return
        lat, lon = hits[0].get("lat"), hits[0].get("lon")
        if lat is None or lon is None:
            return
        query = (
            f"[out:json][timeout:15];"
            f'(node["man_made"="surveillance"](around:1200,{lat},{lon});'
            f'node["surveillance:type"="ALPR"](around:1200,{lat},{lon}););'
            f"out body 25;"
        )
        try:
            ov = ctx.http.post(
                _OVERPASS,
                content=query.encode(),
                headers={**headers, "Content-Type": "text/plain"},
                timeout=min(timeout, 20),
            )
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"Overpass: {exc}")
            return
        if ov.status_code >= 400:
            result.notes.append(f"Overpass HTTP {ov.status_code}")
            return
        try:
            elements = (ov.json() or {}).get("elements") or []
        except Exception:
            return
        n = 0
        for el in elements:
            tags = el.get("tags") or {}
            label = tags.get("name") or tags.get("surveillance:type") or "surveillance camera"
            elat, elon = el.get("lat"), el.get("lon")
            if elat is None:
                continue
            place = f"camera {label} ({float(elat):.5f},{float(elon):.5f})"
            result.entities.append(
                EntityIn(
                    type=EntityType.LOCATION,
                    value=place,
                    confidence=0.5,
                    props={
                        "kind": "osm_surveillance",
                        "osm_id": el.get("id"),
                        "source": "openstreetmap",
                        "deflock_equivalent": True,
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.LOCATION, place),
                    rel=EdgeType.ASSOCIATED_WITH,
                    confidence=0.4,
                    props={"kind": "surveillance", "source": "osm_overpass"},
                )
            )
            n += 1
            if n >= 25:
                break
        if n:
            result.notes.append(f"OSM surveillance/ALPR nodes near {loc!r}: {n}")

    def _ingest_survey(self, src: str, survey: Any, result: CollectorResult) -> None:
        for row in parse_network_survey(survey):
            bssid = row.get("bssid")
            ssid = row.get("ssid")
            if bssid:
                try:
                    facts = mac_facts(bssid)
                    mac = facts["mac"]
                except Exception:
                    mac = str(bssid)
                result.entities.append(
                    EntityIn(
                        type=EntityType.MAC,
                        value=mac,
                        confidence=0.7,
                        props={"ssid": ssid, "source": "network_survey", "kind": "bssid"},
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.MAC, mac),
                        rel=EdgeType.OBSERVED_AT,
                        confidence=0.55,
                        props={"ssid": ssid, "source": "network_survey"},
                    )
                )
            lat, lon = row.get("lat"), row.get("lon")
            if lat is not None and lon is not None:
                place = f"{float(lat):.5f},{float(lon):.5f}"
                result.entities.append(
                    EntityIn(
                        type=EntityType.LOCATION,
                        value=place,
                        confidence=0.55,
                        props={"kind": "survey_fix", "ssid": ssid, "source": "network_survey"},
                    )
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.LOCATION, place),
                        rel=EdgeType.OBSERVED_AT,
                        confidence=0.5,
                        props={"source": "network_survey", "ssid": ssid},
                    )
                )
