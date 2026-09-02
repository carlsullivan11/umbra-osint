"""Find county parcel layers, verify them, and keep only what answered.

`parcels.py` covers five states because five statewide layers were found by
hand. Hand-finding does not scale to 3,143 counties, and neither does writing
3,143 HTML scrapers.

But counties overwhelmingly publish their parcel data as **ArcGIS feature
services**, and ArcGIS Online has a public catalog with ~10,000 items matching
"parcels". That catalog is the discovery surface. It is not the answer:

    a catalog entry is a claim. a probe is evidence.

Roughly 30% of candidates survive the probe. The other 70% fail for reasons
worth keeping apart — no owner field at all (many counties publish geometry
only, deliberately), a dead service, or a field whose *name* looked right and
whose *values* are not names. `TaxPayerAddr1` and `OWNERLAB` both match an
"ownerish" regex and hold, respectively, mailing addresses and map labels.
Trusting the field name would have quietly filled the registry with garbage
that returns confident, wrong answers.

So verification has four gates, and a candidate must pass all four:

    1. the layer metadata loads and exposes a field that could be an owner
    2. a real owner query answers without an error body
    3. the values that come back **look like names** — not house numbers
    4. state and county resolve from the FCC census-area API, or stay NULL

Gate 4 is deliberately allowed to fail open into NULL. A parcel attributed to
the wrong state is worse than one attributed to nowhere, so an extent that
cannot be resolved is left unresolved rather than approximated.

Politeness: this walks other people's servers. Each run is bounded, sleeps
between probes, and remembers which catalog items it already saw so the next
run advances instead of re-probing the same sixty services forever.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Iterable

logger = logging.getLogger(__name__)

ARCGIS_SEARCH = "https://www.arcgis.com/sharing/rest/search"
FCC_AREA = "https://geo.fcc.gov/api/census/area"

#: Catalog queries. Different words find different counties — "parcels" alone
#: skews to whatever is most viewed, which is not what is most useful.
QUERIES: tuple[str, ...] = (
    'title:parcels AND type:"Feature Service" AND access:public',
    'title:"tax parcels" AND type:"Feature Service" AND access:public',
    'title:"parcel" AND tags:"cadastral" AND type:"Feature Service" AND access:public',
    'tags:parcels AND tags:owner AND type:"Feature Service" AND access:public',
    'title:"property" AND tags:parcels AND type:"Feature Service" AND access:public',
)

_OWNERISH = ("ownername", "owner_name", "own_name", "ownnam", "owner1",
             "owner", "ownr", "deeded")
#: Fields whose name says owner and whose content is not an owner name.
_NOT_OWNER = ("addr", "phone", "email", "zip", "city", "state", "type",
              "code", "id", "num", "date", "pct", "occup")
_ADDRESSISH = ("address", "addr", "situs", "location", "site_addr", "adrlabel",
               "pstladress", "e911")
_CITYISH = ("city", "town", "muni", "cntyname", "county")
_PARCELISH = ("parcelid", "parcel_id", "parno", "pin", "apn", "parcelnum")
_VALUEISH = ("totalvalue", "parval", "assessed", "assdvalue", "market", "value")

#: Between probes. Nobody asked these servers to host us.
_SLEEP_S = 0.35


def _pick(fields: list[str], wanted: Iterable[str], avoid: Iterable[str] = ()) -> str:
    low = {f: f.lower() for f in fields}
    for key in wanted:
        for field, name in low.items():
            if key in name and not any(bad in name for bad in avoid):
                return field
    return ""


def looks_like_names(values: list[str]) -> bool:
    """Do these sampled values read as owner names rather than addresses?

    The cheap, reliable signal is a leading house number: assessor address
    fields start with digits and owner fields almost never do. Backed up by
    requiring real alphabetic content, which rejects codes and IDs.
    """
    usable = [v.strip() for v in values if v and str(v).strip()]
    if not usable:
        return False
    numeric_start = sum(1 for v in usable if re.match(r"^\s*\d", str(v)))
    if numeric_start > len(usable) / 2:
        return False
    wordy = sum(1 for v in usable if re.search(r"[A-Za-z]{2,}", str(v)))
    return wordy >= max(1, len(usable) // 2)


@dataclass
class Candidate:
    item_id: str
    title: str
    org: str
    url: str
    extent: Any = None


@dataclass
class Verified:
    layer_url: str
    owner_field: str
    sample: list[str]
    address_field: str = ""
    city_field: str = ""
    parcel_field: str = ""
    value_field: str = ""
    page: int = 200


def _get(http, url: str, **params) -> dict:
    params.setdefault("f", "json")
    resp = http.get(url, params=params, timeout=30)
    resp.raise_for_status()
    payload = resp.json()
    return payload if isinstance(payload, dict) else {}


def search_catalog(http, query: str, *, num: int = 50, start: int = 1) -> list[Candidate]:
    """Candidate feature services from the public ArcGIS Online catalog."""
    try:
        data = _get(http, ARCGIS_SEARCH, q=query, num=num, start=start,
                    sortField="numViews", sortOrder="desc")
    except Exception as exc:  # noqa: BLE001
        logger.warning("arcgis catalog search failed for %r: %s", query, exc)
        return []
    out = []
    for item in data.get("results") or []:
        url = (item.get("url") or "").rstrip("/")
        if not url or "/rest/services/" not in url:
            continue
        out.append(Candidate(
            item_id=item.get("id") or "", title=item.get("title") or "",
            org=item.get("owner") or "", url=url, extent=item.get("extent"),
        ))
    return out


def verify(http, cand: Candidate, *, probe_name: str = "SMITH",
           max_layers: int = 3) -> tuple[Verified | None, str]:
    """Probe a candidate. Returns (Verified, reason) — reason is set either way."""
    try:
        meta = _get(http, cand.url)
    except Exception as exc:  # noqa: BLE001
        return None, f"service metadata unreadable: {type(exc).__name__}"

    layers = meta.get("layers") or []
    if not layers:
        return None, "no layers"

    for layer in layers[:max_layers]:
        layer_url = f"{cand.url}/{layer.get('id')}"
        try:
            lm = _get(http, layer_url)
        except Exception:  # noqa: BLE001
            continue
        if lm.get("error"):
            continue
        fields = [f["name"] for f in lm.get("fields", []) if f.get("name")]
        if not fields:
            continue

        for owner_field in [f for f in fields
                            if any(k in f.lower() for k in _OWNERISH)
                            and not any(b in f.lower() for b in _NOT_OWNER)]:
            time.sleep(_SLEEP_S)
            try:
                sample = _get(
                    http, f"{layer_url}/query",
                    where=f"UPPER({owner_field}) LIKE '%{probe_name}%'",
                    outFields=owner_field, returnGeometry="false",
                    resultRecordCount=5,
                )
            except Exception:  # noqa: BLE001
                continue
            if sample.get("error"):
                continue
            values = [str((f.get("attributes") or {}).get(owner_field) or "")
                      for f in sample.get("features") or []]
            if not values:
                continue
            # Gate 3 — the field name said owner; the values decide.
            if not looks_like_names(values):
                return None, (
                    f"{owner_field} matched by name but its values are not "
                    f"names (e.g. {values[0][:40]!r})"
                )
            return Verified(
                layer_url=layer_url, owner_field=owner_field,
                sample=[v for v in values if v][:5],
                address_field=_pick(fields, _ADDRESSISH),
                city_field=_pick(fields, _CITYISH),
                parcel_field=_pick(fields, _PARCELISH),
                value_field=_pick(fields, _VALUEISH),
                page=min(int(lm.get("maxRecordCount") or 200), 200),
            ), "verified"

    return None, "no queryable owner-name field"


def locate(http, extent: Any) -> tuple[str | None, str | None, str | None]:
    """(state, county, fips) for a layer's extent, or (None, None, None).

    Uses the FCC census-area API, which is authoritative and free. Failing to
    resolve is a fine outcome — see the module docstring on why a NULL beats a
    bounding-box guess.
    """
    try:
        (x1, y1), (x2, y2) = extent[0], extent[1]
        lon, lat = (float(x1) + float(x2)) / 2, (float(y1) + float(y2)) / 2
    except Exception:  # noqa: BLE001
        return None, None, None
    # Outside plausible US lat/lon: the catalog is global and Brisbane's
    # parcels are not a county record.
    if not (-180 <= lon <= -60 and 15 <= lat <= 72):
        return None, None, None
    try:
        data = _get(http, FCC_AREA, lat=f"{lat:.5f}", lon=f"{lon:.5f}", format="json")
    except Exception:  # noqa: BLE001
        return None, None, None
    results = data.get("results") or []
    if not results:
        return None, None, None
    row = results[0]
    return (row.get("state_code") or None, row.get("county_name") or None,
            row.get("county_fips") or None)


def sync(http, lake, *, max_items: int = 120, queries: Iterable[str] = QUERIES,
         progress=None) -> dict[str, Any]:
    """One bounded discovery sweep. Safe to run repeatedly; it advances."""
    seen = lake.already_seen()
    stats = {"probed": 0, "verified": 0, "rejected": 0, "skipped_seen": 0,
             "located": 0}

    for query in queries:
        if stats["probed"] >= max_items:
            break
        for cand in search_catalog(http, query, num=50):
            if stats["probed"] >= max_items:
                break
            if not cand.item_id or cand.item_id in seen:
                stats["skipped_seen"] += 1
                continue
            seen.add(cand.item_id)
            stats["probed"] += 1

            good, reason = verify(http, cand)
            if progress:
                progress(stats["probed"], cand.title, reason)

            if not good:
                lake.mark_seen(cand.item_id, reason)
                lake.record({
                    "layer_url": cand.url, "item_id": cand.item_id,
                    "title": cand.title, "org": cand.org, "owner_field": "-",
                    "status": "rejected", "detail": reason,
                })
                stats["rejected"] += 1
                continue

            state, county, fips = locate(http, cand.extent)
            if state:
                stats["located"] += 1
            lake.record({
                "layer_url": good.layer_url, "item_id": cand.item_id,
                "title": cand.title, "org": cand.org,
                "owner_field": good.owner_field,
                "address_field": good.address_field, "city_field": good.city_field,
                "parcel_field": good.parcel_field, "value_field": good.value_field,
                "state": state, "county": county, "county_fips": fips,
                "page": good.page, "sample": good.sample,
                "status": "verified", "detail": reason,
            })
            lake.mark_seen(cand.item_id, "verified")
            stats["verified"] += 1
            time.sleep(_SLEEP_S)

    return stats
