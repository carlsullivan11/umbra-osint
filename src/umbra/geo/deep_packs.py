"""County deep packs — L2 assessor/clerk portals (data-driven).

SoT: ``src/umbra/data/geo/county_deep_packs.json``
Add a county = add a JSON entry + regenerate tracker. No new Python list required.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_PKG_GEO = Path(__file__).resolve().parent.parent / "data" / "geo"
_PACKS_PATH = _PKG_GEO / "county_deep_packs.json"


@lru_cache(maxsize=1)
def load_deep_packs() -> dict[str, dict[str, Any]]:
    if not _PACKS_PATH.is_file():
        return {}
    data = json.loads(_PACKS_PATH.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def deep_pack_map() -> dict[tuple[str, str], str]:
    """(STATE_ABBR, bare county name) → pack key for tracker generator."""
    out: dict[tuple[str, str], str] = {}
    for key, meta in load_deep_packs().items():
        st = (meta.get("state") or "").strip().upper()
        county = (meta.get("county") or "").strip()
        if st and county:
            out[(st, county)] = key
    return out


def deep_portal_lists() -> dict[str, list[dict[str, str]]]:
    """pack key → list of {name,url,kind} for public_records_portals."""
    out: dict[str, list[dict[str, str]]] = {}
    for key, meta in load_deep_packs().items():
        portals = meta.get("portals") or []
        cleaned: list[dict[str, str]] = []
        for p in portals:
            if not isinstance(p, dict):
                continue
            url = (p.get("url") or "").strip()
            name = (p.get("name") or url).strip()
            kind = (p.get("kind") or "property").strip()
            if url:
                cleaned.append({"name": name, "url": url, "kind": kind})
        if cleaned:
            out[key] = cleaned
    return out


def deep_city_hints() -> list[tuple[str, list[str]]]:
    """(pack_key, city substrings) for resolve_regions."""
    rows: list[tuple[str, list[str]]] = []
    for key, meta in load_deep_packs().items():
        cities = meta.get("cities") or []
        if isinstance(cities, list) and cities:
            rows.append((key, [str(c).lower() for c in cities if c]))
    return rows


def region_place_labels() -> dict[str, str]:
    out: dict[str, str] = {}
    for key, meta in load_deep_packs().items():
        st = meta.get("state") or ""
        county = meta.get("county") or ""
        if st and county:
            label = county if "county" in county.lower() or "city" in county.lower() else f"{county} County"
            out[key] = f"{label}, {st}"
    return out
