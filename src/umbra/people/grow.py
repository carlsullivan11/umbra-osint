"""Grow the people lake: Wikidata harvest + Wikipedia extract seed.

Public deceased US-citizen bios only (Wikidata P27=US + P570 + enwiki).
Nightly automation: ``umbra people grow --add 400``.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.people import PeopleLake
from umbra.people.obituary_parse import parse_obituary_text
from umbra.people.seed import SeedPerson, _load_corpus

logger = logging.getLogger(__name__)

UA = "UmbraOSINT/0.2 (https://umbra-osint.com; security@umbra-osint.com)"
SPARQL = "https://query.wikidata.org/sparql"
WIKI_API = "https://en.wikipedia.org/w/api.php"

_QUERY = """
SELECT ?itemLabel ?enwiki ?placeLabel WHERE {{
  ?item wdt:P31 wd:Q5 .
  ?item wdt:P27 wd:Q30 .
  ?item wdt:P570 ?dod .
  FILTER(YEAR(?dod) >= {year_from} && YEAR(?dod) < {year_to})
  ?sitelink schema:about ?item ;
            schema:isPartOf <https://en.wikipedia.org/> ;
            schema:name ?enwiki .
  OPTIONAL {{ ?item wdt:P20 ?place . }}
  SERVICE wikibase:label {{ bd:serviceParam wikibase:language "en". }}
}}
LIMIT {limit}
"""

_YEAR_WINDOWS = (
    (2020, 2026),
    (2015, 2020),
    (2010, 2015),
    (2000, 2010),
    (1990, 2000),
    (1980, 1990),
    (1970, 1980),
    (1960, 1970),
    (1950, 1960),
    (1900, 1950),
)


def ok_name(name: str) -> bool:
    name = (name or "").strip()
    if len(name) < 5 or " " not in name:
        return False
    low = name.lower()
    if low.startswith("list of") or low.startswith("deaths in"):
        return False
    if name.startswith("Category:"):
        return False
    return True


def packaged_corpus_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "geo" / "people_seed_corpus.json"


def overlay_corpus_path(settings: Any = None) -> Path:
    settings = settings or get_settings()
    return Path(settings.data_dir) / "lake" / "people_seed_corpus.json"


def _rows_from_file(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    return [r for r in (data.get("seeds") or []) if isinstance(r, dict)]


def load_all_seeds(settings: Any = None) -> list[SeedPerson]:
    """Packaged corpus + data-dir overlay (prod harvest writes overlay)."""
    by: dict[str, SeedPerson] = {}
    for sp in _load_corpus():
        by[sp.name.lower()] = sp
    for row in _rows_from_file(overlay_corpus_path(settings)):
        name = str(row.get("name") or "").strip()
        urls = row.get("urls") or []
        if not name or not isinstance(urls, list) or not urls:
            continue
        loc = str(row.get("location") or "").strip() or None
        by[name.lower()] = SeedPerson(name, tuple(str(u) for u in urls if u), loc)
    return list(by.values())


def _save_overlay(seeds: list[dict], settings: Any = None) -> Path:
    path = overlay_corpus_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"version": 1, "count": len(seeds), "seeds": seeds, "source": "wikidata-overlay"}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return path


def harvest_wikidata(*, add: int = 400, settings: Any = None, http: Any = None) -> dict:
    """Append up to ``add`` new US-decedent wiki bios into the overlay corpus."""
    settings = settings or get_settings()
    existing = {sp.name.lower(): sp for sp in load_all_seeds(settings)}
    start = len(existing)
    added = 0
    own_http = http is None
    if own_http:
        http = GuardedClient(
            timeout=90.0,
            headers={"User-Agent": UA, "Accept": "application/sparql-results+json"},
        )
    try:
        for y0, y1 in _YEAR_WINDOWS:
            if added >= add:
                break
            q = _QUERY.format(year_from=y0, year_to=y1, limit=min(4000, max(add * 4, 500)))
            try:
                r = http.get(SPARQL, params={"query": q, "format": "json"})
                if r.status_code >= 400:
                    logger.warning("wikidata HTTP %s", r.status_code)
                    time.sleep(2)
                    continue
                bindings = (r.json().get("results") or {}).get("bindings") or []
            except Exception as exc:  # noqa: BLE001
                logger.warning("wikidata fail %s", exc)
                time.sleep(2)
                continue
            for b in bindings:
                if added >= add:
                    break
                title = ((b.get("enwiki") or {}).get("value") or "").strip()
                name = ((b.get("itemLabel") or {}).get("value") or title.replace("_", " ")).strip()
                place = ((b.get("placeLabel") or {}).get("value") or "").strip()
                if not title or not ok_name(name) or name.lower() in existing:
                    continue
                url = "https://en.wikipedia.org/wiki/" + quote(title.replace(" ", "_"), safe=":_()%,.-")
                loc = place if place and not place.startswith("Q") else ""
                if loc.lower() in {"united states", "usa", "us", "america"}:
                    loc = "United States"
                existing[name.lower()] = SeedPerson(name, (url,), loc or None)
                added += 1
            time.sleep(0.4)
    finally:
        if own_http:
            http.close()

    overlay_rows = []
    packaged = {sp.name.lower() for sp in _load_corpus()}
    for key, sp in existing.items():
        if key in packaged:
            continue
        overlay_rows.append({"name": sp.name, "urls": list(sp.urls), "location": sp.location or ""})
    overlay_rows.sort(key=lambda r: r["name"].lower())
    path = _save_overlay(overlay_rows, settings)
    return {
        "added": added,
        "corpus_total": len(existing),
        "overlay_path": str(path),
        "started": start,
    }


def _title_from_url(url: str) -> str:
    path = urlsplit(url).path
    title = path.split("/wiki/", 1)[-1]
    return unquote(title.replace("_", " "))


def _chunks(seq, n: int):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def seed_extracts(
    seeds: list[SeedPerson],
    *,
    settings: Any = None,
    http: Any = None,
) -> dict:
    """Wikipedia Action API extracts (20 titles/POST). Skip names already in lake."""
    settings = settings or get_settings()
    lake = PeopleLake.from_settings(settings)
    existing = {
        (r[0] or "")
        for r in lake._conn.execute("SELECT lower(full_name) FROM people").fetchall()
    }
    todo = [sp for sp in seeds if sp.name.strip().lower() not in existing and sp.urls]
    ok = fail = 0
    own_http = http is None
    if own_http:
        http = GuardedClient(
            timeout=40.0,
            headers={"User-Agent": UA, "Accept": "application/json"},
        )
    try:
        for batch in _chunks(todo, 20):
            titles = "|".join(_title_from_url(sp.urls[0]) for sp in batch)
            params = {
                "action": "query",
                "format": "json",
                "prop": "extracts|info",
                "exintro": "1",
                "explaintext": "1",
                "exlimit": "20",
                "inprop": "url",
                "redirects": "1",
                "titles": titles,
            }
            try:
                resp = http.post(WIKI_API, data=params)
                if resp.status_code >= 400:
                    fail += len(batch)
                    time.sleep(1)
                    continue
                q = (resp.json() or {}).get("query") or {}
                pages = q.get("pages") or {}
                redirects = q.get("redirects") or []
                normalized = q.get("normalized") or []
            except Exception as exc:  # noqa: BLE001
                logger.warning("wiki extracts fail %s", exc)
                fail += len(batch)
                time.sleep(1)
                continue
            by_title: dict[str, dict] = {}
            for page in pages.values():
                t = (page.get("title") or "").strip()
                if t:
                    by_title[t.lower()] = page
            for nrm in list(normalized) + list(redirects):
                frm = (nrm.get("from") or "").lower()
                to = (nrm.get("to") or "").lower()
                if frm and to and to in by_title:
                    by_title[frm] = by_title[to]
            for sp in batch:
                want = _title_from_url(sp.urls[0]).lower()
                page = by_title.get(want) or by_title.get(sp.name.lower())
                if not page or page.get("missing") is not None:
                    fail += 1
                    continue
                extract = (page.get("extract") or "")[:8000]
                if not extract:
                    fail += 1
                    continue
                title = page.get("title") or sp.name
                url = page.get("fullurl") or sp.urls[0]
                parsed = parse_obituary_text(extract, decedent_name=sp.name, title=title).to_dict()
                if sp.location and not parsed.get("residence"):
                    parsed["residence"] = sp.location
                lake.upsert_person_from_parse(
                    decedent_name=sp.name,
                    parse=parsed,
                    source_url=url,
                    title=title,
                    http_status=200,
                    excerpt=extract[:1500],
                    confidence=0.52,
                )
                ok += 1
            time.sleep(0.12)
    finally:
        if own_http:
            http.close()
    st = lake.status()
    lake.close()
    return {"ok": ok, "fail": fail, "todo": len(todo), "people": st.people, "obituaries": st.obituaries}


def grow(*, add: int = 400, seed: bool = True, settings: Any = None) -> dict:
    """Harvest new Wikidata bios then fast-seed anyone missing from the lake."""
    settings = settings or get_settings()
    harv = harvest_wikidata(add=add, settings=settings)
    out: dict[str, Any] = {"harvest": harv}
    if seed:
        seeds = load_all_seeds(settings)
        out["seed"] = seed_extracts(seeds, settings=settings)
    out["lake"] = PeopleLake.from_settings(settings).status().as_dict()
    return out
