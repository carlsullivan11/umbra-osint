"""Seed the people lake from curated public memorial/wiki URLs.

Does not depend on DuckDuckGo. Uses allowlisted GET + obituary parse + lake upsert
so person search is usable offline after one seed run.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.people import PeopleLake
from umbra.people.obituary_parse import parse_obituary_text, strip_html

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class SeedPerson:
    name: str
    urls: tuple[str, ...]
    location: str | None = None


def _load_corpus() -> tuple[SeedPerson, ...]:
    """Large public-wiki corpus shipped under ``umbra/data/geo/``."""
    path = Path(__file__).resolve().parent.parent / "data" / "geo" / "people_seed_corpus.json"
    if not path.is_file():
        return ()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("people seed corpus unreadable: %s", exc)
        return ()
    out: list[SeedPerson] = []
    for row in data.get("seeds") or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip()
        urls = row.get("urls") or []
        if not name or not isinstance(urls, list) or not urls:
            continue
        loc = str(row.get("location") or "").strip() or None
        out.append(SeedPerson(name, tuple(str(u) for u in urls if u), loc))
    return tuple(out)


# Fallback mini-list if corpus file missing (tests / bare installs).
_FALLBACK_SEEDS: tuple[SeedPerson, ...] = (
    SeedPerson("Steve Jobs", ("https://en.wikipedia.org/wiki/Steve_Jobs",), "Cupertino, CA"),
    SeedPerson("Ruth Bader Ginsburg", ("https://en.wikipedia.org/wiki/Ruth_Bader_Ginsburg",), "Washington, DC"),
    SeedPerson("Sam Walton", ("https://en.wikipedia.org/wiki/Sam_Walton",), "Bentonville, AR"),
)

DEFAULT_SEEDS: tuple[SeedPerson, ...] = _load_corpus() or _FALLBACK_SEEDS


_FETCH_ALLOW = (
    "legacy.com",
    "findagrave.com",
    "echovita.com",
    "tributearchive.com",
    "dignitymemorial.com",
    "loc.gov",
    "wikipedia.org",
)


def _allowed(url: str) -> bool:
    host = (urlsplit(url).hostname or "").lower()
    return any(host == s or host.endswith("." + s) for s in _FETCH_ALLOW)


def seed_people(
    seeds: Iterable[SeedPerson] = DEFAULT_SEEDS,
    *,
    settings: Any = None,
    timeout_s: float = 25.0,
    pause_s: float = 0.35,
) -> dict:
    """Fetch seed URLs, parse, upsert people lake. Returns summary stats."""
    settings = settings or get_settings()
    lake = PeopleLake.from_settings(settings)
    stats = {
        "attempted_people": 0,
        "people_upserted": 0,
        "urls_ok": 0,
        "urls_fail": 0,
        "kinship_total": 0,
        "errors": [],
        "people": [],
    }
    ua = getattr(settings, "user_agent", None) or (
        "UmbraOSINT/0.2 (https://umbra-osint.com; security@umbra-osint.com)"
    )

    with GuardedClient(
        timeout=timeout_s,
        headers={"User-Agent": ua, "Accept": "text/html"},
    ) as http:
        for sp in seeds:
            stats["attempted_people"] += 1
            person_ok = False
            kin_n = 0
            links_ok: list[str] = []
            # Wikipedia first (stable); memorial sites after with pause
            ordered = sorted(
                sp.urls,
                key=lambda u: (0 if "wikipedia.org" in u else 1, u),
            )
            for url in ordered:
                if not _allowed(url):
                    stats["urls_fail"] += 1
                    stats["errors"].append(f"not allowlisted: {url}")
                    continue
                if "findagrave.com" in url or "legacy.com" in url:
                    time.sleep(max(0.0, pause_s))
                try:
                    resp = http.get(url, follow_redirects=True)
                    status = resp.status_code
                    if status >= 400:
                        stats["urls_fail"] += 1
                        stats["errors"].append(f"HTTP {status}: {url}")
                        continue
                    html = (resp.text or "")[:200_000]
                    title = None
                    import re

                    tm = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
                    if tm:
                        title = strip_html(tm.group(1))[:200]
                    text = strip_html(html)
                    parsed = parse_obituary_text(
                        text, decedent_name=sp.name, title=title
                    )
                    pdata = parsed.to_dict()
                    if sp.location and not pdata.get("residence"):
                        pdata["residence"] = sp.location
                    final_url = str(resp.url) if getattr(resp, "url", None) else url
                    lake.upsert_person_from_parse(
                        decedent_name=sp.name,
                        parse=pdata,
                        source_url=final_url,
                        title=title,
                        http_status=status,
                        excerpt=text[:1500],
                        confidence=0.55,
                    )
                    stats["urls_ok"] += 1
                    person_ok = True
                    links_ok.append(final_url)
                    kin_n = max(
                        kin_n,
                        len(pdata.get("survivors") or [])
                        + len(pdata.get("preceded") or []),
                    )
                    # Discover Find a Grave memorials linked from Wikipedia
                    if "wikipedia.org" in final_url:
                        import re as _re
                        last = sp.name.split()[-1].lower().replace(".", "")
                        fg_links = []
                        for murl in _re.findall(
                            r'https?://(?:www\.)?findagrave\.com/memorial/\d+/[a-z0-9\-]+',
                            html,
                            _re.I,
                        ):
                            slug = murl.rstrip("/").rsplit("/", 1)[-1].lower()
                            parts = slug.replace("_", "-").split("-")
                            # require last name token OR first+last tokens
                            tokens = {p.lower().replace(".", "") for p in sp.name.split() if len(p) > 2}
                            if last in parts or tokens & set(parts):
                                if murl not in fg_links:
                                    fg_links.append(murl)
                        for fg in fg_links[:2]:
                            time.sleep(max(0.0, pause_s))
                            try:
                                fr = http.get(fg, follow_redirects=True)
                                if fr.status_code >= 400:
                                    stats["urls_fail"] += 1
                                    stats["errors"].append(f"HTTP {fr.status_code}: {fg}")
                                    continue
                                fhtml = (fr.text or "")[:200_000]
                                ft = None
                                tm2 = _re.search(r"<title[^>]*>(.*?)</title>", fhtml, _re.I | _re.S)
                                if tm2:
                                    ft = strip_html(tm2.group(1))[:200]
                                # Title must roughly match person (avoid wrong memorials)
                                if ft and not any(
                                    tok.lower() in ft.lower()
                                    for tok in sp.name.split()
                                    if len(tok) > 3
                                ):
                                    stats["errors"].append(f"FG title mismatch: {ft!r} for {sp.name}")
                                    continue
                                ftext = strip_html(fhtml)
                                fp = parse_obituary_text(ftext, decedent_name=sp.name, title=ft).to_dict()
                                furl = str(fr.url) if getattr(fr, "url", None) else fg
                                lake.upsert_person_from_parse(
                                    decedent_name=sp.name,
                                    parse=fp,
                                    source_url=furl,
                                    title=ft,
                                    http_status=fr.status_code,
                                    excerpt=ftext[:1500],
                                    confidence=0.55,
                                )
                                stats["urls_ok"] += 1
                                links_ok.append(furl)
                                kin_n = max(
                                    kin_n,
                                    len(fp.get("survivors") or []) + len(fp.get("preceded") or []),
                                )
                            except Exception as exc:  # noqa: BLE001
                                stats["urls_fail"] += 1
                                stats["errors"].append(f"{fg}: {exc}")

                except Exception as exc:  # noqa: BLE001
                    stats["urls_fail"] += 1
                    stats["errors"].append(f"{url}: {exc}")
                    logger.warning("seed fetch failed %s: %s", url, exc)
            if person_ok:
                stats["people_upserted"] += 1
                stats["kinship_total"] += kin_n
                stats["people"].append(
                    {"name": sp.name, "links": links_ok, "kin_parsed": kin_n}
                )
            time.sleep(max(0.0, pause_s * 0.5))

    st = lake.status().as_dict()
    lake.close()
    stats["lake"] = st
    return stats
