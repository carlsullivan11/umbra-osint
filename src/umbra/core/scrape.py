"""Bounded allowlisted HTML crawl — Crawlee/Playwright substitute.

Crawlee (and headless Chrome) would OOM the 8GB app VPS and invite captcha
bypass. Umbra already has httpx + GuardedClient. This module:

- extracts same-document links
- follows only URLs the caller allowlists
- prefers href/text that mention a name token
- caps pages and sleeps between GETs

Not a general web spider. Not PACER/login/captcha.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

_HREF_RE = re.compile(
    r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""",
    re.I | re.S,
)
_SKIP_SCHEME = ("javascript:", "mailto:", "tel:", "data:", "#")
_SKIP_PATH = ("login", "signin", "efile", "e-file", "checkout", "captcha", "cart", "logout")


def _clean_url(url: str) -> str:
    try:
        parts = urlsplit(url)
    except Exception:
        return ""
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return ""
    path = (parts.path or "").lower()
    if any(tok in path for tok in _SKIP_PATH):
        return ""
    return urlunsplit((parts.scheme, parts.netloc.lower(), parts.path, parts.query, ""))


def extract_links(html: str, base_url: str) -> list[tuple[str, str]]:
    """Return (absolute_url, link_text) pairs from an HTML document."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for href, inner in _HREF_RE.findall(html or ""):
        raw = (href or "").strip()
        if not raw or raw.lower().startswith(_SKIP_SCHEME):
            continue
        abs_url = _clean_url(urljoin(base_url, raw))
        if not abs_url or abs_url in seen:
            continue
        seen.add(abs_url)
        text = re.sub(r"<[^>]+>", " ", inner)
        text = re.sub(r"\s+", " ", text).strip()
        out.append((abs_url, text[:200]))
    return out


def pick_follow_urls(
    links: list[tuple[str, str]],
    *,
    allow: Callable[[str], bool],
    needle: str = "",
    limit: int = 4,
    same_host_as: str = "",
) -> list[str]:
    """Rank allowlisted links; prefer those whose URL or text contains needle."""
    host = ""
    if same_host_as:
        try:
            host = (urlsplit(same_host_as).hostname or "").lower()
        except Exception:
            host = ""
    token = (needle or "").replace(",", " ").split()
    last = (token[-1] if token else "").lower()
    scored: list[tuple[int, str]] = []
    seen: set[str] = set()
    for url, text in links:
        if url in seen or not allow(url):
            continue
        if host:
            try:
                if (urlsplit(url).hostname or "").lower() != host:
                    continue
            except Exception:
                continue
        blob = f"{url} {text}".lower()
        score = 0
        if last and len(last) >= 3 and last in blob:
            score += 10
        if any(k in blob for k in ("parcel", "property", "assessor", "memorial", "obituar", "company", "filing")):
            score += 2
        if score == 0 and last:
            continue
        seen.add(url)
        scored.append((score, url))
    scored.sort(key=lambda x: (-x[0], x[1]))
    return [u for _, u in scored[:limit]]


@dataclass
class CrawlPage:
    url: str
    status: int | None
    html: str
    title: str | None
    followed: bool = False


@dataclass
class CrawlResult:
    pages: list[CrawlPage] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def crawl_allowlisted(
    http,
    seeds: list[str],
    *,
    allow: Callable[[str], bool],
    needle: str = "",
    max_pages: int = 8,
    follow_per_page: int = 3,
    user_agent: str = "UmbraOSINT/0.2",
    timeout: float = 20,
    pause_s: float = 0.35,
) -> CrawlResult:
    """GET seed URLs, then follow a few allowlisted name-matching links."""
    out = CrawlResult()
    queue: list[tuple[str, bool]] = [(u, False) for u in seeds if u]
    seen: set[str] = set()
    while queue and len(out.pages) < max_pages:
        url, followed = queue.pop(0)
        if url in seen or not allow(url):
            continue
        seen.add(url)
        html = ""
        status = None
        title = None
        try:
            resp = http.get(
                url,
                headers={"User-Agent": user_agent, "Accept": "text/html, application/json;q=0.9, */*;q=0.5"},
                follow_redirects=True,
                timeout=timeout,
            )
            status = resp.status_code
            if status < 400:
                html = resp.text or ""
                tm = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
                if tm:
                    title = re.sub(r"\s+", " ", tm.group(1)).strip()[:200]
        except Exception as exc:  # noqa: BLE001
            out.notes.append(f"crawl {url!r}: {exc}")
        out.pages.append(CrawlPage(url=url, status=status, html=html, title=title, followed=followed))
        if html and len(out.pages) < max_pages:
            links = extract_links(html, url)
            for nxt in pick_follow_urls(
                links,
                allow=allow,
                needle=needle,
                limit=follow_per_page,
                same_host_as=url,
            ):
                if nxt not in seen:
                    queue.append((nxt, True))
        if pause_s:
            time.sleep(pause_s)
    return out
