"""RSS/Atom parsing and URL canonicalisation (stage S14 / F1).

Deliberately dependency-free: `xml.etree` handles both formats, and adding a
feed-parsing library for two element layouts is not worth the supply chain.

Everything here treats the feed as hostile input. Parsing never raises — one
malformed feed must not take an ingest run down — HTML in a description is
reduced to text at this boundary rather than trusted downstream, and URLs are
canonicalised so the same story does not fill the page three times.
"""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

logger = logging.getLogger(__name__)

_ATOM_NS = "{http://www.w3.org/2005/Atom}"
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_SUMMARY_MAX = 600

# Campaign/analytics parameters. Publishers append these per-channel, so the
# same article arrives with different query strings from different feeds.
_TRACKING_PREFIXES = ("utm_",)
_TRACKING_KEYS = {
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
    "at_medium", "at_campaign", "_hsenc", "_hsmi",
}


def _text(el) -> str:
    """Element text with markup removed and entities already decoded by ET."""
    if el is None:
        return ""
    raw = "".join(el.itertext())
    return _WS_RE.sub(" ", _TAG_RE.sub(" ", raw)).strip()


def _parse_date(value: str) -> datetime | None:
    v = (value or "").strip()
    if not v:
        return None
    try:  # RFC 822 — RSS
        dt = parsedate_to_datetime(v)
    except (TypeError, ValueError, IndexError):
        try:  # ISO 8601 — Atom
            dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def canonical_url(url: str) -> str:
    """Strip the noise that makes one story look like several.

    Lower-cases scheme/host, drops the fragment, removes tracking parameters and
    a trailing slash. Meaningful query parameters are kept — an article id in
    the query string is the difference between two different stories.
    """
    u = (url or "").strip()
    if not u:
        return ""
    parts = urlsplit(u)
    query = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _TRACKING_KEYS
        and not any(k.lower().startswith(p) for p in _TRACKING_PREFIXES)
    ]
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((
        parts.scheme.lower(), parts.netloc.lower(), path, urlencode(query), "",
    ))


def content_hash(url: str) -> str:
    """Dedupe key. URL-based, so syndicated copies collapse to one item."""
    return hashlib.sha256(canonical_url(url).encode("utf-8")).hexdigest()


def _rss_items(root) -> list[dict]:
    out = []
    for item in root.iter("item"):
        link = _text(item.find("link"))
        if not link:
            continue
        guid = item.find("guid")
        out.append({
            "title": _text(item.find("title")) or link,
            "url": link,
            "summary": _text(item.find("description"))[:_SUMMARY_MAX],
            "external_id": _text(guid) or None,
            "published_at": _parse_date(_text(item.find("pubDate"))),
        })
    return out


def _atom_entries(root) -> list[dict]:
    out = []
    for entry in root.iter(f"{_ATOM_NS}entry"):
        link = ""
        for el in entry.findall(f"{_ATOM_NS}link"):
            rel = el.get("rel", "alternate")
            if rel == "alternate" and el.get("href"):
                link = el.get("href", "")
                break
        if not link:
            continue
        summary = _text(entry.find(f"{_ATOM_NS}summary")) or _text(entry.find(f"{_ATOM_NS}content"))
        published = (_text(entry.find(f"{_ATOM_NS}published"))
                     or _text(entry.find(f"{_ATOM_NS}updated")))
        out.append({
            "title": _text(entry.find(f"{_ATOM_NS}title")) or link,
            "url": link,
            "summary": summary[:_SUMMARY_MAX],
            "external_id": _text(entry.find(f"{_ATOM_NS}id")) or None,
            "published_at": _parse_date(published),
        })
    return out


def parse_feed(xml: str) -> list[dict]:
    """RSS 2.0 or Atom -> normalized item dicts. Never raises."""
    if not (xml or "").strip():
        return []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        logger.warning("unparseable feed: %s", exc)
        return []
    items = _rss_items(root)
    if not items:
        items = _atom_entries(root)
    return items
