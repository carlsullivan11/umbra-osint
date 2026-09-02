"""Dark-web exposure collectors — passive & defensive only.

Policy: **passive, defensive dark-web exposure monitoring of authorized assets
only** (see docs/ETHICS.md). These collectors *observe already-public data* —
they never participate, purchase, contact sellers, authenticate to gated
sources, or download stolen corpora. The line is **observation, never
participation**, and the storage discipline is **record the fact of exposure +
a source pointer, never a re-hosted copy of stolen material**.

First implemented source (key-free, clearnet, lawful):
- **ransomware.live** publishes a static, aggregated index of ransomware
  leak-site *victim postings* (public extortion pages) at
  ``https://data.ransomware.live/posts.json``. Monitoring whether *your /
  authorized* org or domain appears as a named victim is standard CTI over
  already-public data — no Tor, no key, no crawling of the criminal sites
  themselves. We consume the aggregator's normalized index.

Design mirrors the reputation collectors: pure, network-free parse/match
functions (``parse_ransomware_posts``, ``match_posts``) that are unit-testable
with fixtures; the collector only wires cached-fetch → parse → match → graph.

Key-optional feed adapters for lawful stealer-log / breach aggregators
(DeHashed, IntelX, ransomware.live v2) are the documented "depth lever" and
plug in here later — each gated behind its own optional key, each an adapter,
never a crawler. See Projects/OSINT/Umbra-DarkWeb-Monitoring in the vault.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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

RANSOMWARE_LIVE_POSTS = "https://data.ransomware.live/posts.json"


# --- normalized record + pure parse/match (unit-tested without network) ----

@dataclass
class RansomwarePost:
    """One ransomware leak-site victim posting (already-public extortion page)."""
    victim: str          # post_title — the named victim org
    group: str           # ransomware group / affiliate
    website: str         # victim's website as posted by the group
    host: str | None     # normalized hostname of `website`, if parseable
    discovered: str      # when the aggregator observed the posting (ISO)
    published: str       # when the group published it (ISO)
    activity: str        # victim's sector, per the aggregator
    country: str
    post_ref: str        # pointer to the leak page (stored as a POINTER, never fetched)
    raw: dict[str, Any]


# Junk / placeholder website values ransomware groups routinely type into the
# leak-site form. Matching a victim's domain against these would raise a false
# "you were ransomwared" alarm — unacceptable for a defensive tool — so they are
# rejected outright and yield no host (the posting still exists for org matching).
_PLACEHOLDER_HOSTS = {
    "example.com", "example.org", "example.net", "test.com", "domain.com",
    "company.com", "companyurl.com", "url.com", "n/a", "na", "none", "null",
    "unknown", "tbd", "localhost",
}


def _valid_host(host: str) -> bool:
    """A conservative real-domain check to reject placeholders / junk / .onion.

    Requires a dotted name with a plausible alphabetic TLD and no whitespace or
    masking characters. Rejects ``.onion`` (that's the leak *site*, not the
    victim's domain) and the known-placeholder set.
    """
    if not host or " " in host or "*" in host:
        return False
    if host in _PLACEHOLDER_HOSTS:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    tld = labels[-1]
    if tld == "onion":
        return False
    if not (2 <= len(tld) <= 24 and tld.isalpha()):
        return False
    # every label must be non-empty and use hostname-legal characters
    for lbl in labels:
        if not lbl or not all(ch.isalnum() or ch == "-" for ch in lbl):
            return False
    return True


def _host_from_website(website: str | None) -> str | None:
    """Best-effort real hostname from a posted website string, stripped of www.

    Returns None for empty, placeholder, malformed, or .onion values so that
    domain-matching can never false-positive on junk the attacker typed.
    """
    if not website:
        return None
    s = website.strip().lower()
    if not s:
        return None
    if "://" not in s:
        s = "http://" + s
    host = (urlparse(s).hostname or "").strip(".")
    if not host:
        return None
    if host.startswith("www."):
        host = host[4:]
    if not _valid_host(host):
        return None
    return host


def norm_org(name: str | None) -> str:
    """Normalize an org name for fuzzy-equality matching.

    Lowercase, drop common corporate suffixes and punctuation, collapse
    whitespace. Deliberately conservative — this gates whether we *flag* an
    exposure, so it favors precision (fewer false victim matches) over recall.
    """
    if not name:
        return ""
    s = name.lower()
    for ch in ",.&/\\-_'\"()":
        s = s.replace(ch, " ")
    tokens = [t for t in s.split() if t]
    _SUFFIXES = {
        "inc", "llc", "ltd", "limited", "corp", "corporation", "co", "company",
        "plc", "gmbh", "sa", "srl", "bv", "ag", "group", "holdings", "the",
    }
    tokens = [t for t in tokens if t not in _SUFFIXES]
    return " ".join(tokens)


def _domains_match(entity_domain: str, post_host: str | None) -> bool:
    """True if the post's website host is the same registrable site as the entity.

    Matches exact host, or a subdomain relationship in either direction
    (``mail.acme.com`` vs ``acme.com``). Dependency-free; conservative.
    """
    if not post_host:
        return False
    a = entity_domain.strip().lower().strip(".")
    if a.startswith("www."):
        a = a[4:]
    b = post_host
    if not a or not b:
        return False
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def parse_ransomware_posts(data: Any) -> list[RansomwarePost]:
    """Normalize the raw ransomware.live posts.json array into RansomwarePost."""
    out: list[RansomwarePost] = []
    if not isinstance(data, list):
        return out
    for row in data:
        if not isinstance(row, dict):
            continue
        website = row.get("website") or ""
        out.append(
            RansomwarePost(
                victim=(row.get("post_title") or "").strip(),
                group=(row.get("group_name") or "").strip(),
                website=website,
                host=_host_from_website(website),
                discovered=(row.get("discovered") or "").strip(),
                published=(row.get("published") or "").strip(),
                activity=(row.get("activity") or "").strip(),
                country=(row.get("country") or "").strip(),
                post_ref=(row.get("post_url") or "").strip(),
                raw=row,
            )
        )
    return out


def match_posts(
    posts: list[RansomwarePost],
    *,
    domain: str | None = None,
    org: str | None = None,
) -> list[RansomwarePost]:
    """Return postings that name the given authorized domain and/or org.

    Domain match is host-based (precise). Org match requires the *full*
    normalized org string to equal the normalized victim name — not a loose
    substring — to avoid false "you were ransomwared" alarms from common words.
    Results are de-duplicated and newest-first by discovery date.
    """
    want_org = norm_org(org) if org else ""
    hits: list[RansomwarePost] = []
    for p in posts:
        matched = False
        if domain and _domains_match(domain, p.host):
            matched = True
        elif want_org and norm_org(p.victim) == want_org:
            matched = True
        if matched:
            hits.append(p)
    hits.sort(key=lambda p: p.discovered or "", reverse=True)
    return hits


# --- feed cache (shared discipline with reputation collectors) -------------

def _cache_get(cache_dir: Path, name: str, ttl_s: float) -> Any | None:
    p = cache_dir / name
    if not p.exists():
        return None
    if (time.time() - p.stat().st_mtime) > ttl_s:
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def _cache_put(cache_dir: Path, name: str, value: Any) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / name).write_text(json.dumps(value))
    except Exception:
        pass


# --- collector -------------------------------------------------------------

class RansomwareExposureCollector(BaseCollector):
    """Flag whether an authorized domain/org appears on a ransomware leak site.

    Passive, defensive, key-free. Consumes ransomware.live's aggregated public
    index of victim postings — it does not touch the criminal leak sites
    themselves, download stolen data, or use Tor. Emits a BREACH entity per
    distinct (group, victim) posting with the leak-page URL kept only as a
    *pointer*, plus an EXPOSED_IN edge and per-posting provenance.
    """
    name = "ransomware_exposure"
    timeout_s = 45
    version = "0.1.0"
    inputs = {EntityType.DOMAIN, EntityType.ORG}
    description = (
        "Ransomware leak-site exposure: is this domain/org a named victim? "
        "(passive, key-free, via ransomware.live public index)"
    )

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        etype = EntityType(entity.type)
        value = entity.value.strip()
        src_key = entity.norm_key
        ttl = getattr(ctx.settings, "darkweb_feed_ttl_s", 3600.0)

        try:
            raw = self._posts(ctx, ttl)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"ransomware_exposure: feed unavailable ({exc})")
            return result

        posts = parse_ransomware_posts(raw)
        if etype == EntityType.DOMAIN:
            hits = match_posts(posts, domain=value.lower())
        else:  # ORG
            hits = match_posts(posts, org=value)

        if not hits:
            result.notes.append(
                f"ransomware_exposure: no leak-site posting for {value} "
                f"(checked {len(posts)} public postings)"
            )
            # Record the clean check on the entity for provenance / freshness.
            result.entities.append(EntityIn(
                type=etype, value=value, confidence=max(0.9, entity.confidence),
                props={"ransomware_victim": False, "ransomware_checked": len(posts)},
            ))
            return result

        # De-dup postings by (group, victim, host) — mirror sites repeat entries.
        seen: set[tuple[str, str, str]] = set()
        unique: list[RansomwarePost] = []
        for p in hits:
            k = (p.group.lower(), norm_org(p.victim), p.host or "")
            if k in seen:
                continue
            seen.add(k)
            unique.append(p)

        for p in unique:
            bid = f"ransomware:{p.group or 'unknown'}:{p.host or norm_org(p.victim) or 'na'}"
            result.entities.append(EntityIn(
                type=EntityType.BREACH,
                value=bid,
                display_name=f"{p.victim or value} — {p.group or 'ransomware'} leak",
                confidence=0.9,
                props={
                    "kind": "ransomware_leak",
                    "victim": p.victim,
                    "group": p.group,
                    "website": p.website,
                    "activity": p.activity,
                    "country": p.country,
                    "discovered": p.discovered,
                    "published": p.published,
                    # POINTER only — never fetched, never a re-hosted copy.
                    "leak_post_ref": p.post_ref[:200],
                    "is_ransomware": True,
                    "severity": "high",
                    "source": "ransomware.live",
                },
            ))
            result.edges.append(EdgeIn(
                source_key=src_key,
                target_key=entity_key(EntityType.BREACH, bid),
                rel=EdgeType.EXPOSED_IN,
                confidence=0.9,
                props={"group": p.group, "discovered": p.discovered, "severity": "high"},
            ))
            result.evidence.append(EvidenceIn(
                collector=self.name,
                source_name="ransomware.live",
                source_url="https://www.ransomware.live/",
                summary=(
                    f"{p.victim or value} listed by {p.group or 'a ransomware group'} "
                    f"(discovered {p.discovered[:10] or '?'}, sector {p.activity or 'n/a'})"
                ),
                confidence=0.9,
                raw={
                    "group": p.group, "victim": p.victim, "website": p.website,
                    "discovered": p.discovered, "published": p.published,
                    "country": p.country, "activity": p.activity,
                },
                entity_key=src_key,
            ))

        # Flag the subject entity itself.
        result.entities.append(EntityIn(
            type=etype, value=value, confidence=max(0.9, entity.confidence),
            props={
                "ransomware_victim": True,
                "ransomware_groups": sorted({p.group for p in unique if p.group}),
                "ransomware_postings": len(unique),
                "ransomware_checked": len(posts),
            },
        ))
        result.notes.append(
            f"ransomware_exposure: ⚠ {len(unique)} leak-site posting(s) for {value} "
            f"— groups: {', '.join(sorted({p.group for p in unique if p.group})) or 'unknown'}"
        )
        return result

    def _posts(self, ctx: CollectorContext, ttl: float) -> Any:
        cached = _cache_get(ctx.settings.cache_dir, "ransomwarelive_posts.json", ttl)
        if cached is not None:
            return cached
        resp = ctx.http.get(RANSOMWARE_LIVE_POSTS)
        resp.raise_for_status()
        data = resp.json()
        _cache_put(ctx.settings.cache_dir, "ransomwarelive_posts.json", data)
        return data
