"""Feed ingest: fetch each source, normalize, dedupe, store (stage S14 / F1).

Ingest is scheduled, not queued through the case job table: `jobs.case_id` is a
non-nullable FK to `cases`, so a global periodic task would need either a fake
case row or an unmanaged column change on the production database. It runs as
`umbra feed ingest` on a systemd timer, the same shape as the backup and
wiki-sync jobs (`deploy/systemd/umbra-feed-ingest.timer`).

Sources fail independently — that is the point of having several — so one dead
host records its error and the run continues.
"""
from __future__ import annotations

import logging

import httpx

from umbra.core.config import get_settings
from umbra.feeds.rss import parse_feed

logger = logging.getLogger(__name__)

# Operator-curated starting pack: public, official, no login, no paywall
# (docs/FEED.md § Ethics). Sources live in the database once seeded, so this is
# a default rather than a hardcoded list.
# Every URL here was fetched and parsed before being added — two plausible
# candidates did not survive that check: CISA's KEV catalogue has no feed at the
# obvious .xml path (404) and msrc.microsoft.com/blog/feed/ serves an HTML page,
# not RSS. A third, MSRC's update-guide feed, parses fine but carries ~5,000
# CVE entries, which is a data dump rather than news.
# CISA is deliberately absent. Its edge answers **403 to every user agent** for
# the advisory XML — verified from the production host against
# /cybersecurity-advisories/all.xml, /uscert/ncas/alerts.xml and /news.xml,
# including the browser-shaped UA below that used to get through. Only static
# files under /sites/default/files/ still serve, which is how the KEV corpus
# import keeps working. Two permanently-red rows are worse than four green ones,
# and a Feedburner mirror of the retired US-CERT feed would answer 200 while
# breaking the official-sources rule in docs/FEED.md.
DEFAULT_SOURCES = [
    {"name": "CERT/CC Vulnerability Notes", "url": "https://www.kb.cert.org/vulfeed/",
     "trust": 0.9},
    {"name": "CERT-EU Security Advisories",
     "url": "https://www.cert.europa.eu/publications/security-advisories-rss",
     "trust": 0.9},
    {"name": "JPCERT/CC Alerts",
     "url": "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf", "trust": 0.85},
    {"name": "NCSC UK News",
     "url": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml", "trust": 0.9},
    {"name": "SANS Internet Storm Center", "url": "https://isc.sans.edu/rssfeed.xml",
     "trust": 0.8},
]

# Identifies Umbra honestly, in the shape a WAF expects. This used to be enough
# for cisa.gov and no longer is — see the note on DEFAULT_SOURCES. It still
# matters for publishers with lighter bot rules.
USER_AGENT = (
    "Mozilla/5.0 (compatible; umbra-feed/0.1; +https://github.com/carlsullivan11/umbra)"
)

# A feed is allowed to be enormous — MSRC's update guide carries ~5,000 entries.
# Storing one poll of that would bury a day of actual news, so a single poll can
# only contribute this many items.
MAX_ITEMS_PER_POLL = 200


def http_fetch(url: str, timeout: float) -> str:
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": USER_AGENT}) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.text


# Status codes a publisher returns when it has decided not to serve robots at
# all. These do not clear on their own and there is nothing for an operator to
# fix, so they are not filed as errors — a red row nobody can act on is how you
# train someone to stop reading red rows.
_BLOCKED_STATUSES = {401, 403, 406, 451}


def _classify_failure(exc: Exception) -> tuple[str, str]:
    """(status, message) for a failed poll: a deliberate block or a fault."""
    code = None
    response = getattr(exc, "response", None)
    if response is not None:
        code = getattr(response, "status_code", None)
    if code in _BLOCKED_STATUSES:
        return "blocked", (
            f"HTTP {code} — the publisher blocks automated fetching of this "
            f"feed. Not an Umbra fault and it will not clear by retrying; the "
            f"source needs replacing or an agreement with the publisher."
        )[:500]
    return "error", f"{type(exc).__name__}: {exc}"[:500]


def ingest_sources(repo, sources, fetch=http_fetch, timeout: float | None = None) -> dict:
    """Poll each enabled source once. Returns counts, never raises."""
    if timeout is None:
        try:
            timeout = float(get_settings().request_timeout_s)
        except Exception:  # noqa: BLE001
            timeout = 20.0

    stats = {"sources": 0, "skipped": 0, "fetched": 0, "new": 0,
             "duplicates": 0, "errors": 0}
    for source in sources:
        if not source.enabled:
            stats["skipped"] += 1
            continue
        stats["sources"] += 1
        try:
            xml = fetch(source.url, timeout)
        except Exception as exc:  # noqa: BLE001 - one bad host must not end the run
            logger.warning("feed %s fetch failed: %s", source.url, exc)
            stats["errors"] += 1
            status, detail = _classify_failure(exc)
            repo.mark_feed_source_polled(source, status=status, error=detail)
            continue

        items = parse_feed(xml)
        if len(items) > MAX_ITEMS_PER_POLL:
            logger.info("feed %s returned %s items; capping at %s",
                        source.url, len(items), MAX_ITEMS_PER_POLL)
            items = items[:MAX_ITEMS_PER_POLL]
        stats["fetched"] += len(items)
        added, dupes = repo.add_feed_items(source, items)
        stats["new"] += added
        stats["duplicates"] += dupes
        repo.mark_feed_source_polled(source, status="ok", error=None)
    return stats


def seed_default_sources(repo) -> int:
    """Ensure the starting pack exists. Idempotent; never re-enables a source
    the operator turned off."""
    before = len(repo.list_feed_sources())
    for spec in DEFAULT_SOURCES:
        repo.upsert_feed_source(name=spec["name"], url=spec["url"], trust=spec["trust"])
    return len(repo.list_feed_sources()) - before
