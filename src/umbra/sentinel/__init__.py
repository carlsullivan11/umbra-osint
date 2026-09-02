"""Who is scanning Umbra — asked passively, on a timer.

Carl's ask, 2026-08-20:

> "I want to run a search on IPs that connect to Umbra. the searches should be
> automated in the background and should count towards the search counters on
> the homepage. so if Google scans Umbra, Umbra fingerprints Google back."

Umbra is a public site, so a large share of its traffic is other people's
automation — Googlebot working through the wiki corpus, and a steady drizzle of
WordPress scanners probing a site that has never run WordPress. Asking who they
are is ordinary defensive work on our own asset, and every tool for it is
already here: RDAP, ASN, geolocation, DNSBL reputation, the abuse.ch lake.

Three constraints define the module.

**Passive only.** Fingerprinting means asking public registries and our own
lakes who an address belongs to. It does **not** mean connecting back to it.
Probing a host because it touched our web server is an unauthorised active scan
(`AGENTS.md` #1), and it would point Umbra's egress at whoever happened to
visit. `COLLECTORS` is an allowlist, and a test asserts no active collector is
in it.

**Scanners only, never visitors.** `PageView` deliberately stores a salted
`visitor_hash` and no raw IP, so a person reading the site is not identifiable
from the database. This module must not be the loophole that undoes that. An
address is recorded only when the request *already* looked like automation —
and `classify` is where that decision lives.

**Bounded.** Capped per tick, one case per address per cooldown window,
observations purged after a few days, and private, loopback and Cloudflare
space skipped entirely.

The homepage counters need no special handling: they count cases and entities,
and these are real cases. That is also the honest answer — a fingerprint *is* a
search Umbra ran.
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import delete, func, select

from umbra.analytics import is_bot_ua, is_probe_path
from umbra.core.models import EntityIn, EntityType, utcnow
from umbra.db.schema import Case, SentinelObservation

logger = logging.getLogger("umbra.sentinel")

# Passive lookups only. Every one of these reads a public registry or a lake we
# already own; none of them opens a connection to the address being looked up.
COLLECTORS = ["rdap_ip", "asn_cymru", "ip_geo", "ip_reputation", "malware_infra"]

# One hit is a visit. A pattern is a pattern.
MIN_HITS = 3

# How far back a tick looks. Wider than the timer interval so a scanner that
# spreads its requests out is still seen as one burst.
WINDOW_HOURS = 24

# Googlebot touches this site all day. Without a cooldown it would earn a case
# every time the timer fires.
COOLDOWN_DAYS = 7

# A scan sweep can come from a whole subnet at once. The cap keeps one bad
# afternoon from filling the case table; what it defers is reported, never
# dropped silently. Raised from 5→15 so an hourly timer clears backlog in a
# few ticks rather than days.
MAX_PER_TICK = 15

# Long enough to notice a pattern across days, short enough that this is not a
# visitor log.
PURGE_DAYS = 14

# Cloudflare's published edge ranges. The origin is only reachable through the
# tunnel, so a missing `CF-Connecting-IP` means we are looking at Cloudflare
# itself — and a case per Cloudflare PoP is noise, not a finding.
_CLOUDFLARE = [
    ipaddress.ip_network(n) for n in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
]

# Space no end user is allocated, so RDAP has nothing to say about it and a case
# would be an empty page with an address on it.
#
# Spelled out rather than left to `ipaddress.is_private`, whose membership has
# moved between CPython releases — 100.64.0.0/10 reports private on some
# versions and not others, and the documentation ranges report private on this
# one. A privacy and egress boundary should not depend on which interpreter is
# installed.
_UNROUTABLE = [
    ipaddress.ip_network(n) for n in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10",   # shared / CGNAT
        "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.0.2.0/24",               # TEST-NET-1
        "192.168.0.0/16", "198.18.0.0/15",            # benchmarking
        "198.51.100.0/24", "203.0.113.0/24",          # TEST-NET-2 / -3
        "224.0.0.0/4", "240.0.0.0/4",
        "::1/128", "::/128", "fc00::/7", "fe80::/10",
        "2001:db8::/32", "ff00::/8",
    )
]

# Requests we make of ourselves, or that the platform makes of us. Fingerprinting
# our own health watcher forever is not intelligence.
_SELF_PATHS = ("/health", "/favicon", "/static/", "/robots.txt", "/sitemap")


def classify(path: str | None, user_agent: str | None,
             status: int | None = 200, *_ignored) -> str | None:
    """Why this request counts as scanning, or `None` if it does not.

    The gate for the whole module. Returning `None` means no address is stored,
    so the bar here is the privacy boundary as much as the signal one: a person
    reading the guide must fall through it.
    """
    try:
        p = (path or "").lower()
        if any(p.startswith(s) or s in p for s in _SELF_PATHS):
            return None
        if is_probe_path(p):
            return "probe_path"
        if is_bot_ua(user_agent):
            return "bot_ua"
        return None
    except Exception:  # noqa: BLE001 - this runs on every request; never 500 a page
        logger.debug("sentinel classify failed", exc_info=True)
        return None


def eligible(ip: str | None) -> bool:
    """Is this an address worth — and lawful — to look up?

    Deliberately stricter than `umbra.email.parse.is_routable`, which allows the
    documentation ranges. The two answer different questions: there it is "was
    this hop internal plumbing", and a documentation address is not, so it gets
    shown. Here it is "should Umbra open a case and query registries about
    this", and for reserved or shared space the answer is no — RDAP has nothing
    to say about an address nobody was allocated, so the case would be an empty
    page with somebody's IP on it.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except (ValueError, TypeError):
        return False
    return not any(addr in net for net in (_UNROUTABLE + _CLOUDFLARE)
                   if net.version == addr.version)


def record(session, *, ip: str | None, path: str, user_agent: str | None,
           method: str = "GET", status: int = 200,
           country: str | None = None) -> bool:
    """Store one scanning observation. Returns whether anything was written."""
    reason = classify(path, user_agent, status)
    if reason is None or not eligible(ip):
        return False
    try:
        session.add(SentinelObservation(
            id=uuid4().hex[:16], ts=utcnow(), ip=str(ip)[:64], reason=reason,
            path=(path or "")[:1024], method=(method or "GET")[:16],
            status=int(status or 0),
            user_agent=(user_agent or None) and str(user_agent)[:512],
            country=(country or None) and str(country)[:8],
        ))
        session.commit()
        return True
    except Exception:  # noqa: BLE001 - an observation must never cost a response
        session.rollback()
        logger.debug("sentinel record failed", exc_info=True)
        return False


def candidates(session, *, min_hits: int = MIN_HITS,
               window_hours: int = WINDOW_HOURS) -> list[dict]:
    """Addresses seen scanning often enough to be worth asking about.

    Busiest first, so that when the per-tick cap bites it defers the quiet ones
    rather than the address that hit us hardest.
    """
    since = utcnow() - timedelta(hours=window_hours)
    rows = session.execute(
        select(SentinelObservation.ip, func.count().label("hits"))
        .where(SentinelObservation.ts >= since)
        .group_by(SentinelObservation.ip)
        .having(func.count() >= min_hits)
        .order_by(func.count().desc())
    ).all()

    out: list[dict] = []
    for ip, hits in rows:
        if not eligible(ip):
            continue
        observations = session.scalars(
            select(SentinelObservation)
            .where(SentinelObservation.ip == ip,
                   SentinelObservation.ts >= since)
            .order_by(SentinelObservation.ts.desc())
            .limit(20)
        ).all()
        out.append({
            "ip": ip,
            "hits": int(hits),
            "reasons": sorted({o.reason for o in observations if o.reason}),
            "paths": sorted({o.path for o in observations if o.path})[:10],
            "user_agents": sorted({o.user_agent for o in observations
                                   if o.user_agent})[:3],
            "first_seen": min(o.ts for o in observations).isoformat() if observations else None,
            "last_seen": max(o.ts for o in observations).isoformat() if observations else None,
        })
    return out


def _recently_fingerprinted(session, ip: str,
                            cooldown_days: int = COOLDOWN_DAYS) -> bool:
    since = utcnow() - timedelta(days=cooldown_days)
    return session.scalar(
        select(func.count()).select_from(Case)
        .where(Case.name == case_name(ip), Case.created_at >= since)
    ) > 0


def case_name(ip: str) -> str:
    return f"Scanned us: {ip}"[:120]


def fingerprint(repo, candidate: dict) -> str | None:
    """One address: open a case, seed it, run the passive lookups.

    The case is created with no owner, which makes it operator-only in the web
    UI (`umbra.web.session`). It still counts toward the public homepage
    figures, which is the right split — an aggregate is not personal data, a
    case page is.
    """
    from umbra.core.orchestrator import Orchestrator

    ip = candidate["ip"]
    case = repo.create_case(
        case_name(ip),
        "own_asset",
        f"observed scanning umbra-osint.com {candidate['hits']}x in the last "
        f"{WINDOW_HOURS}h ({', '.join(candidate['reasons']) or 'automation'})",
    )
    repo.audit(case.id, "sentinel.observed", {
        "ip": ip,
        "hits": candidate["hits"],
        "reasons": candidate["reasons"],
        "paths": candidate["paths"],
        "user_agents": candidate["user_agents"],
        "first_seen": candidate["first_seen"],
        "last_seen": candidate["last_seen"],
        "collectors": COLLECTORS,
        "note": ("Passive lookups only — public registries and Umbra's own "
                 "lakes. Nothing was sent to this address."),
    })
    repo.seed(case.id, EntityIn(
        type=EntityType.IP, value=ip, confidence=0.99,
        props={"source": "sentinel",
               "why": f"scanned umbra-osint.com {candidate['hits']}x"},
    ))
    repo.session.commit()

    # Depth 0 on purpose: depth 1 would pivot off whatever the lookups return
    # and start walking somebody else's estate. The question is "who is this",
    # asked once.
    Orchestrator(repo).run(case.id, depth=0, collectors=COLLECTORS,
                           max_entities=40)
    return case.id


def tick(repo, *, min_hits: int = MIN_HITS, window_hours: int = WINDOW_HOURS,
         cooldown_days: int = COOLDOWN_DAYS,
         max_per_tick: int = MAX_PER_TICK) -> dict:
    """One pass. Returns what it did, including what it chose not to do."""
    session = repo.session
    found = candidates(session, min_hits=min_hits, window_hours=window_hours)
    fresh = [c for c in found
             if not _recently_fingerprinted(session, c["ip"], cooldown_days)]

    done: list[str] = []
    for candidate in fresh[:max_per_tick]:
        try:
            case_id = fingerprint(repo, candidate)
            if case_id:
                done.append(case_id)
                session.execute(
                    SentinelObservation.__table__.update()
                    .where(SentinelObservation.ip == candidate["ip"],
                           SentinelObservation.case_id.is_(None))
                    .values(case_id=case_id)
                )
                session.commit()
        except Exception:  # noqa: BLE001 - one dead registry must not stop the rest
            session.rollback()
            logger.exception("sentinel fingerprint failed for %s",
                             candidate["ip"])

    return {
        "candidates": len(found),
        "fingerprinted": len(done),
        # Never a silent cap: "5 fingerprinted" with no deferral count reads as
        # "that was everyone who scanned us".
        "deferred": max(0, len(fresh) - max_per_tick),
        "cases": done,
    }


def purge_observations(session, days: int = PURGE_DAYS) -> int:
    """Drop observations past the retention window. Returns rows removed."""
    cutoff = utcnow() - timedelta(days=days)
    result = session.execute(
        delete(SentinelObservation).where(SentinelObservation.ts < cutoff))
    session.commit()
    return int(result.rowcount or 0)
