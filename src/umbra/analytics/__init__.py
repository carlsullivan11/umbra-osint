"""First-party visitor analytics (product metrics)."""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import and_, desc, func, select

from umbra.core.models import utcnow
from umbra.db.schema import PageView, get_session

logger = logging.getLogger("umbra.analytics")

# Paths we never record (noise / self)
_SKIP_PREFIXES = (
    "/static/",
    "/favicon",
    "/health",
    "/ops/analytics",
    "/ops/events",
    "/api/wiki/",  # high-chatter drawer
)

_SKIP_EXACT = {"/health", "/favicon.ico"}

# --- automation ------------------------------------------------------------
#
# Measured on production over seven days: 6,061 of 8,020 recorded views were
# automation — Googlebot working through the 3.6k-page wiki corpus, which is the
# SEO work doing its job, plus a steady drizzle of WordPress scanners probing a
# site that has never run WordPress. Summing those with real people overstates
# traffic about fourfold on the one page used to judge traction.
#
# Classification is done on **read**, never on write: the row keeps its user
# agent, so sharpening these rules re-reads history correctly, and a false
# positive mislabels a visitor instead of discarding them at the door.

_BOT_MARKERS = (
    "bot/", "bot;", "bot)", "bot ", "+bot", "-bot", "_bot",
    "crawler", "crawl;", "spider", "slurp", "scrapy", "headless",
    "python-requests", "python-urllib", "aiohttp", "httpx/", "okhttp",
    "curl/", "wget/", "go-http-client", "java/", "libwww-perl", "guzzle",
    "facebookexternalhit", "embedly", "preview", "monitoring", "uptime",
    "censys", "masscan", "zgrab", "nuclei", "nmap", "internet-measurement",
)
# Whole-token names that would be unsafe as bare substrings.
_BOT_NAMES = (
    "googlebot", "bingbot", "yandexbot", "duckduckbot", "baiduspider",
    "ahrefsbot", "semrushbot", "mj12bot", "dotbot", "petalbot", "applebot",
    "gptbot", "ccbot", "claudebot", "bytespider", "amazonbot",
)

# Paths only a scanner asks for. These arrive with a browser-shaped user agent,
# so the UA rules never see them: nothing here has ever run WordPress or PHP.
_PROBE_MARKERS = (
    "/wp-includes/", "/wp-admin", "/wp-content/", "/wordpress",
    "/xmlrpc.php", "/.env", "/.git/", "/phpmyadmin", "/vendor/phpunit",
    "/administrator/", "/cgi-bin/", "/shell", "/config.json", "/.aws/",
)


def is_bot_ua(user_agent: str | None) -> bool:
    """Best-effort: is this user agent automation rather than a person?

    A missing user agent counts as automation. Every real browser sends one, and
    treating "unknown" as a visitor is the direction that flatters the numbers.
    """
    ua = (user_agent or "").strip().lower()
    if not ua:
        return True
    if any(name in ua for name in _BOT_NAMES):
        return True
    return any(marker in ua for marker in _BOT_MARKERS)


def is_probe_path(path: str | None) -> bool:
    """A request only an opportunistic scanner would make."""
    p = (path or "").lower()
    return any(marker in p for marker in _PROBE_MARKERS)


def analytics_enabled() -> bool:
    return os.environ.get("UMBRA_ANALYTICS_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def _salt() -> str:
    """Daily rotating salt so visitor hashes are not a permanent cross-day ID."""
    env = os.environ.get("UMBRA_ANALYTICS_SALT", "").strip()
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base = env or "umbra-analytics"
    return f"{base}:{day}"


def visitor_hash(ip: str | None, user_agent: str | None) -> str:
    raw = f"{_salt()}|{(ip or '').strip()}|{(user_agent or '')[:200]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def should_record(path: str, method: str) -> bool:
    if not analytics_enabled():
        return False
    if method.upper() not in {"GET", "HEAD"}:
        return False
    if path in _SKIP_EXACT:
        return False
    return not any(path.startswith(p) for p in _SKIP_PREFIXES)


def record_page_view(
    *,
    path: str,
    method: str = "GET",
    status: int = 200,
    duration_ms: float = 0.0,
    referrer: str | None = None,
    user_agent: str | None = None,
    client_ip: str | None = None,
    country: str | None = None,
    cf_ray: str | None = None,
    access_email: str | None = None,
    props: dict[str, Any] | None = None,
) -> None:
    if not should_record(path, method):
        return
    session = get_session()
    try:
        row = PageView(
            id=uuid4().hex[:16],
            ts=utcnow(),
            path=path[:1024],
            method=method[:16],
            status=int(status),
            duration_ms=float(duration_ms),
            referrer=(referrer or None) and referrer[:2048],
            user_agent=(user_agent or None) and user_agent[:512],
            visitor_hash=visitor_hash(client_ip, user_agent),
            country=(country or None) and country[:8],
            cf_ray=(cf_ray or None) and cf_ray[:64],
            access_email=(access_email or None) and access_email[:320],
            props=props or {},
        )
        session.add(row)
        session.commit()
    except Exception:
        session.rollback()
        logger.exception("analytics record failed")
    finally:
        session.close()


def _like(value: str) -> str:
    """A LIKE pattern for a literal substring. `_` and `%` are wildcards, and
    several markers contain `_` — unescaped, `_bot` would match `abot`."""
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _human_only():
    """SQL for "a person, probably" — built from the same constants `is_bot_ua`
    and `is_probe_path` use, so the two can never disagree."""
    ua = func.lower(func.coalesce(PageView.user_agent, ""))
    path = func.lower(func.coalesce(PageView.path, ""))
    conditions = [ua != ""]
    for marker in _BOT_NAMES + _BOT_MARKERS:
        conditions.append(~ua.like(_like(marker), escape="\\"))
    for marker in _PROBE_MARKERS:
        conditions.append(~path.like(_like(marker), escape="\\"))
    return and_(*conditions)


def summarize(days: int = 7, limit: int = 50, include_bots: bool = False) -> dict[str, Any]:
    """Traffic for the window. **Automation is excluded by default.**

    Not a cosmetic choice: on production, automation was 76% of recorded views,
    so summing it with real visitors overstated the numbers about fourfold on
    the page used to judge traction. Bot volume is still reported — Googlebot
    working through the corpus is the SEO work paying off, and that is a result
    rather than noise — it simply is not counted as people.
    """
    session = get_session()
    try:
        since = utcnow() - timedelta(days=max(1, days))
        window = [PageView.ts >= since]
        scope = list(window) if include_bots else [*window, _human_only()]

        total = session.scalar(
            select(func.count()).select_from(PageView).where(*scope)
        ) or 0
        all_views = session.scalar(
            select(func.count()).select_from(PageView).where(*window)
        ) or 0
        visitors = session.scalar(
            select(func.count(func.distinct(PageView.visitor_hash))).where(*scope)
        ) or 0
        by_path = session.execute(
            select(PageView.path, func.count())
            .where(*scope)
            .group_by(PageView.path)
            .order_by(desc(func.count()))
            .limit(limit)
        ).all()
        by_country = session.execute(
            select(PageView.country, func.count())
            .where(*scope)
            .group_by(PageView.country)
            .order_by(desc(func.count()))
            .limit(20)
        ).all()
        by_ref = session.execute(
            select(PageView.referrer, func.count())
            .where(*scope)
            .group_by(PageView.referrer)
            .order_by(desc(func.count()))
            .limit(20)
        ).all()
        recent = session.scalars(
            select(PageView).where(*scope).order_by(desc(PageView.ts)).limit(30)
        ).all()
        bot_views = int(all_views) - int(
            session.scalar(select(func.count()).select_from(PageView)
                           .where(*window, _human_only())) or 0
        )
        return {
            "days": days,
            "total_views": int(total),
            "unique_visitors_approx": int(visitors),
            "bot_views": bot_views,
            "bot_share": round(bot_views / all_views, 4) if all_views else 0,
            "counts_bots": include_bots,
            "top_paths": [{"path": p, "count": int(c)} for p, c in by_path],
            "top_countries": [{"country": c or "??", "count": int(n)} for c, n in by_country],
            "top_referrers": [{"referrer": r or "(direct)", "count": int(n)} for r, n in by_ref],
            "recent": [
                {
                    "ts": r.ts.isoformat() if r.ts else None,
                    "path": r.path,
                    "status": r.status,
                    "country": r.country,
                    "visitor": r.visitor_hash,
                    "access_email": r.access_email,
                    "ua": (r.user_agent or "")[:80],
                }
                for r in recent
            ],
        }
    finally:
        session.close()
