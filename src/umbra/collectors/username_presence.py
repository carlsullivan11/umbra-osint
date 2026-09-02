from __future__ import annotations

import re

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

# Free public profile URL patterns — replace paid "username search" APIs
_PLATFORMS: list[tuple[str, str]] = [
    ("github", "https://github.com/{u}"),
    ("gitlab", "https://gitlab.com/{u}"),
    ("reddit", "https://www.reddit.com/user/{u}/about.json"),
    ("devto", "https://dev.to/{u}"),
    ("keybase", "https://keybase.io/{u}"),
    ("hackernews", "https://news.ycombinator.com/user?id={u}"),
    ("pypi", "https://pypi.org/user/{u}/"),
    ("npm", "https://www.npmjs.com/~{u}"),
    ("medium", "https://medium.com/@{u}"),
    ("aboutme", "https://about.me/{u}"),
    ("linktree", "https://linktr.ee/{u}"),
    ("youtube", "https://www.youtube.com/@{u}"),
    ("instagram", "https://www.instagram.com/{u}/"),
    ("tiktok", "https://www.tiktok.com/@{u}"),
    ("x", "https://x.com/{u}"),
    ("codeberg", "https://codeberg.org/{u}"),
    ("sourceforge", "https://sourceforge.net/u/{u}/profile/"),
    ("twitch", "https://www.twitch.tv/{u}"),
]

_SOFT_404 = re.compile(
    r"(page not found|user not found|not found|no such user|couldn't find|"
    r"does not exist|doesn't exist|doesn’t exist|account suspended|"
    r"sorry, nobody on|we couldn't find that|404|repo not found|"
    r"this page is missing|nothing to see here|user has been suspended)",
    re.I,
)

_HIGH_CONF = {"github", "gitlab", "reddit", "devto", "pypi", "codeberg", "keybase"}


def _exists_heuristic(platform: str, code: int, text: str, final_url: str) -> tuple[bool, float]:
    if code == 404:
        return False, 0.0
    if code in {401, 403, 999, 429}:
        return False, 0.0  # caller treats as uncertain separately
    if code != 200:
        return False, 0.0

    t = text[:8000].lower()
    # platform-specific
    if platform == "reddit":
        if "is_employee" in t or '"name"' in t or "total_karma" in t:
            return True, 0.85
        if "page not found" in t or t.strip() in {"", "{}"}:
            return False, 0.0
    if platform == "hackernews":
        if "no such user" in t:
            return False, 0.0
        if "created:" in t or "karma:" in t:
            return True, 0.8
    if platform == "github":
        if "not found" in t and "404" in t:
            return False, 0.0
        if f"github.com/{final_url.rstrip('/').split('/')[-1]}".lower() in final_url.lower() or "repositories" in t or "followers" in t:
            return True, 0.85
    if platform == "pypi":
        if "not found" in t or "oops" in t:
            return False, 0.0
    if platform == "youtube":
        # YT often 200 with "This page isn't available"
        if "this page isn't available" in t or "isn't available" in t:
            return False, 0.0
    if platform in {"instagram", "tiktok", "x", "medium", "linktree"}:
        if _SOFT_404.search(t):
            return False, 0.0
        # very short bodies often login walls / empty
        if len(t) < 200:
            return False, 0.0

    if _SOFT_404.search(t) and platform not in {"github"}:
        # generic soft 404
        if platform in {"aboutme", "npm", "twitch", "sourceforge"}:
            return False, 0.0

    conf = 0.78 if platform in _HIGH_CONF else 0.52
    return True, conf


class UsernamePresenceCollector(BaseCollector):
    name = "username_presence"
    timeout_s = 60
    inputs = {EntityType.USERNAME}
    description = "Probe free public profile URLs across platforms (soft-404 hardened)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        raw = entity.value
        if ":" in raw:
            platform_hint, handle = raw.split(":", 1)
        else:
            platform_hint, handle = "unknown", raw
        handle = handle.lstrip("@").strip()
        if not handle:
            return result

        src = entity.norm_key
        found: list[dict] = []
        uncertain: list[str] = []

        for platform, tmpl in _PLATFORMS:
            url = tmpl.format(u=handle)
            try:
                resp = ctx.http.get(url, follow_redirects=True)
                code = resp.status_code
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"{platform}: {exc}")
                continue

            if code in {401, 403, 999, 429}:
                uncertain.append(f"{platform}:{code}")
                continue

            text = ""
            try:
                text = resp.text[:8000]
            except Exception:
                text = ""

            exists, conf = _exists_heuristic(platform, code, text, str(resp.url))
            if not exists:
                continue

            uname = f"{platform}:{handle}"
            result.entities.append(
                EntityIn(
                    type=EntityType.USERNAME,
                    value=uname,
                    confidence=conf,
                    props={"http_status": code, "final_url": str(resp.url)},
                )
            )
            result.entities.append(EntityIn(type=EntityType.URL, value=str(resp.url), confidence=conf))
            ukey = entity_key(EntityType.USERNAME, uname)
            rel = EdgeType.SAME_AS if platform_hint != platform else EdgeType.HAS_PROFILE
            result.edges.append(EdgeIn(source_key=src, target_key=ukey, rel=rel, confidence=conf))
            result.edges.append(
                EdgeIn(
                    source_key=ukey,
                    target_key=entity_key(EntityType.URL, str(resp.url)),
                    rel=EdgeType.HAS_PROFILE,
                    confidence=conf,
                )
            )
            found.append({"platform": platform, "url": str(resp.url), "status": code, "confidence": conf})

        if uncertain:
            result.notes.append("blocked/uncertain: " + ", ".join(uncertain[:12]))

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="username_presence",
                summary=f"Presence probes for '{handle}': {len(found)} hit(s), {len(uncertain)} uncertain",
                confidence=0.7,
                raw={"handle": handle, "hits": found, "uncertain": uncertain},
                entity_key=src,
            )
        )
        return result
