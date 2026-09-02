from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.I)
_MAILTO_RE = re.compile(r"mailto:([^?\"'\s>]+)", re.I)

_SOCIAL = {
    "github.com": "github",
    "www.github.com": "github",
    "gitlab.com": "gitlab",
    "twitter.com": "twitter",
    "x.com": "x",
    "www.twitter.com": "twitter",
    "instagram.com": "instagram",
    "www.instagram.com": "instagram",
    "linkedin.com": "linkedin",
    "www.linkedin.com": "linkedin",
    "facebook.com": "facebook",
    "www.facebook.com": "facebook",
    "youtube.com": "youtube",
    "www.youtube.com": "youtube",
    "tiktok.com": "tiktok",
    "www.tiktok.com": "tiktok",
    "reddit.com": "reddit",
    "www.reddit.com": "reddit",
    "medium.com": "medium",
}


class HtmlLinksCollector(BaseCollector):
    name = "html_links"
    timeout_s = 30
    inputs = {EntityType.DOMAIN, EntityType.URL}
    description = "Extract emails + social/profile links from public HTML (paid-enrichment substitute)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        if entity.type == EntityType.URL.value:
            urls = [entity.value if "://" in entity.value else f"https://{entity.value}"]
        else:
            host = entity.value
            urls = [f"https://{host}/", f"http://{host}/"]

        src = entity.norm_key
        page_url = None
        html = ""
        for url in urls:
            try:
                resp = ctx.http.get(url, follow_redirects=True)
                if resp.status_code >= 400:
                    continue
                page_url = str(resp.url)
                html = resp.text[:400_000]
                break
            except Exception as exc:  # noqa: BLE001
                result.notes.append(str(exc))
                continue
        if not html or not page_url:
            result.notes.append("html_links: no page fetched")
            return result

        found_social: list[str] = []
        found_emails: list[str] = []
        found_urls: list[str] = []

        for m in _MAILTO_RE.findall(html):
            em = m.strip().rstrip(".")
            if "@" in em and em not in found_emails:
                found_emails.append(em)
                result.entities.append(EntityIn(type=EntityType.EMAIL, value=em, confidence=0.8))
                result.edges.append(
                    EdgeIn(
                        source_key=src,
                        target_key=entity_key(EntityType.EMAIL, em),
                        rel=EdgeType.USES_EMAIL,
                        confidence=0.8,
                    )
                )

        base_host = urlparse(page_url).hostname or ""
        for href in _HREF_RE.findall(html):
            if href.startswith("#") or href.startswith("javascript:"):
                continue
            abs_url = urljoin(page_url, href)
            p = urlparse(abs_url)
            host = (p.hostname or "").lower()
            if not host:
                continue

            # social handles
            for social_host, platform in _SOCIAL.items():
                if host == social_host or host.endswith("." + social_host):
                    path = p.path.strip("/")
                    if not path:
                        break
                    # linkedin/in/foo, github.com/foo, etc.
                    parts = [x for x in path.split("/") if x]
                    handle = None
                    if platform == "linkedin" and len(parts) >= 2 and parts[0] in {"in", "company"}:
                        handle = parts[1]
                        uname = f"linkedin:{handle}"
                    elif platform == "reddit" and parts and parts[0] == "user" and len(parts) >= 2:
                        handle = parts[1]
                        uname = f"reddit:{handle}"
                    elif platform in {"youtube"} and parts:
                        handle = parts[0].lstrip("@")
                        uname = f"youtube:{handle}"
                    elif parts:
                        handle = parts[0].lstrip("@")
                        uname = f"{platform}:{handle}"
                    else:
                        break
                    if handle and uname not in found_social:
                        found_social.append(uname)
                        result.entities.append(
                            EntityIn(type=EntityType.USERNAME, value=uname, confidence=0.7)
                        )
                        result.entities.append(EntityIn(type=EntityType.URL, value=abs_url.split("?")[0], confidence=0.7))
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(EntityType.USERNAME, uname),
                                rel=EdgeType.ASSOCIATED_WITH,
                                confidence=0.7,
                            )
                        )
                    break
            else:
                # same-site or external interesting links (limit)
                if host == base_host.lower() or host.endswith("." + base_host.lower()):
                    if abs_url not in found_urls and len(found_urls) < 40:
                        found_urls.append(abs_url)
                        result.entities.append(EntityIn(type=EntityType.URL, value=abs_url.split("?")[0][:500], confidence=0.5))
                        result.edges.append(
                            EdgeIn(
                                source_key=src,
                                target_key=entity_key(EntityType.URL, abs_url.split("?")[0][:500]),
                                rel=EdgeType.LINKED_FROM,
                                confidence=0.5,
                            )
                        )

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="HTML extract",
                source_url=page_url,
                summary=f"Links from {page_url}: social={len(found_social)} email={len(found_emails)} urls={len(found_urls)}",
                confidence=0.75,
                raw={"social": found_social, "emails": found_emails, "urls": found_urls[:40]},
                entity_key=src,
            )
        )
        return result
