"""Local tech fingerprinting from headers/HTML/JS — replaces BuiltWith API."""

from __future__ import annotations

import re

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

# (name, compiled rule on headers dict lower->val, body lower)
_HEADER_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("cloudflare", re.compile(r"cloudflare", re.I)),
    ("nginx", re.compile(r"^nginx", re.I)),
    ("apache", re.compile(r"apache", re.I)),
    ("iis", re.compile(r"microsoft-iis|iis", re.I)),
    ("vercel", re.compile(r"vercel", re.I)),
    ("netlify", re.compile(r"netlify", re.I)),
    ("github_pages", re.compile(r"github\.com", re.I)),
    ("amazon_s3", re.compile(r"amazons3|amazon.s3", re.I)),
    ("gws", re.compile(r"gws|google frontend", re.I)),
    ("hsts", re.compile(r"max-age=", re.I)),
]

_BODY_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("wordpress", re.compile(r"wp-content|wp-includes|wordpress", re.I)),
    ("woocommerce", re.compile(r"woocommerce", re.I)),
    ("drupal", re.compile(r"drupal|sites/default/files", re.I)),
    ("joomla", re.compile(r"/media/jui/|joomla", re.I)),
    ("shopify", re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I)),
    ("squarespace", re.compile(r"squarespace", re.I)),
    ("wix", re.compile(r"wix\.com|X-Wix", re.I)),
    ("react", re.compile(r"data-reactroot|__NEXT_DATA__|react", re.I)),
    ("nextjs", re.compile(r"__NEXT_DATA__|_next/static", re.I)),
    ("nuxt", re.compile(r"__NUXT__", re.I)),
    ("angular", re.compile(r"ng-version|angular", re.I)),
    ("vue", re.compile(r"data-v-[a-f0-9]{6,}|vue\.js", re.I)),
    ("jquery", re.compile(r"jquery[.-]", re.I)),
    ("bootstrap", re.compile(r"bootstrap(\.min)?\.css", re.I)),
    ("tailwind", re.compile(r"tailwind", re.I)),
    ("ga4", re.compile(r"gtag\(|G-[A-Z0-9]+|google-analytics\.com/g/collect", re.I)),
    ("google_analytics", re.compile(r"google-analytics\.com|UA-\d+", re.I)),
    ("google_tag_manager", re.compile(r"googletagmanager\.com/gtm\.js", re.I)),
    ("facebook_pixel", re.compile(r"fbevents\.js|facebook\.com/tr", re.I)),
    ("hotjar", re.compile(r"static\.hotjar\.com", re.I)),
    ("segment", re.compile(r"cdn\.segment\.com", re.I)),
    ("stripe", re.compile(r"js\.stripe\.com", re.I)),
    ("recaptcha", re.compile(r"google\.com/recaptcha|grecaptcha", re.I)),
    ("cloudflare_insights", re.compile(r"cloudflareinsights|beacon\.min\.js", re.I)),
    ("font_awesome", re.compile(r"font-awesome|fontawesome", re.I)),
    ("bootstrap_cdn", re.compile(r"cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com", re.I)),
]


class TechFingerprintCollector(BaseCollector):
    name = "tech_fingerprint"
    timeout_s = 30
    inputs = {EntityType.DOMAIN, EntityType.URL}
    description = "Local BuiltWith-style stack fingerprint from headers/HTML"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        if entity.type == EntityType.URL.value:
            urls = [entity.value if "://" in entity.value else f"https://{entity.value}"]
        else:
            urls = [f"https://{entity.value}/", f"http://{entity.value}/"]
        src = entity.norm_key

        resp = None
        for url in urls:
            try:
                r = ctx.http.get(url, follow_redirects=True)
                if r.status_code < 500:
                    resp = r
                    break
            except Exception as exc:  # noqa: BLE001
                result.notes.append(str(exc))
        if resp is None:
            result.notes.append("tech_fingerprint: fetch failed")
            return result

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = ""
        try:
            body = resp.text[:250_000]
        except Exception:
            body = ""
        body_l = body.lower()
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())

        found: list[str] = []
        server = headers.get("server")
        if server:
            found.append(f"server:{server.split('/')[0].split()[0]}")
        powered = headers.get("x-powered-by")
        if powered:
            found.append(f"powered_by:{powered.split()[0][:40]}")
        if "cf-ray" in headers:
            found.append("cloudflare")

        for name, pat in _HEADER_RULES:
            # check relevant header values
            if name == "hsts" and "strict-transport-security" in headers:
                found.append("hsts")
                continue
            for hk, hv in headers.items():
                if pat.search(hv) or pat.search(hk):
                    found.append(name)
                    break

        for name, pat in _BODY_RULES:
            if pat.search(body) or pat.search(body_l):
                found.append(name)

        # generator meta
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if not gen:
            gen = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.I)
        if gen:
            found.append(f"generator:{gen.group(1)[:60]}")

        # unique preserve order
        uniq: list[str] = []
        for f in found:
            fl = f.lower()
            if fl not in {u.lower() for u in uniq}:
                uniq.append(f)

        for tech in uniq:
            result.entities.append(EntityIn(type=EntityType.TECHNOLOGY, value=tech, confidence=0.7))
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.TECHNOLOGY, tech),
                    rel=EdgeType.USES_TECH,
                    confidence=0.7,
                )
            )

        result.entities.append(
            EntityIn(
                type=EntityType(entity.type),
                value=entity.value,
                confidence=0.9,
                props={"tech": uniq, "final_url": str(resp.url), "status": resp.status_code},
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="local_fingerprint",
                source_url=str(resp.url),
                summary=f"Tech fingerprint: {', '.join(uniq[:12]) or 'none'}",
                confidence=0.75,
                raw={"tech": uniq, "server": server, "powered_by": powered},
                entity_key=src,
            )
        )
        return result
