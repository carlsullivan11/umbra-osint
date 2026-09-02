"""HTTP(S) probe — status, title, tech hints, and how the server answered.

The response to the GET this collector already makes carries a second, quieter
signal: **the order the server listed its headers in.** Stacks are consistent
about it — nginx, Apache, IIS and the big CDNs each have a habitual order — so
the sequence is a coarse hint about what is serving the page.

Only header **names** are hashed, never values. Values carry `Set-Cookie`,
session identifiers and other things that have no business in a durable
fingerprint; names carry the shape of the stack and nothing about a visitor.

It is a weak signal and is treated as one. Header order is stable across an
entire CDN, so a match means "same stack", never "same operator".
"""

from __future__ import annotations

import hashlib
import re

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

#: Enough to capture a stack's habitual ordering; past this it is mostly
#: per-response noise (caching, tracing, rate-limit counters).
_HEADER_ORDER_LIMIT = 32


def header_order_sha256(resp) -> str | None:
    """SHA-256 of the first 32 header names, lowercased and comma-joined.

    Reads the raw wire order rather than a dict: httpx's mapping view collapses
    repeated headers, and a collapsed `Set-Cookie` would silently change the
    hash for a site that sends two of them.
    """
    try:
        raw = getattr(resp.headers, "raw", None)
        if raw:
            names = [k.decode("latin-1", "replace") if isinstance(k, bytes) else str(k)
                     for k, _ in raw]
        else:
            names = [k for k, _ in resp.headers.items()]
    except Exception:  # noqa: BLE001
        return None
    if not names:
        return None
    joined = ",".join(n.lower() for n in names[:_HEADER_ORDER_LIMIT])
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


#: A favicon larger than this is not being used as an icon and is not worth
#: holding in memory to hash.
_FAVICON_MAX_BYTES = 1_048_576


def favicon_facts(http, origin: str) -> dict[str, object]:
    """SHA-256 and size of `{origin}/favicon.ico`, or nothing.

    Called **only after** the HTML fetch for that same origin succeeded, and
    aimed at that origin rather than the seed: if the seed redirected, the host
    that actually served the page is the one being fingerprinted. It never
    leads — an unreachable site gets no favicon request at all.

    An empty body is not hashed. Plenty of hosts answer 200 with zero bytes,
    and hashing that would collide every one of them onto one digest that looks
    like a match.
    """
    try:
        resp = http.get(f"{origin}/favicon.ico", follow_redirects=True)
        if resp.status_code != 200:
            return {}
        body = resp.content or b""
    except Exception:  # noqa: BLE001
        # The favicon is a bonus on top of a probe that already succeeded.
        # Failing to get it must never cost the caller the rest of the result.
        return {}
    if not body or len(body) > _FAVICON_MAX_BYTES:
        return {}
    return {
        "fp_favicon_sha256": hashlib.sha256(body).hexdigest(),
        "fp_favicon_bytes": len(body),
    }


class HttpProbeCollector(BaseCollector):
    name = "http_probe"
    timeout_s = 25
    inputs = {EntityType.DOMAIN, EntityType.URL}
    description = "HTTP(S) probe: status, headers, title, simple tech hints"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        if entity.type == EntityType.URL.value:
            urls = [entity.value]
            src_key = entity.norm_key
        else:
            host = entity.value
            urls = [f"https://{host}/", f"http://{host}/"]
            src_key = entity.norm_key

        last_err = None
        for url in urls:
            try:
                resp = ctx.http.get(url, follow_redirects=True)
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                continue

            final = str(resp.url)
            result.entities.append(EntityIn(type=EntityType.URL, value=final, confidence=0.9))
            result.edges.append(
                EdgeIn(
                    source_key=src_key,
                    target_key=entity_key(EntityType.URL, final),
                    rel=EdgeType.LINKED_FROM,
                    confidence=0.8,
                    props={"status": resp.status_code},
                )
            )
            if str(resp.url.host) and entity.type == EntityType.DOMAIN.value:
                # redirect host
                host2 = str(resp.url.host).lower()
                if host2 != entity.value:
                    result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host2, confidence=0.75))
                    result.edges.append(
                        EdgeIn(
                            source_key=src_key,
                            target_key=entity_key(EntityType.DOMAIN, host2),
                            rel=EdgeType.REDIRECTS_TO,
                            confidence=0.75,
                        )
                    )

            headers = {k.lower(): v for k, v in resp.headers.items()}
            techs: list[str] = []
            server = headers.get("server")
            if server:
                techs.append(server.split()[0])
            powered = headers.get("x-powered-by")
            if powered:
                techs.append(powered.split()[0])
            if "cf-ray" in headers or headers.get("server", "").lower() == "cloudflare":
                techs.append("cloudflare")

            body = ""
            try:
                body = resp.text[:200_000]
            except Exception:
                body = ""
            title = None
            m = _TITLE_RE.search(body or "")
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]

            for tech in techs:
                result.entities.append(
                    EntityIn(type=EntityType.TECHNOLOGY, value=tech, confidence=0.65)
                )
                result.edges.append(
                    EdgeIn(
                        source_key=src_key,
                        target_key=entity_key(EntityType.TECHNOLOGY, tech),
                        rel=EdgeType.USES_TECH,
                        confidence=0.65,
                    )
                )

            # Fingerprint props are added only when the server actually told
            # us something. An absent Server header is unknown, not "none".
            fp: dict[str, object] = {}
            order = header_order_sha256(resp)
            if order:
                fp["fp_header_order_sha256"] = order
            if server:
                fp["fp_server"] = server
            # Same origin as the HTML that just answered — not the seed, which
            # may have redirected elsewhere.
            origin = f"{resp.url.scheme}://{resp.url.netloc.decode()}" if isinstance(
                resp.url.netloc, bytes) else f"{resp.url.scheme}://{resp.url.netloc}"
            fp.update(favicon_facts(ctx.http, origin))

            result.entities.append(
                EntityIn(
                    type=EntityType(entity.type),
                    value=entity.value,
                    confidence=0.9,
                    props={
                        "http_status": resp.status_code,
                        "final_url": final,
                        "title": title,
                        "server": server,
                        **fp,
                    },
                )
            )
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="HTTP",
                    source_url=final,
                    summary=f"HTTP {resp.status_code} title={title!r} server={server!r}",
                    confidence=0.85,
                    raw={
                        "status": resp.status_code,
                        "headers": dict(list(headers.items())[:40]),
                        "title": title,
                    },
                    entity_key=src_key,
                )
            )
            return result

        if last_err:
            result.notes.append(f"http_probe failed: {last_err}")
        return result
