"""SSRF guard for collector egress.

`POST /run` is public, so an anonymous visitor chooses which URLs this server
fetches — and the worker sits on the Docker bridge, one hop from `postgres:5432`
and `redis:6379`, with link-local metadata reachable on any cloud host. Without
this, "scan this domain" is a request to fetch anything the server can reach,
with the response stored as evidence.

The guard judges the **resolved IP**, not the name: `internal.attacker.com A
127.0.0.1` is a five-minute DNS record, and the name tells you nothing. Every
answer in the record set must be public, because the client may connect to any
of them, and every redirect hop is re-checked, because a public URL that 302s to
`169.254.169.254` is the same attack with one more step.

**Residual risk, stated plainly:** the validated address is not pinned through to
the socket, so a DNS entry that changes between check and connect (classic
rebinding) is not fully closed. Blocking the ranges and validating every hop
removes the practical attack; pinning the connection is the follow-up.

Resolution goes through `umbra.core.dns`, which never fails over to a public
resolver — the same discipline the DNSBL path requires.
"""
from __future__ import annotations

import ipaddress
import logging
import os
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 3


class BlockedAddress(Exception):
    """The request was refused before any packet left the box."""


def allow_private_egress() -> bool:
    """Escape hatch for a local lab. Off unless deliberately set."""
    return os.environ.get("UMBRA_ALLOW_PRIVATE_EGRESS", "").lower() in ("1", "true", "yes")


def is_public_ip(addr: str) -> bool:
    """Public unicast only.

    `is_global` alone is not enough — it lets through some reserved space — so
    the disqualifying categories are named explicitly.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified):
        return False
    return bool(ip.is_global)


def resolve_all(host: str) -> list[str]:
    """Every A/AAAA answer for a host, via the project resolver.

    A literal IP resolves to itself. An empty list means nothing was validated,
    and the caller fails closed.
    """
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass

    out: list[str] = []
    try:
        from umbra.core.dns import get_resolver

        resolver = get_resolver()
        for rtype in ("A", "AAAA"):
            try:
                out.extend(str(r).strip() for r in resolver.resolve(host, rtype))
            except Exception:  # noqa: BLE001 - no answer of this type
                continue
    except Exception:  # noqa: BLE001 - resolver unavailable
        logger.warning("SSRF guard could not resolve %s", host)
        return []
    return [a for a in out if a]


def check_url(url: str) -> None:
    """Raise `BlockedAddress` unless this URL is safe to fetch."""
    parts = urlsplit(str(url))

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedAddress(f"scheme not allowed: {parts.scheme or '(none)'}")
    if parts.username or parts.password:
        raise BlockedAddress("credentials in URL are not allowed")

    host = (parts.hostname or "").strip()
    if not host:
        raise BlockedAddress("no host in URL")

    if allow_private_egress():
        return

    addrs = resolve_all(host)
    if not addrs:
        # Fail closed: nothing resolved means nothing was checked.
        raise BlockedAddress(f"{host} did not resolve; refusing to connect")

    for addr in addrs:
        if not is_public_ip(addr):
            raise BlockedAddress(f"{host} resolves to non-public address {addr}")


class GuardedClient(httpx.Client):
    """An `httpx.Client` that validates before connecting, on every hop.

    Redirects are followed manually so each `Location` is re-validated. Passing
    `follow_redirects=True` to a normal client would hand redirect handling to
    httpx, where the guard never sees hop two — which is the bypass.
    """

    def __init__(self, *args, max_redirects: int = MAX_REDIRECTS, **kwargs):
        kwargs["follow_redirects"] = False
        super().__init__(*args, **kwargs)
        self._max_redirects = max_redirects

    def request(self, method: str, url, *args, **kwargs):  # type: ignore[override]
        follow = bool(kwargs.pop("follow_redirects", False))
        current = str(url)
        for hop in range(self._max_redirects + 1):
            check_url(current)
            response = super().request(method, current, *args, **kwargs)
            if not (follow and response.is_redirect):
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = str(response.next_request.url if response.next_request
                          else httpx.URL(current).join(location))
            # A redirect chain that changes method (303) is still followed as a
            # GET by httpx semantics; keep it simple and mirror that.
            if response.status_code == 303:
                method = "GET"
                kwargs.pop("content", None)
                kwargs.pop("data", None)
                kwargs.pop("json", None)
        raise httpx.TooManyRedirects(
            f"exceeded {self._max_redirects} redirects", request=response.request
        )
