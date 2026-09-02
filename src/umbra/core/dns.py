"""DNS resolution helpers with a correct, DNSBL-aware resolver.

Two distinct needs, deliberately separated:

- **General resolution** (`resolve_a_record`, ASN/TXT lookups): a configured
  primary resolver with a public `1.1.1.1` failover is fine — public resolvers
  answer ordinary A/TXT queries correctly.

- **DNSBL lookups** (`dnsbl_lookup`, Spamhaus zen/dbl): public resolvers like
  1.1.1.1 / 8.8.8.8 are **refused** by Spamhaus and answer every query with a
  `127.255.255.x` error code. So DNSBL queries must go through a *local
  recursive* resolver and must **never** fall back to a public one — and the
  return codes must be classified (a `127.255.255.x` error is NOT a listing).

This module fixes three real bugs in the prior implementation: a bare hostname
("unbound") assigned to `resolver.nameservers` (dnspython requires IPs), a
public `1.1.1.1` failover that made Spamhaus mark every IP as listed, and
silent failure to an empty/"clean" result.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from umbra.core.config import get_settings

logger = logging.getLogger(__name__)

FAILOVER_DNS = "1.1.1.1"

# Well-known public recursive resolvers. DNSBLs (Spamhaus et al.) refuse queries
# arriving via these and answer 127.255.255.x for *everything*, so a DNSBL
# lookup that egresses through one produces false positives on every address.
# They must never be used for blocklist queries — including via the system
# resolver fallback, which inside a Docker container is typically exactly these
# (Docker's default /etc/resolv.conf on this host lists 1.1.1.1 and 8.8.4.4).
PUBLIC_RESOLVERS = frozenset({
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "8.8.8.8", "8.8.4.4",              # Google
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "64.6.64.6", "64.6.65.6",          # Verisign
    "77.88.8.8", "77.88.8.1",          # Yandex
    "4.2.2.1", "4.2.2.2",              # Level3
})


def _to_ip(host_or_ip: str) -> str | None:
    """Return an IP string for a resolver spec, resolving a hostname if needed.

    dnspython's `resolver.nameservers` requires IP addresses — a bare hostname
    like "unbound" raises ValueError. We resolve it to an IP here (e.g. the
    Docker service name → its container IP) and return None if it can't be
    resolved, so a bad spec is skipped rather than crashing every lookup.
    """
    s = (host_or_ip or "").strip()
    if not s:
        return None
    try:
        ipaddress.ip_address(s)
        return s  # already an IP
    except ValueError:
        pass
    try:
        return socket.gethostbyname(s)
    except OSError as exc:
        logger.warning("DNS primary %r could not be resolved to an IP: %s", s, exc)
        return None


def get_resolver(allow_public_failover: bool = True) -> dns.resolver.Resolver:
    """Build a resolver from settings.

    - Primary: `settings.dns_resolver` (IP, or hostname resolved to IP).
    - Public failover (`1.1.1.1`): appended only when `allow_public_failover`
      is True. DNSBL callers pass False — there is no valid public fallback for
      a blocklist query.
    - When `allow_public_failover` is False, public resolvers are stripped from
      the **system** fallback too. Inside a container the system resolvers are
      usually 1.1.1.1/8.8.4.4, so silently inheriting them would send DNSBL
      queries through a public resolver — the precise failure this split
      exists to prevent. If nothing safe remains the nameserver list is left
      empty, and `dnsbl_lookup` reports an actionable error instead of
      guessing (never "clean", never "listed").
    """
    resolver = dns.resolver.Resolver()  # seeded from system config
    nameservers: list[str] = []

    primary = get_settings().primary_dns
    if primary:
        ip = _to_ip(primary)
        if ip:
            nameservers.append(ip)

    if allow_public_failover and FAILOVER_DNS not in nameservers:
        nameservers.append(FAILOVER_DNS)

    if nameservers:
        resolver.nameservers = nameservers  # all guaranteed to be IPs
    elif not allow_public_failover:
        safe = [ns for ns in list(resolver.nameservers) if str(ns) not in PUBLIC_RESOLVERS]
        if not safe:
            logger.warning(
                "no local recursive resolver for DNSBL: system resolvers %s are public. "
                "Set UMBRA_DNS_RESOLVER to a local recursive resolver (see docs/DNS-SERVICE.md)",
                list(resolver.nameservers),
            )
        resolver.nameservers = safe
    # else: ordinary queries may keep system defaults

    resolver.timeout = 4.0
    resolver.lifetime = 12.0
    logger.debug("DNS resolver nameservers=%s (public_failover=%s)",
                 nameservers or resolver.nameservers, allow_public_failover)
    return resolver


def resolve_a_record(domain: str) -> list[str]:
    """Resolve A records for ordinary DNS (public failover allowed)."""
    resolver = get_resolver(allow_public_failover=True)
    try:
        return [str(r) for r in resolver.resolve(domain, "A")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as exc:
        logger.debug("A lookup failed for %s: %s", domain, exc)
        return []


# --- DNSBL (blocklist) queries -------------------------------------------

@dataclass
class DnsblResult:
    """Classified result of a DNSBL query.

    status:
      - "listed"     → a real listing (127.0.0.x / 127.0.1.x below .255)
      - "not_listed" → NXDOMAIN / no answer (the address is not on the list)
      - "error"      → the query could not be answered authoritatively
                       (127.255.255.x refusal — e.g. public resolver used —
                       or a resolver/timeout error). NEVER treat as a listing
                       and NEVER treat as clean.
    """
    status: str
    codes: list[str] = field(default_factory=list)
    detail: str = ""


def classify_dnsbl_codes(codes: list[str]) -> DnsblResult:
    """Interpret DNSBL A-record return codes.

    `127.255.255.x` is Spamhaus's error/refused range (e.g. .254 = query via a
    public/open resolver, .252 = prohibited, .255 = blocked/over-limit). DBL's
    `127.0.1.255` is likewise a typing-error/misuse signal. Everything else in
    127.0.0.0/8 is a genuine listing.
    """
    if not codes:
        return DnsblResult("not_listed", [], "not listed")
    listed: list[str] = []
    errors: list[str] = []
    for c in codes:
        if c.startswith("127.255.255.") or c == "127.0.1.255":
            errors.append(c)
        elif c.startswith("127."):
            listed.append(c)
        else:  # anything outside 127/8 is unexpected for a DNSBL
            errors.append(c)
    if listed:
        return DnsblResult("listed", listed, f"listed ({', '.join(listed)})")
    return DnsblResult(
        "error", errors,
        "blocklist query refused/blocked — likely a public resolver; "
        "configure UMBRA_DNS_RESOLVER to a local recursive resolver "
        f"({', '.join(errors)})",
    )


def dnsbl_lookup(query_name: str, timeout: float = 8.0) -> DnsblResult:
    """Query a DNSBL zone through the local resolver (no public failover).

    Distinguishes not-listed (NXDOMAIN) from error (resolver failure / refusal)
    so a failed check is never silently reported as clean or as a hit.
    """
    resolver = get_resolver(allow_public_failover=False)
    if not resolver.nameservers:
        # Refusing to query is correct: going out via a public resolver would
        # return 127.255.255.x for every address and read as "listed".
        return DnsblResult(
            "error", [],
            "no local recursive resolver available for DNSBL "
            "(system resolvers are public) — set UMBRA_DNS_RESOLVER; see docs/DNS-SERVICE.md",
        )
    resolver.lifetime = min(8.0, timeout)
    resolver.timeout = min(4.0, timeout)
    try:
        codes = [r.to_text() for r in resolver.resolve(query_name, "A")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return DnsblResult("not_listed", [], "not listed")
    except dns.exception.DNSException as exc:
        return DnsblResult("error", [], f"resolver error: {exc}")
    return classify_dnsbl_codes(codes)
