"""Public DNS blocklists derived from Umbra's owned abuse.ch lake.

Formats aimed at Pi-hole, AdGuard Home, dnsmasq, and plain hosts files.
Sources are **already-mirrored** public CTI (URLhaus / ThreatFox / Feodo) —
not Umbra active scans. Attribution required downstream.
"""
from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass

from umbra.core.config import Settings, get_settings
from umbra.lake.store import LakeStore

# Domains only — labels of 1–63 chars, multi-label.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)

# Never ship these into a public blocklist even if they appear in a feed.
_DENY_EXACT = frozenset({
    "localhost",
    "local",
    "localdomain",
    "invalid",
    "example",
    "example.com",
    "example.net",
    "example.org",
    "test",
})
_DENY_SUFFIX = (
    ".local",
    ".localhost",
    ".invalid",
    ".example",
    ".test",
    ".arpa",
)

_CACHE_TTL_S = 900.0  # 15 minutes
_cache: dict[str, tuple[float, object]] = {}


@dataclass(frozen=True)
class BlocklistSnapshot:
    domains: tuple[str, ...]
    ips: tuple[str, ...]
    generated_at: str
    sources: tuple[str, ...]


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return False
    if ip.is_reserved or ip.is_unspecified:
        return False
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def _normalize_host(raw: str | None) -> str | None:
    h = (raw or "").strip().lower().rstrip(".")
    if not h:
        return None
    # strip scheme leftovers
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    h = h.split("?", 1)[0]
    # IPv4 with port
    if h.count(":") == 1 and "." in h:
        host, _, port = h.partition(":")
        if port.isdigit():
            h = host
    # bracketed IPv6
    if h.startswith("[") and "]" in h:
        h = h[1:h.index("]")]
    return h or None


def _is_blockable_domain(host: str) -> bool:
    if host in _DENY_EXACT:
        return False
    if any(host.endswith(s) for s in _DENY_SUFFIX):
        return False
    if host.startswith("*."):
        host = host[2:]
    if not _DOMAIN_RE.match(host):
        return False
    # single-label public suffix alone is too broad
    if host.count(".") < 1:
        return False
    return True


def collect_from_store(store: LakeStore, *, max_hosts: int = 50_000) -> BlocklistSnapshot:
    """Pull distinct hosts from the abuse lake and split domains vs IPs."""
    from datetime import datetime, timezone

    domains: set[str] = set()
    ips: set[str] = set()

    # Prefer dedicated helper when present; fall back to broad host scan.
    try:
        raw_hosts = store.abuse_all_hosts(limit=max_hosts * 2)
    except AttributeError:
        raw_hosts = list(store.abuse_distinct_ip_hosts(limit=max_hosts))
        # domain-ish: also sample urlhaus hosts via ioc path if available
        try:
            raw_hosts.extend(store.abuse_distinct_domain_hosts(limit=max_hosts))
        except AttributeError:
            pass

    for raw in raw_hosts:
        h = _normalize_host(raw)
        if not h:
            continue
        try:
            ipaddress.ip_address(h)
            if _is_public_ip(h):
                ips.add(h)
            continue
        except ValueError:
            pass
        if _is_blockable_domain(h):
            domains.add(h)
        if len(domains) + len(ips) >= max_hosts:
            break

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return BlocklistSnapshot(
        domains=tuple(sorted(domains)),
        ips=tuple(sorted(ips, key=lambda s: (":" in s, s))),
        generated_at=now,
        sources=("urlhaus", "threatfox", "feodo"),
    )


def snapshot(settings: Settings | None = None, *, force: bool = False) -> BlocklistSnapshot:
    key = "snap"
    now = time.monotonic()
    if not force and key in _cache:
        ts, val = _cache[key]
        if now - ts < _CACHE_TTL_S and isinstance(val, BlocklistSnapshot):
            return val
    settings = settings or get_settings()
    store = LakeStore.from_settings(settings)
    snap = collect_from_store(store)
    _cache[key] = (now, snap)
    return snap


def render_domains(snap: BlocklistSnapshot) -> str:
    header = (
        f"# Umbra malware domain blocklist\n"
        f"# Generated: {snap.generated_at}\n"
        f"# Sources: abuse.ch ({', '.join(snap.sources)}) via Umbra owned lake\n"
        f"# Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"# Format: one domain per line (Pi-hole / AdGuard Home adlist)\n"
        f"# Count: {len(snap.domains)}\n"
        f"# License: feed content inherits upstream abuse.ch terms; Umbra packaging MIT\n"
        f"#\n"
    )
    return header + "\n".join(snap.domains) + ("\n" if snap.domains else "")


def render_hosts(snap: BlocklistSnapshot) -> str:
    header = (
        f"# Umbra malware hosts file\n"
        f"# Generated: {snap.generated_at}\n"
        f"# Sources: abuse.ch ({', '.join(snap.sources)}) via Umbra owned lake\n"
        f"# Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"# Format: 0.0.0.0 domain (hosts / dnsmasq-compatible)\n"
        f"# Count: {len(snap.domains)}\n"
        f"#\n"
    )
    body = "\n".join(f"0.0.0.0 {d}" for d in snap.domains)
    return header + body + ("\n" if body else "")


def render_ips(snap: BlocklistSnapshot) -> str:
    header = (
        f"# Umbra malware IP list (C2 / infra indicators)\n"
        f"# Generated: {snap.generated_at}\n"
        f"# Sources: abuse.ch ({', '.join(snap.sources)}) via Umbra owned lake\n"
        f"# Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"# Format: one IP per line (use with firewall / IP blocking — not pure DNS)\n"
        f"# Count: {len(snap.ips)}\n"
        f"#\n"
    )
    return header + "\n".join(snap.ips) + ("\n" if snap.ips else "")


def render_adblock(snap: BlocklistSnapshot) -> str:
    header = (
        f"! Title: Umbra malware domains\n"
        f"! Generated: {snap.generated_at}\n"
        f"! Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"! Expires: 1 day\n"
        f"! Count: {len(snap.domains)}\n"
    )
    body = "\n".join(f"||{d}^" for d in snap.domains)
    return header + body + ("\n" if body else "")
