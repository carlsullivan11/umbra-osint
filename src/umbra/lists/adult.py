"""Adult-content domain blocklist (parental / workplace DNS filter).

Built from free public filter projects (not Umbra scans). Domains only —
no page content is stored or served. Attribution in every feed header.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from umbra.core.config import Settings, get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lists import (
    BlocklistSnapshot,
    _is_blockable_domain,
    _normalize_host,
    render_adblock,
    render_domains,
    render_hosts,
)

logger = logging.getLogger("umbra.lists.adult")

# Fixed allowlist of upstream lists (MIT / public filter projects).
# check_url in GuardedClient still validates egress.
_SOURCES: tuple[tuple[str, str], ...] = (
    (
        "blocklistproject-porn",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
    ),
    (
        "stevenblack-porn",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    ),
)

_DISK_TTL_S = 24 * 3600
_MEM_TTL_S = 900.0
_MAX_BYTES = 40 * 1024 * 1024  # 40 MiB hard cap per source
_MAX_DOMAINS = 500_000

_mem: dict[str, tuple[float, BlocklistSnapshot]] = {}


def _cache_path(settings: Settings) -> Path:
    base = Path(getattr(settings, "cache_dir", None) or Path(settings.data_dir) / "cache")
    return base / "lists" / "adult-domains.json"


def _parse_body(text: str) -> set[str]:
    """Parse domain-list or hosts-file bodies into blockable domains."""
    out: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        # hosts: "0.0.0.0 domain" / "127.0.0.1 domain"
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):
            cand = parts[1]
        else:
            cand = parts[0]
        h = _normalize_host(cand)
        if h and _is_blockable_domain(h):
            out.add(h)
            if len(out) >= _MAX_DOMAINS:
                break
    return out


def _fetch_sources(settings: Settings) -> tuple[set[str], list[str]]:
    domains: set[str] = set()
    used: list[str] = []
    headers = {"User-Agent": settings.user_agent}
    with GuardedClient(headers=headers, timeout=min(60.0, settings.request_timeout_s * 3)) as http:
        for name, url in _SOURCES:
            try:
                resp = http.get(url, follow_redirects=True)
                resp.raise_for_status()
                raw = resp.content
                if len(raw) > _MAX_BYTES:
                    logger.warning("adult list %s too large (%s bytes)", name, len(raw))
                    continue
                text = raw.decode("utf-8", "replace")
                got = _parse_body(text)
                if got:
                    domains |= got
                    used.append(name)
                    logger.info("adult list %s: +%s domains", name, len(got))
            except Exception as exc:  # noqa: BLE001 - one source down is OK
                logger.warning("adult list %s failed: %s", name, exc)
    return domains, used


def _load_disk(path: Path) -> BlocklistSnapshot | None:
    if not path.is_file():
        return None
    age = time.time() - path.stat().st_mtime
    if age > _DISK_TTL_S:
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        domains = tuple(data.get("domains") or ())
        sources = tuple(data.get("sources") or ())
        generated = data.get("generated_at") or ""
        if not domains:
            return None
        return BlocklistSnapshot(
            domains=domains,
            ips=(),
            generated_at=generated,
            sources=sources,
        )
    except Exception:  # noqa: BLE001
        return None


def _save_disk(path: Path, snap: BlocklistSnapshot) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "generated_at": snap.generated_at,
                    "sources": list(snap.sources),
                    "domains": list(snap.domains),
                }
            ),
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("adult list disk cache write failed: %s", exc)


def snapshot_adult(
    settings: Settings | None = None,
    *,
    force: bool = False,
) -> BlocklistSnapshot:
    """Return adult domain snapshot (memory → disk → fetch)."""
    settings = settings or get_settings()
    now = time.monotonic()
    if not force and "adult" in _mem:
        ts, val = _mem["adult"]
        if now - ts < _MEM_TTL_S:
            return val

    path = _cache_path(settings)
    if not force:
        disk = _load_disk(path)
        if disk is not None:
            _mem["adult"] = (now, disk)
            return disk

    domains, used = _fetch_sources(settings)
    if not domains:
        # Stale disk better than empty
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                snap = BlocklistSnapshot(
                    domains=tuple(data.get("domains") or ()),
                    ips=(),
                    generated_at=str(data.get("generated_at") or "stale"),
                    sources=tuple(data.get("sources") or ("stale-cache",)),
                )
                if snap.domains:
                    _mem["adult"] = (now, snap)
                    return snap
            except Exception:  # noqa: BLE001
                pass
        return BlocklistSnapshot(
            domains=(),
            ips=(),
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            sources=("unavailable",),
        )

    snap = BlocklistSnapshot(
        domains=tuple(sorted(domains)),
        ips=(),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        sources=tuple(used) or ("adult-filter",),
    )
    _save_disk(path, snap)
    _mem["adult"] = (now, snap)
    return snap


def render_adult_domains(snap: BlocklistSnapshot) -> str:
    # Reuse malware renderers with swapped header via thin wrappers
    body = "\n".join(snap.domains)
    header = (
        f"# Umbra adult-content domain blocklist\n"
        f"# Generated: {snap.generated_at}\n"
        f"# Sources: {', '.join(snap.sources)}\n"
        f"# Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"# Format: one domain per line (Pi-hole / AdGuard Home adlist)\n"
        f"# Count: {len(snap.domains)}\n"
        f"# Purpose: parental control / workplace filter — optional second list\n"
        f"# License: upstream filter projects; Umbra packaging MIT\n"
        f"# Note: false positives possible; whitelist locally when needed\n"
        f"#\n"
    )
    return header + body + ("\n" if body else "")


def render_adult_hosts(snap: BlocklistSnapshot) -> str:
    header = (
        f"# Umbra adult-content hosts file\n"
        f"# Generated: {snap.generated_at}\n"
        f"# Sources: {', '.join(snap.sources)}\n"
        f"# Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"# Format: 0.0.0.0 domain\n"
        f"# Count: {len(snap.domains)}\n"
        f"#\n"
    )
    body = "\n".join(f"0.0.0.0 {d}" for d in snap.domains)
    return header + body + ("\n" if body else "")


def render_adult_adblock(snap: BlocklistSnapshot) -> str:
    header = (
        f"! Title: Umbra adult-content domains\n"
        f"! Generated: {snap.generated_at}\n"
        f"! Homepage: https://umbra-osint.com/wiki/p/tool/dns-blocklist\n"
        f"! Expires: 1 day\n"
        f"! Count: {len(snap.domains)}\n"
    )
    body = "\n".join(f"||{d}^" for d in snap.domains)
    return header + body + ("\n" if body else "")
