"""Known high-risk / high-signal on-chain services (mixers, bridges, …).

v0 ships an empty/default registry; C3 loads curated JSON (Tornado pools, etc.).
Interaction ≠ guilt — callers must treat hits as signals.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from umbra.crypto.normalize import detect_and_normalize
from umbra.crypto.types import ServiceDef, ServiceKind


logger = logging.getLogger(__name__)


class ServiceRegistry:
    def __init__(self, services: list[ServiceDef] | None = None) -> None:
        self._services: list[ServiceDef] = list(services or [])
        self._index: dict[str, list[ServiceDef]] = {}
        for svc in self._services:
            self._index_service(svc)

    def _index_service(self, svc: ServiceDef) -> None:
        for addr in svc.addresses:
            norm = detect_and_normalize(addr, chain_hint=svc.chain)
            key = norm.key if norm else f"{svc.chain}:{addr.lower()}"
            self._index.setdefault(key, []).append(svc)
            # Also index raw lower for EVM
            self._index.setdefault(f"{svc.chain}:{addr.lower()}", []).append(svc)

    def add(self, svc: ServiceDef) -> None:
        self._services.append(svc)
        self._index_service(svc)

    def match(self, chain: str, address: str) -> list[ServiceDef]:
        norm = detect_and_normalize(address, chain_hint=chain)
        keys = []
        if norm:
            keys.append(norm.key)
        keys.append(f"{chain}:{address}")
        keys.append(f"{chain}:{address.lower()}")
        found: list[ServiceDef] = []
        seen: set[int] = set()
        for k in keys:
            for svc in self._index.get(k, []):
                i = id(svc)
                if i not in seen:
                    seen.add(i)
                    found.append(svc)
        return found

    def all(self) -> list[ServiceDef]:
        return list(self._services)

    def addresses(self, chain: str) -> set[str]:
        """Every address on one chain — the head-follower's watch set.

        Mixer pools belong in it so an interaction is caught as it happens
        rather than discovered later by asking an explorer.
        """
        want = (chain or "").lower()
        return {addr.lower() for svc in self._services if svc.chain == want
                for addr in svc.addresses}


def addresses_of(registry: "ServiceRegistry", chain: str) -> list[str]:
    """Every address the registry knows on one chain, lowercased."""
    return registry.addresses(chain)


DEFAULT_DATA = Path(__file__).resolve().parent / "data" / "services.json"


def load_default_registry(path: Path | None = None) -> "ServiceRegistry":
    """The curated registry shipped with Umbra.

    Every entry in the file carries a `verification` block — the shipped
    Tornado Cash pools were checked with `eth_getCode` against a public node,
    and three of them share byte-identical bytecode, which is what one contract
    deployed at several denominations looks like. A candidate address that
    turned out to have no code at all was dropped rather than shipped: an
    address labelled "mixer" that is not one is a false accusation against
    whoever controls it.

    A missing or unreadable file yields an empty registry rather than an
    exception — screening degrades to "no service data", never to a crash.
    """
    target = path or DEFAULT_DATA
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - a missing registry is not fatal
        logger.warning("service registry unavailable (%s): %s", target, exc)
        return ServiceRegistry()

    services: list[ServiceDef] = []
    for entry in payload.get("services") or []:
        try:
            kind = ServiceKind(str(entry.get("kind", "other")).lower())
        except ValueError:
            kind = ServiceKind.OTHER
        addresses = tuple(str(a).strip().lower()
                          for a in (entry.get("addresses") or []) if str(a).strip())
        if not addresses:
            continue
        services.append(ServiceDef(
            name=str(entry.get("name") or "unnamed service"),
            kind=kind,
            chain=str(entry.get("chain") or "eth").lower(),
            addresses=addresses,
            tags=tuple(str(t) for t in (entry.get("tags") or [])),
            notes=str(entry.get("notes") or ""),
            url=entry.get("url"),
        ))
    return ServiceRegistry(services)
