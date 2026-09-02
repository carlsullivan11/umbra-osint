"""Durable label lake — the C1 backing for `umbra.crypto.labels`.

Thin layer over `LakeStore` so the crypto labels live beside the CT corpus, the
OUI table and the abuse.ch feeds: reference data Umbra owns and queries with no
external API at screening time.

The one rule worth stating twice: **a sync is a reconciliation, not an append.**
OFAC removes entries, and an address Umbra keeps labelling `sanctioned_ofac`
after removal is a false accusation of sanctions evasion. Anything absent from
the new snapshot is delisted with a date; nothing is deleted, because "this was
sanctioned until March" is true, useful, and unsayable from an append-only
cache.
"""
from __future__ import annotations

import logging
from typing import Iterable

from umbra.crypto.types import Label

logger = logging.getLogger(__name__)


def _as_row(label: Label) -> dict:
    return {
        "chain": label.address.chain,
        "address": label.address.address,
        "tag": label.tag.value if hasattr(label.tag, "value") else str(label.tag),
        "confidence": label.confidence,
        "summary": label.summary,
        "url": label.url,
        "props": dict(label.props or {}),
    }


def replace_source(store, source: str, labels: Iterable[Label], *,
                   allow_empty: bool = False) -> dict:
    """Reconcile one source's labels against a full snapshot.

    `allow_empty=False` is the default and refuses to treat an empty snapshot as
    "everything was delisted". A fetch that came back empty because the server
    erred looks identical to a genuine mass delisting, and only one of those
    should silently clear the sanctions labels off every address.
    """
    rows = [_as_row(label) for label in labels]
    if not rows and not allow_empty:
        logger.warning(
            "refusing to reconcile %s against an empty snapshot; pass "
            "allow_empty=True if the source really is empty", source)
        return {"added": 0, "refreshed": 0, "delisted": 0, "active": 0,
                "skipped": "empty snapshot"}
    return store.crypto_replace_source(source, rows)


def screen(store, chain: str, address: str) -> dict:
    """Everything the lake knows about one address, ready to render.

    `checked` distinguishes "no labels for this address" from "no labels
    anywhere yet". An unsynced lake answering "clean" would be the same failure
    the DNSBL, crt.sh and KEV paths are built to avoid.
    """
    from umbra.crypto.services import load_default_registry

    stats = store.crypto_label_stats()
    labels = store.crypto_labels(chain, address)
    history = store.crypto_labels(chain, address, include_delisted=True)
    former = [lab for lab in history if not lab["active"]]

    # Is the address itself a known service? Distinct from "interacted with
    # one" — a mixer pool is not a suspect, it is infrastructure.
    services = [
        {"name": svc.name, "kind": svc.kind.value, "tags": list(svc.tags),
         "notes": svc.notes, "url": svc.url}
        for svc in load_default_registry().match(chain, address)
    ]

    return {
        "chain": chain,
        "address": address,
        "checked": stats["active"] > 0,
        "labels": labels,
        "former_labels": former,
        "services": services,
        "sanctioned": any(lab["tag"] == "sanctioned_ofac" for lab in labels),
        "indexed": stats,
    }


def service_touches(chain: str, counterparties: list[str]) -> dict[str, list[dict]]:
    """Which counterparties are known services, keyed by address.

    Interaction is a **signal**, never a finding: people use privacy tools for
    private reasons, and Tornado Cash is not currently OFAC-listed. Umbra
    records the touch and its provenance; a human decides what it means.
    """
    from umbra.crypto.services import load_default_registry

    registry = load_default_registry()
    out: dict[str, list[dict]] = {}
    for address in counterparties:
        hits = registry.match(chain, address)
        if hits:
            out[address.lower()] = [
                {"name": h.name, "kind": h.kind.value, "url": h.url}
                for h in hits
            ]
    return out
