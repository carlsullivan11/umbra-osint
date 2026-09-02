"""Targeted transfer index — the part that is actually better than an explorer.

Free RPC gives ~15 minutes of Ethereum history, so Umbra cannot out-archive
Etherscan and should not pretend to. What it can do is follow the head of the
chain continuously and keep the transfers that touch addresses it already cares
about — the OFAC label set, case addresses, anything on the watch list.

That inverts the trade:

- **Nobody learns what you are investigating.** Every Etherscan lookup tells
  Etherscan which address you are interested in. This tells nobody.
- **It answers a question an explorer API cannot be asked**: "tell me when any
  of these 961 sanctioned addresses moves funds."
- **The history is owned** and accumulates going forward — the same
  tail-forward bargain the CT corpus already makes, and honest about being
  tail-forward rather than complete.

Indexing everything is deliberately not attempted: USDT alone is ~1.3M transfers
a day, ~47 GB a year for one token, against a 5 GB/year budget for all crypto
data. Targeting is what makes the numbers work — and it is also what makes the
index useful rather than a worse copy of a public database.
"""
from __future__ import annotations

import logging

from umbra.crypto.providers.evm_rpc import (
    DEFAULT_TOKENS,
    FREE_WINDOW_BLOCKS,
    decode_transfer,
)

logger = logging.getLogger(__name__)

# One tick should stay well inside the free window, or every call is refused.
DEFAULT_BLOCKS_PER_TICK = 24


def watch_set(store) -> set[str]:
    """Addresses worth keeping transfers for: every active EVM label.

    Lowercased, because EVM addresses are stored lowercased for lookup and a
    checksummed comparison would silently match nothing.
    """
    from umbra.crypto.services import load_default_registry

    out: set[str] = set()
    for chain in ("eth", "bsc"):
        for row in store.crypto_labelled_addresses(chain):
            out.add(row.lower())
    # Mixer and bridge contracts belong in the watch set: a deposit into one is
    # exactly the event worth catching as it happens, rather than discovering
    # later by asking an explorer — which would also tell the explorer what we
    # are looking for.
    registry = load_default_registry()
    for chain in ("eth", "bsc"):
        out |= registry.addresses(chain)
    return out


def tick(store, rpc, *, blocks: int = DEFAULT_BLOCKS_PER_TICK,
         tokens: dict | None = None, watch: set[str] | None = None,
         repo=None) -> dict:
    """Pull one window of Transfer logs and keep the ones that matter.

    Returns counts rather than raising: a public RPC endpoint refusing a range
    is a normal Tuesday, not an incident.
    """
    tokens = tokens or DEFAULT_TOKENS
    stats = {"blocks": 0, "logs": 0, "kept": 0, "stored": 0, "errors": 0,
             "alerted": 0, "head": None, "note": ""}

    head = rpc.block_number()
    if head is None:
        stats["errors"] += 1
        stats["note"] = "no endpoint answered eth_blockNumber"
        return stats
    stats["head"] = head

    span = max(1, min(blocks, FREE_WINDOW_BLOCKS))
    start = store.crypto_tail_checkpoint("eth")
    from_block = max(head - span + 1, (start + 1) if start else head - span + 1)
    # Never reach past the free window: those calls are refused outright, and a
    # gap is more honest than a retry storm.
    from_block = max(from_block, head - FREE_WINDOW_BLOCKS + 1)
    if from_block > head:
        stats["note"] = "already at head"
        return stats

    watching = watch if watch is not None else watch_set(store)
    stats["blocks"] = head - from_block + 1

    for contract in tokens:
        result = rpc.transfer_logs(contract, from_block, head)
        if not result.ok:
            stats["errors"] += 1
            stats["note"] = result.error
            continue
        logs = result.value if isinstance(result.value, list) else []
        stats["logs"] += len(logs)
        rows = []
        for log in logs:
            record = decode_transfer(log, tokens)
            if record is None:
                continue
            # The whole point: keep only what touches something we care about.
            if watching and not (record["from_addr"] in watching
                                 or record["to_addr"] in watching):
                continue
            rows.append(record)
        stats["kept"] += len(rows)
        added = store.crypto_store_transfers(rows)
        stats["stored"] += added
        if added and repo is not None:
            # Alert only on what was newly stored: the published window overlaps
            # every tick, and re-alerting a replayed transfer is how a channel
            # gets muted.
            from umbra.crypto import alerts

            fresh = rows[-added:] if added <= len(rows) else rows
            stats["alerted"] += alerts.raise_for_transfers(repo, store, fresh)

    if stats["errors"] == 0:
        store.crypto_set_tail_checkpoint("eth", head)
    return stats
