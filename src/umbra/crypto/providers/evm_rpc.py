"""EVM transfers from raw JSON-RPC — no Etherscan, no key.

Measured against free public RPC (`ethereum-rpc.publicnode.com`) before this was
designed, because the constraints decide the shape:

| | |
|--|--|
| `eth_getLogs` without a contract `address` | refused |
| `eth_getLogs` beyond ~64–128 blocks | "archive requests require a personal token" |
| USDT `Transfer` logs in a single block | ~182 |

So free RPC gives roughly **fifteen minutes of history**. No amount of cleverness
turns that into Etherscan's archive, and pretending otherwise would be the worst
outcome — a screen that looks complete and is not.

What it *is* good for is following the head of the chain. `umbra.crypto.tail`
uses this to keep a **targeted** index: Transfer logs are pulled block by block
and only those touching an address Umbra already cares about are stored. That
inverts the trade in Umbra's favour —

- no key, no rate limit, no third party;
- **nobody learns which addresses you are investigating**, which querying an
  explorer necessarily reveals;
- history accumulates going forward and is owned, the same tail-forward bargain
  the CT corpus already makes;
- and it can answer "tell me when any of these 961 sanctioned addresses moves",
  which an explorer API cannot be asked at all.

Indexing *everything* is deliberately not attempted: USDT alone is ~1.3M
transfers a day, which is ~47 GB a year for one token against a stated budget of
5 GB a year for all crypto data.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Free, key-free, and the only one of five probed that answered cleanly.
DEFAULT_ENDPOINTS = ("https://ethereum-rpc.publicnode.com",)

# keccak256("Transfer(address,address,uint256)")
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

# The contracts worth following first: the dominant cash-out rails per
# docs/CRYPTO-EXPLORATION.md.
DEFAULT_TOKENS = {
    "0xdac17f958d2ee523a2206206994597c13d831ec7": ("USDT", 6),
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": ("USDC", 6),
}

# Free endpoints refuse archive reads past roughly this depth.
FREE_WINDOW_BLOCKS = 64


@dataclass
class RpcResult:
    ok: bool
    value: object = None
    error: str = ""


class EvmRpc:
    """A small JSON-RPC client. Deliberately not a web3 dependency."""

    def __init__(self, http, endpoints: tuple[str, ...] = DEFAULT_ENDPOINTS):
        self.http = http
        self.endpoints = tuple(endpoints)
        self._id = 0

    def call(self, method: str, params: list) -> RpcResult:
        self._id += 1
        body = {"jsonrpc": "2.0", "id": self._id, "method": method,
                "params": params}
        last = ""
        for endpoint in self.endpoints:
            try:
                resp = self.http.post(endpoint, json=body)
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001 - try the next endpoint
                last = f"{type(exc).__name__}: {exc}"
                continue
            if isinstance(payload, dict) and payload.get("error"):
                # An RPC-level refusal (archive token, bad filter) is not a
                # transport failure and trying another endpoint rarely helps.
                return RpcResult(False, None, str(payload["error"])[:200])
            return RpcResult(True, (payload or {}).get("result"))
        return RpcResult(False, None, last or "no endpoint answered")

    def block_number(self) -> int | None:
        result = self.call("eth_blockNumber", [])
        if not result.ok or not isinstance(result.value, str):
            return None
        try:
            return int(result.value, 16)
        except ValueError:
            return None

    def transfer_logs(self, contract: str, from_block: int,
                      to_block: int) -> RpcResult:
        """Transfer logs for one contract over a block range.

        A contract address is mandatory: free endpoints refuse an unscoped topic
        filter outright, and scanning every contract would be the wrong shape
        anyway.
        """
        return self.call("eth_getLogs", [{
            "address": contract,
            "fromBlock": hex(from_block),
            "toBlock": hex(to_block),
            "topics": [TRANSFER_TOPIC],
        }])


def _addr_from_topic(topic: str) -> str:
    """A 32-byte topic carries a 20-byte address in its low bits."""
    raw = (topic or "").lower().replace("0x", "")
    return "0x" + raw[-40:] if len(raw) >= 40 else ""


def decode_transfer(log: dict, tokens: dict | None = None) -> dict | None:
    """One `Transfer` log into a flat record, or None if it is not one."""
    topics = log.get("topics") or []
    # Exactly three: the event signature plus two indexed addresses. ERC-721
    # shares the signature but indexes a third topic (the token id), and
    # decoding one as a fungible amount would invent a transfer that never
    # happened.
    if len(topics) != 3 or (topics[0] or "").lower() != TRANSFER_TOPIC:
        return None
    contract = str(log.get("address") or "").lower()
    symbol, decimals = (tokens or DEFAULT_TOKENS).get(contract, ("", 0))
    try:
        amount = int(str(log.get("data") or "0x0"), 16)
    except ValueError:
        amount = 0
    try:
        block = int(str(log.get("blockNumber") or "0x0"), 16)
    except ValueError:
        block = 0
    return {
        "chain": "eth",
        "txid": str(log.get("transactionHash") or ""),
        "from_addr": _addr_from_topic(topics[1]),
        "to_addr": _addr_from_topic(topics[2]),
        "contract": contract,
        "asset": symbol or contract,
        "amount_raw": amount,
        "decimals": decimals,
        "block_number": block,
        "log_index": int(str(log.get("logIndex") or "0x0"), 16)
        if str(log.get("logIndex") or "").startswith("0x") else 0,
    }


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)
