"""Detect and normalize crypto addresses for screening keys.

Conservative: unknown formats return None rather than guessing a chain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Ethereum-style (ETH, BSC, many EVM L2s) — 0x + 40 hex
_EVM_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Tron base58check typically starts with T and is 34 chars
_TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
# Bitcoin bech32
_BTC_BECH32_RE = re.compile(r"^(bc1|tb1)[0-9a-z]{6,87}$", re.IGNORECASE)
# Bitcoin legacy / p2sh base58 (very rough length gate)
_BTC_BASE58_RE = re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")
# Solana base58 pubkeys are 32–44 chars; overlap with others — require explicit chain hint
_SOL_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


@dataclass(frozen=True, slots=True)
class NormalizedAddress:
    chain: str
    address: str
    original: str

    @property
    def key(self) -> str:
        return f"{self.chain}:{self.address}"


def _evm_checksum_optional(addr: str) -> str:
    """Lowercase storage key; EIP-55 display can be added later without breaking keys."""
    return addr.lower()


def detect_and_normalize(value: str, chain_hint: str | None = None) -> NormalizedAddress | None:
    """Return normalized address or None if unrecognized.

    ``chain_hint`` forces interpretation when formats collide (e.g. Solana).
    """
    raw = (value or "").strip()
    if not raw:
        return None
    hint = (chain_hint or "").strip().lower() or None

    if hint in {"eth", "ethereum", "bsc", "arb", "optimism", "polygon", "evm"}:
        if _EVM_RE.match(raw):
            chain = "bsc" if hint == "bsc" else "eth"
            return NormalizedAddress(chain=chain, address=_evm_checksum_optional(raw), original=raw)
        return None

    if hint in {"btc", "bitcoin"}:
        if _BTC_BECH32_RE.match(raw):
            return NormalizedAddress(chain="btc", address=raw.lower(), original=raw)
        if _BTC_BASE58_RE.match(raw):
            return NormalizedAddress(chain="btc", address=raw, original=raw)
        return None

    if hint in {"tron", "trx"}:
        if _TRON_RE.match(raw):
            return NormalizedAddress(chain="tron", address=raw, original=raw)
        return None

    if hint in {"sol", "solana"}:
        if _SOL_RE.match(raw) and not raw.startswith("0x"):
            return NormalizedAddress(chain="sol", address=raw, original=raw)
        return None

    # Auto-detect unambiguous forms first
    if _EVM_RE.match(raw):
        return NormalizedAddress(chain="eth", address=_evm_checksum_optional(raw), original=raw)
    if _TRON_RE.match(raw):
        return NormalizedAddress(chain="tron", address=raw, original=raw)
    if _BTC_BECH32_RE.match(raw):
        return NormalizedAddress(chain="btc", address=raw.lower(), original=raw)
    if _BTC_BASE58_RE.match(raw):
        return NormalizedAddress(chain="btc", address=raw, original=raw)

    # Solana last and only with low confidence path — require hint to avoid BTC collision
    return None
