"""TRON TRC-20 transfers — the cash-out rail, and its impersonation problem.

TRON matters to this module more than its market cap suggests: **277 of the 961
sanctioned addresses** in the OFAC lake are TRON, second only to Bitcoin, and
`docs/CRYPTO-EXPLORATION.md` names TRC-20 USDT the dominant cash-out rail.
TronGrid serves address history key-free, so no account is required.

**Token metadata is attacker-controlled.** A TRC-20 contract reports its own
name, symbol and decimals, and anyone can deploy one calling itself USDT.
Measured across eight sanctioned addresses in our own lake, 83 transfers:

| Contract | Symbol it claims | Count |
|---|---|---|
| `TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t` | USDT | 77 |
| `TJXUL2YGcoVaNpFpNrQ9FjeE5AVMMSk6UJ` | `TG: jieuu` | 3 |
| `THxYWbzAgzQgQaYi9G4mjeL1tq1hdrZe55` | `ha138 com` | 2 |
| `TNVd8VBGWUjhHy1dtcmmwuXmBVyy6MUW16` | `unfreeze` | 1 |

Seven percent of what lands at a sanctioned address is dust-spam wearing a
deceptive name — the address-poisoning pattern. Rendering `token_info.symbol`
verbatim would put "300,000 USDT" on a page for a worthless token from a
contract nobody has heard of, which is inventing a finding.

So the symbol is trusted **only** when the contract is on the verified list
below. Everything else is reported as the contract address with the claimed
symbol marked unverified. Same rule as C1's "the asset code is not the chain":
provenance decides, not a label somebody else controls.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from umbra.crypto.providers.base import ProviderCaps
from umbra.crypto.types import AddressRef, Transfer

logger = logging.getLogger(__name__)

DEFAULT_INSTANCES = ("https://api.trongrid.io",)

# Contracts whose self-reported symbol may be shown as fact. The USDT entry was
# confirmed empirically: it carried 77 of 83 transfers sampled across eight
# independent sanctioned addresses, while every impostor appeared once or twice.
VERIFIED_TOKENS: dict[str, tuple[str, int]] = {
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": ("USDT", 6),
}

TRX_DECIMALS = 6


@dataclass
class FetchResult:
    transfers: list[Transfer]
    unavailable: bool
    instance: str | None
    note: str = ""
    spoofed: int = 0


class TronGridProvider:
    """TRC-20 history for one address. Key-free; a key only raises the limits."""

    chain = "tron"

    def __init__(self, http, instances: tuple[str, ...] = DEFAULT_INSTANCES,
                 api_key: str | None = None):
        self.http = http
        self.instances = tuple(instances)
        self.api_key = api_key

    def fetch(self, address: AddressRef,
              caps: ProviderCaps | None = None) -> FetchResult:
        caps = caps or ProviderCaps()
        headers = {"TRON-PRO-API-KEY": self.api_key} if self.api_key else None
        last_error = ""

        for base in self.instances:
            url = (f"{base.rstrip('/')}/v1/accounts/{address.address}"
                   f"/transactions/trc20?limit={min(200, caps.max_transfers)}")
            try:
                resp = self.http.get(url, headers=headers) if headers else self.http.get(url)
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001 - try the next instance
                last_error = f"{type(exc).__name__}: {exc}"
                logger.info("trongrid %s failed: %s", base, last_error)
                continue
            if not isinstance(payload, dict) or payload.get("success") is False:
                last_error = "unexpected response shape"
                continue
            transfers, spoofed = self._to_transfers(payload.get("data") or [], caps)
            return FetchResult(transfers=transfers, unavailable=False,
                               instance=base, spoofed=spoofed)

        # Not "no transfers" — not checked.
        return FetchResult(transfers=[], unavailable=True, instance=None,
                           note=f"no TronGrid instance answered ({last_error})")

    def get_transfers(self, address: AddressRef, *,
                      caps: ProviderCaps | None = None) -> list[Transfer]:
        return self.fetch(address, caps).transfers

    def _to_transfers(self, records: list, caps: ProviderCaps) -> tuple[list[Transfer], int]:
        out: list[Transfer] = []
        spoofed = 0
        for record in records:
            if len(out) >= caps.max_transfers:
                break
            if str(record.get("type") or "").lower() != "transfer":
                continue
            token = record.get("token_info") or {}
            contract = str(token.get("address") or "").strip()
            claimed = str(token.get("symbol") or "").strip()

            verified = VERIFIED_TOKENS.get(contract)
            if verified:
                asset, decimals = verified
                trusted = True
            else:
                # The contract is the only thing here we did not take on the
                # contract's own word.
                asset = contract or "unknown-trc20"
                trusted = False
                spoofed += 1
                try:
                    decimals = int(token.get("decimals") or 0)
                except (TypeError, ValueError):
                    decimals = 0

            try:
                amount = int(record.get("value") or 0)
            except (TypeError, ValueError):
                amount = 0
            stamp = record.get("block_timestamp")
            when = (datetime.fromtimestamp(stamp / 1000, tz=timezone.utc)
                    if isinstance(stamp, (int, float)) and stamp else None)

            out.append(Transfer(
                chain="tron",
                txid=str(record.get("transaction_id") or ""),
                from_addr=str(record.get("from") or ""),
                to_addr=str(record.get("to") or ""),
                asset=asset,
                amount_raw=amount,
                decimals=decimals,
                block_time=when,
                props={
                    "contract": contract,
                    "token_verified": trusted,
                    # Kept so an analyst can see what it *claimed* to be —
                    # "USDT" from an unknown contract is itself a finding.
                    "claimed_symbol": claimed,
                    "claimed_name": str(token.get("name") or ""),
                },
            ))
        return out, spoofed
