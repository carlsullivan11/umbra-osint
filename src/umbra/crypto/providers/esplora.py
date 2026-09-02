"""Bitcoin transfers via Esplora — no key, no account, no Etherscan.

Esplora is Blockstream's open block-explorer backend. Two independent public
instances run it (mempool.space and blockstream.info), it needs no key, and —
the part that matters for the long game — **it is the same software Umbra can
self-host** against a Bitcoin full node later. That is the difference between
depending on an explorer and using one until you replace it: the API contract
does not change when the backend becomes yours.

Failover is across instances rather than retries against one, because the
failure being defended is "that operator is down or rate-limiting me", not
"packet loss".

`unavailable` on the result is load-bearing. If every instance refuses, the
answer is *not checked*, never *no transactions* — the same rule as the DNSBL,
crt.sh and KEV paths.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from umbra.crypto.providers.base import ProviderCaps
from umbra.crypto.types import AddressRef, Transfer

logger = logging.getLogger(__name__)

# Independent operators running the same open backend. Order is preference.
DEFAULT_INSTANCES = (
    "https://mempool.space/api",
    "https://blockstream.info/api",
)

SATS_DECIMALS = 8


@dataclass
class FetchResult:
    transfers: list[Transfer]
    unavailable: bool
    instance: str | None
    note: str = ""


class EsploraProvider:
    """Address history from any Esplora instance, including a self-hosted one."""

    chain = "btc"

    def __init__(self, http, instances: tuple[str, ...] = DEFAULT_INSTANCES):
        self.http = http
        self.instances = tuple(instances)

    def fetch(self, address: AddressRef,
              caps: ProviderCaps | None = None) -> FetchResult:
        caps = caps or ProviderCaps()
        last_error = ""
        for base in self.instances:
            url = f"{base.rstrip('/')}/address/{address.address}/txs"
            try:
                resp = self.http.get(url)
                resp.raise_for_status()
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001 - try the next operator
                last_error = f"{type(exc).__name__}: {exc}"
                logger.info("esplora %s failed: %s", base, last_error)
                continue
            if not isinstance(payload, list):
                last_error = "unexpected response shape"
                continue
            return FetchResult(
                transfers=self._to_transfers(payload, address, caps),
                unavailable=False, instance=base)

        # Every instance refused. Not "no transactions" — not checked.
        return FetchResult(transfers=[], unavailable=True, instance=None,
                           note=f"no Esplora instance answered ({last_error})")

    def get_transfers(self, address: AddressRef, *,
                      caps: ProviderCaps | None = None) -> list[Transfer]:
        return self.fetch(address, caps).transfers

    def _to_transfers(self, txs: list, address: AddressRef,
                      caps: ProviderCaps) -> list[Transfer]:
        """Flatten Bitcoin's UTXO shape into directed transfers.

        A Bitcoin transaction has many inputs and many outputs, so "who paid
        whom" is an interpretation rather than a field. The conservative reading
        used here: if the address appears in the inputs it is a sender, and each
        output it does not own is a counterparty; if it appears only in outputs
        it is a receiver from the transaction's inputs. Change outputs back to
        the same address are dropped rather than counted as self-payments.
        """
        me = address.address
        out: list[Transfer] = []
        for tx in txs:
            if len(out) >= caps.max_transfers:
                break
            txid = str(tx.get("txid") or "")
            status = tx.get("status") or {}
            block_time = status.get("block_time")
            when = (datetime.fromtimestamp(block_time, tz=timezone.utc)
                    if isinstance(block_time, (int, float)) else None)

            inputs = [(v.get("prevout") or {}).get("scriptpubkey_address")
                      for v in (tx.get("vin") or [])]
            spends = me in inputs

            for index, vout in enumerate(tx.get("vout") or []):
                if len(out) >= caps.max_transfers:
                    break
                counterparty = vout.get("scriptpubkey_address")
                if not counterparty:
                    continue  # OP_RETURN and other non-address outputs
                if spends and counterparty == me:
                    continue  # change back to self is not a payment
                if not spends and counterparty != me:
                    continue  # someone else's output in a tx that paid us
                out.append(Transfer(
                    chain="btc",
                    txid=txid,
                    from_addr=me if spends else (next(
                        (i for i in inputs if i), "") or ""),
                    to_addr=counterparty,
                    asset="BTC",
                    amount_raw=int(vout.get("value") or 0),
                    decimals=SATS_DECIMALS,
                    index=index,
                    block_time=when,
                    props={"confirmed": bool(status.get("confirmed")),
                           "block_height": status.get("block_height")},
                ))
        return out
