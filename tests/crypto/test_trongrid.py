"""TRON TRC-20 — the cash-out rail, and the impersonation it invites.

277 of the 961 sanctioned addresses in the OFAC lake are TRON, second only to
Bitcoin, and TronGrid serves address history without a key.

The hazard is specific and was measured, not imagined. A TRC-20 contract reports
its own name, symbol and decimals, so anyone can deploy one calling itself USDT.
Across eight sanctioned addresses in our own lake, 83 transfers: 77 from the real
USDT contract, and six from impostors named `TG: jieuu`, `ha138 com` and
`unfreeze` — dust-spam wearing a deceptive name, the address-poisoning pattern.

Rendering `token_info.symbol` verbatim would print "300,000 USDT" for a
worthless token from a contract nobody has heard of. That is inventing a
finding, so the symbol is trusted only when the contract is on the verified
list, and what an impostor *claimed* is kept — a fake USDT arriving at a
sanctioned address is itself worth seeing.
"""
from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.crypto.providers.base import ProviderCaps  # noqa: E402
from umbra.crypto.providers.trongrid import (  # noqa: E402
    VERIFIED_TOKENS,
    TronGridProvider,
)
from umbra.crypto.types import AddressRef  # noqa: E402

ME = "TA3941uFAvmVibSkQ6fMJXxmaSNovX86mz"
THEM = "TUZPztRsZQMUJVXQYKwEuwdGhzgTGjieuu"
REAL_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
FAKE = "TJXUL2YGcoVaNpFpNrQ9FjeE5AVMMSk6UJ"


def _record(contract=REAL_USDT, symbol="USDT", decimals=6, value="302676000000",
            name="Tether USD", txid="tx1", kind="Transfer"):
    return {
        "transaction_id": txid,
        "from": THEM,
        "to": ME,
        "value": value,
        "type": kind,
        "block_timestamp": 1784187189000,
        "token_info": {"symbol": symbol, "address": contract,
                       "decimals": decimals, "name": name},
    }


class _Resp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttp:
    def __init__(self, by_host):
        self.by_host = by_host
        self.headers_seen: list = []

    def get(self, url, headers=None, **kw):
        self.headers_seen.append(headers)
        for host, payload in self.by_host.items():
            if host in url:
                if isinstance(payload, Exception):
                    raise payload
                return _Resp(payload)
        raise RuntimeError("no route")


def _provider(records, host="api.trongrid.io", **kw):
    payload = records if isinstance(records, Exception) else {
        "success": True, "data": records}
    return TronGridProvider(FakeHttp({host: payload}), **kw)


# --- the real thing -------------------------------------------------------

def test_a_real_usdt_transfer_is_read():
    result = _provider([_record()]).fetch(AddressRef("tron", ME))
    transfer = result.transfers[0]
    assert transfer.asset == "USDT"
    assert transfer.decimals == 6
    assert transfer.amount_raw == 302676000000
    assert transfer.props["token_verified"] is True


def test_the_verified_list_holds_the_contract_not_the_symbol():
    """The symbol is what an impostor copies; the contract is what it cannot."""
    assert REAL_USDT in VERIFIED_TOKENS
    assert VERIFIED_TOKENS[REAL_USDT] == ("USDT", 6)


def test_the_timestamp_becomes_a_datetime():
    transfer = _provider([_record()]).fetch(AddressRef("tron", ME)).transfers[0]
    assert transfer.block_time is not None
    assert transfer.block_time.year >= 2023


# --- impersonation --------------------------------------------------------

def test_a_token_claiming_to_be_usdt_from_another_contract_is_not_usdt():
    """The failure this exists to prevent: 300,000 "USDT" on a page, from a
    contract nobody has heard of."""
    result = _provider([_record(contract=FAKE, symbol="USDT",
                                name="Tether USD")]).fetch(AddressRef("tron", ME))
    transfer = result.transfers[0]
    assert transfer.asset != "USDT"
    assert transfer.asset == FAKE
    assert transfer.props["token_verified"] is False


def test_what_the_impostor_claimed_is_kept():
    """A fake USDT arriving at a sanctioned address is itself worth seeing."""
    transfer = _provider([_record(contract=FAKE, symbol="USDT")]).fetch(
        AddressRef("tron", ME)).transfers[0]
    assert transfer.props["claimed_symbol"] == "USDT"


def test_spam_tokens_are_counted():
    """7% of what lands at a sanctioned address is dust-spam; the count tells an
    analyst how much of the page to discount."""
    records = [_record(), _record(contract=FAKE, symbol="TG: jieuu", txid="tx2"),
               _record(contract="TNVd8VBGWUjhHy1dtcmmwuXmBVyy6MUW16",
                       symbol="unfreeze", txid="tx3")]
    result = _provider(records).fetch(AddressRef("tron", ME))
    assert result.spoofed == 2
    assert len(result.transfers) == 3


def test_an_unverified_token_keeps_its_own_decimals():
    """Wrong decimals would misstate the amount by orders of magnitude, which is
    worse than admitting the token is unknown."""
    transfer = _provider([_record(contract=FAKE, decimals=18)]).fetch(
        AddressRef("tron", ME)).transfers[0]
    assert transfer.decimals == 18


def test_junk_decimals_do_not_crash_it():
    transfer = _provider([_record(contract=FAKE, decimals="lots")]).fetch(
        AddressRef("tron", ME)).transfers[0]
    assert transfer.decimals == 0


# --- shape and bounds -----------------------------------------------------

def test_non_transfer_events_are_skipped():
    assert _provider([_record(kind="Approval")]).fetch(
        AddressRef("tron", ME)).transfers == []


def test_the_cap_is_enforced():
    records = [_record(txid=f"tx{i}") for i in range(40)]
    result = _provider(records).fetch(AddressRef("tron", ME),
                                      ProviderCaps(max_transfers=5))
    assert len(result.transfers) == 5


def test_a_junk_value_does_not_crash_it():
    transfer = _provider([_record(value="not-a-number")]).fetch(
        AddressRef("tron", ME)).transfers[0]
    assert transfer.amount_raw == 0


# --- availability ---------------------------------------------------------

def test_a_dead_instance_is_unavailable_not_empty():
    provider = TronGridProvider(FakeHttp({"api.trongrid.io": RuntimeError("503")}))
    result = provider.fetch(AddressRef("tron", ME))
    assert result.unavailable is True
    assert result.transfers == []
    assert result.note


def test_a_failed_response_flag_is_treated_as_a_failure():
    provider = TronGridProvider(FakeHttp({"api.trongrid.io": {"success": False}}))
    assert provider.fetch(AddressRef("tron", ME)).unavailable is True


def test_it_works_without_a_key():
    """TronGrid serves this key-free; a key only raises the rate limit."""
    provider = _provider([_record()])
    provider.fetch(AddressRef("tron", ME))
    assert provider.http.headers_seen[0] is None


def test_a_key_is_sent_when_configured():
    provider = _provider([_record()], api_key="secret")
    provider.fetch(AddressRef("tron", ME))
    assert provider.http.headers_seen[0]["TRON-PRO-API-KEY"] == "secret"
