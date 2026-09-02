"""Bitcoin neighbours via Esplora — the no-key, no-Etherscan path.

Two independent public operators run the same open backend, and the same
software can be self-hosted against a full node later, so the API contract does
not change when the backend becomes Umbra's own.

The interpretation problem is the interesting part. A Bitcoin transaction has
many inputs and many outputs; "who paid whom" is a reading, not a field. The
reading here is deliberately conservative, and the tests below pin the three
places where a careless one invents relationships that are not there: change
outputs read as self-payments, unrelated outputs in a transaction that merely
paid you, and OP_RETURN data outputs with no address at all.
"""
from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.crypto.providers.base import ProviderCaps  # noqa: E402
from umbra.crypto.providers.esplora import EsploraProvider  # noqa: E402
from umbra.crypto.types import AddressRef  # noqa: E402

ME = "bc1qme000000000000000000000000000000000000"
THEM = "bc1qthem00000000000000000000000000000000000"
CHANGE = ME


def _tx(txid="tx1", inputs=(), outputs=(), block_time=1_700_000_000, confirmed=True):
    return {
        "txid": txid,
        "status": {"confirmed": confirmed, "block_time": block_time,
                   "block_height": 800000},
        "vin": [{"prevout": {"scriptpubkey_address": a}} for a in inputs],
        "vout": [{"scriptpubkey_address": a, "value": v} for a, v in outputs],
    }


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttp:
    """Per-instance canned responses, so failover can be exercised."""

    def __init__(self, by_host: dict):
        self.by_host = by_host
        self.calls: list[str] = []

    def get(self, url, **kw):
        self.calls.append(url)
        for host, payload in self.by_host.items():
            if host in url:
                if isinstance(payload, Exception):
                    raise payload
                return _Resp(payload)
        raise RuntimeError("no route")


def _provider(by_host):
    return EsploraProvider(FakeHttp(by_host))


# --- reading the UTXO shape -----------------------------------------------

def test_a_payment_out_is_one_transfer_to_the_counterparty():
    tx = _tx(inputs=[ME], outputs=[(THEM, 50_000)])
    result = _provider({"mempool.space": [tx]}).fetch(AddressRef("btc", ME))
    assert len(result.transfers) == 1
    transfer = result.transfers[0]
    assert transfer.from_addr == ME
    assert transfer.to_addr == THEM
    assert transfer.amount_raw == 50_000
    assert transfer.decimals == 8


def test_change_back_to_self_is_not_a_payment():
    """Nearly every real spend has a change output. Counting it would make every
    address look like it pays itself constantly."""
    tx = _tx(inputs=[ME], outputs=[(THEM, 50_000), (CHANGE, 20_000)])
    result = _provider({"mempool.space": [tx]}).fetch(AddressRef("btc", ME))
    assert [t.to_addr for t in result.transfers] == [THEM]


def test_receiving_only_picks_up_our_own_output():
    """In a transaction that paid us, the other outputs are somebody else's
    business and are not our counterparties."""
    other = "bc1qother0000000000000000000000000000000000"
    tx = _tx(inputs=[THEM], outputs=[(ME, 70_000), (other, 30_000)])
    result = _provider({"mempool.space": [tx]}).fetch(AddressRef("btc", ME))
    assert len(result.transfers) == 1
    assert result.transfers[0].to_addr == ME
    assert result.transfers[0].from_addr == THEM


def test_outputs_with_no_address_are_skipped():
    """OP_RETURN carries data, not a recipient."""
    tx = _tx(inputs=[ME], outputs=[(None, 0), (THEM, 10_000)])
    result = _provider({"mempool.space": [tx]}).fetch(AddressRef("btc", ME))
    assert [t.to_addr for t in result.transfers] == [THEM]


def test_the_block_time_becomes_a_datetime():
    tx = _tx(inputs=[ME], outputs=[(THEM, 1)])
    transfer = _provider({"mempool.space": [tx]}).fetch(AddressRef("btc", ME)).transfers[0]
    assert transfer.block_time is not None
    assert transfer.block_time.year >= 2023


def test_an_unconfirmed_transaction_is_marked_as_such():
    tx = _tx(inputs=[ME], outputs=[(THEM, 1)], confirmed=False, block_time=None)
    transfer = _provider({"mempool.space": [tx]}).fetch(AddressRef("btc", ME)).transfers[0]
    assert transfer.props["confirmed"] is False
    assert transfer.block_time is None


# --- bounded --------------------------------------------------------------

def test_the_cap_is_enforced():
    """A hot address has hundreds of thousands of transactions. Unbounded
    expansion here is how a case turns into a crawl of the whole chain."""
    txs = [_tx(txid=f"tx{i}", inputs=[ME], outputs=[(THEM, 1)]) for i in range(50)]
    result = _provider({"mempool.space": txs}).fetch(
        AddressRef("btc", ME), ProviderCaps(max_transfers=10))
    assert len(result.transfers) == 10


# --- failover -------------------------------------------------------------

def test_a_dead_instance_falls_through_to_the_next():
    tx = _tx(inputs=[ME], outputs=[(THEM, 1)])
    provider = _provider({"mempool.space": RuntimeError("503"),
                          "blockstream.info": [tx]})
    result = provider.fetch(AddressRef("btc", ME))
    assert result.unavailable is False
    assert result.instance and "blockstream" in result.instance
    assert len(result.transfers) == 1


def test_every_instance_down_is_unavailable_not_empty():
    """The distinction that matters: "we could not look" is not "it has no
    transactions"."""
    provider = _provider({"mempool.space": RuntimeError("503"),
                          "blockstream.info": RuntimeError("timeout")})
    result = provider.fetch(AddressRef("btc", ME))
    assert result.unavailable is True
    assert result.transfers == []
    assert "esplora" in result.note.lower() or "instance" in result.note.lower()


def test_a_nonsense_response_is_treated_as_a_failure():
    provider = _provider({"mempool.space": {"error": "nope"},
                          "blockstream.info": {"error": "nope"}})
    assert provider.fetch(AddressRef("btc", ME)).unavailable is True


def test_the_first_healthy_instance_wins():
    tx = _tx(inputs=[ME], outputs=[(THEM, 1)])
    provider = _provider({"mempool.space": [tx], "blockstream.info": [tx, tx]})
    result = provider.fetch(AddressRef("btc", ME))
    assert "mempool.space" in result.instance


def test_a_self_hosted_instance_can_be_first():
    """The point of Esplora over a proprietary explorer: the same contract runs
    against your own node."""
    tx = _tx(inputs=[ME], outputs=[(THEM, 1)])
    provider = EsploraProvider(FakeHttp({"127.0.0.1:3000": [tx]}),
                               instances=("http://127.0.0.1:3000/api",))
    assert provider.fetch(AddressRef("btc", ME)).transfers
