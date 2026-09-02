"""The targeted transfer index — where "better than Etherscan" has to earn it.

Measured against free public RPC before this was designed, because the limits
decide the shape: `eth_getLogs` is refused without a contract address, refused
beyond ~64 blocks ("archive requests require a personal token"), and USDT alone
produces ~182 Transfer logs per block. Free RPC is about **fifteen minutes** of
history.

So Umbra cannot out-archive an explorer and does not try. It follows the head
and keeps only transfers touching an address it already cares about, which is
better on the axes that matter here:

- **nobody learns what you are investigating** — every explorer lookup tells the
  explorer which address interests you, and this tells nobody;
- it answers a question an explorer API cannot be asked at all: *tell me when
  any of these 961 sanctioned addresses moves*;
- the history is owned and accumulates, honestly labelled tail-forward.

Indexing everything is refused on arithmetic: USDT alone is ~47 GB/year against
a 5 GB/year budget for all crypto data.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.crypto import lake as crypto_lake  # noqa: E402
from umbra.crypto import tail  # noqa: E402
from umbra.crypto.providers.evm_rpc import TRANSFER_TOPIC, decode_transfer  # noqa: E402
from umbra.crypto.types import AddressRef, Label, LabelTag  # noqa: E402
from umbra.lake.store import LakeStore  # noqa: E402

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
WATCHED = "0x7f367cc41522ce07553e823bf3be79a889debe1b"
STRANGER = "0x1111111111111111111111111111111111111111"


def _topic(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def _log(frm: str, to: str, block: int = 1000, index: int = 0, amount: int = 1_000_000):
    return {
        "address": USDT,
        "topics": [TRANSFER_TOPIC, _topic(frm), _topic(to)],
        "data": hex(amount),
        "blockNumber": hex(block),
        "transactionHash": f"0xtx{block}{index}",
        "logIndex": hex(index),
    }


@pytest.fixture
def store(tmp_path: Path) -> LakeStore:
    store = LakeStore(f"sqlite:///{tmp_path / 'lake.db'}")
    crypto_lake.replace_source(store, "ofac_sdn", [Label(
        address=AddressRef(chain="eth", address=WATCHED),
        tag=LabelTag.SANCTIONED_OFAC, source="ofac_sdn", confidence=0.98,
        summary="OFAC SDN listing: TEST")])
    return store


class FakeRpc:
    def __init__(self, head=1000, logs=None, ok=True, error=""):
        self._head, self._logs, self._ok, self._error = head, logs or [], ok, error
        self.ranges: list[tuple[int, int]] = []

    def block_number(self):
        return self._head

    def transfer_logs(self, contract, from_block, to_block):
        from umbra.crypto.providers.evm_rpc import RpcResult

        self.ranges.append((from_block, to_block))
        if not self._ok:
            return RpcResult(False, None, self._error or "archive token required")
        # Only this contract's logs — the tail queries each token separately,
        # and a fake that ignores the filter double-counts every transfer.
        return RpcResult(True, [lg for lg in self._logs
                                if lg.get("address", "").lower() == contract.lower()])


# --- decoding -------------------------------------------------------------

def test_a_transfer_log_decodes_to_a_flat_record():
    record = decode_transfer(_log(STRANGER, WATCHED, amount=2_500_000))
    assert record["from_addr"] == STRANGER
    assert record["to_addr"] == WATCHED
    assert record["amount_raw"] == 2_500_000
    assert record["asset"] == "USDT"
    assert record["decimals"] == 6


def test_addresses_come_out_lowercased():
    """They are stored and compared lowercased; a checksummed compare silently
    matches nothing."""
    record = decode_transfer(_log(STRANGER.upper().replace("0X", "0x"), WATCHED))
    assert record["from_addr"] == record["from_addr"].lower()


def test_a_non_transfer_log_is_ignored():
    log = _log(STRANGER, WATCHED)
    log["topics"] = ["0xdeadbeef"]
    assert decode_transfer(log) is None


def test_an_erc721_transfer_is_not_treated_as_erc20():
    """ERC-721 shares the event signature but indexes a third topic, the token
    id. Decoding one as a fungible amount invents a transfer of 1,000,000 USDT
    that never happened."""
    log = _log(STRANGER, WATCHED)
    log["topics"] = log["topics"] + [_topic(STRANGER)]
    assert decode_transfer(log) is None


# --- the targeting, which is the whole idea -------------------------------

def test_a_transfer_touching_a_watched_address_is_kept(store):
    rpc = FakeRpc(logs=[_log(STRANGER, WATCHED)])
    stats = tail.tick(store, rpc)
    assert stats["kept"] == 1
    assert stats["stored"] == 1


def test_a_transfer_between_strangers_is_dropped(store):
    """This is what keeps 1.3M transfers a day from becoming Umbra's problem."""
    rpc = FakeRpc(logs=[_log(STRANGER, "0x2222222222222222222222222222222222222222")])
    stats = tail.tick(store, rpc)
    assert stats["logs"] == 1
    assert stats["kept"] == 0
    assert stats["stored"] == 0


def test_the_watch_set_comes_from_the_active_labels(store):
    assert WATCHED in tail.watch_set(store)


def test_a_delisted_label_stops_being_watched(store):
    """Following an address because it *used* to be sanctioned is surveillance
    without a reason. The registry's own service contracts stay watched — they
    are infrastructure, not a listing that can lapse."""
    from umbra.crypto.services import load_default_registry

    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=True)
    remaining = tail.watch_set(store)
    assert WATCHED not in remaining
    assert remaining == load_default_registry().addresses("eth")


def test_either_direction_counts(store):
    rpc = FakeRpc(logs=[_log(WATCHED, STRANGER, index=1)])
    assert tail.tick(store, rpc)["kept"] == 1


# --- bounded and resumable ------------------------------------------------

def test_the_tick_never_reaches_past_the_free_window(store):
    """Those calls are refused outright; a gap is more honest than a retry
    storm against someone's free endpoint."""
    from umbra.crypto.providers.evm_rpc import FREE_WINDOW_BLOCKS

    rpc = FakeRpc(head=5_000_000)
    tail.tick(store, rpc, blocks=10_000)
    start, end = rpc.ranges[0]
    assert end - start < FREE_WINDOW_BLOCKS


def test_progress_is_checkpointed(store):
    rpc = FakeRpc(head=1000, logs=[_log(STRANGER, WATCHED)])
    tail.tick(store, rpc)
    assert store.crypto_tail_checkpoint("eth") == 1000


def test_a_failed_tick_does_not_advance_the_checkpoint(store):
    """Otherwise a refused range silently becomes a permanent hole."""
    tail.tick(store, FakeRpc(head=1000, logs=[_log(STRANGER, WATCHED)]))
    tail.tick(store, FakeRpc(head=1100, ok=False))
    assert store.crypto_tail_checkpoint("eth") == 1000


def test_a_refusal_is_reported_rather_than_swallowed(store):
    stats = tail.tick(store, FakeRpc(ok=False, error="archive token required"))
    assert stats["errors"] >= 1
    assert "archive" in stats["note"]


def test_a_dead_endpoint_is_not_an_empty_chain(store):
    class Dead(FakeRpc):
        def block_number(self):
            return None

    stats = tail.tick(store, Dead())
    assert stats["errors"] == 1
    assert stats["stored"] == 0
    assert stats["note"]


def test_the_same_transfer_is_not_stored_twice(store):
    rpc = FakeRpc(logs=[_log(STRANGER, WATCHED)])
    tail.tick(store, rpc)
    stats = tail.tick(store, FakeRpc(head=1001, logs=[_log(STRANGER, WATCHED)]))
    assert stats["stored"] == 0


def test_a_uint256_amount_survives_storage(store):
    """Token amounts exceed BIGINT; storing them as integers would overflow or
    silently truncate somebody's balance."""
    huge = 2 ** 200
    rpc = FakeRpc(logs=[_log(STRANGER, WATCHED, amount=huge)])
    tail.tick(store, rpc)
    stored = store.crypto_transfers_for("eth", WATCHED)[0]
    assert int(stored["amount_raw"]) == huge


# --- what it can then answer ----------------------------------------------

def test_transfers_can_be_looked_up_by_address(store):
    tail.tick(store, FakeRpc(logs=[_log(STRANGER, WATCHED)]))
    hits = store.crypto_transfers_for("eth", WATCHED)
    assert len(hits) == 1
    assert hits[0]["asset"] == "USDT"


def test_stats_report_the_index_and_position(store):
    tail.tick(store, FakeRpc(head=1234, logs=[_log(STRANGER, WATCHED)]))
    stats = store.crypto_transfer_stats()
    assert stats["transfers"] == 1
    assert stats["checkpoints"]["eth"]["last_block"] == 1234


def test_service_contracts_are_watched_too(store):
    """A deposit into a mixer is the event worth catching live. Discovering it
    later by asking an explorer would also tell the explorer what we look for."""
    from umbra.crypto.services import load_default_registry

    watching = tail.watch_set(store)
    for address in load_default_registry().addresses("eth"):
        assert address in watching


def test_a_transfer_into_a_mixer_pool_is_kept(store):
    tornado = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"
    rpc = FakeRpc(logs=[_log(STRANGER, tornado)])
    assert tail.tick(store, rpc)["kept"] == 1
