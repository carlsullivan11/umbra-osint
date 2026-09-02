"""The crypto label lake, and what happens when a listing goes away.

`docs/CRYPTO-EXPLORATION.md` names the trap: *"Do not treat delisted mixer
contracts as 'still OFAC' without live list."* Tornado Cash was designated in
August 2022 and removed from the SDN list in 2025. An address Umbra keeps
labelling `sanctioned_ofac` after removal is not a stale cache entry — it is a
false accusation of sanctions evasion, about a real party, from a tool whose
whole pitch is provenance.

So a sync is a **full-file reconciliation**, not an append: every address in the
new file is current, every address absent from it is delisted with the date, and
nothing is deleted. The history is the point — "this was sanctioned until March"
is a true and useful statement, and it is the one an append-only cache cannot
make.

Same shape as the phone listing lifecycle, for the same reason: a listing is a
claim about *now*.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.crypto import lake as crypto_lake  # noqa: E402
from umbra.crypto.types import AddressRef, Label, LabelTag  # noqa: E402
from umbra.lake.store import LakeStore  # noqa: E402

BTC = "12QtD5BFwRsdNsAZY76UVE1xyCGNTojH9h"
ETH = "0x7f367cc41522ce07553e823bf3be79a889debe1b"


@pytest.fixture
def store(tmp_path: Path) -> LakeStore:
    return LakeStore(f"sqlite:///{tmp_path / 'lake.db'}")


def _label(address: str, chain: str = "btc", name: str = "YAN", **props) -> Label:
    return Label(
        address=AddressRef(chain=chain, address=address),
        tag=LabelTag.SANCTIONED_OFAC, source="ofac_sdn", confidence=0.98,
        url="https://sanctionslist.ofac.treas.gov/Home/SdnList",
        summary=f"OFAC SDN listing: {name}",
        props={"sdn_uid": "25308", "sdn_name": name, "programs": ["SDNTK"], **props},
    )


# --- storing and finding --------------------------------------------------

def test_a_label_can_be_stored_and_found(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    hits = store.crypto_labels("btc", BTC)
    assert len(hits) == 1
    assert hits[0]["tag"] == "sanctioned_ofac"


def test_lookup_is_by_chain_and_address(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    assert store.crypto_labels("eth", BTC) == []


def test_an_unknown_address_returns_nothing(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    assert store.crypto_labels("btc", "1SomeOtherAddressThatIsNotListed") == []


def test_the_sanctioned_party_survives_storage(store):
    """The label has to stay checkable against the public file."""
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    hit = store.crypto_labels("btc", BTC)[0]
    assert "YAN" in hit["summary"]
    assert hit["props"]["sdn_uid"] == "25308"


def test_re_syncing_the_same_file_does_not_duplicate(store):
    for _ in range(3):
        crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    assert len(store.crypto_labels("btc", BTC)) == 1


# --- delisting: the Tornado Cash case -------------------------------------

def test_an_address_absent_from_the_new_file_is_delisted(store):
    """The specific failure this prevents: Umbra asserting a sanctions listing
    that OFAC has removed."""
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC), _label(ETH, "eth")])
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])

    still = store.crypto_labels("btc", BTC)[0]
    gone = store.crypto_labels("eth", ETH, include_delisted=True)[0]
    assert still["active"] is True
    assert gone["active"] is False
    assert gone["delisted_at"] is not None


def test_a_delisted_label_is_not_returned_by_default(store):
    """A caller asking "is this sanctioned" must not get a yes from history."""
    crypto_lake.replace_source(store, "ofac_sdn", [_label(ETH, "eth")])
    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=True)
    assert store.crypto_labels("eth", ETH) == []


def test_the_history_is_kept_rather_than_deleted(store):
    """"This was sanctioned until March" is true, useful, and impossible to say
    if the row is dropped."""
    crypto_lake.replace_source(store, "ofac_sdn", [_label(ETH, "eth")])
    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=True)
    history = store.crypto_labels("eth", ETH, include_delisted=True)
    assert len(history) == 1
    assert history[0]["first_seen"] is not None


def test_a_relisted_address_becomes_active_again(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(ETH, "eth")])
    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=True)
    crypto_lake.replace_source(store, "ofac_sdn", [_label(ETH, "eth")])
    hit = store.crypto_labels("eth", ETH)[0]
    assert hit["active"] is True
    assert hit["delisted_at"] is None


def test_one_source_delisting_does_not_touch_another(store):
    """Reconciliation is per source. A ransomware feed going quiet must not
    delist OFAC's entries."""
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    other = Label(address=AddressRef(chain="btc", address=BTC),
                  tag=LabelTag.RANSOMWARE_PAYMENT, source="ransomwhere",
                  confidence=0.6, summary="reported ransom payment")
    crypto_lake.replace_source(store, "ransomwhere", [other])
    crypto_lake.replace_source(store, "ransomwhere", [], allow_empty=True)

    tags = {h["tag"] for h in store.crypto_labels("btc", BTC)}
    assert tags == {"sanctioned_ofac"}


def test_an_empty_sync_does_not_wipe_a_source_by_accident(store):
    """A fetch that returned nothing because the server erred must not be
    mistaken for "OFAC delisted everybody"."""
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=False)
    assert store.crypto_labels("btc", BTC)


def test_an_intentional_empty_sync_is_still_possible(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    crypto_lake.replace_source(store, "ofac_sdn", [], allow_empty=True)
    assert store.crypto_labels("btc", BTC) == []


# --- reporting ------------------------------------------------------------

def test_stats_report_what_is_indexed(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC), _label(ETH, "eth")])
    stats = store.crypto_label_stats()
    assert stats["active"] == 2
    assert stats["sources"]["ofac_sdn"]["active"] == 2
    assert stats["sources"]["ofac_sdn"]["synced_at"]


def test_stats_count_delisted_separately(store):
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC), _label(ETH, "eth")])
    crypto_lake.replace_source(store, "ofac_sdn", [_label(BTC)])
    stats = store.crypto_label_stats()
    assert stats["active"] == 1
    assert stats["delisted"] == 1


def test_an_unsynced_lake_says_so(store):
    """Nothing indexed is not "this address is clean" — the same rule as the
    DNSBL, crt.sh and KEV paths."""
    stats = store.crypto_label_stats()
    assert stats["active"] == 0
    assert stats["sources"] == {}


def test_a_duplicated_address_in_one_snapshot_is_stored_once(store):
    """The live SDN file lists some addresses under more than one entry. A
    second row for the same key violates the unique constraint and adds
    nothing — this was a real crash on the first full sync."""
    dupes = [_label(BTC, name="YAN"), _label(BTC, name="SOMEONE ELSE")]
    stats = crypto_lake.replace_source(store, "ofac_sdn", dupes)
    assert stats["active"] == 1
    assert len(store.crypto_labels("btc", BTC)) == 1
