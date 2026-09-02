"""C0 crypto framework unit tests (no network)."""

from __future__ import annotations

from umbra.crypto import (
    AddressRef,
    InMemoryLabelStore,
    Label,
    LabelTag,
    detect_and_normalize,
)
from umbra.crypto.services import ServiceRegistry, load_default_registry
from umbra.crypto.types import ServiceDef, ServiceKind


def test_normalize_eth_lowercase_key():
    n = detect_and_normalize("0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936")
    assert n is not None
    assert n.chain == "eth"
    assert n.address.startswith("0x")
    assert n.address == n.address.lower()


def test_normalize_btc_bech32():
    n = detect_and_normalize("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    assert n is not None
    assert n.chain == "btc"
    assert n.address.startswith("bc1")


def test_normalize_tron():
    # Well-formed shape (not checksum-verified in C0)
    n = detect_and_normalize("T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb")
    assert n is not None
    assert n.chain == "tron"


def test_normalize_sol_requires_hint():
    sol = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
    assert detect_and_normalize(sol) is None
    n = detect_and_normalize(sol, chain_hint="sol")
    assert n is not None
    assert n.chain == "sol"


def test_label_store_upsert_and_lookup():
    store = InMemoryLabelStore()
    addr = AddressRef(chain="btc", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    store.upsert(
        Label(
            address=addr,
            tag=LabelTag.RANSOMWARE_PAYMENT,
            source="ransomwhere",
            confidence=0.6,
            summary="fixture",
        )
    )
    hits = store.lookup(addr)
    assert len(hits) == 1
    assert hits[0].tag == LabelTag.RANSOMWARE_PAYMENT
    assert store.count() == 1


def test_service_registry_tornado_match():
    """C0 shipped an illustrative one-entry helper; C3 replaced it with the
    curated registry, where every entry carries on-chain verification."""
    reg = load_default_registry()
    hits = reg.match("eth", "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936")
    assert len(hits) == 1
    assert hits[0].kind == ServiceKind.MIXER
    assert "tornado" in hits[0].name.lower()


def test_service_registry_miss():
    reg = ServiceRegistry(
        [
            ServiceDef(
                name="x",
                kind=ServiceKind.BRIDGE,
                chain="eth",
                addresses=("0x0000000000000000000000000000000000000001",),
            )
        ]
    )
    assert reg.match("eth", "0x0000000000000000000000000000000000000002") == []
