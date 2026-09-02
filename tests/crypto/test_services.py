"""The service registry — mixers and bridges, and the care they demand.

This is the most defamation-adjacent thing in the crypto module. Labelling an
address "mixer" when it is not is a false accusation against whoever controls
it, and mixer *interaction* is not a crime — people use privacy tools for
private reasons. So the registry has two hard rules and this file pins both.

**Nothing enters on recollection.** Every entry carries a `verification` block
saying how the address was checked. The shipped Tornado Cash pools were verified
with `eth_getCode` against a public node: three share byte-identical bytecode
(sha256 `57632dbb86b78ae0`, 5191 bytes), which is what one contract deployed at
several denominations looks like. A fifth candidate address turned out to have
no code at all and was dropped rather than shipped.

**The registry never claims sanctions.** OFAC listings change — Tornado Cash was
designated in 2022 and removed in 2025 — so only the live SDN lake answers that
question. A static file asserting "sanctioned" would be wrong the day it went
stale, and wrong in the direction that accuses people.
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.crypto.services import ServiceRegistry, load_default_registry  # noqa: E402
from umbra.crypto.types import ServiceKind  # noqa: E402

DATA = (Path(__file__).resolve().parents[2]
        / "src/umbra/crypto/data/services.json")
TORNADO_1ETH = "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936"


# --- the shipped data -----------------------------------------------------

def test_the_registry_file_parses():
    payload = json.loads(DATA.read_text())
    assert payload["services"]


def test_every_entry_records_how_it_was_verified():
    """An unverified "mixer" label is a false accusation waiting to happen."""
    for entry in json.loads(DATA.read_text())["services"]:
        assert entry.get("verification"), entry["name"]
        assert entry["verification"].get("method")
        assert entry["verification"].get("checked_at")


def test_verified_contracts_carry_their_code_hash():
    """The check is repeatable: read the code again and compare."""
    for entry in json.loads(DATA.read_text())["services"]:
        verification = entry["verification"]
        assert verification.get("code_sha256")
        assert verification.get("code_bytes", 0) > 0


def test_the_registry_never_asserts_sanctions_status():
    """Only the live SDN lake may answer that. A static file would be wrong the
    day it went stale, in the direction that accuses people."""
    raw = DATA.read_text().lower()
    for entry in json.loads(DATA.read_text())["services"]:
        assert "sanctions_status" not in entry
        assert "sanctioned" not in json.dumps(entry).lower()
    assert "sanctions_status is deliberately not a field" in raw.replace("**", "")


def test_the_pools_that_share_code_share_a_hash():
    """1, 10 and 100 ETH are one contract at three denominations — the
    corroboration that these are what they are said to be."""
    entries = json.loads(DATA.read_text())["services"]
    hashes = [e["verification"]["code_sha256"] for e in entries
              if e["verification"]["code_bytes"] == 5191]
    assert len(hashes) == 3
    assert len(set(hashes)) == 1


def test_addresses_are_stored_lowercased():
    """EVM lookups are lowercased; a checksummed entry would never match."""
    for entry in json.loads(DATA.read_text())["services"]:
        for address in entry["addresses"]:
            assert address == address.lower()


# --- matching -------------------------------------------------------------

def test_the_default_registry_loads():
    registry = load_default_registry()
    assert len(registry.all()) >= 4


def test_a_known_pool_matches():
    hits = load_default_registry().match("eth", TORNADO_1ETH)
    assert hits
    assert hits[0].kind == ServiceKind.MIXER


def test_matching_is_case_insensitive():
    """A visitor pastes a checksummed address; it has to find the entry."""
    checksummed = "0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"
    assert load_default_registry().match("eth", checksummed)


def test_an_unrelated_address_does_not_match():
    assert load_default_registry().match(
        "eth", "0x1111111111111111111111111111111111111111") == []


def test_the_chain_has_to_match():
    assert load_default_registry().match("btc", TORNADO_1ETH) == []


def test_service_addresses_are_exposed_for_the_watch_set():
    """C2's head-follower keeps transfers touching addresses of interest.
    Mixer pools are exactly that, so interactions are caught as they happen
    rather than looked up afterwards."""
    addresses = load_default_registry().addresses("eth")
    assert TORNADO_1ETH in addresses
    assert all(a == a.lower() for a in addresses)


# --- the framing ----------------------------------------------------------

def test_every_entry_says_interaction_is_a_signal():
    """The copy rule from docs/CRYPTO-EXPLORATION.md, enforced in the data."""
    registry = load_default_registry()
    combined = " ".join((svc.notes or "") for svc in registry.all()).lower()
    assert "signal" in combined or "not guilt" in combined


def test_a_registry_can_be_built_empty_without_the_file():
    """A missing data file must not break importing the module."""
    assert ServiceRegistry().all() == []
    assert ServiceRegistry().match("eth", TORNADO_1ETH) == []


def test_the_registry_file_is_actually_committed():
    """`.gitignore` had an unanchored `data/` rule for the runtime directory,
    which also matched src/umbra/crypto/data/. The file existed locally, was
    never committed, and every registry test passed here and failed inside the
    deploy image."""
    import subprocess

    root = DATA.parents[3]
    if not (root / ".git").exists():
        pytest.skip("no git checkout here (the deploy image copies files, not history)")
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", str(DATA)],
        capture_output=True, cwd=root)
    assert tracked.returncode == 0, "services.json is not tracked by git"
