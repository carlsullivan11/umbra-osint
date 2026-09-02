from __future__ import annotations

import base64
import json
import struct
from pathlib import Path

import pytest

from umbra.lake.ct import CertRecord, parse_ct_entry, reverse_domain
from umbra.lake.store import LakeStore

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "ct_entries.json").read_text())


# --- reverse_domain --------------------------------------------------------

def test_reverse_domain():
    assert reverse_domain("www.example.com") == "com.example.www"
    assert reverse_domain("example.com") == "com.example"
    assert reverse_domain("*.example.com") == "com.example.*"
    assert reverse_domain("") == ""
    assert reverse_domain("A.B.C") == "c.b.a"


# --- parsing real CT entries ----------------------------------------------

def test_parse_real_x509_entry():
    e = FIXTURE["0"]
    rec = parse_ct_entry(e["leaf_input"], e["extra_data"])
    assert rec is not None and rec.error is None
    assert rec.entry_type == 0
    assert set(rec.domains) == set(e["expected_domains"])
    assert rec.issuer  # issuer org present
    assert rec.not_before and rec.not_after


def test_precert_path_extracts_same_domains():
    """Precert path reads the DER from extra_data. Build a precert-shaped entry
    from the real x509 cert's DER and assert the entry_type==1 branch extracts
    the same domains — a deterministic test of the extra_data offset logic."""
    e = FIXTURE["0"]
    leaf = base64.b64decode(e["leaf_input"])
    clen = int.from_bytes(leaf[12:15], "big")
    der = leaf[15:15 + clen]                       # the real DER cert
    # Fake precert leaf: version|leaf_type|timestamp|entry_type=1 (+ dummy body)
    fake_leaf = leaf[0:10] + struct.pack(">H", 1) + b"\x00" * 4
    # extra_data PrecertChainEntry: 3-byte len + DER (+ empty chain)
    extra = len(der).to_bytes(3, "big") + der
    rec = parse_ct_entry(base64.b64encode(fake_leaf).decode(),
                         base64.b64encode(extra).decode())
    assert rec is not None and rec.error is None
    assert rec.entry_type == 1
    assert set(rec.domains) == set(e["expected_domains"])


def test_parse_bad_input_never_raises():
    assert parse_ct_entry("!!notb64!!", "") is not None  # returns error record
    assert parse_ct_entry("", "") is None                # too short → None
    # unknown entry type → None
    leaf = b"\x00\x00" + b"\x00" * 8 + struct.pack(">H", 9)
    assert parse_ct_entry(base64.b64encode(leaf).decode(), "") is None


# --- owned corpus store ----------------------------------------------------

@pytest.fixture
def store(tmp_path):
    return LakeStore(f"sqlite:///{tmp_path / 'lake.db'}")


def _rec(domains, ts=1000, idx_type=0):
    return CertRecord(idx_type, ts, sorted(domains), domains[0], "Test CA",
                      "ff", "2026-01-01T00:00:00+00:00", "2026-04-01T00:00:00+00:00")


def test_store_add_and_subtree_search(store):
    recs = [
        _rec(["example.com", "www.example.com"]),
        _rec(["api.example.com"]),
        _rec(["*.cdn.example.com"]),
        _rec(["notexample.com"]),        # must NOT match example.com subtree
        _rec(["example.com.evil.net"]),  # must NOT match (different registrable)
    ]
    certs, domains = store.add_records("testlog", 0, recs)
    assert certs == 5 and domains == 6

    subs = store.distinct_subdomains("example.com")
    assert "example.com" in subs
    assert "www.example.com" in subs
    assert "api.example.com" in subs
    assert "*.cdn.example.com" in subs
    assert "notexample.com" not in subs
    assert "example.com.evil.net" not in subs


def test_store_exact_vs_subtree(store):
    store.add_records("t", 0, [_rec(["example.com"]), _rec(["a.example.com"])])
    assert len(store.search("example.com", exact=True)) == 1
    assert len(store.search("example.com", exact=False)) == 2


def test_store_idempotent_reingest(store):
    recs = [_rec(["example.com"]), _rec(["a.example.com"])]
    a = store.add_records("t", 0, recs)
    b = store.add_records("t", 0, recs)   # same indices again
    assert a == (2, 2)
    assert b == (0, 0)                     # nothing duplicated
    assert store.stats()["certs"] == 2


def test_store_checkpoint_roundtrip(store):
    assert store.get_checkpoint("t") is None
    store.set_checkpoint("t", 500, 1000)
    assert store.get_checkpoint("t") == 500
    store.set_checkpoint("t", 750, 1200)
    assert store.get_checkpoint("t") == 750
    assert store.stats()["checkpoints"]["t"]["tree_size"] == 1200
