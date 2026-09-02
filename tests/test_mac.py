"""Stage S13 / MAC lookup M1–M3.

M1 normalize + bit flags · M2 OUI lake lookup · M3 intent wiring + CLI + evidence.

Two things drive the design:

**Longest-prefix match.** IEEE carves MA-M (28-bit) and MA-S (36-bit) blocks out
of the 24-bit MA-L space, so a 24-bit-only lookup returns the *umbrella* holder
— usually "IEEE Registration Authority" — instead of the real vendor. Measured
on the live registries that is wrong for ~13,500 prefixes. It is the easiest way
for this collector to be confidently wrong, so it is pinned here.

**A MAC is a layer-2 identifier.** It is not routable, not geolocatable, and a
randomized one is not a durable device ID. The collector has to say so rather
than let a vendor string imply more than it knows.
"""
from __future__ import annotations

import csv
from pathlib import Path

import pytest

from umbra.core.mac import (
    canonical_mac,
    is_mac_like,
    mac_facts,
    normalize_mac,
)
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key, normalize_value
from umbra.lake.oui import OuiTable

APPLE = "A4:83:E7:11:22:33"


# --- M1: normalize --------------------------------------------------------

@pytest.mark.parametrize("raw", [
    "a4:83:e7:11:22:33",
    "A4-83-E7-11-22-33",
    "a483.e711.2233",     # Cisco
    "a483e7112233",
    " A4:83:E7:11:22:33 ",
])
def test_every_format_operators_paste_normalizes_to_one_value(raw):
    """DHCP exports, switch CAM tables and EDR all disagree about separators.
    They must all collapse to one entity, not four."""
    assert normalize_value(EntityType.MAC, raw) == APPLE


def test_the_same_address_in_two_formats_is_one_entity():
    assert entity_key(EntityType.MAC, "a483.e711.2233") == entity_key(EntityType.MAC, APPLE)


@pytest.mark.parametrize("bad", [
    "", "   ", "not-a-mac", "a4:83:e7:11:22", "a4:83:e7:11:22:33:44",
    "zz:83:e7:11:22:33", "a483e71122",
])
def test_invalid_input_is_rejected(bad):
    with pytest.raises(ValueError):
        normalize_value(EntityType.MAC, bad)


def test_a_bare_oui_prefix_is_accepted_as_a_prefix():
    """`aa:bb:cc` from a vendor-lookup question is a legitimate query, and must
    not be silently padded into a full address that does not exist."""
    assert normalize_value(EntityType.MAC, "a4:83:e7") == "A4:83:E7"
    assert mac_facts("A4:83:E7")["is_prefix"] is True
    assert mac_facts(APPLE)["is_prefix"] is False


def test_normalize_mac_strips_to_hex():
    assert normalize_mac("a4:83:e7:11:22:33") == "A483E7112233"
    assert canonical_mac("A483E7112233") == APPLE


def test_is_mac_like_does_not_match_ordinary_text():
    assert is_mac_like(APPLE)
    assert not is_mac_like("192.168.1.1")
    assert not is_mac_like("2026-08-15")
    assert not is_mac_like("example.com")


# --- M1: the bits ---------------------------------------------------------

def test_unicast_universal_address_is_unremarkable():
    f = mac_facts(APPLE)
    assert f["is_multicast"] is False
    assert f["is_local"] is False
    assert f["is_probably_randomized"] is False


def test_multicast_bit_is_read_from_the_low_bit_of_the_first_octet():
    assert mac_facts("01:00:5E:00:00:01")["is_multicast"] is True
    assert mac_facts("33:33:00:00:00:01")["is_multicast"] is True   # IPv6 multicast
    assert mac_facts("A4:83:E7:11:22:33")["is_multicast"] is False


def test_broadcast_is_recognised_rather_than_looked_up_as_a_vendor():
    f = mac_facts("FF:FF:FF:FF:FF:FF")
    assert f["is_broadcast"] is True
    assert f["is_multicast"] is True


def test_locally_administered_bit():
    assert mac_facts("02:00:00:11:22:33")["is_local"] is True
    assert mac_facts("A4:83:E7:11:22:33")["is_local"] is False


@pytest.mark.parametrize("mac", ["02:1A:2B:3C:4D:5E", "6E:1A:2B:3C:4D:5E",
                                 "AA:1A:2B:3C:4D:5E", "EE:1A:2B:3C:4D:5E"])
def test_private_wifi_addresses_are_flagged_as_probably_randomized(mac):
    """iOS/Android private Wi-Fi addresses set the local bit. Treating one as a
    durable hardware ID is the mistake this flag exists to prevent."""
    f = mac_facts(mac)
    assert f["is_local"] is True
    assert f["is_probably_randomized"] is True


def test_a_randomized_address_says_it_is_not_a_durable_identifier():
    assert any("not" in n.lower() and "durable" in n.lower()
               for n in mac_facts("02:1A:2B:3C:4D:5E")["notes"])


def test_facts_include_the_oui():
    assert mac_facts(APPLE)["oui"] == "A4:83:E7"


# --- M2: the OUI lake -----------------------------------------------------

@pytest.fixture
def table(tmp_path: Path) -> OuiTable:
    """A slice of the real registries, including an MA-S block carved out of an
    MA-L block registered to the umbrella authority."""
    rows = [
        ("A483E7", 24, "MA-L", "Apple, Inc."),
        ("8C1F64", 24, "MA-L", "IEEE Registration Authority"),
        ("8C1F64A", 28, "MA-M", "Wuhan Xingtuxinke ElectronicCo.,Ltd"),
        ("8C1F642", 28, "MA-M", "Shenzhen Tuge Technology Co., Ltd."),
        ("8C1F64000", 36, "MA-S", "Xiamen Cheerzing IOT Technology Co.,Ltd."),
        ("080030", 24, "MA-L",
         "NETWORK RESEARCH CORPORATION | ROYAL MELBOURNE INST OF TECH | CERN"),
    ]
    csv_path = tmp_path / "oui.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["prefix", "bits", "registry", "vendor"])
        w.writerows(rows)
    return OuiTable(csv_path)


def test_plain_ma_l_lookup(table):
    hit = table.lookup(APPLE)
    assert hit["vendor"] == "Apple, Inc."
    assert hit["registry"] == "MA-L"
    assert hit["bits"] == 24


def test_ma_s_wins_over_its_ma_l_parent(table):
    """The whole point of the data layer: 8C1F64 is the umbrella registration,
    8C1F64000 is the actual company. A 24-bit-only lookup answers 'IEEE
    Registration Authority' — technically a real row, and useless."""
    hit = table.lookup("8C:1F:64:00:0A:BC")
    assert hit["vendor"] == "Xiamen Cheerzing IOT Technology Co.,Ltd."
    assert hit["bits"] == 36


def test_ma_m_wins_over_its_ma_l_parent(table):
    hit = table.lookup("8C:1F:64:A5:00:01")
    assert hit["vendor"] == "Wuhan Xingtuxinke ElectronicCo.,Ltd"
    assert hit["bits"] == 28


def test_an_address_in_the_umbrella_block_with_no_finer_match_falls_back(table):
    hit = table.lookup("8C:1F:64:FF:FF:FF")
    assert hit["vendor"] == "IEEE Registration Authority"
    assert hit["bits"] == 24


def test_multiple_claimants_are_all_surfaced(table):
    """IEEE registered a few legacy prefixes to several organisations. Picking
    one silently would invent a fact."""
    hit = table.lookup("08:00:30:11:22:33")
    assert len(hit["vendors"]) == 3
    assert "CERN" in hit["vendors"]


def test_unknown_prefix_is_a_miss_not_a_guess(table):
    assert table.lookup("00:00:00:11:22:33") is None


def test_a_bare_prefix_resolves(table):
    assert table.lookup("A4:83:E7")["vendor"] == "Apple, Inc."


def test_a_missing_data_file_is_not_a_crash(tmp_path):
    """The corpus is optional — Umbra runs without it, and the collector must
    degrade to 'unknown vendor', not take the run down."""
    t = OuiTable(tmp_path / "nope.csv")
    assert t.available is False
    assert t.lookup(APPLE) is None


def test_the_real_corpus_table_loads_if_present():
    """Guards the wiring between the app and the wiki data file. Skips where the
    corpus is not checked out (CI without the wiki repo)."""
    t = OuiTable()
    if not t.available:
        pytest.skip("no OUI corpus on this machine")
    assert t.size > 40_000, "the real registries hold ~53k registrations"
    hit = t.lookup(APPLE)
    assert hit and "apple" in hit["vendor"].lower()


# --- M3: the collector ----------------------------------------------------

def _run_collector(mac: str, table: OuiTable):
    from types import SimpleNamespace

    from umbra.collectors.mac_oui import MacOuiCollector

    col = MacOuiCollector(table=table)
    entity = SimpleNamespace(
        type="mac", value=mac, norm_key=entity_key(EntityType.MAC, mac), props={},
    )
    ctx = SimpleNamespace(settings=None, case_id="c_test", run_id="r_test", http=None)
    return col.collect(entity, ctx)


def test_collector_emits_vendor_evidence(table):
    """The stage DoD: 'collector evidence vendor'."""
    res = _run_collector(APPLE, table)
    assert res.evidence, "a lookup with a hit must leave evidence"
    ev = res.evidence[0]
    assert "Apple" in ev.summary
    assert ev.collector == "mac_oui"
    assert ev.raw["registry"] == "MA-L"


def test_collector_links_the_address_to_the_registrant_org(table):
    res = _run_collector(APPLE, table)
    orgs = [e for e in res.entities if e.type == EntityType.ORG]
    assert orgs and "apple" in orgs[0].value.lower()
    assert res.edges, "the graph should show who registered the block"


def test_collector_records_every_claimant_as_its_own_org(table):
    res = _run_collector("08:00:30:11:22:33", table)
    assert len({e.value for e in res.entities if e.type == EntityType.ORG}) == 3


def test_collector_says_a_mac_is_layer_2(table):
    """A vendor string invites 'so where is it?'. The answer is in the notes,
    every time, not just when someone asks."""
    notes = " ".join(_run_collector(APPLE, table).notes).lower()
    assert "layer 2" in notes or "l2" in notes
    assert "geolocat" in notes


def test_collector_does_not_invent_a_vendor_on_a_miss(table):
    res = _run_collector("00:00:00:11:22:33", table)
    assert not [e for e in res.entities if e.type == EntityType.ORG]
    assert any("no registration" in n.lower() or "unknown" in n.lower() for n in res.notes)


def test_collector_flags_a_randomized_address_and_skips_the_vendor_claim(table):
    """A locally administered address has no registrant by construction —
    resolving one to a vendor would be pure fiction."""
    res = _run_collector("02:1A:2B:3C:4D:5E", table)
    assert not [e for e in res.entities if e.type == EntityType.ORG]
    assert any("randomi" in n.lower() or "locally administered" in n.lower()
               for n in res.notes)


def test_collector_without_the_corpus_reports_it_instead_of_failing(tmp_path):
    res = _run_collector(APPLE, OuiTable(tmp_path / "nope.csv"))
    assert res.notes
    assert any("corpus" in n.lower() or "not available" in n.lower() for n in res.notes)


def test_collector_is_registered_and_accepts_mac_entities():
    from umbra.collectors.base import default_registry

    col = default_registry().get("mac_oui")
    assert col is not None, "mac_oui must be in default_registry()"
    assert EntityType.MAC in col.inputs


# --- M3: intent wiring ----------------------------------------------------

def test_intent_detects_a_mac_in_free_text():
    from umbra.intent.extract import extract_hits

    hits = extract_hits("unknown NIC a4:83:e7:11:22:33 on the guest vlan")
    macs = [h for h in hits if h.type == EntityType.MAC]
    assert macs and macs[0].value == APPLE


@pytest.mark.parametrize("text", [
    "aabb.ccdd.eeff from the switch CAM table",
    "hardware address A4-83-E7-11-22-33",
])
def test_intent_detects_the_other_formats(text):
    from umbra.intent.extract import extract_hits

    assert any(h.type == EntityType.MAC for h in extract_hits(text))


def test_intent_does_not_mistake_other_identifiers_for_macs():
    """A 12-hex-digit blob is a common shape — commit SHAs, hashes, ids. Only
    separated forms and unambiguous context should become a MAC seed."""
    from umbra.intent.extract import extract_hits

    text = "commit 4f3a2b1c9d8e and build 2026081512 for example.com"
    assert not [h for h in extract_hits(text) if h.type == EntityType.MAC]


def test_a_mac_seed_plans_the_mac_collector():
    from umbra.intent.plan import analyze_intent
    from umbra.intent.schema import AnalyzeRequest

    plan = analyze_intent(AnalyzeRequest(
        text="a4:83:e7:11:22:33", authorization_basis="own_asset", use_llm=False,
    ))
    assert "mac_oui" in plan.collectors


def test_a_mac_only_plan_does_not_drag_in_web_search():
    """The fallback for 'no collectors matched' is ddg_search. A MAC lookup is
    an offline table read; it should not quietly become a web search."""
    from umbra.intent.plan import analyze_intent
    from umbra.intent.schema import AnalyzeRequest

    plan = analyze_intent(AnalyzeRequest(
        text="a4:83:e7:11:22:33", authorization_basis="own_asset", use_llm=False,
    ))
    assert "ddg_search" not in plan.collectors


# --- M3: CLI --------------------------------------------------------------

def test_cli_mac_lookup_prints_the_vendor():
    from typer.testing import CliRunner

    from umbra.cli.main import app

    t = OuiTable()
    if not t.available:
        pytest.skip("no OUI corpus on this machine")
    res = CliRunner().invoke(app, ["mac", "lookup", "a4:83:e7:11:22:33"])
    assert res.exit_code == 0, res.output
    assert "Apple" in res.output


def test_cli_mac_lookup_rejects_nonsense():
    from typer.testing import CliRunner

    from umbra.cli.main import app

    res = CliRunner().invoke(app, ["mac", "lookup", "not-a-mac"])
    assert res.exit_code != 0
