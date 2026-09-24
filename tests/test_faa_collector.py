"""faa_registry — offline, and careful about what a registration means.

The honesty rules here are the point of the collector, not decoration on top of
it. A registration record is routinely read as three things it is not: proof of
who was flying, proof of who owns the airframe economically, and — on a miss —
proof that no registration exists.
"""
from __future__ import annotations

from pathlib import Path

import pytest

import httpx

from umbra.collectors.base import CollectorContext, default_registry
from umbra.core.config import Settings
from umbra.collectors.faa_registry import FaaRegistryCollector
from umbra.core.models import EntityType
from umbra.db.schema import Entity
from umbra.lake.faa import FaaLake

from faa_fixtures import _acftref_row, _master_row, build_zip


def _entity(value: str) -> Entity:
    return Entity(id="e1", case_id="c1", type=EntityType.AIRCRAFT.value, value=value,
                  norm_key=f"aircraft:{value}", props={}, confidence=0.9, is_seed=True)


def _ctx() -> CollectorContext:
    return CollectorContext(settings=Settings(), case_id="c", run_id="r",
                            http=httpx.Client(timeout=5))


@pytest.fixture
def lake(tmp_path: Path) -> FaaLake:
    z = build_zip(
        tmp_path / "r.zip",
        [
            _master_row(n_number="737KL", name="ACME AVIATION LLC",
                        mfr_code="0020901", type_reg="7"),
            _master_row(n_number="100", name="BENE MARY D", mfr_code="7100510",
                        type_reg="1"),
            _master_row(n_number="55X", name="OLD IRON LLC", mfr_code="7100510",
                        type_reg="7", status="X"),
        ],
        [
            _acftref_row(code="0020901", mfr="AAR AIRLIFT GROUP INC", model="UH-60A"),
            _acftref_row(code="7100510", mfr="PIPER", model="J3C-65"),
        ],
    )
    lk = FaaLake(tmp_path / "faa.sqlite")
    lk.import_zip(z)
    return lk


def run(lake, value):
    return FaaRegistryCollector(lake=lake).collect(_entity(value), _ctx())


# --- registration, the question it actually answers ------------------------

def test_a_registered_aircraft_produces_evidence(lake):
    res = run(lake, "N737KL")
    assert len(res.evidence) == 1
    assert "ACME AVIATION LLC" in res.evidence[0].summary


def test_the_airframe_is_reported(lake):
    assert "UH-60A" in run(lake, "N737KL").evidence[0].summary


def test_evidence_cites_the_file_and_the_import_date(lake):
    ev = run(lake, "N737KL").evidence[0]
    assert "FAA Releasable Aircraft Database" in ev.source_name
    assert "imported" in ev.source_name
    assert ev.raw["lake_imported_at"]


def test_evidence_confidence_matches_the_declared_trust(lake):
    from umbra.core.scoring import COLLECTOR_TRUST

    assert run(lake, "N737KL").evidence[0].confidence == pytest.approx(
        COLLECTOR_TRUST["faa_registry"])


# --- registrant is not operator --------------------------------------------

def test_every_hit_says_registrant_is_not_operator(lake):
    notes = " ".join(run(lake, "N737KL").notes)
    assert "not necessarily the operator" in notes


def test_an_org_registrant_is_a_candidate_not_an_identity(lake):
    res = run(lake, "N737KL")
    org = [e for e in res.entities if e.type == EntityType.ORG]
    assert len(org) == 1
    assert org[0].value == "ACME AVIATION LLC"
    # Below the 0.85 evidence confidence on purpose: the record is a name
    # string in a government file, not a verified corporate identity.
    assert org[0].confidence < 0.85
    assert res.edges[0].props["candidate"] is True


def test_an_individual_registrant_does_not_become_a_person_entity(lake):
    """A registration record says nothing about conduct. Minting a PERSON node
    invites a pivot into person collectors off exactly that."""
    res = run(lake, "N100")
    assert not [e for e in res.entities if e.type == EntityType.PERSON]
    assert not [e for e in res.entities if e.type == EntityType.ORG]


def test_an_individual_registrant_is_still_reported_in_evidence(lake):
    """Withholding the fact would be its own dishonesty — it is a public
    record. The care is in not turning it into a graph pivot."""
    res = run(lake, "N100")
    assert "BENE MARY D" in res.evidence[0].summary


# --- absence is unchecked, never "not registered" --------------------------

def test_a_miss_never_says_not_registered(lake):
    notes = " ".join(run(lake, "N99999").notes).lower()
    assert "not registered" not in notes
    assert not run(lake, "N99999").evidence


def test_a_miss_explains_the_withholding_programme(lake):
    notes = " ".join(run(lake, "N99999").notes)
    assert "44114" in notes


def test_an_empty_lake_is_unchecked_not_a_clean_result(tmp_path):
    res = FaaRegistryCollector(lake=FaaLake(tmp_path / "none.sqlite")).collect(
        _entity("N737KL"), _ctx())
    notes = " ".join(res.notes).lower()
    assert "unknown rather than unregistered" in notes
    assert "umbra faa sync" in notes
    assert not res.evidence


def test_an_empty_lake_reads_differently_from_a_miss(tmp_path, lake):
    """Two different facts. Collapsing them is how a cold lake becomes a
    confident all-clear."""
    empty = FaaRegistryCollector(lake=FaaLake(tmp_path / "none.sqlite")).collect(
        _entity("N737KL"), _ctx())
    miss = run(lake, "N99999")
    assert " ".join(empty.notes) != " ".join(miss.notes)


def test_a_non_n_number_is_refused_without_touching_the_lake(lake):
    res = run(lake, "example.com")
    assert "Not a US N-number" in " ".join(res.notes)
    assert not res.evidence


# --- status ----------------------------------------------------------------

def test_a_non_valid_status_code_is_flagged(lake):
    assert "not 'V'" in " ".join(run(lake, "N55X").notes)


def test_a_valid_status_is_not_flagged(lake):
    assert "not 'V'" not in " ".join(run(lake, "N737KL").notes)


# --- wiring ----------------------------------------------------------------

def test_the_collector_is_registered():
    assert "faa_registry" in {c.name for c in default_registry().list()}


def test_it_declares_aircraft_as_its_only_input():
    reg = {c.name: c for c in default_registry().list()}
    assert reg["faa_registry"].inputs == {EntityType.AIRCRAFT}


def test_it_makes_no_network_call(lake, monkeypatch):
    """Offline is a property, not an intention. Any egress here is a bug."""
    import httpx

    def boom(*a, **k):
        raise AssertionError("faa_registry must not touch the network")

    monkeypatch.setattr(httpx.Client, "request", boom)
    monkeypatch.setattr(httpx.Client, "send", boom)
    assert run(lake, "N737KL").evidence


def test_the_playbook_list_still_matches_the_registry():
    """_PLAYBOOK_COLLECTORS is pinned to the live registry so a new collector
    cannot be silently left out of the playbooks."""
    from umbra.cli.playbook_cmd import _PLAYBOOK_COLLECTORS

    assert set(_PLAYBOOK_COLLECTORS) == {c.name for c in default_registry().list()}
