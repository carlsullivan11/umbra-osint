"""animal_registry — the publication rules are the feature.

A registry that names people as animal abusers is only as defensible as its
worst row. These tests pin the rules in the storage layer: only cited findings
are stored, reports never surface, disputes hide, delistings propagate, and a
broken export cannot wipe a source.
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from umbra.collectors.animal_registry import AnimalRegistryCollector
from umbra.collectors.base import CollectorContext, default_registry
from umbra.core.config import Settings
from umbra.core.models import EntityType
from umbra.db.schema import Entity
from umbra.lake.animal_registry import AnimalRegistryLake, RegistryError

SRC_URL = "https://registry.example.gov/animal-abuse"


def _row(name="Jane Q Doe", disposition="convicted", **kw):
    base = {"name": name, "offense": "Aggravated animal cruelty",
            "disposition": disposition, "state": "NY", "county": "Suffolk",
            "finding_date": "2024-03-01"}
    base.update(kw)
    return base


@pytest.fixture
def lake(tmp_path: Path) -> AnimalRegistryLake:
    lk = AnimalRegistryLake(tmp_path / "ar.sqlite")
    lk.add_source("ny-test", name="Test County Registry", kind="government_registry",
                  url=SRC_URL, jurisdiction="NY")
    yield lk
    lk.close()


def _import(lake, rows, **kw):
    return lake.import_rows("ny-test", rows, **kw)


# --- only findings are stored ----------------------------------------------

def test_a_conviction_is_stored_and_searchable(lake):
    res = _import(lake, [_row(record_id="A1")])
    assert res.stored == 1
    hits = lake.search("Jane Doe")
    assert [h["entry_id"] for h in hits] == ["ny-test:A1"]
    assert hits[0]["match"] == "partial"  # middle initial was not confirmed
    assert hits[0]["source_url"] == SRC_URL  # falls back to the source's URL


@pytest.mark.parametrize("disposition", ["charged", "arrested", "pending", "acquitted",
                                         "expunged", "something new"])
def test_allegations_reversals_and_unknowns_are_never_stored(lake, disposition):
    res = _import(lake, [_row(record_id="ok"), _row(name="John Roe", disposition=disposition)])
    assert res.skipped_not_a_finding == 1
    assert lake.search("John Roe") == []
    assert lake.status()["entries"] == 1


def test_rows_without_first_and_last_name_or_offense_are_invalid(lake):
    res = _import(lake, [_row(record_id="ok"), _row(name="Cher"), _row(name="Al Poe", offense="")])
    assert res.skipped_invalid == 2


def test_no_street_address_or_dob_column_exists(lake):
    _import(lake, [_row(record_id="A1", address="1 Main St", dob="01/01/1980")])
    e = lake.entry("ny-test:A1")
    assert "address" not in e and "dob" not in e


def test_unknown_source_is_refused(lake):
    with pytest.raises(RegistryError):
        lake.import_rows("nope", [_row()])


# --- snapshots, delisting, retention ---------------------------------------

def test_a_snapshot_delists_rows_the_source_dropped_and_relists_on_return(lake):
    _import(lake, [_row(record_id="A1"), _row(name="John Roe", record_id="B2")])
    res = _import(lake, [_row(record_id="A1")])
    assert res.delisted == 1
    assert lake.search("John Roe") == []
    assert lake.entry("ny-test:B2")["removed_at"]
    res = _import(lake, [_row(record_id="A1"), _row(name="John Roe", record_id="B2")])
    assert res.relisted == 1 and lake.search("John Roe")


def test_append_mode_does_not_delist(lake):
    _import(lake, [_row(record_id="A1")])
    res = _import(lake, [_row(name="John Roe", record_id="B2")], snapshot=False)
    assert res.delisted == 0 and lake.search("Jane Doe")


def test_an_export_with_no_valid_findings_cannot_wipe_the_source(lake):
    _import(lake, [_row(record_id="A1")])
    with pytest.raises(RegistryError):
        _import(lake, [_row(disposition="charged"), {"junk": "x"}])
    assert lake.search("Jane Doe")


def test_retention_stops_publication_of_old_findings(lake):
    _import(lake, [_row(record_id="old", finding_date="2001-01-01"),
                   _row(name="John Roe", record_id="new",
                        finding_date=date.today().replace(day=1).isoformat())])
    lake.add_source("ny-test", name="Test County Registry", kind="government_registry",
                    url=SRC_URL, retention_years=10)
    assert lake.search("Jane Doe") == []
    assert lake.search("John Roe")


# --- reports are leads, never entries --------------------------------------

def test_a_report_is_never_searchable_or_browsable(lake):
    lake.submit_report(submitter_org="Happy Tails Rescue", subject_name="Rex Owner",
                       narrative="Dogs found starved at property", state="NY")
    assert lake.search("Rex Owner") == []
    assert lake.browse() == []
    assert lake.status()["reports_pending"] == 1


def test_a_report_needs_an_organisation(lake):
    with pytest.raises(RegistryError):
        lake.submit_report(submitter_org=" ", subject_name="Rex Owner", narrative="x")


def test_a_report_becomes_visible_only_through_a_cited_finding(lake):
    rep = lake.submit_report(submitter_org="Happy Tails Rescue", subject_name="Rex Owner",
                             narrative="Dogs found starved", state="NY")
    with pytest.raises(RegistryError):
        lake.add_finding(name="Rex Owner", offense="cruelty", disposition="charged",
                         source_url="https://court.example.gov/1", citation="No. 1")
    with pytest.raises(RegistryError):
        lake.add_finding(name="Rex Owner", offense="cruelty", disposition="convicted",
                         source_url="https://court.example.gov/1", citation="")
    e = lake.add_finding(name="Rex Owner", offense="cruelty", disposition="convicted",
                         source_url="https://court.example.gov/1", citation="No. 1",
                         state="NY", actor="reviewer1")
    lake.link_report(rep["report_id"], e["entry_id"], reviewer="reviewer1")
    assert lake.report(rep["report_id"])["status"] == "linked"
    assert [h["entry_id"] for h in lake.search("Rex Owner")] == [e["entry_id"]]
    with pytest.raises(RegistryError):  # already closed
        lake.reject_report(rep["report_id"], reviewer="r", note="n")


def test_manual_source_cannot_be_bulk_imported(lake):
    lake.add_finding(name="Rex Owner", offense="c", disposition="convicted",
                     source_url="https://court.example.gov/1", citation="No. 1")
    with pytest.raises(RegistryError):
        lake.import_rows("manual", [_row()])


# --- disputes --------------------------------------------------------------

def test_an_open_dispute_hides_and_a_rejected_one_restores(lake):
    _import(lake, [_row(record_id="A1")])
    d = lake.open_dispute("ny-test:A1", basis="wrong person")
    assert lake.search("Jane Doe") == [] and lake.browse() == []
    lake.resolve_dispute(d["dispute_id"], upheld=False, reviewer="r", note="DOB matches record")
    assert lake.search("Jane Doe")


def test_an_upheld_dispute_survives_reimport(lake):
    _import(lake, [_row(record_id="A1")])
    d = lake.open_dispute("ny-test:A1", basis="conviction vacated on appeal")
    lake.resolve_dispute(d["dispute_id"], upheld=True, reviewer="r", note="appellate order")
    _import(lake, [_row(record_id="A1")])
    assert lake.search("Jane Doe") == []
    assert lake.entry("ny-test:A1")["suppressed_at"]


def test_moderation_is_audited(lake):
    _import(lake, [_row(record_id="A1")])
    d = lake.open_dispute("ny-test:A1", basis="wrong person", actor="visitor")
    lake.resolve_dispute(d["dispute_id"], upheld=True, reviewer="rev", note="n")
    actions = [e["action"] for e in lake.events(target="ny-test:A1")]
    assert actions == ["dispute.upheld", "dispute.open"]


# --- search ----------------------------------------------------------------

def test_state_filter_and_match_strength(lake):
    _import(lake, [_row(record_id="A1"), _row(record_id="A2", state="TX")])
    assert {h["state"] for h in lake.search("Jane Doe", state="ny")} == {"NY"}
    assert lake.search("Jane Q Doe")[0]["match"] == "exact"
    assert lake.search("J Doe")[0]["match"] == "weak"


# --- collector -------------------------------------------------------------

def _entity(value, **props):
    return Entity(id="e1", case_id="c1", type=EntityType.PERSON.value, value=value,
                  norm_key=f"person:{value.lower()}", props=props, confidence=0.9,
                  is_seed=True)


def _ctx():
    return CollectorContext(settings=Settings(), case_id="c", run_id="r",
                            http=httpx.Client(timeout=5))


def test_collector_is_registered():
    assert "animal_registry" in {c.name for c in default_registry().list()}


def test_collector_empty_lake_is_unknown_not_clean(tmp_path):
    lk = AnimalRegistryLake(tmp_path / "e.sqlite")
    res = AnimalRegistryCollector(lake=lk).collect(_entity("Jane Doe"), _ctx())
    assert res.evidence == []
    assert any("unknown, not clean" in n for n in res.notes)


def test_collector_reports_cited_evidence_without_new_person_nodes(lake):
    _import(lake, [_row(record_id="A1", citation="Ind. 123-2024")])
    res = AnimalRegistryCollector(lake=lake).collect(_entity("Jane Doe"), _ctx())
    assert res.entities == [] and res.edges == []
    ev = res.evidence[0]
    assert ev.source_url == SRC_URL
    assert ev.raw["citation"] == "Ind. 123-2024"
    assert ev.raw["identity_confirmed"] is False
    assert "convicted" in ev.summary


def test_collector_drops_weak_matches(lake):
    _import(lake, [_row(name="Jane Doe", record_id="A1")])
    res = AnimalRegistryCollector(lake=lake).collect(_entity("Jim Doe"), _ctx())
    assert res.evidence == []


def test_collector_honours_state_prop(lake):
    _import(lake, [_row(record_id="A1", state="TX")])
    res = AnimalRegistryCollector(lake=lake).collect(_entity("Jane Doe", state="NY"), _ctx())
    assert res.evidence == []


# --- CLI -------------------------------------------------------------------

def test_cli_round_trip(tmp_path, monkeypatch):
    from umbra.cli.main import app

    monkeypatch.setenv("UMBRA_ANIMAL_REGISTRY_DB", str(tmp_path / "cli.sqlite"))
    csv = tmp_path / "export.csv"
    csv.write_text("Name,Offense,Disposition,State,Record_ID\n"
                   "Jane Doe,Animal cruelty,Convicted,NY,A1\n"
                   "John Roe,Animal cruelty,Charged,NY,B2\n")
    run = CliRunner().invoke
    r = run(app, ["animal-registry", "source", "add", "ny-test", "--name", "Test",
                  "--url", SRC_URL])
    assert r.exit_code == 0, r.output
    r = run(app, ["animal-registry", "import-csv", "ny-test", str(csv)])
    assert r.exit_code == 0 and "stored 1" in r.output, r.output
    r = run(app, ["animal-registry", "search", "Jane Doe", "--json"])
    assert '"ny-test:A1"' in r.output
    r = run(app, ["animal-registry", "search", "John Roe"])
    assert "No publishable finding" in r.output
    r = run(app, ["animal-registry", "add-finding", "--name", "Rex Owner", "--offense", "x",
                  "--disposition", "arrested", "--source-url", "https://c.example.gov/1",
                  "--citation", "No. 1"])
    assert r.exit_code == 2 and "not a finding" in r.output
