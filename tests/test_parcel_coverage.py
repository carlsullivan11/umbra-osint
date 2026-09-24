"""Coverage against all 3,143 counties, and targeted discovery to close it.

Discovery ran five generic catalog queries — `title:parcels AND type:"Feature
Service"` and four like it. The ArcGIS catalog returns what it feels like for a
generic term, which is why 3,143 counties produced one or two verified layers
per state. Nothing anywhere said which counties were missing, so "expand
coverage" had no target and no finish line.

Two pieces:

**Targeted queries.** A state name and a county name are the discriminating
terms. 51 state queries plus a query per uncovered county is a plan; five
generic queries is a lottery.

**A ledger.** Coverage is measured against the real county list, so an absent
name reads as "Orange County, TX is not ingested" rather than as an answer
about a person. "Every county" is only a meaningful goal if the gap is
countable.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.records.coverage import (
    county_queries,
    coverage_report,
    state_queries,
    uncovered_counties,
)


# --- targeted queries ------------------------------------------------------

def test_there_is_a_query_for_every_state():
    qs = state_queries()
    assert len(qs) >= 50, "51 states and DC"
    joined = " ".join(qs)
    for st in ("Texas", "California", "Florida", "Vermont"):
        assert st in joined


def test_a_state_query_still_scopes_to_public_feature_services():
    for q in state_queries()[:5]:
        assert "Feature Service" in q
        assert "access:public" in q


def test_county_queries_name_the_county_and_its_state():
    qs = county_queries([{"state": "TX", "county": "Orange County"}])
    assert any("Orange" in q for q in qs)
    assert any("Texas" in q or "TX" in q for q in qs)


def test_county_queries_drop_the_word_county_from_the_search_term():
    """"Orange County County parcels" finds nothing."""
    qs = county_queries([{"state": "TX", "county": "Orange County"}])
    assert not any("Orange County County" in q for q in qs)


def test_county_queries_are_bounded():
    """3,143 counties is 3,143 catalog requests. A sweep must be able to take
    a slice rather than run the whole list every time."""
    many = [{"state": "TX", "county": f"C{i}"} for i in range(500)]
    assert len(county_queries(many, limit=25)) == 25


def test_no_queries_for_an_empty_list():
    assert county_queries([]) == []


# --- the ledger ------------------------------------------------------------

class FakeLake:
    """Stands in for ParcelLake, and must keep matching its interface.

    `count()` was added here when `coverage_report` stopped summing
    `ingested.rows` — that column records what a run *wrote*, and rows whose
    storage key collided were never stored, so the sum overstated the lake by
    77,675 on 2026-09-16. A stub that lags the real object turns a genuine fix
    into a red test about nothing.
    """

    def __init__(self, rows, stored=None):
        self._rows = rows
        self._stored = stored

    def coverage(self):
        return self._rows

    def count(self):
        if self._stored is not None:
            return self._stored
        return sum(int(r.get("rows") or 0) for r in self._rows)


def test_the_report_counts_against_every_county():
    rep = coverage_report(FakeLake([]))
    assert rep["counties_total"] == 3143
    assert rep["counties_covered"] == 0
    assert rep["percent"] == 0.0


def test_a_covered_county_is_counted():
    rep = coverage_report(FakeLake([
        {"state": "FL", "county": "Hillsborough County", "rows": 367316},
    ]))
    assert rep["counties_covered"] == 1
    assert rep["parcels"] == 367316


def test_a_county_with_zero_rows_is_not_counted_as_covered():
    """A layer that was probed and yielded nothing has not covered anybody."""
    rep = coverage_report(FakeLake([
        {"state": "FL", "county": "Hillsborough County", "rows": 0},
    ]))
    assert rep["counties_covered"] == 0


def test_the_report_never_rounds_a_gap_away():
    rep = coverage_report(FakeLake([
        {"state": "FL", "county": "Hillsborough County", "rows": 10},
    ]))
    assert rep["counties_missing"] == 3143 - 1
    assert "3,142" in rep["note"] or "3142" in rep["note"]


def test_the_note_says_absence_is_not_an_answer_about_a_person():
    rep = coverage_report(FakeLake([]))
    low = rep["note"].lower()
    assert "not ingested" in low or "unchecked" in low


def test_uncovered_counties_are_named_not_just_counted():
    """"Expand coverage" needs a target list, not a percentage."""
    missing = uncovered_counties(FakeLake([
        {"state": "FL", "county": "Hillsborough County", "rows": 10},
    ]), limit=5)
    assert len(missing) == 5
    assert all("state" in m and "county" in m for m in missing)
    assert not any(m["county"] == "Hillsborough County" and m["state"] == "FL"
                   for m in missing)


def test_uncovered_is_empty_when_everything_is_covered():
    from umbra.geo.us_counties import coverage_rollup  # noqa: F401

    from umbra.records.coverage import _all_counties

    everything = [{"state": c["state"], "county": c["county"], "rows": 1}
                  for c in _all_counties()]
    assert uncovered_counties(FakeLake(everything)) == []


def test_county_names_match_regardless_of_the_county_suffix():
    """Registries write 'Orange' and 'Orange County' for the same place."""
    rep = coverage_report(FakeLake([
        {"state": "FL", "county": "Hillsborough", "rows": 5},
    ]))
    assert rep["counties_covered"] == 1


def test_a_statewide_layer_can_cover_many_counties():
    """One NC OneMap layer covers 100 counties. Counting it as one would
    understate coverage by 99."""
    rep = coverage_report(FakeLake([
        {"state": "NC", "county": None, "rows": 2_000_000, "statewide": True},
    ]))
    assert rep["counties_covered"] >= 100


def test_a_null_county_without_the_statewide_flag_covers_nothing():
    """A layer whose region could not be resolved is not a claim about a state."""
    rep = coverage_report(FakeLake([
        {"state": None, "county": None, "rows": 500},
    ]))
    assert rep["counties_covered"] == 0


# --- the CLI must use the public API ---------------------------------------

def test_parcels_sync_does_not_reach_past_the_registry_api(tmp_path, monkeypatch):
    """It read `src_lake._conn.execute(...)`. That connection is lazy, so the
    first production run got None and died with AttributeError before touching
    a single layer. Unit tests of the lake could not see it; running the
    command can."""
    from typer.testing import CliRunner

    from umbra.cli.main import app

    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "p.sqlite"))
    out = CliRunner().invoke(app, ["records", "parcels-sync", "--sources", "1"])
    assert "AttributeError" not in out.stdout
    assert "NoneType" not in out.stdout


def test_parcel_coverage_runs_on_an_empty_lake(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from umbra.cli.main import app

    monkeypatch.setenv("UMBRA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("UMBRA_PARCEL_DB", str(tmp_path / "p.sqlite"))
    out = CliRunner().invoke(app, ["records", "parcel-coverage"])
    assert out.exit_code == 0
    assert "3,143" in out.stdout


def test_the_registry_is_opened_from_settings_not_the_bare_constructor():
    """`default_path()` falls back to a home-relative directory. In the
    container that path does not exist, so a bare `ParcelSourceLake()` reported
    "no verified parcel layers" while 36 verified layers sat in /data/lake — an
    empty registry and an unreadable one looked identical from the CLI."""
    import inspect

    import umbra.cli.records_cmd as mod

    # Executable lines only. Checking raw source would forbid the comment that
    # explains the fix — the fourth time that trap has bitten in this repo.
    code = "\n".join(
        line for line in inspect.getsource(mod).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "ParcelSourceLake()" not in code, (
        "use ParcelSourceLake.from_settings(get_settings())"
    )
