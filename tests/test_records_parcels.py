"""Statewide parcel search: real property records, honest about covering 5 states.

Properties of the code only — never live ArcGIS content. A test that asserted
"Arkansas returns rows for SMITH" would fail the day the state reindexes, and a
failing test in the deploy gate stops every unrelated commit behind it.
"""
from __future__ import annotations

import pytest

from umbra.records.parcels import (
    COVERED_STATES,
    SOURCES,
    ParcelSource,
    search,
    where_clause,
)


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _Http:
    def __init__(self, payload=None, boom=False):
        self.payload = payload if payload is not None else {"features": []}
        self.boom = boom
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        if self.boom:
            raise RuntimeError("connection reset")
        return _Resp(self.payload)


def _rows(n, owner="SMITH, JANE"):
    return {"features": [{"attributes": {"ownername": owner, "adrlabel": "1 MAIN ST",
                                         "adrcity": "ROGERS", "county": "Benton",
                                         "totalvalue": "100"}} for _ in range(n)]}


# --- the where clause is the only place user text reaches a query -----------

def test_tokens_are_anded_so_name_order_does_not_matter():
    """Assessor rolls write 'DOE, JANE' and 'JANE DOE' for the same person."""
    clause = where_clause("ownername", "Jane Doe")
    assert clause.count("LIKE") == 2
    assert " AND " in clause
    assert "'%JANE%'" in clause and "'%DOE%'" in clause


def test_injection_leaves_nothing_that_can_end_a_literal_or_start_a_comment():
    clause = where_clause("ownername", "O'Brien'; DROP TABLE parcels-- x")
    # Statement separator and comment token cannot survive at all.
    assert ";" not in clause
    assert "--" not in clause
    # Every quote is a delimiter or half of a doubled escape, so the attacker's
    # text stays inside the literal it was placed in.
    assert clause.count("'") % 2 == 0
    assert "O''BRIEN" in clause


def test_hyphenated_owner_names_still_work():
    """The `--` defence must not break Wal-Mart."""
    assert "'%WAL-MART%'" in where_clause("ownername", "Wal-Mart Real Estate")


def test_short_tokens_are_dropped():
    """A two-letter token matches most of a state."""
    assert where_clause("f", "Jo") == ""
    assert "LIKE" in where_clause("f", "Jo Smith")
    assert where_clause("f", "Jo Smith").count("LIKE") == 1


def test_query_is_never_sent_for_an_unusable_name():
    http = _Http()
    out = search("J.", http=http)
    assert http.calls == []
    assert out.hits == []
    assert out.notes


# --- absence must never read as a clean result ------------------------------

def test_zero_rows_names_the_states_actually_searched():
    out = search("Jane Doe", http=_Http(), states=["AR"])
    assert out.hits == []
    assert out.searched == ["AR"]
    assert any("not evidence that the name owns no property" in n for n in out.notes)


def test_uncovered_state_says_so_rather_than_returning_empty():
    out = search("Jane Doe", http=_Http(), states=["TX"])
    assert out.hits == []
    assert out.searched == []
    assert any("No parcel layer for TX" in n for n in out.notes)


def test_arcgis_error_body_is_a_source_failure_not_an_absence():
    """ArcGIS answers HTTP 200 with an error payload. unchecked != clean."""
    http = _Http({"error": {"message": "Invalid field: ownername"}})
    out = search("Jane Doe", http=http, states=["AR"])
    assert out.hits == []
    assert any("refused the query" in n and "not an absence" in n for n in out.notes)


def test_transport_failure_is_reported_not_swallowed():
    out = search("Jane Doe", http=_Http(boom=True), states=["AR"])
    assert out.hits == []
    assert any("parcels_AR" in n or "AR" in n for n in out.notes)


# --- results ---------------------------------------------------------------

def test_rows_become_hits_with_state_and_attribution():
    out = search("Jane Smith", http=_Http(_rows(2)), states=["AR"])
    assert len(out.hits) == 2
    assert all(h.state == "AR" for h in out.hits)
    assert all(h.source for h in out.hits)
    assert out.hits[0].address == "1 MAIN ST"


def test_full_page_is_reported_never_silently_capped():
    src = next(s for s in SOURCES if s.state == "AR")
    out = search("Jane Smith", http=_Http(_rows(src.page)), states=["AR"], limit=src.page)
    assert any("probably more" in n for n in out.notes)


def test_truncation_note_blames_the_right_cap():
    """Our page size is ours; do not report it as the source's limit."""
    src = next(s for s in SOURCES if s.state == "AR")

    ours = search("Jane Smith", http=_Http(_rows(5)), states=["AR"], limit=5)
    assert any("Umbra's page size" in n for n in ours.notes)

    # Asking for more than the layer will give makes the cap genuinely theirs.
    theirs = search("Jane Smith", http=_Http(_rows(src.page)), states=["AR"],
                    limit=src.page + 50)
    assert any("layer's own cap" in n for n in theirs.notes)


def test_results_carry_the_home_address_caution():
    out = search("Jane Smith", http=_Http(_rows(1)), states=["AR"])
    assert any("home addresses" in n for n in out.notes)
    assert any("not an identity" in n for n in out.notes)


def test_rows_missing_the_owner_field_are_skipped_not_rendered_blank():
    http = _Http({"features": [{"attributes": {"adrlabel": "1 MAIN ST"}}]})
    assert search("Jane Smith", http=http, states=["AR"]).hits == []


def test_as_dict_is_json_safe():
    import json

    json.dumps(search("Jane Smith", http=_Http(_rows(1)), states=["AR"]).as_dict())


# --- the registry itself ---------------------------------------------------

def test_every_source_is_https_and_names_its_owner_field():
    for s in SOURCES:
        assert s.url.startswith("https://"), s.state
        assert s.owner, s.state
        assert s.attribution, s.state


def test_covered_states_matches_the_registry():
    """Coverage is claimed in notes; it must be derived, never hand-written."""
    assert set(COVERED_STATES) == {s.state for s in SOURCES}
    assert len(COVERED_STATES) == len(set(COVERED_STATES))


def test_out_fields_skips_absent_columns():
    """Not every layer has a value or county column; asking for '' breaks query."""
    s = ParcelSource(state="XX", label="x", url="https://x", owner="OWN")
    assert s.out_fields() == "OWN"
    assert "," not in s.out_fields()


def test_truncation_note_names_the_layer_not_just_the_state():
    """Three identical 'NY: showing 25' lines cannot be told apart."""
    from umbra.records.parcels import from_registry

    # A statewide layer is its state — there is only one of them.
    assert next(s for s in SOURCES if s.state == "AR").where_label() == "AR"

    # Two county layers in one state must not produce identical notes.
    # Built through from_registry because that is the production path.
    albany = from_registry({"layer_url": "https://a/0", "owner_field": "OWNER",
                            "state": "NY", "county": "Albany County",
                            "title": "Tax Parcels"})
    oswego = from_registry({"layer_url": "https://b/0", "owner_field": "OWNER",
                            "state": "NY", "county": "Oswego County",
                            "title": "Tax Parcels"})
    assert albany.where_label() == "Albany County NY"
    assert albany.where_label() != oswego.where_label()


def test_a_layer_with_unresolved_geography_still_gets_a_distinct_label():
    """Gate 4 may leave state/county NULL; the note must not become bare '??'."""
    from umbra.records.parcels import from_registry

    src = from_registry({"layer_url": "https://c/0", "owner_field": "OWNER",
                         "title": "Some County Parcels"})
    assert src.where_label() == "Some County Parcels"
