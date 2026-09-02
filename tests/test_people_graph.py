"""Person case-graph: kin + location + org entities from an obituary parse."""

from __future__ import annotations

from umbra.core.models import EdgeType, EntityType
from umbra.core.normalize import entity_key
from umbra.people.graph import graph_from_parse
from umbra.people.obituary_parse import parse_obituary_text


def test_graph_emits_person_location_org():
    text = (
        "Jane Roe, 70, of Oakland, CA, passed away March 1, 2025. "
        "She is survived by her husband John Roe. "
        "Smith Funeral Home. Interment Oak Cemetery. "
        "US Marine Corps veteran."
    )
    parsed = parse_obituary_text(text, decedent_name="Jane Roe").to_dict()
    ents, edges = graph_from_parse(
        "Jane Roe",
        parsed,
        source_url="https://en.wikipedia.org/wiki/Jane_Roe",
    )
    types = {e.type for e in ents}
    assert EntityType.PERSON in types
    assert EntityType.LOCATION in types
    assert EntityType.ORG in types
    rels = {e.rel for e in edges}
    assert EdgeType.RELATED_TO in rels
    assert EdgeType.LOCATED_IN in rels
    names = {e.value.lower() for e in ents if e.type == EntityType.PERSON}
    assert "john roe" in names or any("john" in n for n in names)
    src = entity_key(EntityType.PERSON, "Jane Roe")
    assert all(e.source_key == src for e in edges)


def test_graph_skips_empty_name():
    ents, edges = graph_from_parse("", {})
    assert ents == []
    assert edges == []


def test_aka_emits_same_as():
    ents, edges = graph_from_parse(
        "Elizabeth II",
        {"aka": ["Queen Elizabeth II", "Elizabeth Alexandra Mary"]},
    )
    assert any(e.rel == EdgeType.SAME_AS for e in edges)
    names = {e.value.lower() for e in ents if e.type == EntityType.PERSON}
    assert "queen elizabeth ii" in names


def test_attach_land_corp_camera():
    from umbra.people.graph import graph_from_lake
    ents, edges = graph_from_lake(
        "Jane Roe",
        {"full_name": "Jane Roe", "residence": "Oakland, CA"},
        land=[{"apn": "12-345", "situs": "100 Main Street", "source_url": "https://example.gov/a"}],
        corps=[{"org_name": "Roe Holdings LLC", "source_url": "https://example.gov/b"}],
        cameras=[{"label": "Flock Falcon", "lat": 37.8, "lon": -122.27, "osm_id": 1}],
        county=[{"url": "https://www.acgov.org/assessor/", "kind": "property", "title": "Alameda Assessor"}],
    )
    kinds = {e.props.get("kind") for e in ents}
    assert "parcel" in kinds
    assert "sos_candidate" in kinds
    assert "osm_surveillance" in kinds
    rels = {e.props.get("kind") for e in edges}
    assert "land_candidate" in rels
    assert "corp_officer_candidate" in rels
    assert "surveillance" in rels
    assert any(e.type == EntityType.URL and "acgov.org" in e.value for e in ents)
