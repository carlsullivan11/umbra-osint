"""Land / corp candidate parse from public HTML."""

from umbra.people.records_parse import parse_public_records_text


def test_parse_requires_name_token():
    out = parse_public_records_text(
        "APN 12-345-678 100 Main Street. Acme Holdings LLC.",
        person_name="Jane Doe",
        kind="property",
    )
    assert out["land"] == []
    assert out["name_hit"] is False


def test_parse_land_when_name_present():
    out = parse_public_records_text(
        "Owner Jane Doe. APN 12-345-678 situs 100 Main Street Bentonville.",
        person_name="Jane Doe",
        kind="property",
        source_url="https://www.bentoncountyar.gov/assessor/",
    )
    assert out["name_hit"] is True
    assert out["land"]
    assert out["land"][0]["apn"].startswith("12")


def test_parse_corp_near_name():
    out = parse_public_records_text(
        "Jane Doe, agent for Doe Holdings LLC file number 1234567.",
        person_name="Jane Doe",
        kind="business",
    )
    assert any("doe holdings llc" in (c["org_name"] or "").lower() for c in out["corps"])


def test_parse_index_json_courtlistener():
    from umbra.people.records_parse import parse_index_json

    payload = """
    {"count": 1, "results": [
      {"caseName": "United States v. Doe", "absolute_url": "/opinion/1/us-v-doe/"}
    ]}
    """
    out = parse_index_json(
        payload,
        person_name="Jane Doe",
        source_url="https://www.courtlistener.com/api/rest/v4/search/?q=Doe",
    )
    assert out["name_hit"] is True
    assert out["urls"][0].startswith("https://www.courtlistener.com/")
