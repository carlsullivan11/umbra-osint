"""Sex-offender registry parse: first+last required."""

from umbra.people.sor_parse import parse_sor_html


def test_sor_requires_first_and_last():
    html = """
    <html><body>
    John Q Public, also known as Johnny Public.
    DOB: 01/02/1980. Offender ID: AR-12345. Tier 2.
    Address: 100 Main Street. Sexual assault.
    </body></html>
    """
    hit = parse_sor_html(html, person_name="John Public", source_url="https://www.nsopw.gov/x")
    assert hit["name_hit"] is True
    assert hit["dob"]
    assert hit["addresses"]
    assert "sexual assault" in hit["offenses"]
    assert hit["registry_id"] == "AR-12345"

    miss = parse_sor_html(html, person_name="Jane Public")
    assert miss["name_hit"] is False


def test_sor_last_name_only_is_not_a_hit():
    html = "<p>The Public family of Bentonville. Sex offender registry search.</p>"
    parsed = parse_sor_html(html, person_name="John Public")
    assert parsed["name_hit"] is False
