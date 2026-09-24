"""parse_inmate_json: first AND last, or it is not a hit."""
from __future__ import annotations

from umbra.people.inmate_parse import parse_inmate_json

PAYLOAD = {
    "Captcha": False,
    "Messages": {},
    "InmateLocator": [
        {
            "nameLast": "SMITH",
            "nameFirst": "JOHN",
            "nameMiddle": "LEE",
            "sex": "Male",
            "race": "Black",
            "age": "80",
            "inmateNum": "00123-871",
            "releaseCode": "R",
            "faclCode": "CDT",
            "faclName": "Detroit",
            "faclType": "RRM",
            "faclURL": "/locations/ccm/cdt/",
            "projRelDate": "",
            "actRelDate": "02/17/1994",
        },
        {
            "nameLast": "SMITH",
            "nameFirst": "JANE",
            "nameMiddle": "",
            "sex": "Female",
            "race": "White",
            "age": "40",
            "inmateNum": "00531-196",
            "releaseCode": "",
            "faclCode": "",
            "faclName": "IN TRANSIT",
            "faclType": "",
            "faclURL": "",
            "projRelDate": "UNKNOWN",
            "actRelDate": "",
        },
    ],
}


def test_first_and_last_together_is_a_hit():
    out = parse_inmate_json(PAYLOAD, person_name="John Smith", source_url="https://www.bop.gov/inmateloc/")
    assert out["name_hit"] is True
    assert len(out["matches"]) == 1
    assert out["matches"][0]["register_number"] == "00123-871"
    assert out["matches"][0]["facility_name"] == "Detroit"


def test_last_name_alone_is_not_a_hit():
    out = parse_inmate_json(PAYLOAD, person_name="Madonna Smith", source_url="x")
    assert out["name_hit"] is False
    assert out["matches"] == []


def test_no_matching_row_at_all_is_not_a_hit():
    out = parse_inmate_json(PAYLOAD, person_name="Zed Zapata", source_url="x")
    assert out["name_hit"] is False
    assert out["total_rows"] == 2


def test_empty_payload_is_handled():
    out = parse_inmate_json({}, person_name="John Smith", source_url="x")
    assert out["name_hit"] is False
    assert out["matches"] == []
    assert out["total_rows"] == 0


def test_non_dict_payload_is_handled():
    out = parse_inmate_json(None, person_name="John Smith", source_url="x")
    assert out["name_hit"] is False


def test_captcha_flag_is_surfaced():
    out = parse_inmate_json({"Captcha": True, "InmateLocator": []}, person_name="John Smith", source_url="x")
    assert out["captcha"] is True
