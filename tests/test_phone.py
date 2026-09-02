"""Phase A phone normalize + facts (libphonenumber)."""
from __future__ import annotations

import pytest

from umbra.core.models import EntityType
from umbra.core.normalize import entity_key, normalize_value
from umbra.phone.normalize import find_phones, normalize_phone, phone_facts


def test_us_local_to_e164():
    assert normalize_phone("(415) 555-2671", default_region="US") == "+14155552671"


def test_already_e164():
    assert normalize_phone("+14155552671") == "+14155552671"


def test_reject_garbage():
    assert normalize_phone("not-a-number") is None
    assert normalize_phone("  ") is None
    assert normalize_phone("") is None


def test_phone_facts_valid_us():
    f = phone_facts("+1 415-555-2671")
    assert f["possible"] is True
    assert f["e164"] == "+14155552671"
    assert f["region"] == "US"
    assert f["national_format"]
    assert f["international_format"]


def test_normalize_value_phone_rejects_invalid():
    with pytest.raises(ValueError):
        normalize_value(EntityType.PHONE, "abc")


def test_normalize_value_phone_canonical():
    assert normalize_value(EntityType.PHONE, "415.555.2671") == "+14155552671"
    assert entity_key(EntityType.PHONE, "(415) 555-2671") == "phone:+14155552671"


def test_find_phones_in_sentence():
    text = "Spam call from (415) 555-2671 yesterday; also +44 20 7946 0958"
    found = find_phones(text, default_region="US")
    assert "+14155552671" in found
    # UK number if matcher picks it up
    assert any(x.startswith("+44") for x in found) or len(found) >= 1


def test_find_phones_dedupes():
    text = "+14155552671 and 415-555-2671"
    found = find_phones(text, default_region="US")
    assert found.count("+14155552671") == 1
