"""US-wide state packs: 50 states + DC, comma-state matching."""

from umbra.collectors.public_records_portals import _PORTALS, resolve_regions
from umbra.collectors.us_state_portals import STATE_ABBRS, detect_state_keys, state_packs


def test_all_states_have_packs():
    packs = state_packs()
    assert len(STATE_ABBRS) == 51  # 50 + DC
    for abbr in STATE_ABBRS:
        key = f"us-{abbr}"
        assert key in packs
        assert key in _PORTALS
        assert len(_PORTALS[key]) >= 3


def test_comma_state_austin_tx():
    regs = resolve_regions({"location": "Austin, TX"})
    assert "us-tx" in regs
    assert "us-federal" in regs


def test_full_name_oregon_not_or_token():
    regs = resolve_regions({"location": "Portland, Oregon"})
    assert "us-or" in regs
    # prose "in" must not become Indiana
    assert "us-in" not in resolve_regions({"location": "born in Texas"})
    assert "us-tx" in resolve_regions({"location": "born in Texas"})


def test_washington_county_md_is_not_arkansas():
    regs = resolve_regions({"location": "Washington County, MD"})
    assert "us-ar-washington" not in regs
    assert "us-md" in regs


def test_fayetteville_still_washington_county_ar():
    regs = resolve_regions({"location": "Fayetteville, AR"})
    assert "us-ar-washington" in regs
    assert "us-ar" in regs


def test_explicit_state_prop():
    assert "us-oh" in resolve_regions({"state": "OH"})
    assert "us-oh" in detect_state_keys("", {"state": "Ohio"})
