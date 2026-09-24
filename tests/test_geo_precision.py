"""City-grade data must not be rendered to eleven centimetres.

Production showed `1.1.1.1 ≈ Sydney, New South Wales, AU (-33.8688,151.209)`.
Six decimal places on a latitude is roughly 11 cm of precision. DB-IP City Lite
is city-grade, and 1.1.1.1 is anycast — the coordinate is where APNIC registered
the block, not where the machine answering you is.

The collector already says so: the module docstring names anycast explicitly and
`_CAVEAT` goes into the notes of every run. The wording was honest and the
number beside it was not, which is the same shape of defect as scoring an
unchecked source at 0.5 while the text said "check error".

Rounding to two decimals (~1.1 km) needs no list of special addresses and cannot
go stale. Full precision stays in `raw` for anyone who wants it.
"""
from __future__ import annotations

import pytest

from umbra.collectors.ip_geo import format_coords


def test_six_decimals_are_not_claimed():
    assert format_coords(-33.868800, 151.209000) == "-33.87,151.21"


def test_rounding_is_to_city_scale():
    """Two decimals is about 1.1 km — the right order for a city database."""
    out = format_coords(37.774929, -122.419418)
    lat, lon = out.split(",")
    assert len(lat.split(".")[1]) <= 2
    assert len(lon.split(".")[1]) <= 2


def test_zero_is_rendered_not_dropped():
    """0.0 is a real coordinate (Gulf of Guinea) and must not fall to a
    falsy check — the classic way a null island becomes a missing field."""
    assert format_coords(0.0, 0.0) == "0.0,0.0"


@pytest.mark.parametrize("lat,lon", [(None, 1.0), (1.0, None), (None, None)])
def test_missing_coordinates_render_as_nothing(lat, lon):
    assert format_coords(lat, lon) == ""


def test_negative_values_keep_their_sign():
    assert format_coords(-0.127758, -51.5) == "-0.13,-51.5"


def test_the_summary_uses_the_rounded_form():
    """Guard against the formatter existing but not being wired in."""
    import inspect

    from umbra.collectors import ip_geo

    src = inspect.getsource(ip_geo)
    assert "format_coords(" in src
    assert "{hit.latitude},{hit.longitude}" not in src
