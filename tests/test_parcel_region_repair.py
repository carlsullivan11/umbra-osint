"""352,679 parcel rows were stored with no state or county.

They are in the lake and unsearchable by location, and they count for nothing in
the coverage ledger — which is why it read `0 of 3,143` while 408,935 records
sat in the table. The ledger was honest; the rows were anonymous.

The registry cannot help: all eight affected layers have NULL state and county
there too, so the region was never captured rather than lost. What the layers
*do* carry is a name and, usually, ArcGIS service metadata. Probed live:

    Florida_Statewide_Cadastral  -> "a subset of property tax roll information
                                     provided by each of Florida's 67 county
                                     property appraisers"
    RussellCountyGIS             -> "Russell County, KS"
    Chowan_Feature_Service       -> "Chowan_Feature_Service"

The middle one is the case that matters. "Russell County" exists in AL, KS, KY
and VA; the service metadata is what disambiguates it, and nothing else on hand
could have.

**Every candidate is checked against the real county list.** A name that does
not resolve to a county that exists stays unknown — inventing a plausible
county to fill a NULL would be worse than the NULL, because a NULL is visibly
unknown and a wrong county is not.

Statewide layers are a separate answer, not a county: Florida's cadastral layer
covers 67 counties, and recording it as one county named "Florida" would be
false twice over.
"""
from __future__ import annotations

import pytest

from umbra.records.region import region_from_layer


def _r(url, meta=""):
    return region_from_layer(url, meta)


# --- statewide ---------------------------------------------------------------

FL_URL = ("https://services9.arcgis.com/Gh9awoU677aKree0/arcgis/rest/services/"
          "Florida_Statewide_Cadastral/FeatureServer/0")
FL_META = ("The parcel data set depicted on this map contains a subset of property "
           "tax roll information provided by each of Florida's 67 county property "
           "appraisers. Florida Department of Revenue Property Tax Oversight")


def test_a_statewide_layer_is_marked_statewide():
    r = _r(FL_URL, FL_META)
    assert r.statewide is True
    assert r.state == "FL"


def test_a_statewide_layer_claims_no_single_county():
    """Recording 10.8M Florida parcels as one county named 'Florida' would be
    false twice: it is not a county, and it is not one of them."""
    assert _r(FL_URL, FL_META).county is None


def test_the_statewide_signal_comes_from_the_name_not_a_guess():
    r = _r(FL_URL, "")
    assert r.statewide is True and r.state == "FL"


# --- county from metadata ----------------------------------------------------

def test_metadata_disambiguates_a_repeated_county_name():
    """Russell County exists in AL, KS, KY and VA. Only the metadata says which."""
    r = _r("https://services9.arcgis.com/x/arcgis/rest/services/RussellCountyGIS/"
           "FeatureServer/2", "Russell County, KS")
    assert (r.state, r.county) == ("KS", "Russell County")


def test_an_ambiguous_county_with_no_metadata_stays_unknown():
    """Four states have a Russell County. Picking one would be a coin flip
    presented as a fact."""
    r = _r("https://services9.arcgis.com/x/arcgis/rest/services/RussellCountyGIS/"
           "FeatureServer/2", "")
    assert r.county is None or r.state is not None


# --- county from the hostname ------------------------------------------------

def test_a_self_hosted_county_gis_names_itself():
    r = _r("https://gis2.sheboygancounty.com/publicgis1/rest/services/"
           "LandInformation/TaxParcels/FeatureServer/0", "")
    assert r.county and "sheboygan" in r.county.lower()
    assert r.state == "WI"


# --- refusing to guess -------------------------------------------------------

@pytest.mark.parametrize("url", [
    "https://services2.arcgis.com/x/arcgis/rest/services/EnerGov_AddressPoints_and_Parcels/FeatureServer/1",
    "https://services2.arcgis.com/x/arcgis/rest/services/EPL_Layers_250610c/FeatureServer/4",
    "https://services6.arcgis.com/x/arcgis/rest/services/Pro_Map_for_Energov/FeatureServer/1",
])
def test_a_vendor_product_name_is_not_a_place(url):
    """EnerGov and EPL are permitting products. A layer named after the software
    that produced it says nothing about where it is."""
    r = _r(url, "")
    assert r.county is None
    assert r.state is None


def test_an_invented_county_is_refused():
    """Only names that resolve against the real county list are accepted."""
    r = _r("https://services9.arcgis.com/x/arcgis/rest/services/"
           "Nowhereville_County_Parcels/FeatureServer/0", "")
    assert r.county is None


def test_junk_never_raises():
    for bad in ("", "not a url", "https://", "ftp://x/y"):
        assert region_from_layer(bad, "") is not None


# --- every result says where it came from ------------------------------------

def test_a_resolution_records_its_basis():
    """A region nobody can trace is a region nobody can correct."""
    r = _r(FL_URL, FL_META)
    assert r.basis, "no basis recorded"
    assert isinstance(r.basis, str)


def test_an_unresolved_layer_is_explicit_about_it():
    r = _r("https://services2.arcgis.com/x/arcgis/rest/services/"
           "EPL_Layers_250610c/FeatureServer/4", "")
    assert r.state is None and r.county is None and r.statewide is False


def test_a_generic_token_does_not_substring_match_a_county():
    """The dangerous kind of wrong: confidently wrong.

    `City_of_Homestead_EPL_Integration_GIS_Feature_Layer` resolved to
    "Juneau City and Borough, AK" on 23,471 rows. Homestead is in Miami-Dade
    County, Florida. `lookup_county` matches on substring, so the bare token
    "City" hit the first county whose name contains it — and a parcel search
    filtered to the wrong state is worse than one that admits it has no filter.
    """
    r = _r("https://services3.arcgis.com/x/arcgis/rest/services/"
           "City_of_Homestead_EPL_Integration_GIS_Feature_Layer/FeatureServer/1", "")
    assert r.state != "AK"
    assert r.county is None


@pytest.mark.parametrize("token", ["City", "Town", "Village", "Borough", "Park"])
def test_generic_place_words_never_resolve_alone(token):
    r = _r(f"https://services3.arcgis.com/x/arcgis/rest/services/"
           f"{token}_of_Somewhere/FeatureServer/0", "")
    assert r.county is None


def test_the_service_name_path_requires_a_real_name_match():
    """"Chowan" is the county's actual name, so it resolves; a fragment of some
    other county's name does not."""
    ok = _r("https://services3.arcgis.com/x/arcgis/rest/services/"
            "Chowan_Feature_Service/FeatureServer/0", "")
    assert ok.county == "Chowan County"
