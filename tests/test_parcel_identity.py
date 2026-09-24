"""A layer with no parcel-ID field was losing most of its rows, silently.

Found by running the sweep for the first time. The ingest log and the coverage
line, printed one second apart, disagreed:

    parcel lake 881,971 owner records across 18 county layer(s)
    parcel coverage 9 / 3,143 counties · 959,646 owner records

77,675 rows were written and not stored. Per layer:

    Fairbanks North Star Borough   wrote 57,839   stored 30,964   -46%
    New Haven County (dup entry)   wrote 120,000  stored 106,490  -11%
    New Haven County (good entry)  wrote 120,000  stored 118,783   -1%

The storage key is ``layer_url|parcel_id|owner_canonical``. Its comment says it
exists so "a re-ingest updates rather than duplicating, and two owners on one
parcel stay two rows" — both true, and both assume a parcel id. The registry
records `parcel_field` as an empty string for Fairbanks and for one of the two
New Haven entries, so `parcel_id` is NULL, the key collapses to
``layer_url||owner``, and **every parcel a person owns in that county merges
into one row.** A landlord with forty properties became one.

`OBJECTID` is the fix and it was always available: every ArcGIS FeatureServer
exposes one, it is stable per feature, and it is precisely "which row is this".
The layer's own parcel id stays preferred where it exists — it survives a
layer being republished with new OBJECTIDs, which is the case the original key
was written for.

Nothing here is a *dedupe* change. Two owners on one parcel are still two rows.
"""
from __future__ import annotations

from umbra.lake.parcels import ParcelSource, parse_features, row_key


def _feature(**attrs):
    return {"attributes": attrs}


SRC_WITH_ID = ParcelSource(
    layer_url="https://x/FeatureServer/0", state="CT", county="New Haven",
    owner_field="Owner", address_field="Mailing_Address", parcel_field="Parcel_ID",
)
SRC_NO_ID = ParcelSource(
    layer_url="https://y/FeatureServer/0", state="AK", county="Fairbanks",
    owner_field="Owner1", address_field="Mailing_Address", parcel_field=None,
)


# --- OBJECTID is requested and captured -------------------------------------

def test_objectid_is_always_requested():
    """It cannot be a fallback if it was never asked for."""
    assert "OBJECTID" in SRC_NO_ID.out_fields()
    assert "OBJECTID" in SRC_WITH_ID.out_fields()


def test_objectid_is_captured_when_present():
    rows = parse_features([_feature(Owner1="RILEY JAMES W", OBJECTID=4071)], SRC_NO_ID)
    assert rows[0].object_id == "4071"


def test_a_missing_objectid_is_not_fatal():
    rows = parse_features([_feature(Owner1="RILEY JAMES W")], SRC_NO_ID)
    assert rows and rows[0].object_id is None


# --- the key no longer collapses --------------------------------------------

def test_one_owner_many_parcels_stays_many_rows():
    """The production defect. Same owner, same mailing address, three parcels."""
    feats = [_feature(Owner1="RILEY JAMES W", Mailing_Address="1206 WINTERGREEN LN",
                      OBJECTID=n) for n in (1, 2, 3)]
    rows = parse_features(feats, SRC_NO_ID)
    assert len({row_key(r) for r in rows}) == 3


def test_it_collapsed_to_one_without_objectid():
    """The counter-example, so the regression is legible."""
    feats = [_feature(Owner1="RILEY JAMES W", Mailing_Address="1206 WINTERGREEN LN")
             for _ in range(3)]
    rows = parse_features(feats, SRC_NO_ID)
    assert len({row_key(r) for r in rows}) == 1


def test_the_parcel_id_is_still_preferred_where_it_exists():
    """It survives a layer being republished with new OBJECTIDs — the case the
    original key was written for."""
    a = parse_features([_feature(Owner="A", Parcel_ID="P-1", OBJECTID=10)], SRC_WITH_ID)[0]
    b = parse_features([_feature(Owner="A", Parcel_ID="P-1", OBJECTID=99)], SRC_WITH_ID)[0]
    assert row_key(a) == row_key(b), "re-ingest must update, not duplicate"


def test_two_owners_on_one_parcel_stay_two_rows():
    feats = [_feature(Owner="A", Parcel_ID="P-1", OBJECTID=1),
             _feature(Owner="B", Parcel_ID="P-1", OBJECTID=2)]
    rows = parse_features(feats, SRC_WITH_ID)
    assert len({row_key(r) for r in rows}) == 2


def test_a_re_ingest_of_an_id_less_layer_updates_rather_than_duplicating():
    """OBJECTID is stable per feature, so paging the layer again overwrites."""
    first = parse_features([_feature(Owner1="A", OBJECTID=7)], SRC_NO_ID)[0]
    again = parse_features([_feature(Owner1="A", OBJECTID=7)], SRC_NO_ID)[0]
    assert row_key(first) == row_key(again)


def test_layers_do_not_collide_with_each_other():
    a = parse_features([_feature(Owner1="A", OBJECTID=1)], SRC_NO_ID)[0]
    b = parse_features([_feature(Owner="A", Parcel_ID=None, OBJECTID=1)], SRC_WITH_ID)[0]
    assert row_key(a) != row_key(b)


# --- the two totals must agree ----------------------------------------------

def test_coverage_counts_stored_rows_not_written_ones():
    """Two lines one second apart disagreed by 77,675 rows:

        parcel lake 881,971 owner records across 18 county layer(s)
        parcel coverage 9 / 3,143 counties · 959,646 owner records

    `ingested.rows` is what a run wrote. Rows whose key collided were never
    stored, so summing that column overstates the lake.
    """
    from umbra.records.coverage import coverage_report

    class _Lake:
        def count(self):
            return 881_971

        def coverage(self):
            # What the runs claimed to write — deliberately larger.
            return [{"state": "CT", "county": "New Haven", "rows": 500_000},
                    {"state": "AK", "county": "Fairbanks", "rows": 459_646}]

    assert coverage_report(_Lake())["parcels"] == 881_971


def test_coverage_survives_a_lake_that_cannot_count():
    from umbra.records.coverage import coverage_report

    class _Broken:
        def count(self):
            raise RuntimeError("locked")

        def coverage(self):
            return []

    assert coverage_report(_Broken())["parcels"] == 0
