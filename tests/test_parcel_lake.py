"""Bulk parcel ingest — own the roll instead of querying it per name.

`umbra.records.parcels` queries a county layer for one name at a time. That is
right for a live lookup and useless for building a corpus: `land_facts` sat at
zero for the life of the project while 100 verified ArcGIS layers went unread.

Probed on the real endpoints (2026-09-06):

    Hillsborough County FL  367,316 parcels  maxRecordCount 2000  pagination yes
    Ramsey County MN         83,505 parcels  maxRecordCount 2000  pagination yes

184 requests owns a county's entire owner roll, and every ArcGIS FeatureServer
speaks the same dialect. So this pages `resultOffset` and writes owners into a
lake Umbra owns.

Honesty carried from `records.parcels`: **these are homes.** A row is a real
person's residential address and what their county thinks it is worth. It is
public record — states publish it deliberately — and a name match is still not
an identity. Coverage is per county and stated, so an absent name means "this
county is not ingested", never "owns no property".
"""
from __future__ import annotations

from pathlib import Path

import pytest

from umbra.lake.parcels import ParcelLake, ParcelSource, parse_features

SOURCE = ParcelSource(
    layer_url="https://gis.test/FeatureServer/1",
    state="FL",
    county="Hillsborough County",
    owner_field="OWNER",
    address_field="ADDR_1",
    parcel_field="PIN",
    city_field="CITY",
    page=2000,
)


def _feat(owner, addr="1 Main St", pin="P-1", city="Odessa"):
    return {"attributes": {"OWNER": owner, "ADDR_1": addr, "PIN": pin, "CITY": city}}


def _distinct(n: int) -> dict:
    """A feature that stays distinct after canonicalisation.

    `canonical` strips digits — correct, since names do not contain them — so
    "OWNER 0".."OWNER 999" all normalise to "owner" and collapse onto one key.
    Letters keep the rows distinct the way real owner names would.
    """
    a, b = chr(65 + n % 26), chr(65 + (n // 26) % 26)
    return _feat(f"Ada{a}{b} Lovelace{b}{a}", pin=f"P-{n}")


# --- parsing ---------------------------------------------------------------

def test_features_map_through_the_per_source_field_names():
    """Five states name the owner field five different ways — the map is data,
    not a guess."""
    rows = parse_features([_feat("Patricia Anne Sevigny Trustee")], SOURCE)
    assert rows[0].owner == "Patricia Anne Sevigny Trustee"
    assert rows[0].address == "1 Main St"
    assert rows[0].parcel_id == "P-1"


def test_the_owner_is_canonicalised_for_search():
    rows = parse_features([_feat("SMITH, JOHN A")], SOURCE)
    assert rows[0].owner_canonical == "john a smith"


def test_a_feature_with_no_owner_is_dropped():
    assert parse_features([_feat("")], SOURCE) == []
    assert parse_features([{"attributes": {"ADDR_1": "x"}}], SOURCE) == []


def test_the_literal_string_none_is_not_an_address():
    """ArcGIS ships the string 'None' for empty fields, which would otherwise
    be stored as a real address."""
    rows = parse_features([_feat("Jane Doe", addr="None")], SOURCE)
    assert rows[0].address is None


def test_malformed_features_do_not_raise():
    assert parse_features([{}, {"attributes": None}, None], SOURCE) == []


# --- ingest ----------------------------------------------------------------

class FakeClient:
    """Serves pages the way a FeatureServer does."""

    def __init__(self, total: int, page: int = 2000, fail_at: int | None = None):
        self.total, self.page, self.fail_at = total, page, fail_at
        self.offsets: list[int] = []

    def get(self, url, params=None, **kw):
        p = params or {}
        if p.get("returnCountOnly"):
            return _Resp({"count": self.total})
        off = int(p.get("resultOffset", 0))
        self.offsets.append(off)
        if self.fail_at is not None and off >= self.fail_at:
            raise RuntimeError("county server blew up")
        n = max(0, min(self.page, self.total - off))
        return _Resp({"features": [_distinct(off + i) for i in range(n)]})

    def close(self):
        pass


class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


def test_a_layer_is_paged_to_completion(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        http = FakeClient(total=5000, page=2000)
        stats = lake.ingest_source(SOURCE, http=http, pause_s=0)
        assert stats["rows"] == 5000
        assert http.offsets == [0, 2000, 4000]
    finally:
        lake.close()


def test_paging_stops_at_the_end_rather_than_looping(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        http = FakeClient(total=100, page=2000)
        lake.ingest_source(SOURCE, http=http, pause_s=0)
        assert len(http.offsets) == 1
    finally:
        lake.close()


def test_a_failed_page_keeps_what_came_before(tmp_path):
    """A county server that dies at page three must not lose pages one and two."""
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        http = FakeClient(total=10000, page=2000, fail_at=4000)
        stats = lake.ingest_source(SOURCE, http=http, pause_s=0)
        assert stats["rows"] == 4000
        assert stats["errors"]
        assert lake.count() == 4000
    finally:
        lake.close()


def test_reingest_does_not_duplicate(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        for _ in range(2):
            lake.ingest_source(SOURCE, http=FakeClient(total=1000), pause_s=0)
        assert lake.count() == 1000
    finally:
        lake.close()


def test_a_max_rows_cap_is_honoured_and_reported(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        stats = lake.ingest_source(SOURCE, http=FakeClient(total=100000),
                                   pause_s=0, max_rows=3000)
        assert stats["rows"] == 3000
        assert stats["capped"] is True
        assert "100,000" in stats["note"] or "100000" in stats["note"]
    finally:
        lake.close()


def test_an_uncapped_full_run_is_not_reported_as_capped(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        stats = lake.ingest_source(SOURCE, http=FakeClient(total=500), pause_s=0)
        assert stats["capped"] is False
    finally:
        lake.close()


# --- lookup ----------------------------------------------------------------

def test_an_owner_is_findable_by_name(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        lake.ingest_source(SOURCE, http=FakeClient(total=10), pause_s=0)
        # The name _distinct(3) produces.
        assert lake.lookup("AdaDA LovelaceAD")
    finally:
        lake.close()


def test_lookup_is_index_backed(tmp_path):
    """A LIKE scan over millions of parcels is what this design avoids."""
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        plan = lake._conn.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM parcel WHERE owner_canonical = ?",
            ("john smith",)).fetchall()
        assert "USING INDEX" in " ".join(str(r[-1]) for r in plan).upper()
    finally:
        lake.close()


def test_a_miss_is_empty_not_an_error(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        assert lake.lookup("Nobody Here") == []
    finally:
        lake.close()


def test_coverage_reports_which_counties_are_ingested(tmp_path):
    """Absence must read as 'this county is not ingested', never as 'owns no
    property'."""
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        lake.ingest_source(SOURCE, http=FakeClient(total=10), pause_s=0)
        cov = lake.coverage()
        assert cov[0]["state"] == "FL"
        assert cov[0]["county"] == "Hillsborough County"
        assert cov[0]["rows"] == 10
    finally:
        lake.close()


def test_status_on_an_empty_lake_is_honest(tmp_path):
    lake = ParcelLake(tmp_path / "p.sqlite")
    try:
        st = lake.status()
        assert st["parcels"] == 0
        assert st["counties"] == 0
        assert st["available"] is False
    finally:
        lake.close()
