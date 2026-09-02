"""RF lake sync stores OSM cameras; wifi_maps hydrates from it."""

from pathlib import Path
from types import SimpleNamespace

from umbra.lake.rf import RfLake, sync_regions


def test_rf_lake_upsert_and_lookup(tmp_path: Path):
    lake = RfLake(tmp_path / "rf.sqlite")
    lake.upsert_camera(
        osm_id=1,
        lat=36.372,
        lon=-94.208,
        label="ALPR",
        region="Bentonville, AR",
        tags={"surveillance:type": "ALPR"},
    )
    lake.mark_synced()
    st = lake.status()
    assert st.cameras == 1
    assert st.synced
    rows = lake.cameras_for_region("Bentonville")
    lake.close()
    assert rows[0]["label"] == "ALPR"


def test_sync_regions_uses_http_mock(tmp_path: Path):
    lake = RfLake(tmp_path / "rf.sqlite")

    class _Resp:
        def __init__(self, code, payload):
            self.status_code = code
            self._payload = payload

        def json(self):
            return self._payload

    class _Http:
        def get(self, url, **kwargs):
            return _Resp(200, [{"lat": "36.37", "lon": "-94.20"}])

        def post(self, url, **kwargs):
            return _Resp(
                200,
                {
                    "elements": [
                        {
                            "id": 99,
                            "lat": 36.371,
                            "lon": -94.209,
                            "tags": {"name": "City cam", "man_made": "surveillance"},
                        }
                    ]
                },
            )

    stats = sync_regions(
        _Http(),
        lake=lake,
        regions=["Bentonville, AR"],
        pause_s=0,
    )
    assert stats["cameras_upserted"] == 1
    assert lake.cameras_for_region("Bentonville")
    assert lake.geocode_get("Bentonville, AR")
    near = lake.cameras_near(36.371, -94.209, km=2)
    assert near and near[0]["label"] == "City cam"
    lake.close()


def test_cameras_near_radius(tmp_path: Path):
    lake = RfLake(tmp_path / "rf.sqlite")
    lake.upsert_camera(osm_id=1, lat=37.80, lon=-122.27, label="Oakland cam", region="Oakland, CA")
    lake.upsert_camera(osm_id=2, lat=32.71, lon=-117.16, label="SD cam", region="San Diego, CA")
    lake.backfill_geocode_from_cameras()
    assert lake.geocode_get("Oakland, CA")
    near = lake.cameras_near(37.804, -122.271, km=6)
    labels = {r["label"] for r in near}
    assert "Oakland cam" in labels
    assert "SD cam" not in labels
    lake.close()
