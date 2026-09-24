"""people fill — bounded, resumable bulk-lake top-ups for a timer.

The rules that matter: never import the open FEC cycle (it would double every
total weekly), never guess an NPPES URL, re-check the egress guard on every
redirect hop, refuse a download the disk cannot hold, and let one failing
source not stop the others.
"""
from __future__ import annotations

import zipfile
from datetime import date
from pathlib import Path

import httpx
import pytest

from umbra.core.http_guard import BlockedAddress
from umbra.people import fill
from umbra.people.fill import (
    FillError,
    closed_fec_cycles,
    current_fec_cycle,
    guarded_download,
    next_fec_cycle,
    pick_nppes_monthly,
    run_fill,
)

TODAY = date(2026, 9, 24)


# --- FEC cycle selection ----------------------------------------------------

def test_the_open_cycle_is_never_selected():
    assert current_fec_cycle(TODAY) == 2026
    assert current_fec_cycle(date(2027, 1, 5)) == 2028
    assert 2026 not in closed_fec_cycles(TODAY)
    assert closed_fec_cycles(TODAY, oldest=2020) == [2024, 2022, 2020]


def test_next_cycle_skips_imported_ones_newest_first():
    assert next_fec_cycle([], TODAY, oldest=2020) == 2024
    assert next_fec_cycle(["indiv24.zip"], TODAY, oldest=2020) == 2022
    assert next_fec_cycle(["indiv24.zip", "INDIV22.zip", "indiv20.zip"], TODAY, oldest=2020) is None


# --- NPPES link discovery ---------------------------------------------------

INDEX = """
<a href="NPPES_Data_Dissemination_August_2026.zip">Aug</a>
<a href="/nppes/NPPES_Data_Dissemination_September_2026_V2.zip">Sep</a>
<a href="NPPES_Data_Dissemination_091526_092126_Weekly.zip">weekly</a>
<a href="NPPES_Deactivated_NPI_Report_091526.zip">deact</a>
"""


def test_the_newest_monthly_file_is_picked_and_others_ignored():
    url = pick_nppes_monthly(INDEX, "https://download.cms.gov/nppes/NPI_Files.html")
    assert url == "https://download.cms.gov/nppes/NPPES_Data_Dissemination_September_2026_V2.zip"


def test_no_monthly_link_is_a_failure_not_a_guess():
    with pytest.raises(FillError):
        pick_nppes_monthly('<a href="NPPES_Data_Dissemination_091526_Weekly.zip">', "https://x.gov/")


# --- guarded download -------------------------------------------------------

def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_download_follows_a_redirect_and_writes_the_body(tmp_path):
    def handler(req):
        if req.url.path == "/a.zip":
            return httpx.Response(302, headers={"location": "/b.zip"})
        return httpx.Response(200, content=b"PK-data")
    dest = guarded_download(_client(handler), "https://example.com/a.zip", tmp_path / "a.zip",
                            disk_free=lambda p: 1000.0)
    assert dest.read_bytes() == b"PK-data"


def test_every_redirect_hop_is_checked_by_the_guard(tmp_path):
    def handler(req):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest"})
    with pytest.raises(BlockedAddress):
        guarded_download(_client(handler), "https://example.com/a.zip", tmp_path / "a.zip",
                         disk_free=lambda p: 1000.0)
    assert not (tmp_path / "a.zip").exists()


def test_a_download_the_disk_cannot_hold_is_refused(tmp_path):
    def handler(req):
        return httpx.Response(200, headers={"content-length": str(4 * 10**9)}, content=b"x")
    with pytest.raises(FillError, match="not enough disk"):
        guarded_download(_client(handler), "https://example.com/a.zip", tmp_path / "a.zip",
                         min_free_gb=15, disk_free=lambda p: 10.0)


# --- the run ----------------------------------------------------------------

class FakeLake:
    def __init__(self, files=(), fail=False):
        self.files = list(files)
        self.imported: list[str] = []
        self.years: list[int] = []
        self.fail = fail

    def __call__(self):  # used as the factory
        return self

    def status(self):
        return {"available": bool(self.files), "files": [
            {"filename": f, "imported_at": "2026-09-20T00:00:00Z"} for f in self.files]}

    def import_zip(self, path: Path):
        assert path.is_file()
        if self.fail:
            raise ValueError("bad archive")
        self.imported.append(path.name)
        return {"rows": 1}

    def import_year(self, year, max_files):
        self.years.append(year)
        return {"officers_kept": 2, "year": year}

    def close(self):
        pass


def _serve(req: httpx.Request) -> httpx.Response:
    if req.url.path.endswith("NPI_Files.html"):
        return httpx.Response(200, text=INDEX)
    return httpx.Response(200, content=b"PK")


def _run(tmp_path, lakes, **kw):
    return {o.source: o for o in run_fill(http=_client(_serve), work_dir=tmp_path,
                                          today=TODAY, lakes=lakes, **kw)}


def test_a_pass_imports_one_unit_per_source_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setattr(fill, "free_gb", lambda p: 1000.0)
    monkeypatch.setattr(fill, "guarded_download", _fake_download)
    lakes = {"fec": FakeLake(["indiv24.zip"]), "nppes": FakeLake(), "uls": FakeLake(),
             "990": FakeLake()}
    out = _run(tmp_path, lakes)
    assert lakes["fec"].imported == ["indiv22.zip"]
    assert lakes["nppes"].imported == ["NPPES_Data_Dissemination_September_2026_V2.zip"]
    assert lakes["uls"].imported == ["l_amat.zip"]
    assert lakes["990"].years == [2026, 2025]
    assert all(o.status == "imported" for o in out.values())
    assert not list(tmp_path.glob("*.zip"))  # archives deleted after import


def test_current_sources_are_skipped_without_downloading(tmp_path, monkeypatch):
    fetched: list[str] = []

    def no_download(http, url, dest, **kw):
        fetched.append(url)
        raise AssertionError("should not download")

    monkeypatch.setattr(fill, "guarded_download", no_download)
    lakes = {"fec": FakeLake([f"indiv{y % 100:02d}.zip" for y in range(2012, 2025, 2)]),
             "nppes": FakeLake(["NPPES_Data_Dissemination_September_2026_V2.zip"]),
             "uls": FakeLake(["l_amat.zip"]), "990": FakeLake()}
    out = _run(tmp_path, lakes, only=["fec", "nppes", "uls"])
    assert {o.status for o in out.values()} == {"skipped"}
    assert fetched == []


def test_one_failing_source_does_not_stop_the_others(tmp_path, monkeypatch):
    monkeypatch.setattr(fill, "guarded_download", _fake_download)
    lakes = {"fec": FakeLake(fail=True), "nppes": FakeLake(), "uls": FakeLake(),
             "990": FakeLake()}
    out = _run(tmp_path, lakes)
    assert out["fec"].status == "failed" and "bad archive" in out["fec"].detail
    assert out["nppes"].status == "imported"
    assert not list(tmp_path.glob("*.zip"))  # the failed archive is removed too


def _fake_download(http, url, dest, **kw):
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"PK")
    return dest


def test_fec_fill_imports_a_real_archive(tmp_path, monkeypatch):
    """End to end through the real FEC lake, only the network faked."""
    from umbra.lake.fec import FecLake

    row = "|".join(["C1", "N", "A", "P", "1", "15", "IND", "DOE, JANE", "AUSTIN", "TX",
                    "787011234", "ACME", "ENGINEER", "01152023", "250"] + [""] * 6)

    def real_zip(http, url, dest, **kw):
        with zipfile.ZipFile(dest, "w") as z:
            z.writestr("itcont.txt", row + "\n")
        return dest

    monkeypatch.setattr(fill, "guarded_download", real_zip)
    lake_path = tmp_path / "fec.sqlite"
    out = _run(tmp_path / "work", {"fec": lambda: FecLake(lake_path)}, only=["fec"])
    assert out["fec"].status == "imported" and out["fec"].detail == "cycle 2024"
    lake = FecLake(lake_path)
    assert lake.lookup("Jane Doe")
    assert [f["filename"] for f in lake.status()["files"]] == ["indiv24.zip"]
    lake.close()
