"""People lake seed command tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from umbra.lake.people import PeopleLake
from umbra.people.seed import SeedPerson, seed_people


def test_seed_people_fetches_and_stores(tmp_path: Path, monkeypatch):
    html = """
    <html><head><title>Test Person (1900-2000)</title></head>
    <body>Test Person died January 1, 2000. Survived by wife Alice Person
    and son Bob Person. Smith Funeral Home.</body></html>
    """

    class _Resp:
        status_code = 200
        text = html
        url = "https://en.wikipedia.org/wiki/Test_Person"

    class _Http:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, **k):
            return _Resp()

    import umbra.people.seed as seed_mod

    monkeypatch.setattr(seed_mod, "GuardedClient", lambda *a, **k: _Http())
    settings = SimpleNamespace(data_dir=tmp_path, user_agent="test")
    seeds = (
        SeedPerson(
            "Test Person",
            ("https://en.wikipedia.org/wiki/Test_Person",),
            "Testville",
        ),
    )
    stats = seed_people(seeds, settings=settings)
    assert stats["people_upserted"] == 1
    assert stats["urls_ok"] >= 1
    lake = PeopleLake.from_settings(settings)
    hits = lake.lookup_name("Test Person")
    assert hits
    assert hits[0]["death_date"]
    obits = lake.obituaries_for_person(hits[0]["id"])
    assert obits and "wikipedia.org" in obits[0]["url"]
    kin = lake.kinship_for_person(hits[0]["id"])
    names = {k["relative_name"] for k in kin}
    assert "Alice Person" in names or "Bob Person" in names
    lake.close()
