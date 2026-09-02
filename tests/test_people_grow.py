"""People lake grow (harvest + extract seed)."""

from umbra.people.grow import load_all_seeds, ok_name


def test_ok_name_rejects_lists_and_single_tokens():
    assert ok_name("Steve Jobs")
    assert not ok_name("Prince")
    assert not ok_name("List of American actors")
    assert not ok_name("Deaths in 2020")
    assert not ok_name("Category:2020 deaths")


def test_load_all_seeds_includes_packaged_corpus():
    seeds = load_all_seeds()
    assert len(seeds) >= 100
    names = {s.name.lower() for s in seeds}
    assert "steve jobs" in names
    assert all(s.urls for s in seeds[:20])
