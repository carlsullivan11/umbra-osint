"""Wide-coverage tests for obituary survivor + field parsing."""

from __future__ import annotations

from umbra.people.obituary_parse import parse_obituary_text


def test_classic_survived_by_list():
    text = (
        "Mary Jane Doe, 84, of Bentonville, AR, passed away on March 3, 2024. "
        "She is survived by her husband John Doe; children Robert Doe and "
        "Susan Smith; sister Helen Brown; and grandchildren Emma Doe and Liam Doe. "
        "She was preceded in death by her parents Frank Miller and Alice Miller. "
        "Funeral services will be held at Smith Funeral Home. "
        "Interment at Benton County Memorial Cemetery."
    )
    p = parse_obituary_text(text, decedent_name="Mary Jane Doe", title="Mary Jane Doe Obituary")
    assert p.age == 84
    assert p.death_date and "2024" in p.death_date
    assert p.residence and "Bentonville" in p.residence
    assert p.funeral_home and "Funeral Home" in p.funeral_home
    assert p.cemetery and "Cemetery" in p.cemetery
    names = {s.name for s in p.survivors}
    assert "John Doe" in names
    assert "Robert Doe" in names or "Susan Smith" in names
    assert "Helen Brown" in names
    roles = {s.name: s.role for s in p.survivors}
    assert roles.get("John Doe") == "spouse"
    preceded = {s.name for s in p.preceded}
    assert "Frank Miller" in preceded or "Alice Miller" in preceded


def test_loving_husband_of_form():
    text = (
        "John Smith, loving husband of Jane Smith, died Monday. "
        "He is survived by sons Michael Smith and David Smith."
    )
    p = parse_obituary_text(text, decedent_name="John Smith")
    names = {s.name for s in p.survivors}
    assert "Jane Smith" in names
    assert any(s.role == "spouse" for s in p.survivors if s.name == "Jane Smith")


def test_bare_children_erin_reed_eve():
    text = (
        "Steve Jobs is survived by his wife Laurene, and their three children, "
        "Erin, Reed and Eve. His sister is Mona Simpson."
    )
    p = parse_obituary_text(text, decedent_name="Steve Jobs")
    names = {s.name for s in p.survivors}
    assert "Laurene Jobs" in names
    assert "Mona Simpson" in names
    # bare children get surname
    assert "Erin Jobs" in names or "Reed Jobs" in names or "Eve Jobs" in names


def test_hyphenated_daughter():
    text = (
        "He is survived by his daughter Lisa Brennan-Jobs and wife Laurene Powell Jobs."
    )
    p = parse_obituary_text(text, decedent_name="Steve Jobs")
    names = {s.name for s in p.survivors}
    assert "Lisa Brennan-Jobs" in names
    assert "Laurene Powell Jobs" in names


def test_step_and_inlaws():
    text = (
        "Survivors include his stepson Mark Taylor; daughter-in-law Amy Taylor; "
        "and brother-in-law Paul Green."
    )
    p = parse_obituary_text(text, decedent_name="William Taylor")
    roles = {s.name: s.role for s in p.survivors}
    assert any(r == "in_law" for r in roles.values())
    assert roles.get("Amy Taylor") == "in_law" or any(
        "Amy" in n and roles[n] == "in_law" for n in roles
    )
    assert roles.get("Paul Green") == "in_law" or any(
        "Paul" in n and roles[n] == "in_law" for n in roles
    )


def test_preceded_only():
    text = "She was preceded in death by her husband Carl Brown and son Timothy Brown."
    p = parse_obituary_text(text, decedent_name="Anna Brown")
    assert p.preceded
    names = {s.name for s in p.preceded}
    assert "Carl Brown" in names
    assert all(s.living is False for s in p.preceded)


def test_military_and_occupation():
    text = (
        "James Lee, 79, of Tulsa, died May 1, 2020. He served in the U.S. Marine Corps "
        "and later worked as a firefighter for the City of Tulsa. "
        "He is survived by his wife Patricia Lee."
    )
    p = parse_obituary_text(text, decedent_name="James Lee")
    assert p.military and "Marine" in p.military
    assert p.occupation and "firefighter" in p.occupation.lower()
    assert any(s.name == "Patricia Lee" for s in p.survivors)


def test_born_died_dates():
    text = (
        "Born January 12, 1940, in Little Rock, she passed away on June 4, 2022 "
        "in Rogers, AR. Survivors include her son Kevin White."
    )
    p = parse_obituary_text(text, decedent_name="Dorothy White")
    assert p.birth_date and "1940" in p.birth_date
    assert p.death_date and "2022" in p.death_date


def test_title_lifespan():
    p = parse_obituary_text(
        "Memorial page.",
        decedent_name="Steve Jobs",
        title="Steve Jobs (1955-2011) - Find a Grave Memorial",
    )
    assert p.birth_date == "1955"
    assert p.death_date == "2011"


def test_no_false_sister_surname_attach():
    text = "Survived by his sister Mona Simpson and wife Laurene."
    p = parse_obituary_text(text, decedent_name="Steve Jobs")
    names = {s.name for s in p.survivors}
    assert "Mona Simpson" in names
    assert "Mona Jobs" not in names
    assert "Laurene Jobs" in names


def test_empty_text():
    p = parse_obituary_text("", decedent_name="Nobody")
    assert p.survivors == []
    assert p.age is None
