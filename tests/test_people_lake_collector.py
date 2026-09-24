"""The largest corpus Umbra owns could not be reached from a case.

**No collector imports `FecLake`.** 2,250,469 contributor records — name, city,
state, employer, occupation, contribution count and date range, all public FEC
filings — were reachable only from the `/people` web page. A person search in a
case got this instead:

    public_records_portals  Linked 18 free portals for manual search
    edgar_search            browse_hits=0 efts_total=0
    opencorporates          captcha wall or block — not scraped

Eighteen links to go and do it yourself, a miss from a corporate-filings
database, and a permanent error — while 14,663 people and 2.25M contributors sat
one function call away.

`people_lake` closes that. It is offline, like `mac_oui` and `email_profile`: no
request, no key, nothing to rate-limit.

**It emits evidence and no entities, deliberately.** An FEC row says *somebody
with this name, in this city, gave money and listed this employer*. Turning that
into an ORG entity joined to a PERSON asserts that a particular person works
somewhere, which the filing does not establish and this project does not claim —
`umbra.people.search` refuses to merge the two lakes for the same reason. The
record belongs in evidence; the claim does not belong anywhere.

**Ambiguity is the finding, not a caveat.** At 2.25M rows a common name matches
people in many states, and saying *how many* is what makes the result usable
rather than misleading. That is the cheap version of project 3 in
[[Umbra-Data-Science-Plan-2026-09-09]].
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from umbra.collectors.people_lake import PeopleLakeCollector, summarize


class _Result:
    """Stands in for `umbra.people.search.UnifiedResult`."""

    def __init__(self, people=None, contributors=None, ambiguous=False, note=""):
        self.query = "Janice Miller"
        self.people = people or []
        self.contributors = contributors or []
        self.ambiguous = ambiguous
        self.note = note

    @property
    def total(self):
        return len(self.people) + len(self.contributors)


def _fec(state, city="Springfield", employer="ACME", n=3):
    return {"name_raw": "MILLER, JANICE", "city": city, "state": state,
            "employers": employer, "occupations": "ENGINEER",
            "contributions": n, "total_amount": 250}


def _person(name="Janice Miller", **kw):
    return {"id": "p1", "full_name": name, **kw}


# --- the summary says what was found ---------------------------------------

def test_a_hit_reports_both_corpora():
    s = summarize("Janice Miller", _Result(
        people=[_person()], contributors=[_fec("IL"), _fec("TX")]))
    assert "1" in s and "2" in s


def test_nothing_found_is_unchecked_not_absence():
    """Coverage is partial, so a miss is not evidence the person does not exist."""
    s = summarize("Nobody Here", _Result()).lower()
    assert "unchecked" in s or "not an absence" in s


def test_the_states_are_named():
    s = summarize("Janice Miller", _Result(contributors=[_fec("IL"), _fec("TX")]))
    assert "IL" in s and "TX" in s


# --- ambiguity is the point -------------------------------------------------

def test_many_states_is_called_ambiguous():
    s = summarize("James Smith", _Result(
        contributors=[_fec(st) for st in ("IL", "TX", "CA", "NY")],
        ambiguous=True)).lower()
    assert "name match" in s or "ambiguous" in s or "distinct" in s


def test_a_single_state_is_not_oversold():
    """One state is still not one person."""
    s = summarize("Janice Miller", _Result(contributors=[_fec("IL"), _fec("IL")]))
    assert "not an identification" in s.lower() or "name match" in s.lower()


def test_the_count_is_stated_so_a_reader_can_judge():
    s = summarize("James Smith", _Result(
        contributors=[_fec("IL") for _ in range(12)], ambiguous=True))
    assert "12" in s


# --- the collector -----------------------------------------------------------

def _run(monkeypatch, result, *, lake_ok=True):
    import umbra.collectors.people_lake as mod

    class _Lake:
        def close(self):
            pass

    def _fake_lake(_ctx):
        if not lake_ok:
            raise RuntimeError("lake unavailable")
        return _Lake()

    monkeypatch.setattr(mod, "_lake", _fake_lake)
    monkeypatch.setattr(mod, "_search", lambda _lake, q, **kw: result)
    ent = SimpleNamespace(value="Janice Miller", norm_key="person:janice miller",
                          type="person", props={})
    return PeopleLakeCollector().collect(ent, SimpleNamespace(http=None, settings=None))


def test_the_collector_needs_no_http(monkeypatch):
    """Offline, like mac_oui — ctx.http is None here on purpose."""
    res = _run(monkeypatch, _Result(people=[_person()]))
    assert res.evidence


def test_it_emits_no_entities(monkeypatch):
    """An FEC row does not establish that a named person works somewhere, and an
    ORG entity joined to a PERSON would assert exactly that."""
    res = _run(monkeypatch, _Result(
        people=[_person()], contributors=[_fec("IL", employer="ACME")]))
    assert res.entities == []
    assert res.edges == []


def test_a_miss_is_a_note_not_silence(monkeypatch):
    res = _run(monkeypatch, _Result())
    assert res.notes, "a miss must say the corpora were searched"
    assert "unchecked" in " ".join(res.notes).lower()


def test_an_unavailable_lake_is_reported_as_unchecked(monkeypatch):
    """An optional multi-GB lake failing to open is not an absence of the person."""
    res = _run(monkeypatch, _Result(), lake_ok=False)
    assert res.evidence == []
    joined = " ".join(res.notes).lower()
    assert "unchecked" in joined or "unavailable" in joined


def test_an_empty_query_does_nothing(monkeypatch):
    import umbra.collectors.people_lake as mod

    monkeypatch.setattr(mod, "_lake", lambda _c: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(mod, "_search", lambda *a, **k: _Result())
    ent = SimpleNamespace(value="   ", norm_key="person:", type="person", props={})
    res = PeopleLakeCollector().collect(ent, SimpleNamespace(http=None, settings=None))
    assert res.evidence == []


def test_it_accepts_person(monkeypatch):
    from umbra.core.models import EntityType

    assert EntityType.PERSON in PeopleLakeCollector.inputs


def test_the_evidence_cites_the_corpora_not_a_url(monkeypatch):
    """Owned data has no third-party URL to link, and inventing one would be
    worse than none."""
    res = _run(monkeypatch, _Result(people=[_person()]))
    ev = res.evidence[0]
    assert ev.source_name
    assert "local" in ev.source_name or "owned" in ev.source_name.lower()
