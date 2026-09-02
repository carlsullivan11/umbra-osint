"""Court records: a name match is a lead, never a person.

CourtListener was already listed at L0 of the county tracker — as a *link* for
the operator to click. This retrieves the data instead.

The tests that matter are not "does it fetch". They are about what the output
claims. Court records name defendants who were acquitted, parties to suits that
settled, and everyone who happens to share those names. The county tracker's own
rule is *name-token ≠ identity*, and it binds hardest here.
"""
from __future__ import annotations

import warnings
from types import SimpleNamespace

import pytest

warnings.filterwarnings("ignore")

from umbra.collectors.court_records import (  # noqa: E402
    FCRA_NOTE,
    MAX_PER_TYPE,
    CourtRecordsCollector,
)
from umbra.core.models import EntityType  # noqa: E402


class Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class Http:
    """Answers opinions then dockets, in the order the collector asks."""

    def __init__(self, *payloads):
        self._queue = list(payloads)
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw.get("params", {})))
        return self._queue.pop(0) if self._queue else Resp({"count": 0, "results": []})


def ctx(http):
    return SimpleNamespace(settings=SimpleNamespace(), case_id="c", run_id="r", http=http)


def person(name="Jane Q Doe"):
    return SimpleNamespace(value=name, norm_key=f"person:{name.lower()}", type="person")


ROW = {
    "caseName": "United States v. Doe",
    "court": "Ninth Circuit",
    "dateFiled": "2021-04-01",
    "absolute_url": "/opinion/123/united-states-v-doe/",
    "docketNumber": "20-1234",
}


class TestItNeverClaimsIdentity:
    def test_evidence_says_name_match_not_confirmed_identity(self):
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 1, "results": [ROW]}))))
        assert res.evidence
        for ev in res.evidence:
            assert "not a confirmed identity" in ev.summary

    def test_confidence_stays_low(self):
        """A namesake must not harden into a fact after one scoring pass."""
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 1, "results": [ROW]}))))
        for e in res.entities:
            assert e.confidence <= 0.5
        for ev in res.evidence:
            assert ev.confidence <= 0.5

    def test_the_entity_records_that_identity_is_unconfirmed(self):
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 1, "results": [ROW]}))))
        assert res.entities[0].props["identity_confirmed"] is False
        assert res.entities[0].props["matched_name"] == "Jane Q Doe"

    def test_no_person_entity_is_invented_from_a_case_caption(self):
        """"United States v. Doe" contains a name. Emitting it as a PERSON would
        manufacture an identity out of a caption."""
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 1, "results": [ROW]}))))
        assert all(e.type != EntityType.PERSON for e in res.entities)


class TestHonestAboutAbsenceAndVolume:
    def test_no_match_does_not_read_as_a_clean_record(self):
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 0, "results": []}),
                                             Resp({"count": 0, "results": []}))))
        joined = " ".join(res.notes)
        assert "Absence is not a clean record" in joined
        assert "sealed or expunged" in joined

    def test_truncation_is_stated_with_the_real_total(self):
        rows = [dict(ROW, absolute_url=f"/opinion/{i}/x/") for i in range(50)]
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 883, "results": rows}))))
        assert len(res.entities) <= MAX_PER_TYPE * 2
        assert any("883" in n for n in res.notes)

    def test_a_large_count_is_explained_as_a_common_name(self):
        rows = [dict(ROW, absolute_url=f"/opinion/{i}/x/") for i in range(20)]
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 900, "results": rows}))))
        assert any("common name" in n for n in res.notes)


class TestFcra:
    def test_the_fcra_warning_rides_on_every_run_with_results(self):
        """Not once in a terms page nobody opens."""
        col = CourtRecordsCollector()
        res = col.collect(person(), ctx(Http(Resp({"count": 1, "results": [ROW]}))))
        assert FCRA_NOTE in res.notes

    def test_the_warning_names_the_prohibited_uses(self):
        for word in ("employment", "housing", "credit"):
            assert word in FCRA_NOTE
        assert "consumer reporting agency" in FCRA_NOTE


class TestInputHandling:
    @pytest.mark.parametrize("bad", ["", "  ", "a", "x" * 200, "'; DROP TABLE--"])
    def test_non_name_input_is_not_sent_to_a_public_api(self, bad):
        http = Http()
        col = CourtRecordsCollector()
        res = col.collect(person(bad), ctx(http))
        assert http.calls == [], "a malformed query was sent upstream"
        assert any("name-shaped" in n for n in res.notes)

    def test_the_name_is_quoted_so_it_matches_as_a_phrase(self):
        """Unquoted, "Jane Q Doe" matches any document containing all three
        tokens anywhere — which is a different and much wider question."""
        http = Http(Resp({"count": 0, "results": []}))
        CourtRecordsCollector().collect(person(), ctx(http))
        assert http.calls[0][1]["q"] == '"Jane Q Doe"'

    def test_an_api_failure_reports_unknown_not_clean(self):
        class Boom:
            def get(self, *a, **k):
                raise RuntimeError("connection reset")

        res = CourtRecordsCollector().collect(person(), ctx(Boom()))
        joined = " ".join(res.notes)
        assert "unreachable" in joined
        assert "unknown rather than clean" in joined
