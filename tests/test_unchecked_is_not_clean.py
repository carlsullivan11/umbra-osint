"""A source that failed is not a source that said no.

This is the principle the codebase repeats most, and the audit found it broken
in the collector users hit most. `reputation.py` scored evidence as::

    confidence=hit.weight if hit.listed else 0.5

so a DNSBL resolver error and a confirmed not-listed both landed at 0.50. On
production 32 rows were resolver failures presented at the same confidence as a
real negative answer — including for `1.1.1.1`, where the visible summary said
"check error" while the number beside it said "clean".

The verdict layer had the same hole one level up: `if not listed: return
"clean"` treats "nothing fired" and "nothing could be asked" identically, so an
address whose every source errored came back clean.
"""
from __future__ import annotations

from umbra.collectors.reputation import dnsbl_hit, verdict_from_hits
from umbra.core.dns import DnsblResult

ZONE = "zen.spamhaus.org"


def _result(status: str, codes=None, detail=""):
    return DnsblResult(status, codes or [], detail)


def _hit(status: str, detail: str = "boom"):
    return dnsbl_hit("spamhaus_zen", 0.6, ZONE, _result(status, detail=detail))


# --- the hit knows the difference ------------------------------------------

def test_a_clean_check_is_marked_checked():
    assert _hit("not_listed").checked is True


def test_an_errored_check_is_marked_unchecked():
    assert _hit("error").checked is False


def test_a_listing_is_checked():
    h = dnsbl_hit("spamhaus_zen", 0.6, ZONE, _result("listed", ["127.0.0.4"]))
    assert h.checked is True


def test_an_error_is_still_not_a_listing():
    """The older bug, which must stay fixed: a refusal is not an accusation."""
    assert _hit("error").listed is False


# --- the verdict knows the difference --------------------------------------

def test_all_sources_failing_is_unknown_not_clean():
    verdict, score, _ = verdict_from_hits([_hit("error"), _hit("error")])
    assert verdict == "unknown"
    assert score == 0


def test_one_good_negative_among_failures_is_clean():
    """Partial coverage still answers — it just answers from what worked."""
    verdict, _, _ = verdict_from_hits([_hit("error"), _hit("not_listed")])
    assert verdict == "clean"


def test_a_listing_beats_an_unrelated_failure():
    listed = dnsbl_hit("spamhaus_zen", 0.6, ZONE, _result("listed", ["127.0.0.4"]))
    verdict, _, _ = verdict_from_hits([_hit("error"), listed])
    assert verdict in {"suspicious", "malicious"}


def test_no_hits_at_all_is_still_unknown():
    assert verdict_from_hits([])[0] == "unknown"


# --- the number a user sees -------------------------------------------------

def test_unchecked_scores_below_clean():
    """The specific production defect: both were 0.5."""
    from umbra.collectors.reputation import evidence_confidence

    assert evidence_confidence(_hit("error")) < evidence_confidence(_hit("not_listed"))


def test_a_clean_check_keeps_its_confidence():
    from umbra.collectors.reputation import evidence_confidence

    assert evidence_confidence(_hit("not_listed")) == 0.5


def test_the_error_detail_still_says_what_failed():
    assert "check error" in _hit("error", detail="resolver timeout").detail
