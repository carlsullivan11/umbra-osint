"""The community verdict — deliberately dumb, and defensible line by line.

Everything on this page is a user allegation about a phone line somebody may
own, use for work, or have been reassigned. That makes the aggregation rules the
product's legal surface as much as its UX, so they stay arithmetic a person can
read and argue with, not a model nobody can interrogate.

The rules that exist to protect the number's owner rather than the reader:

- **One reporter is never a verdict.** A single "scam" report renders as
  *unconfirmed*, because one stranger's word about someone's phone line is not a
  finding — and one motivated person is exactly how a personal number gets
  brigaded.
- **Disagreement is shown as disagreement.** Conflicting reports produce
  *disputed*, never a winner picked by majority.
- **Silence is silence.** No reports means *unknown*, never "clean" — the same
  unchecked-is-not-clean rule the collectors follow.
- **The counts are always visible.** A verdict word with no numbers under it
  cannot be argued with.
"""
from __future__ import annotations

from umbra.phone.verdict import compute_verdict


def _v(counts=None, agree=0, disagree=0, reporters=0):
    return compute_verdict(counts or {}, agree=agree, disagree=disagree,
                           reporters=reporters)


# --- the protective floor --------------------------------------------------

def test_no_reports_is_unknown_not_clean():
    out = _v()
    assert out["code"] == "unknown"
    assert "not" in out["note"].lower()


def test_a_single_report_is_never_confirmed():
    """One person's allegation about someone's phone line is not a finding."""
    out = _v({"scam": 1}, reporters=1)
    assert out["code"] == "unconfirmed"
    assert out["code"] != "likely_spam"


def test_a_single_report_stays_unconfirmed_however_many_agrees_it_has():
    """Otherwise one reporter plus a handful of sockpuppet votes is a verdict."""
    out = _v({"scam": 1}, agree=50, reporters=1)
    assert out["code"] == "unconfirmed"


def test_conflicting_reports_are_disputed_not_resolved():
    out = _v({"scam": 4, "not_spam": 4}, reporters=8)
    assert out["code"] == "disputed"


def test_a_strong_consensus_reads_as_likely_not_certain():
    out = _v({"scam": 9, "robocall": 3}, agree=6, reporters=12)
    assert out["code"] == "likely_spam"
    assert "likely" in out["label"].lower()
    assert "confirmed" not in out["label"].lower()


def test_people_saying_it_is_fine_can_outweigh(reporters=6):
    out = _v({"not_spam": 7}, disagree=4, reporters=7)
    assert out["code"] == "likely_legit"


# --- scam counts for more than spam ---------------------------------------

def test_a_scam_report_weighs_more_than_a_telemarketing_one():
    scam = _v({"scam": 4}, reporters=4)["score"]
    telemarketing = _v({"telemarketing": 4}, reporters=4)["score"]
    assert scam > telemarketing


def test_not_spam_reports_pull_the_score_down():
    assert _v({"scam": 5, "not_spam": 4}, reporters=9)["score"] < \
           _v({"scam": 5}, reporters=5)["score"]


# --- what the page must be able to show ------------------------------------

def test_the_categories_come_back_ordered_with_counts():
    out = _v({"telemarketing": 2, "scam": 7, "robocall": 4}, reporters=13)
    assert [c["code"] for c in out["categories"]] == ["scam", "robocall", "telemarketing"]
    assert out["categories"][0]["count"] == 7


def test_unknown_categories_are_dropped_rather_than_shown():
    """The enum is fixed on purpose — 'cheater' and 'ex' invite interpersonal
    abuse, so nothing outside the list is ever rendered."""
    out = _v({"scam": 2, "my_neighbour": 9}, reporters=11)
    assert [c["code"] for c in out["categories"]] == ["scam"]


def test_every_verdict_carries_a_plain_english_note():
    for counts, reporters in (({}, 0), ({"scam": 1}, 1), ({"scam": 9}, 9),
                              ({"scam": 4, "not_spam": 4}, 8)):
        out = _v(counts, reporters=reporters)
        assert out["note"] and len(out["note"]) > 20


def test_the_reporter_count_is_reported_back():
    assert _v({"scam": 3}, reporters=3)["reporters"] == 3


# --- it cannot be talked into certainty ------------------------------------

def test_nothing_ever_returns_a_confirmed_or_criminal_label():
    """No verdict may read as a finding of fact or an accusation of a crime."""
    for counts, agree, reporters in (({"scam": 99}, 99, 99), ({"spam": 40}, 20, 40)):
        label = _v(counts, agree=agree, reporters=reporters)["label"].lower()
        assert "confirmed" not in label
        assert "fraud" not in label
        assert "criminal" not in label


def test_negative_or_junk_counts_do_not_crash_it():
    assert _v({"scam": -5}, agree=-2, disagree=-3, reporters=-1)["code"] == "unknown"
