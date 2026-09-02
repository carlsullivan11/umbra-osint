"""The community write path — reports, votes, retraction, moderation.

This is the point where Umbra starts hosting strangers' allegations about phone
lines that belong to somebody. Every rule below exists because of a specific way
that goes wrong:

| Failure | Rule |
|---|---|
| One person decides a number's reputation | One report per reporter, and one reporter is never a verdict |
| Sockpuppets vote a number down | One vote per principal, changeable, counted separately from reports |
| A note becomes a doxxing field | 280 chars, no emails, no addresses, no SSN/card-shaped digits, no links |
| Somebody reports in anger and regrets it | Retract, by the reporter, without asking anyone |
| A number is brigaded and nobody can stop it | Operator hide, on the number and on individual reports |
| Reporting identifies the reporter | `reporter_key` is an HMAC of the anonymous cookie and nothing else |

The counters are recomputed from rows rather than incremented, because a
counter that drifts from its rows is a number the page states as fact and
cannot back up.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.db.schema import PhoneNumber, PhoneReport, PhoneVote, get_session, init_db  # noqa: E402
from umbra.phone import store as phone_store  # noqa: E402

NUMBER = "+14155550134"


@pytest.fixture
def session(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("UMBRA_SESSION_SECRET", "test-session-secret-long-enough")
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    s = get_session()
    yield s
    s.close()


@pytest.fixture
def phone(session):
    return phone_store.get_or_create(session, NUMBER)


def _key(owner: str) -> str:
    return phone_store.reporter_key(owner)


# --- who is reporting -----------------------------------------------------

def test_the_reporter_key_is_not_the_cookie(session):
    """Storing the session id would tie every report to a browser."""
    key = _key("owner-abc")
    assert "owner-abc" not in key
    assert len(key) >= 32


def test_the_same_visitor_gets_the_same_key(session):
    assert _key("owner-abc") == _key("owner-abc")


def test_different_visitors_get_different_keys(session):
    assert _key("owner-abc") != _key("owner-def")


def test_rotating_the_secret_rotates_the_keys(session, monkeypatch):
    before = _key("owner-abc")
    monkeypatch.setenv("UMBRA_SESSION_SECRET", "an-entirely-different-secret")
    assert _key("owner-abc") != before


# --- reporting ------------------------------------------------------------

def test_a_report_is_stored_and_counted(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    session.refresh(phone)
    assert phone.report_count == 1
    assert phone.first_report_at and phone.last_report_at


def test_one_reporter_one_report_per_number(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone_store.add_report(session, phone.id, _key("a"), "telemarketing")
    assert session.query(PhoneReport).count() == 1
    session.refresh(phone)
    assert phone.report_count == 1


def test_reporting_again_updates_the_category(session, phone):
    """Changing your mind is not a second voice."""
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone_store.add_report(session, phone.id, _key("a"), "telemarketing")
    assert session.query(PhoneReport).one().category == "telemarketing"


def test_a_category_outside_the_enum_is_refused(session, phone):
    assert phone_store.add_report(session, phone.id, _key("a"), "my_ex") is None
    assert session.query(PhoneReport).count() == 0


def test_two_reporters_are_two_reports(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone_store.add_report(session, phone.id, _key("b"), "scam")
    session.refresh(phone)
    assert phone.report_count == 2


# --- the note field, which is the dangerous one ---------------------------

def test_a_note_is_kept_short(session, phone):
    report = phone_store.add_report(session, phone.id, _key("a"), "scam",
                                    note="x" * 900)
    assert len(report.note) <= 280


def test_a_note_containing_an_email_is_refused(session, phone):
    """A note is about a caller's behaviour, not a place to publish somebody's
    contact details."""
    assert phone_store.add_report(session, phone.id, _key("a"), "scam",
                                  note="this is bob@example.com") is None


def test_a_note_containing_a_long_digit_run_is_refused(session, phone):
    """SSN- and card-shaped strings do not belong in a public note."""
    for pii in ("ssn 123-45-6789", "card 4111 1111 1111 1111"):
        assert phone_store.add_report(session, phone.id, _key("a"), "scam",
                                      note=pii) is None


def test_a_note_containing_a_link_is_refused(session, phone):
    assert phone_store.add_report(session, phone.id, _key("a"), "scam",
                                  note="see https://evil.example/x") is None


def test_a_note_containing_a_street_address_is_refused(session, phone):
    assert phone_store.add_report(session, phone.id, _key("a"), "scam",
                                  note="he lives at 123 Main Street") is None


def test_an_ordinary_note_is_kept(session, phone):
    report = phone_store.add_report(
        session, phone.id, _key("a"), "scam",
        note="Claimed to be from my bank and asked for a one-time code.")
    assert report.note.startswith("Claimed to be")


def test_a_refused_note_does_not_half_write_the_report(session, phone):
    """Rejecting the note must not leave the report behind without it."""
    phone_store.add_report(session, phone.id, _key("a"), "scam", note="a@b.com")
    assert session.query(PhoneReport).count() == 0


# --- retraction -----------------------------------------------------------

def test_a_reporter_can_retract(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    assert phone_store.retract(session, phone.id, _key("a")) is True
    session.refresh(phone)
    assert phone.report_count == 0


def test_a_retracted_report_stops_counting_in_the_verdict(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone_store.add_report(session, phone.id, _key("b"), "scam")
    phone_store.retract(session, phone.id, _key("a"))
    view = phone_store.public_view(session, phone.id)
    assert view["reports"] == 1


def test_you_cannot_retract_somebody_elses_report(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    assert phone_store.retract(session, phone.id, _key("b")) is False
    session.refresh(phone)
    assert phone.report_count == 1


def test_retracting_twice_is_harmless(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone_store.retract(session, phone.id, _key("a"))
    assert phone_store.retract(session, phone.id, _key("a")) is False


# --- votes ----------------------------------------------------------------

def test_a_vote_is_counted(session, phone):
    phone_store.cast_vote(session, phone.id, _key("a"), 1)
    session.refresh(phone)
    assert phone.agree_count == 1


def test_one_voter_one_vote(session, phone):
    phone_store.cast_vote(session, phone.id, _key("a"), 1)
    phone_store.cast_vote(session, phone.id, _key("a"), 1)
    assert session.query(PhoneVote).count() == 1
    session.refresh(phone)
    assert phone.agree_count == 1


def test_a_voter_can_change_their_mind(session, phone):
    phone_store.cast_vote(session, phone.id, _key("a"), 1)
    phone_store.cast_vote(session, phone.id, _key("a"), -1)
    session.refresh(phone)
    assert phone.agree_count == 0
    assert phone.disagree_count == 1


def test_a_junk_vote_value_is_refused(session, phone):
    for bad in (0, 5, -9, None):
        assert phone_store.cast_vote(session, phone.id, _key("a"), bad) is False
    session.refresh(phone)
    assert phone.agree_count == 0


def test_votes_alone_never_make_a_verdict(session, phone):
    """Otherwise a number with no reports at all could be voted into a label."""
    for who in "abcdefghij":
        phone_store.cast_vote(session, phone.id, _key(who), 1)
    assert phone_store.public_view(session, phone.id)["verdict"]["code"] == "unknown"


# --- moderation, shipped with the write path not after it -----------------

def test_an_operator_can_hide_a_single_report(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam", note="fine note")
    phone_store.add_report(session, phone.id, _key("b"), "scam")
    report = session.query(PhoneReport).first()
    assert phone_store.hide_report(session, report.id, actor="carl",
                                   reason="abusive") is True
    assert phone_store.public_view(session, phone.id)["reports"] == 1


def test_an_operator_can_hide_a_whole_number(session, phone):
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    assert phone_store.hide_phone(session, phone.id, actor="carl",
                                  reason="brigaded") is True
    assert phone_store.public_view(session, phone.id) is None


def test_moderation_is_recorded_with_a_reason(session, phone):
    from umbra.db.schema import PhoneModerationEvent

    phone_store.hide_phone(session, phone.id, actor="carl", reason="brigaded")
    event = session.query(PhoneModerationEvent).one()
    assert event.actor == "carl"
    assert event.reason == "brigaded"
    assert event.action


def test_hiding_survives_new_reports(session, phone):
    """A hidden number stays hidden; it is not un-hidden by more traffic."""
    phone_store.hide_phone(session, phone.id, actor="carl", reason="brigaded")
    phone_store.add_report(session, phone.id, _key("z"), "scam")
    assert phone_store.public_view(session, phone.id) is None


# --- counters cannot drift ------------------------------------------------

def test_counters_are_recomputed_not_incremented(session, phone):
    """A counter that drifts from its rows is a number the page states as fact
    and cannot back up."""
    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone_store.add_report(session, phone.id, _key("b"), "scam")
    phone.report_count = 99  # simulate drift
    session.commit()
    phone_store.add_report(session, phone.id, _key("c"), "scam")
    session.refresh(phone)
    assert phone.report_count == 3


def test_a_reported_number_is_not_purged_by_retention(session, phone):
    from datetime import timedelta

    from umbra.core.models import utcnow

    phone_store.add_report(session, phone.id, _key("a"), "scam")
    phone.created_at = utcnow() - timedelta(days=400)
    session.commit()
    assert phone_store.purge_unreported(session, days=30) == 0
