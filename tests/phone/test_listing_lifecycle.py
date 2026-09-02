"""Where a number's spam listing comes from, and when it stops.

Two additions, both about not overstating what Umbra knows.

**Whose report is it.** Seeding a list of numbers from one person's call log and
rendering it as community consensus would be fabricating a crowd. Operator
reports are marked as such, counted as the one voice they are, and labelled on
the page as coming from the operator — a named, accountable party — rather than
from "the community".

**A listing is a claim about now.** Spam numbers are recycled, reassigned and
abandoned; a number reported heavily in March and silent since is not evidence
about whoever answers it today. So a listing goes **inactive** once nothing has
happened for the window, and the page says it was previously reported instead of
carrying a live accusation forever.

Delisting is not deletion. The reports stay, the dates stay, and the moderation
log records the delisting — "it was on the list once" has to remain answerable,
both for the operator and for whoever the number belongs to.
"""
from __future__ import annotations

import warnings
from datetime import timedelta
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.core.models import utcnow  # noqa: E402
from umbra.db.schema import (  # noqa: E402
    PhoneModerationEvent,
    PhoneNumber,
    PhoneReport,
    get_session,
    init_db,
)
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


def _age(session, phone, days: float):
    """Push every report and the number's activity back in time."""
    when = utcnow() - timedelta(days=days)
    for report in session.query(PhoneReport).filter_by(phone_id=phone.id):
        report.created_at = when
    phone.last_report_at = when
    session.commit()


# --- whose report is it ---------------------------------------------------

def test_a_report_records_its_source(session, phone):
    community = phone_store.add_report(session, phone.id, phone_store.reporter_key("a"),
                                       "spam")
    assert community.source == "community"


def test_an_operator_report_is_marked_as_one(session, phone):
    """Seeding a call log and rendering it as community consensus would be
    inventing a crowd out of one person."""
    report = phone_store.add_report(session, phone.id, "operator:carl", "spam",
                                    source="operator")
    assert report.source == "operator"


def test_the_page_says_when_a_report_came_from_the_operator(session, phone):
    phone_store.add_report(session, phone.id, "operator:carl", "spam",
                           source="operator")
    view = phone_store.public_view(session, phone.id)
    assert view["operator_reports"] == 1
    assert "operator" in view["verdict"]["note"].lower()


def test_an_operator_report_is_still_only_one_voice(session, phone):
    """It does not get to be a consensus by itself. The protective floor holds
    for the operator too."""
    phone_store.add_report(session, phone.id, "operator:carl", "spam",
                           source="operator")
    assert phone_store.public_view(session, phone.id)["verdict"]["code"] == "unconfirmed"


def test_community_reports_stack_on_top_of_an_operator_one(session, phone):
    phone_store.add_report(session, phone.id, "operator:carl", "scam", source="operator")
    for who in "abcdef":
        phone_store.add_report(session, phone.id, phone_store.reporter_key(who), "scam")
    view = phone_store.public_view(session, phone.id)
    assert view["verdict"]["code"] == "likely_spam"
    assert view["operator_reports"] == 1


# --- a listing goes quiet -------------------------------------------------

def test_a_fresh_listing_is_active(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    assert phone_store.public_view(session, phone.id)["active"] is True


def test_a_silent_listing_expires(session, phone):
    """Numbers get reassigned. A report from six months ago is not evidence
    about whoever answers today."""
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    assert phone_store.expire_stale_listings(session, days=180) == 1
    assert phone_store.public_view(session, phone.id)["active"] is False


def test_an_expired_listing_keeps_its_reports(session, phone):
    """Delisting is not deletion — "it was on the list once" stays answerable."""
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    phone_store.expire_stale_listings(session, days=180)
    assert session.query(PhoneReport).count() == 1
    view = phone_store.public_view(session, phone.id)
    assert view["reports"] == 1
    assert view["delisted_at"] is not None


def test_an_expired_page_says_previously_rather_than_currently(session, phone):
    for who in "abcdefgh":
        phone_store.add_report(session, phone.id, phone_store.reporter_key(who), "scam")
    _age(session, phone, 400)
    phone_store.expire_stale_listings(session, days=180)
    note = phone_store.public_view(session, phone.id)["verdict"]["note"].lower()
    assert "previously" in note or "no longer" in note or "not been reported since" in note


def test_the_delisting_is_logged(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    phone_store.expire_stale_listings(session, days=180)
    event = session.query(PhoneModerationEvent).filter_by(action="delist").one()
    assert event.phone_id == phone.id
    assert event.reason


def test_a_recent_listing_is_left_alone(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 30)
    assert phone_store.expire_stale_listings(session, days=180) == 0


def test_a_number_with_no_reports_is_not_a_listing_to_expire(session, phone):
    _age(session, phone, 999)
    assert phone_store.expire_stale_listings(session, days=180) == 0


def test_expiry_is_disabled_by_a_zero_window(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 999)
    assert phone_store.expire_stale_listings(session, days=0) == 0


def test_expiring_twice_does_not_re_log_it(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    phone_store.expire_stale_listings(session, days=180)
    assert phone_store.expire_stale_listings(session, days=180) == 0
    assert session.query(PhoneModerationEvent).filter_by(action="delist").count() == 1


# --- and comes back -------------------------------------------------------

def test_a_new_report_relists_the_number(session, phone):
    """If it starts calling people again it is live again."""
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    phone_store.expire_stale_listings(session, days=180)
    phone_store.add_report(session, phone.id, phone_store.reporter_key("b"), "spam")
    assert phone_store.public_view(session, phone.id)["active"] is True


def test_the_earlier_delisting_is_still_in_the_log(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    phone_store.expire_stale_listings(session, days=180)
    phone_store.add_report(session, phone.id, phone_store.reporter_key("b"), "spam")
    assert session.query(PhoneModerationEvent).filter_by(action="delist").count() == 1


def test_a_vote_alone_does_not_relist(session, phone):
    """Otherwise one agree click resurrects a listing everyone else forgot."""
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    _age(session, phone, 200)
    phone_store.expire_stale_listings(session, days=180)
    phone_store.cast_vote(session, phone.id, phone_store.reporter_key("c"), 1)
    assert phone_store.public_view(session, phone.id)["active"] is False


# --- the active list ------------------------------------------------------

def test_the_active_list_excludes_expired_numbers(session):
    live = phone_store.get_or_create(session, "+14155550111")
    stale = phone_store.get_or_create(session, "+14155550222")
    phone_store.add_report(session, live.id, phone_store.reporter_key("a"), "spam")
    phone_store.add_report(session, stale.id, phone_store.reporter_key("b"), "spam")
    _age(session, stale, 300)
    phone_store.expire_stale_listings(session, days=180)
    listed = [p["e164"] for p in phone_store.active_listings(session)]
    assert listed == ["+14155550111"]


def test_the_active_list_excludes_hidden_numbers(session, phone):
    phone_store.add_report(session, phone.id, phone_store.reporter_key("a"), "spam")
    phone_store.hide_phone(session, phone.id, actor="carl", reason="brigaded")
    assert phone_store.active_listings(session) == []


# --- the operator's own seed list -----------------------------------------

def test_seeding_files_operator_reports_not_community_ones(session, tmp_path, monkeypatch):
    """`umbra phone seed` is how the operator puts their own call log in. It
    must not arrive looking like other people said it."""
    from typer.testing import CliRunner

    from umbra.cli.main import app

    settings = Settings(data_dir=tmp_path)
    monkeypatch.setattr("umbra.cli.phone_cmd.get_settings", lambda: settings,
                        raising=False)
    numbers = tmp_path / "spam.txt"
    numbers.write_text("+14155550111\n+14155550222\n+14155550111\n")

    result = CliRunner().invoke(app, ["phone", "seed", "--file", str(numbers)])
    assert result.exit_code == 0
    assert "2 reported" in result.output
    assert "1 duplicate" in result.output

    s = get_session()
    try:
        reports = s.query(PhoneReport).all()
        assert len(reports) == 2
        assert {r.source for r in reports} == {"operator"}
    finally:
        s.close()


def test_a_seeded_number_reads_as_one_source_not_a_consensus(session, tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from umbra.cli.main import app

    settings = Settings(data_dir=tmp_path)
    monkeypatch.setattr("umbra.cli.phone_cmd.get_settings", lambda: settings,
                        raising=False)
    CliRunner().invoke(app, ["phone", "seed", "+14155550111"])

    s = get_session()
    try:
        row = s.query(PhoneNumber).one()
        view = phone_store.public_view(s, row.id)
        assert view["verdict"]["code"] == "unconfirmed"
        assert "operator" in view["verdict"]["note"].lower()
    finally:
        s.close()


def test_the_daily_sweep_expires_listings():
    """Delisting only matters if something runs it."""
    src = (Path(__file__).resolve().parents[2]
           / "src/umbra/cli/case_cmd.py").read_text()
    assert "expire_stale_listings" in src
