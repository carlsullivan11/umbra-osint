"""The community phone store.

Kept deliberately separate from the investigation graph: a case is evidence an
operator collected under an authorization basis, and a community report is a
stranger's allegation. Letting the second flow into the first would poison the
provenance model the whole product rests on.

Two privacy decisions are pinned here.

**A lookup is not a report.** Rows created by someone merely searching carry no
reports and are prunable, so the table does not silently become a log of every
number anyone typed. Retention has a sweep for exactly that.

**The URL is opaque.** Result pages are keyed by an id, not by the number, so a
shared link does not spread the number through referrers, histories and search
indexes — and the table cannot be enumerated by walking phone numbers.
"""
from __future__ import annotations

import warnings
from datetime import timedelta
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.core.models import utcnow  # noqa: E402
from umbra.db.schema import PhoneNumber, get_session, init_db  # noqa: E402
from umbra.phone import store as phone_store  # noqa: E402


@pytest.fixture
def session(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    s = get_session()
    yield s
    s.close()


# --- lookup ---------------------------------------------------------------

def test_a_lookup_creates_one_row_and_reuses_it(session):
    first = phone_store.get_or_create(session, "+14155550134")
    second = phone_store.get_or_create(session, "+14155550134")
    assert first.id == second.id
    assert session.query(PhoneNumber).count() == 1


def test_only_e164_is_stored(session):
    row = phone_store.get_or_create(session, "+14155550134")
    assert row.e164 == "+14155550134"
    assert not hasattr(row, "raw_input")


def test_the_id_is_opaque_and_not_the_number(session):
    """A result URL must not carry the number into referrers and histories."""
    row = phone_store.get_or_create(session, "+14155550134")
    assert "4155550134" not in row.id
    assert len(row.id) >= 16


def test_ids_are_not_guessable_from_each_other(session):
    ids = {phone_store.get_or_create(session, f"+1415555{n:04d}").id
           for n in range(20)}
    assert len(ids) == 20


def test_an_unparseable_number_is_refused(session):
    for junk in ("", "   ", "not-a-number", "12"):
        assert phone_store.get_or_create(session, junk) is None
    assert session.query(PhoneNumber).count() == 0


def test_emergency_numbers_are_refused(session):
    """911 is not a spam report target, and a page implying otherwise is a
    liability with no upside."""
    for emergency in ("911", "+1911", "999", "112"):
        assert phone_store.get_or_create(session, emergency) is None


def test_short_codes_are_refused(session):
    """Five-digit shortcodes are shared marketing infrastructure, not lines."""
    assert phone_store.get_or_create(session, "62966") is None


# --- the public view ------------------------------------------------------

def test_a_fresh_number_has_an_honest_empty_verdict(session):
    row = phone_store.get_or_create(session, "+14155550134")
    view = phone_store.public_view(session, row.id)
    assert view["verdict"]["code"] == "unknown"
    assert view["reports"] == 0


def test_the_view_carries_the_offline_facts(session):
    """L0 validation is the one thing Umbra can state as fact here, and on a
    page with no community data it is all there is."""
    row = phone_store.get_or_create(session, "+14155550134")
    view = phone_store.public_view(session, row.id)
    assert view["facts"]["e164"] == "+14155550134"
    assert view["facts"]["region"] == "US"
    assert view["facts"]["national_format"]


def test_an_unknown_id_returns_nothing(session):
    assert phone_store.public_view(session, "nope") is None


def test_a_hidden_number_is_not_served(session):
    """Operator moderation has to actually remove the page from the public."""
    row = phone_store.get_or_create(session, "+14155550134")
    row.hidden = True
    session.commit()
    assert phone_store.public_view(session, row.id) is None


# --- retention: a search is not a record ----------------------------------

def test_report_less_lookups_are_prunable(session):
    """Otherwise the table quietly becomes a list of every number anyone
    searched for."""
    row = phone_store.get_or_create(session, "+14155550134")
    row.created_at = utcnow() - timedelta(days=60)
    session.commit()
    assert phone_store.purge_unreported(session, days=30) == 1
    assert session.query(PhoneNumber).count() == 0


def test_a_recent_lookup_is_kept(session):
    phone_store.get_or_create(session, "+14155550134")
    assert phone_store.purge_unreported(session, days=30) == 0


def test_a_reported_number_is_never_purged(session):
    """The reports are the reason the row exists; they are not lookup residue."""
    row = phone_store.get_or_create(session, "+14155550134")
    row.created_at = utcnow() - timedelta(days=400)
    row.report_count = 3
    session.commit()
    assert phone_store.purge_unreported(session, days=30) == 0


def test_a_number_whose_only_report_was_retracted_is_kept(session):
    """Retraction zeroes report_count but the report row stays. Deleting the
    number would violate phone_reports' foreign key and abort the sweep."""
    row = phone_store.get_or_create(session, "+14155550134")
    key = phone_store.reporter_key("owner-1")
    phone_store.add_report(session, row.id, key, "scam")
    assert phone_store.retract(session, row.id, key)
    assert row.report_count == 0
    lookup = phone_store.get_or_create(session, "+14155550199")
    row.created_at = lookup.created_at = utcnow() - timedelta(days=60)
    session.commit()

    assert phone_store.purge_unreported(session, days=30) == 1
    assert session.get(PhoneNumber, row.id) is not None
    assert session.get(PhoneNumber, lookup.id) is None


def test_a_voted_on_number_is_kept(session):
    row = phone_store.get_or_create(session, "+14155550134")
    phone_store.cast_vote(session, row.id, phone_store.reporter_key("owner-2"), 1)
    row.created_at = utcnow() - timedelta(days=60)
    session.commit()
    assert phone_store.purge_unreported(session, days=30) == 0


def test_purge_is_disabled_by_a_zero_window(session):
    row = phone_store.get_or_create(session, "+14155550134")
    row.created_at = utcnow() - timedelta(days=999)
    session.commit()
    assert phone_store.purge_unreported(session, days=0) == 0


# --- it stays out of the investigation graph ------------------------------

def test_the_community_tables_are_not_the_case_graph():
    """A stranger's allegation must never arrive in a case as collected
    evidence — the provenance model is the product."""
    from umbra.db import schema

    assert not hasattr(schema.PhoneNumber, "case_id")
    assert not hasattr(schema.PhoneReport, "case_id")
