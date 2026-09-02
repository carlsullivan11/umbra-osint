"""FTC Do Not Call complaints — a second, independent source.

Consumer-reported calls published by the FTC. Independent of Umbra's own
community, so it corroborates rather than echoes; published by the government,
so provenance is checkable; and **explicitly unverified by the FTC**, so it is a
signal and never a finding.

**The API is the trap; the daily CSV is the source.** Measured against both from
production: the API cannot be filtered by number (unknown parameters are
silently ignored), caps a page at 50, ignores `page`, and walks ~19M records
from the oldest end with `offset` — 384,000 requests and still no way to ask
"complaints about this number". Its rows are also misaligned about 2% of the
time.

`DNC_Complaint_Numbers_<date>.csv` carries ~11,000 complaints and ~9,900
distinct numbers per day, over a 26-day rolling window, with clean columns and
no key. Same trade as abuse.ch and CISA KEV: the bulk download is the real
source and the API is the thing that looks convenient.

Rows are keyed by a content hash because the CSV has no row id, so re-reading an
overlapping day costs nothing.
"""
from __future__ import annotations

import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.db.schema import FtcComplaint, get_session, init_db  # noqa: E402
from umbra.phone import ftc  # noqa: E402

HEADER = ("Company_Phone_Number,Created_Date,Violation_Date,Consumer_City,"
          "Consumer_State,Consumer_Area_Code,Subject,Recorded_Message_Or_Robocall")

# Rows in the exact shape the live file uses.
GOOD = ("6302719743,2026-07-23 00:05:35,2026-07-22 23:46:00,harlingen,Texas,956,"
        "Calls pretending to be government,Y")
BLANK_PHONE = (",2026-07-23 00:07:00,2026-07-16 10:54:00,,Florida,239,Other,Y")
SHIFTED = ("06/10/2026,20261235,G,\"Otsuka Holdings Co., Ltd.\","
           "\"Transcend Therapeutics, Inc.\",\"Transcend Therapeutics, Inc.\",,")
NO_DATE = "6302719743,notadate,alsonot,harlingen,Texas,956,Other,Y"


def _csv(*rows):
    return "\n".join([HEADER, *rows]) + "\n"


@pytest.fixture
def session(tmp_path: Path):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    s = get_session()
    yield s
    s.close()


# --- parsing, which is mostly refusing ------------------------------------

def test_a_good_row_parses():
    rows = ftc.parse(_csv(GOOD), source_day="2026-07-23")
    assert len(rows) == 1
    assert rows[0].e164 == "+16302719743"
    assert rows[0].is_robocall is True
    assert rows[0].subject.startswith("Calls pretending")
    assert rows[0].source_day == "2026-07-23"


def test_a_row_with_no_phone_number_is_refused():
    assert ftc.parse(_csv(BLANK_PHONE)) == []


def test_a_field_shifted_row_is_refused():
    """A date in the phone column. Storing it would put "+0610 2026" on a page
    as a complaint about somebody."""
    assert ftc.parse(_csv(SHIFTED)) == []


def test_a_row_with_no_usable_date_is_refused():
    assert ftc.parse(_csv(NO_DATE)) == []


def test_the_good_rows_survive_the_bad_ones():
    rows = ftc.parse(_csv(SHIFTED, GOOD, BLANK_PHONE, NO_DATE))
    assert len(rows) == 1


def test_an_impossible_number_is_refused():
    assert ftc.parse(_csv("0000000000,2026-07-23 00:05:35,2026-07-22 23:46:00,,TX,956,Other,Y")) == []


def test_junk_input_is_not_a_crash():
    for junk in ("", "   ", "not,a,csv\n1,2,3"):
        assert ftc.parse(junk) == []


def test_the_robocall_flag_is_read_honestly():
    row = ftc.parse(_csv(GOOD.rsplit(",", 1)[0] + ",N"))[0]
    assert row.is_robocall is False


def test_the_same_row_hashes_the_same_way():
    """Re-reading an overlapping day must not duplicate it."""
    a = ftc.parse(_csv(GOOD), source_day="2026-07-23")[0]
    b = ftc.parse(_csv(GOOD), source_day="2026-07-24")[0]
    assert a.id == b.id


# --- which days to pull ---------------------------------------------------

INDEX = '''<a href="/sites/default/files/DNC_Complaint_Numbers_2026-08-18.csv">x</a>
<a href="/sites/default/files/DNC_Complaint_Numbers_2026-08-14.csv">x</a>
<a href="/sites/default/files/DNC_Complaint_Numbers_2026-07-16_0.csv">x</a>'''


def test_available_days_are_newest_first():
    assert ftc.available_days(INDEX) == ["2026-08-18", "2026-08-14", "2026-07-16"]


def test_the_file_url_keeps_the_suffix_some_days_carry():
    """Some days are published as `_0.csv`; guessing the plain name 404s."""
    assert ftc.file_url(INDEX, "2026-07-16").endswith("DNC_Complaint_Numbers_2026-07-16_0.csv")


def test_an_empty_index_yields_nothing():
    assert ftc.available_days("") == []


# --- ingest ---------------------------------------------------------------

def test_ingest_stores_rows(session):
    assert ftc.ingest(session, ftc.parse(_csv(GOOD), "2026-07-23")) == 1
    assert session.query(FtcComplaint).count() == 1


def test_ingest_is_idempotent(session):
    """The published window overlaps every run. Keying on the row's content
    makes re-reading a day free."""
    rows = ftc.parse(_csv(GOOD), "2026-07-23")
    ftc.ingest(session, rows)
    assert ftc.ingest(session, rows) == 0
    assert session.query(FtcComplaint).count() == 1


def test_a_day_already_ingested_is_not_downloaded_again(session):
    ftc.ingest(session, ftc.parse(_csv(GOOD), "2026-07-23"))
    assert "2026-07-23" in ftc.ingested_days(session)


def test_ingest_skips_nothing_silently(session):
    assert ftc.ingest(session, []) == 0


# --- the point lookup -----------------------------------------------------

def _many(session, digits: str, n: int, subject="Other", robocall=True):
    rows = [
        f"{digits},2026-07-23 00:{i // 60:02d}:{i % 60:02d},"
        f"2026-07-22 23:46:00,city{i},Texas,956,{subject},{'Y' if robocall else 'N'}"
        for i in range(n)
    ]
    ftc.ingest(session, ftc.parse(_csv(*rows), "2026-07-23"))


def test_a_number_with_no_complaints_says_so(session):
    summary = ftc.summary(session, "+16302719743")
    assert summary["complaints"] == 0
    assert "not" in summary["note"].lower()


def test_complaints_are_counted_for_the_number(session):
    _many(session, "6302719743", 7)
    summary = ftc.summary(session, "+16302719743")
    assert summary["complaints"] == 7


def test_the_summary_names_the_top_subjects(session):
    _many(session, "6302719743", 5, subject="Calls pretending to be government")
    summary = ftc.summary(session, "+16302719743")
    assert summary["subjects"][0]["subject"].startswith("Calls pretending")


def test_the_summary_says_the_ftc_does_not_verify(session):
    """The FTC states this plainly, and a page that omits it is claiming more
    than its source does."""
    _many(session, "6302719743", 3)
    assert "not verified" in ftc.summary(session, "+16302719743")["note"].lower()


def test_the_summary_is_attributed(session):
    _many(session, "6302719743", 3)
    summary = ftc.summary(session, "+16302719743")
    assert "ftc" in summary["source"].lower()
    assert summary["source_url"].startswith("https://")


def test_an_empty_index_is_not_reported_as_a_clean_number(session):
    """Nothing ingested yet is not "the FTC has no complaints" — the same
    unchecked-is-not-clean rule as everywhere else."""
    summary = ftc.summary(session, "+16302719743")
    assert summary["checked"] is False
    assert "no complaints" not in summary["note"].lower() or "not" in summary["note"].lower()


def test_a_populated_index_reports_a_real_zero(session):
    _many(session, "2125550000", 2)  # some other number
    summary = ftc.summary(session, "+16302719743")
    assert summary["checked"] is True
    assert summary["complaints"] == 0


# --- it stays a separate layer --------------------------------------------

def test_ftc_counts_do_not_feed_the_community_verdict(session):
    """Mixing a government feed into a community verdict blurs which is which.
    They sit side by side."""
    from umbra.phone import store as phone_store

    row = phone_store.get_or_create(session, "+16302719743")
    _many(session, "6302719743", 40)
    view = phone_store.public_view(session, row.id)
    assert view["verdict"]["code"] == "unknown"
    assert view["ftc"]["complaints"] == 40


def test_the_notes_are_plain_text_not_markdown(session):
    """These strings are rendered into HTML, where `**bold**` renders as
    literal asterisks."""
    _many(session, "6302719743", 3)
    for note in (ftc.summary(session, "+16302719743")["note"],
                 ftc.summary(session, "+12125550000")["note"]):
        assert "**" not in note
        assert "__" not in note
