"""Telling visitors apart from crawlers.

Measured on production over seven days: **6,061 of 8,020 recorded views were
automation** — Googlebot sweeping the 3.6k-page wiki corpus (which is the SEO
work doing exactly its job), plus a steady drizzle of WordPress scanners asking
for `/xmlrpc.php` and `wp-includes/wlwmanifest.xml` on a site that has never run
WordPress.

Summing those with real people makes the one page Carl reads to judge traction
overstate it by roughly 4x. The counts were never wrong; the question they
answered was.

**Classification happens at read time, not write time.** The raw row keeps its
user agent, so improving these rules re-reads history correctly instead of only
applying to whatever is recorded next — and nothing is silently discarded at the
door on the strength of a substring match.
"""
from __future__ import annotations

import warnings
from pathlib import Path
from uuid import uuid4

import pytest

warnings.filterwarnings("ignore")

from umbra.analytics import is_bot_ua, summarize  # noqa: E402
from umbra.core.config import Settings  # noqa: E402
from umbra.core.models import utcnow  # noqa: E402
from umbra.db.schema import PageView, get_session, init_db  # noqa: E402

BROWSER = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/126.0 Safari/537.36")
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@pytest.fixture
def db(tmp_path: Path, monkeypatch):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    monkeypatch.setattr("umbra.analytics.get_settings", lambda: settings, raising=False)
    return settings


def _view(path: str, ua: str | None, visitor: str = "v1", status: int = 200):
    session = get_session()
    session.add(PageView(id=uuid4().hex[:16], ts=utcnow(), path=path, method="GET",
                         status=status, duration_ms=1.0, user_agent=ua,
                         visitor_hash=visitor))
    session.commit()
    session.close()


# --- what counts as automation --------------------------------------------

@pytest.mark.parametrize("ua", [
    GOOGLEBOT,
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl)",
    "python-requests/2.31.0",
    "curl/8.5.0",
    "Wget/1.21",
    "Go-http-client/1.1",
    "Scrapy/2.11 (+https://scrapy.org)",
    "HeadlessChrome/120.0.0.0",
    "Mozilla/5.0 (compatible; CensysInspect/1.1)",
    "zgrab/0.x",
    "",
    None,
])
def test_automation_is_recognised(ua):
    assert is_bot_ua(ua) is True


@pytest.mark.parametrize("ua", [
    BROWSER,
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0 Safari/537.36 Edg/125.0",
])
def test_a_real_browser_is_not_flagged(ua):
    assert is_bot_ua(ua) is False


def test_the_word_bot_inside_a_browser_string_does_not_trip_it():
    """"Ubuntu" and "robot" both contain letters that a careless substring rule
    catches. A false positive here erases a real visitor."""
    assert is_bot_ua("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) "
                     "Gecko/20100101 Firefox/127.0") is False


# --- the summary answers the question that was asked ----------------------

def test_the_headline_numbers_exclude_automation(db):
    for i in range(6):
        _view("/wiki/cve/cve-2021-44228", GOOGLEBOT, visitor=f"bot{i}")
    _view("/", BROWSER, visitor="human1")
    _view("/reputation", BROWSER, visitor="human1")

    data = summarize(days=7)
    assert data["total_views"] == 2
    assert data["unique_visitors_approx"] == 1


def test_the_bot_traffic_is_reported_rather_than_hidden(db):
    """It is 76% of the log and it is how the corpus gets indexed — that is a
    result, not noise to bury."""
    for i in range(6):
        _view("/wiki/x", GOOGLEBOT, visitor=f"bot{i}")
    _view("/", BROWSER, visitor="human1")

    data = summarize(days=7)
    assert data["bot_views"] == 6
    assert data["bot_share"] == pytest.approx(6 / 7, abs=0.01)


def test_top_paths_reflect_people_not_crawlers(db):
    """Otherwise every ranking is just the sitemap read back."""
    for i in range(20):
        _view(f"/wiki/page-{i}", GOOGLEBOT, visitor=f"bot{i}")
    for _ in range(3):
        _view("/reputation", BROWSER, visitor="human1")

    paths = [p["path"] for p in summarize(days=7)["top_paths"]]
    assert paths[0] == "/reputation"
    assert not any(p.startswith("/wiki/page-") for p in paths)


def test_scanner_probes_do_not_count_as_visits(db):
    """`/xmlrpc.php` on a site that has never run WordPress is not a visitor
    with an interest in the product."""
    _view("/xmlrpc.php", BROWSER, visitor="scanner", status=404)
    _view("/wordpress/wp-includes/wlwmanifest.xml", BROWSER, visitor="scanner", status=404)
    _view("/", BROWSER, visitor="human1")

    data = summarize(days=7)
    assert data["total_views"] == 1


def test_a_real_404_by_a_real_visitor_still_counts(db):
    """A person following a stale link is a person. Only known probe paths are
    discounted, not every miss."""
    _view("/wiki/does-not-exist", BROWSER, visitor="human1", status=404)
    assert summarize(days=7)["total_views"] == 1


def test_bots_can_be_included_when_that_is_the_question(db):
    for i in range(4):
        _view("/wiki/x", GOOGLEBOT, visitor=f"bot{i}")
    _view("/", BROWSER, visitor="human1")
    assert summarize(days=7, include_bots=True)["total_views"] == 5


def test_an_empty_window_does_not_break(db):
    data = summarize(days=7)
    assert data["total_views"] == 0
    assert data["bot_views"] == 0
    assert data["bot_share"] == 0


# --- nothing is thrown away ------------------------------------------------

def test_classification_happens_on_read_not_on_write(db):
    """Filtering at the door would mean a rule change can never fix history,
    and a false positive would delete evidence rather than mislabel it."""
    src = Path(__file__).resolve().parents[1] / "src/umbra/analytics/__init__.py"
    body = src.read_text()
    record = body[body.index("def record_page_view"):body.index("def _like")]
    assert "is_bot_ua" not in record, "the recorder must keep every row"
    assert "is_probe_path" not in record
