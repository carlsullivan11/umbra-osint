"""A favicon is not a lead.

Measured on a real visitor search. `sflix.today` produced **159 evidence rows**,
of which **126** were three collectors re-run on 42 discovered URLs:

    tech_fingerprint  42      http_probe  42      html_links  42

Most of those 42 were not pages:

    Links from https://sflix.today/favicon-16x16.png: social=0 email=0 urls=0
    Links from https://sflix.today/icons/icon-512.png: social=0 email=0 urls=0
    Links from https://sflix.today/_next/static/chunks/3a3nn_aa4vhkp.js: …
    HTTP 200 title=None server='cloudflare'      x19

The cause is precise. `html_links` extracts with
``_HREF_RE = href=["']([^"']+)["']`` — which matches **every** `href`, not only
`<a href>`. `<link rel="icon">`, `<link rel="stylesheet">`,
`<link rel="manifest">` and `<link rel="alternate" type="application/rss+xml">`
all match, so every asset a page references became a URL entity worth fetching
three more times.

The cost is 42 wasted requests against someone else's host per search, the
substantive answer buried under six times its own weight, and
`tech_fingerprint` reporting the server stack of a PNG.

Filtered at **emission**, not at the collector: a URL a user pastes deliberately
should still be probed, because that is what they asked for. What must stop is
*pivoting into* assets nobody asked about.
"""
from __future__ import annotations

import pytest

from umbra.core.normalize import is_static_asset

ASSETS = [
    "https://sflix.today/favicon.ico",
    "https://sflix.today/favicon-16x16.png",
    "https://sflix.today/icons/icon-512.png",
    "https://sflix.today/icons/apple-touch-icon.png",
    "https://sflix.today/favicon.svg",
    "https://sflix.today/_next/static/chunks/003741ctaas8d.css",
    "https://sflix.today/_next/static/chunks/3a3nn_aa4vhkp.js",
    "https://sflix.today/manifest.webmanifest",
    "https://sflix.today/opensearch.xml",
    "https://sflix.today/feeds/trending.xml",
    "https://example.com/fonts/inter.woff2",
    "https://example.com/video/clip.mp4",
    "https://example.com/logo.JPG",              # case must not matter
    "https://example.com/a.png?v=8e1bcc8f82",    # cache-buster query
    "https://example.com/style.css#frag",
]

PAGES = [
    "https://sflix.today/",
    "https://sflix.today/ar",
    "https://sflix.today/transparency",
    "https://example.com/about/team",
    "https://example.com/blog/2026/a-post",
    "https://example.com/search?q=widgets",
    "https://example.com/download",
    "https://example.com/",
]


@pytest.mark.parametrize("url", ASSETS)
def test_assets_are_recognised(url):
    assert is_static_asset(url) is True


@pytest.mark.parametrize("url", PAGES)
def test_pages_are_not_assets(url):
    assert is_static_asset(url) is False


def test_a_path_that_merely_mentions_an_extension_is_a_page():
    """`/css-frameworks` and `/blog/png-vs-webp` are articles, not assets."""
    assert is_static_asset("https://example.com/css-frameworks") is False
    assert is_static_asset("https://example.com/blog/png-vs-webp") is False


def test_a_directory_ending_in_a_dotted_name_is_not_confused():
    assert is_static_asset("https://example.com/v1.2/docs") is False


@pytest.mark.parametrize("bad", ["", "not a url", "https://", "mailto:a@b.c"])
def test_junk_never_raises(bad):
    assert is_static_asset(bad) in (True, False)


# --- the emitter must apply it ---------------------------------------------

HTML = """
<html><head>
  <link rel="icon" href="/favicon.ico">
  <link rel="stylesheet" href="/_next/static/chunks/a.css">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="alternate" type="application/rss+xml" href="/feeds/trending.xml">
  <link rel="apple-touch-icon" href="/icons/apple-touch-icon.png">
</head><body>
  <a href="/about">About</a>
  <a href="/transparency">Transparency</a>
  <script src="/x.js"></script>
</body></html>
"""


def _urls_from(html: str, page: str = "https://example.com/"):
    from types import SimpleNamespace

    from umbra.collectors.html_links import HtmlLinksCollector
    from umbra.core.models import EntityType

    class _Resp:
        status_code = 200
        text = html
        url = page
        headers: dict = {}

    class _Http:
        def get(self, *_a, **_kw):
            return _Resp()

    entity = SimpleNamespace(type=EntityType.DOMAIN.value, value="example.com",
                             norm_key="domain:example.com", props={})
    res = HtmlLinksCollector().collect(
        entity, SimpleNamespace(http=_Http(), settings=None))
    return [e.value for e in res.entities if e.type == EntityType.URL]


def test_the_collector_does_not_emit_asset_urls():
    urls = _urls_from(HTML)
    for u in urls:
        assert not is_static_asset(u), f"{u} should not have become a URL entity"


def test_the_collector_still_emits_real_pages():
    urls = _urls_from(HTML)
    joined = " ".join(urls)
    assert "/about" in joined
    assert "/transparency" in joined


def test_the_favicon_case_specifically():
    """The exact row seen in production."""
    assert not any("favicon" in u for u in _urls_from(HTML))


# --- recording a link is free; following it is not --------------------------

MANY_LOCALES = "<html><body>" + "".join(
    f'<a href="/{loc}">x</a>' for loc in
    "es pt-br it fr de ru uk zh sv bg el tr hi nl ar ja ko pl cs fi".split()
) + "</body></html>"


def test_only_a_few_links_become_entities():
    """40 near-identical locale pages produced 126 of one search's 159 rows."""
    from umbra.collectors.html_links import _MAX_URL_ENTITIES

    urls = _urls_from(MANY_LOCALES)
    assert len(urls) <= _MAX_URL_ENTITIES


def test_every_link_is_still_recorded_in_evidence():
    """The cost is the crawling, not the record — `raw` keeps the structure."""
    from types import SimpleNamespace

    from umbra.collectors.html_links import HtmlLinksCollector
    from umbra.core.models import EntityType

    class _Resp:
        status_code = 200
        text = MANY_LOCALES
        url = "https://example.com/"
        headers: dict = {}

    class _Http:
        def get(self, *_a, **_kw):
            return _Resp()

    entity = SimpleNamespace(type=EntityType.DOMAIN.value, value="example.com",
                            norm_key="domain:example.com", props={})
    res = HtmlLinksCollector().collect(entity, SimpleNamespace(http=_Http(), settings=None))
    raw_urls = res.evidence[0].raw["urls"]
    assert len(raw_urls) == 20, "all 20 locale links belong in the record"


def test_the_summary_says_how_many_were_followed():
    """Never a silent cap: a reader must see that 20 were found and 6 followed."""
    from types import SimpleNamespace

    from umbra.collectors.html_links import HtmlLinksCollector
    from umbra.core.models import EntityType

    class _Resp:
        status_code = 200
        text = MANY_LOCALES
        url = "https://example.com/"
        headers: dict = {}

    class _Http:
        def get(self, *_a, **_kw):
            return _Resp()

    entity = SimpleNamespace(type=EntityType.DOMAIN.value, value="example.com",
                            norm_key="domain:example.com", props={})
    res = HtmlLinksCollector().collect(entity, SimpleNamespace(http=_Http(), settings=None))
    assert "urls=20" in res.evidence[0].summary
    assert "followed" in res.evidence[0].summary


def test_the_site_root_is_not_promoted():
    """`https://host` and `https://host/` are the same page as the domain entity
    that started the run — promoting both spent two of six slots re-probing it."""
    html = ('<html><body><a href="/">home</a><a href="https://example.com">home2</a>'
            '<a href="/about">about</a></body></html>')
    urls = _urls_from(html)
    assert not any(u.rstrip("/") == "https://example.com" for u in urls)
    assert any(u.endswith("/about") for u in urls)
