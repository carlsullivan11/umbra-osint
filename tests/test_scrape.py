"""Bounded allowlisted crawl (httpx, no Crawlee/Chromium)."""

from types import SimpleNamespace

from umbra.core.scrape import crawl_allowlisted, extract_links, pick_follow_urls


def test_extract_and_pick_name_link():
    html = """
    <a href="/parcel/jane-doe">Jane Doe parcel</a>
    <a href="https://evil.example/x">ignore</a>
    <a href="/login">skip</a>
    """
    links = extract_links(html, "https://www.bentoncountyar.gov/assessor/")
    urls = [u for u, _ in links]
    assert any("/parcel/jane-doe" in u for u in urls)
    picked = pick_follow_urls(
        links,
        allow=lambda u: "bentoncountyar.gov" in u and "/login" not in u,
        needle="Jane Doe",
        same_host_as="https://www.bentoncountyar.gov/assessor/",
    )
    assert picked
    assert "jane-doe" in picked[0]


def test_crawl_follows_name_link():
    pages = {
        "https://www.bentoncountyar.gov/assessor/": SimpleNamespace(
            status_code=200,
            text='<a href="/parcel/doe">Doe APN 12-345-678</a>',
        ),
        "https://www.bentoncountyar.gov/parcel/doe": SimpleNamespace(
            status_code=200,
            text="<title>Parcel</title> Jane Doe APN 12-345-678 100 Main Street",
        ),
    }

    class _Http:
        def get(self, url, **kwargs):
            return pages[url]

    out = crawl_allowlisted(
        _Http(),
        ["https://www.bentoncountyar.gov/assessor/"],
        allow=lambda u: "bentoncountyar.gov" in u,
        needle="Jane Doe",
        max_pages=4,
        pause_s=0,
    )
    urls = [p.url for p in out.pages]
    assert "https://www.bentoncountyar.gov/parcel/doe" in urls
    assert any(p.followed for p in out.pages)
