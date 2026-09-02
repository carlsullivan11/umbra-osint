from __future__ import annotations

from umbra.collectors.base import default_registry
from umbra.collectors.darkweb import (
    RansomwareExposureCollector,
    RansomwarePost,
    _domains_match,
    _host_from_website,
    match_posts,
    norm_org,
    parse_ransomware_posts,
)
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity


def _domain_entity(v: str) -> Entity:
    return Entity(id="1", case_id="c", type="domain", value=v,
                  norm_key=entity_key(EntityType.DOMAIN, v), props={},
                  confidence=1.0, is_seed=True)


def _org_entity(v: str) -> Entity:
    return Entity(id="2", case_id="c", type="org", value=v,
                  norm_key=entity_key(EntityType.ORG, v), props={},
                  confidence=1.0, is_seed=True)


# A trimmed real-shape fixture from ransomware.live posts.json.
FIXTURE = [
    {
        "post_title": "Acme Widgets, Inc.",
        "group_name": "qilin",
        "discovered": "2026-08-13T13:29:41+00:00",
        "published": "2026-08-13T13:29:20+00:00",
        "website": "www.acmewidgets.com",
        "country": "US",
        "activity": "Manufacturing",
        "description": "N/A",
        "post_url": "http://ijzn3sicrcy7guixkzjkib4ukbiilwc3xhnmby4mcbccnsd7j2rek.onion/x",
        "extrainfos": {},
    },
    {
        "post_title": "Acme Widgets Inc",  # mirror / duplicate posting
        "group_name": "qilin",
        "discovered": "2026-08-12T10:00:00+00:00",
        "published": "2026-08-12T09:00:00+00:00",
        "website": "acmewidgets.com",
        "country": "US",
        "activity": "Manufacturing",
        "post_url": "http://mirror.onion/x",
    },
    {
        "post_title": "Globex Corporation",
        "group_name": "lockbit",
        "discovered": "2026-07-01T00:00:00+00:00",
        "published": "2026-07-01T00:00:00+00:00",
        "website": "https://globex.example/",
        "country": "DE",
        "activity": "Energy",
        "post_url": "http://another.onion/y",
    },
]


# --- registration + supports ---------------------------------------------

def test_registered():
    reg = default_registry()
    assert reg.get("ransomware_exposure") is not None


def test_supports_domain_and_org_not_ip():
    c = RansomwareExposureCollector()
    assert c.supports(_domain_entity("acmewidgets.com"))
    assert c.supports(_org_entity("Acme Widgets"))
    ip = Entity(id="3", case_id="c", type="ip", value="1.2.3.4",
                norm_key=entity_key(EntityType.IP, "1.2.3.4"), props={},
                confidence=1.0, is_seed=True)
    assert not c.supports(ip)


# --- pure helpers ---------------------------------------------------------

def test_host_from_website():
    assert _host_from_website("www.acmewidgets.com") == "acmewidgets.com"
    assert _host_from_website("https://globex.example/") == "globex.example"
    assert _host_from_website("HTTP://Foo.COM/path") == "foo.com"
    assert _host_from_website("") is None
    assert _host_from_website(None) is None


def test_host_rejects_placeholders_and_junk():
    # the exact junk values observed in the live feed
    for junk in ("example.com", "https", "company url", "-", "c",
                 "s****.com", "N/A", "localhost"):
        assert _host_from_website(junk) is None, junk
    # .onion is the leak site, never the victim's domain
    assert _host_from_website("http://abc123.onion/x") is None
    # real domains still pass
    assert _host_from_website("cisco.com") == "cisco.com"
    assert _host_from_website("bioclimaservice.it") == "bioclimaservice.it"


def test_placeholder_domain_never_false_positives():
    # feed row with example.com placeholder must not match a real example.com check
    fixture = [{"post_title": "Some Victim", "group_name": "killsec",
                "website": "example.com", "discovered": "2026-01-01",
                "published": "2026-01-01", "post_url": "x"}]
    posts = parse_ransomware_posts(fixture)
    assert posts[0].host is None
    assert match_posts(posts, domain="example.com") == []
    # but the posting still exists and is findable by org name
    assert len(match_posts(posts, org="Some Victim")) == 1


def test_norm_org_strips_suffixes_and_punct():
    assert norm_org("Acme Widgets, Inc.") == "acme widgets"
    assert norm_org("Acme Widgets Inc") == "acme widgets"
    assert norm_org("The Globex Corporation") == "globex"
    assert norm_org(None) == ""


def test_domains_match_subdomain_either_direction():
    assert _domains_match("acmewidgets.com", "acmewidgets.com")
    assert _domains_match("www.acmewidgets.com", "acmewidgets.com")
    assert _domains_match("acmewidgets.com", "mail.acmewidgets.com")
    assert not _domains_match("acmewidgets.com", "evilacmewidgets.com")
    assert not _domains_match("acmewidgets.com", None)


def test_parse_posts_shape():
    posts = parse_ransomware_posts(FIXTURE)
    assert len(posts) == 3
    p = posts[0]
    assert isinstance(p, RansomwarePost)
    assert p.victim == "Acme Widgets, Inc."
    assert p.group == "qilin"
    assert p.host == "acmewidgets.com"


def test_parse_posts_tolerates_garbage():
    assert parse_ransomware_posts(None) == []
    assert parse_ransomware_posts("nope") == []
    assert parse_ransomware_posts([1, "x", {"post_title": "Ok"}]) != []


# --- matching -------------------------------------------------------------

def test_match_by_domain():
    posts = parse_ransomware_posts(FIXTURE)
    hits = match_posts(posts, domain="acmewidgets.com")
    assert len(hits) == 2  # both acme postings
    assert all(h.group == "qilin" for h in hits)
    # newest first
    assert hits[0].discovered >= hits[1].discovered


def test_match_by_org_is_exact_normalized_not_substring():
    posts = parse_ransomware_posts(FIXTURE)
    assert len(match_posts(posts, org="Acme Widgets Inc.")) == 2
    assert len(match_posts(posts, org="Globex")) == 1
    # a common substring must NOT match a different victim
    assert match_posts(posts, org="Acme") == []


def test_no_false_positive_for_unrelated():
    posts = parse_ransomware_posts(FIXTURE)
    assert match_posts(posts, domain="unrelated.org") == []
    assert match_posts(posts, org="Nonexistent Company") == []
