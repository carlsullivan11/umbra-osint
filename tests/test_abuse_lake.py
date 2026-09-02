"""The owned abuse.ch lake — parsers, store, and the honesty of a miss.

Umbra already touched abuse.ch: `domain_reputation` calls the URLhaus *API*,
which has needed a free Auth-Key since 2024, so for anyone without one it
reported "skipped" forever. The **bulk downloads are still key-free**, so owning
the data removes the key requirement and the per-run network call at the same
time — the same trade already made for the OUI table, the CT corpus and KEV.

Two properties are load-bearing and are what most of this file tests:

1. **Accumulation.** The feeds publish a rolling recent window. Syncing into a
   store that keeps what it has seen means the lake grows past what abuse.ch
   will hand you today — that is the difference between owning the data and
   proxying it.
2. **A miss is only clean if the feed was actually checked.** An unsynced lake
   answers "no records" to every question, which reads exactly like "not
   malicious". Every read carries whether the feed was ever synced.
"""
from __future__ import annotations

import json
import warnings
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")

from umbra.lake import abusech  # noqa: E402
from umbra.lake.store import LakeStore  # noqa: E402

URLHAUS = '''\
# Dump generated 2026-08-16
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3904166","2026-08-16 04:51:08","http://42.224.248.160:54570/bin.sh","online","2026-08-16 04:51:08","malware_download","32-bit,elf,mips,Mozi","https://urlhaus.abuse.ch/url/3904166/","geenensp"
"3904100","2026-08-15 11:00:00","https://Bad.Example.COM/panel/x.exe","offline","2026-08-15 12:00:00","malware_download","exe,RedLine","https://urlhaus.abuse.ch/url/3904100/","anonymous"
'''

THREATFOX = '''\
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-08-16 04:39:22", "1877000", "c2.example.com", "domain", "payload_delivery", "js.clearfake", "None", "ClearFake", "", "100", "False", "None", "ClearFake,macos", "1", "anonymous"
"2026-08-16 04:05:06", "1876998", "111.170.148.132:10001", "ip:port", "botnet_cc", "unknown", "None", "Unknown malware", "", "75", "True", "None", "viper", "1", "anonymous"
'''

SSLBL = '''\
# Listingdate,SHA1,Listingreason
2026-08-15 15:52:47,057b2084f877c8737e60de6c07ad829ea411b9c6,Vidar C&C
2026-08-14 09:00:00,aaaabbbbccccddddeeeeffff0000111122223333,Cobalt Strike C2
'''

FEODO = json.dumps([
    {"ip_address": "162.243.103.246", "port": 8080, "status": "offline",
     "hostname": None, "as_number": 14061, "as_name": "DIGITALOCEAN-ASN",
     "country": "US", "first_seen": "2022-06-04 21:24:53",
     "last_online": "2026-03-07", "malware": "Emotet"},
])


@pytest.fixture
def store(tmp_path: Path) -> LakeStore:
    return LakeStore(f"sqlite:///{tmp_path / 'lake.db'}")


class FakeHttp:
    """Serves canned feed bodies by URL substring."""

    def __init__(self, bodies: dict[str, str] | None = None, fail: set[str] | None = None):
        self.bodies = bodies if bodies is not None else {
            "urlhaus": URLHAUS, "threatfox": THREATFOX,
            "sslbl": SSLBL, "feodo": FEODO,
        }
        self.fail = fail or set()
        self.calls: list[str] = []

    def get(self, url: str, **kw):
        self.calls.append(url)
        for key, body in self.bodies.items():
            if key in url:
                if key in self.fail:
                    raise RuntimeError(f"{key} unreachable")
                return _Resp(body)
        raise AssertionError(f"unexpected fetch: {url}")


class _Resp:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200
        self.content = text.encode()

    def raise_for_status(self):
        return None


# --- parsers ---------------------------------------------------------------

def test_urlhaus_rows_carry_the_host_not_just_the_url():
    """The graph asks about a host. Keeping only the URL would mean a LIKE scan
    over a million-row table for every lookup."""
    rows = abusech.parse_urlhaus(URLHAUS)
    assert [r.host for r in rows] == ["42.224.248.160", "bad.example.com"]


def test_urlhaus_host_drops_the_port_and_lowercases():
    rows = abusech.parse_urlhaus(URLHAUS)
    assert rows[0].host == "42.224.248.160", "the :54570 belongs to the URL, not the host"
    assert rows[1].host == "bad.example.com", "hosts are case-insensitive"


def test_urlhaus_keeps_the_threat_and_the_tags():
    """`malware_download` plus `Mozi` is the whole finding; without them the row
    says only 'something bad', which an analyst cannot act on."""
    row = abusech.parse_urlhaus(URLHAUS)[0]
    assert row.threat == "malware_download"
    assert "Mozi" in row.tags


def test_urlhaus_keeps_online_status():
    rows = abusech.parse_urlhaus(URLHAUS)
    assert rows[0].status == "online"
    assert rows[1].status == "offline"


def test_threatfox_attributes_the_malware_family():
    """The hostfile export is hostnames only. The CSV names the family, which is
    the reason to prefer it."""
    rows = abusech.parse_threatfox(THREATFOX)
    assert rows[0].malware == "ClearFake"
    assert rows[0].threat_type == "payload_delivery"


def test_threatfox_ip_port_iocs_reduce_to_a_host():
    rows = abusech.parse_threatfox(THREATFOX)
    assert rows[1].host == "111.170.148.132"
    assert rows[1].ioc == "111.170.148.132:10001", "the port is evidence, keep it"


def test_threatfox_keeps_the_confidence_level():
    """A 25%-confidence IOC and a 100% one should not score the same."""
    rows = abusech.parse_threatfox(THREATFOX)
    assert rows[0].confidence == 100
    assert rows[1].confidence == 75


def test_sslbl_rows_are_sha1_fingerprints():
    rows = abusech.parse_sslbl(SSLBL)
    assert rows[0].sha1 == "057b2084f877c8737e60de6c07ad829ea411b9c6"
    assert len(rows) == 2


def test_sslbl_reason_is_split_into_family_and_role():
    """'Vidar C&C' is two facts. Reporting the family alone loses that it is a
    controller; reporting the raw string makes it unqueryable."""
    rows = abusech.parse_sslbl(SSLBL)
    assert rows[0].malware == "Vidar"
    assert rows[1].malware == "Cobalt Strike"
    assert rows[0].reason == "Vidar C&C"


def test_feodo_becomes_an_ioc_like_everything_else():
    """One IOC table, a feed column. Feodo is a botnet C2 list; modelling it
    separately would mean two code paths for one question."""
    rows = abusech.parse_feodo(FEODO)
    assert rows[0].host == "162.243.103.246"
    assert rows[0].malware == "Emotet"
    assert rows[0].threat_type == "botnet_cc"


def test_a_comment_only_feed_parses_to_nothing_rather_than_raising():
    assert abusech.parse_urlhaus("# nothing here\n\n") == []
    assert abusech.parse_sslbl("# only a header\n") == []


def test_a_malformed_row_does_not_discard_the_good_ones():
    """One truncated line in a 16,000-row feed must not cost the sync."""
    broken = SSLBL + "not,enough\n" + "2026-01-01 00:00:00,ffff,Junk C2\n"
    assert len(abusech.parse_sslbl(broken)) == 3


# --- sync + store ----------------------------------------------------------

def test_sync_loads_every_feed(store):
    counts = abusech.sync(store, FakeHttp())
    assert counts["urlhaus"] == 2
    assert counts["threatfox"] == 2
    assert counts["sslbl"] == 2
    assert counts["feodo"] == 1


def test_syncing_twice_does_not_duplicate(store):
    """The recent windows overlap on every run. Without upsert the lake doubles
    in size daily and every count becomes a lie."""
    http = FakeHttp()
    abusech.sync(store, http)
    abusech.sync(store, http)
    assert len(store.abuse_urls_for_host("bad.example.com")) == 1


def test_the_lake_keeps_rows_that_fell_out_of_the_recent_window(store):
    """This is the whole point of owning it: abuse.ch will not serve you last
    month's recent feed, and after this sync we still have it."""
    abusech.sync(store, FakeHttp())
    shrunk = FakeHttp({"urlhaus": URLHAUS.rsplit("\n", 2)[0] + "\n",
                       "threatfox": THREATFOX, "sslbl": SSLBL, "feodo": FEODO})
    abusech.sync(store, shrunk)
    assert store.abuse_urls_for_host("bad.example.com"), "dropped when the feed dropped it"


def test_a_repeat_sync_updates_a_changed_status(store):
    """A URL going online again is news; a stale 'offline' would bury it."""
    http = FakeHttp()
    abusech.sync(store, http)
    revived = URLHAUS.replace('"offline"', '"online"')
    abusech.sync(store, FakeHttp({"urlhaus": revived, "threatfox": THREATFOX,
                                  "sslbl": SSLBL, "feodo": FEODO}))
    assert store.abuse_urls_for_host("bad.example.com")[0]["status"] == "online"


def test_one_dead_feed_does_not_abort_the_others(store):
    """Four independent downloads. Losing SSLBL should not cost URLhaus."""
    counts = abusech.sync(store, FakeHttp(fail={"sslbl"}))
    assert counts["urlhaus"] == 2
    assert counts["sslbl"] == 0
    assert store.abuse_feed_synced_at("urlhaus")
    assert not store.abuse_feed_synced_at("sslbl"), "a failed fetch is not a sync"


# --- lookups ---------------------------------------------------------------

def test_a_host_lookup_finds_its_urls(store):
    abusech.sync(store, FakeHttp())
    hits = store.abuse_urls_for_host("42.224.248.160")
    assert len(hits) == 1
    assert hits[0]["url"].endswith("/bin.sh")


def test_host_lookup_is_case_insensitive(store):
    abusech.sync(store, FakeHttp())
    assert store.abuse_urls_for_host("BAD.example.com")


def test_an_ioc_lookup_finds_the_family(store):
    abusech.sync(store, FakeHttp())
    hits = store.abuse_iocs_for_host("c2.example.com")
    assert hits[0]["malware"] == "ClearFake"
    assert hits[0]["feed"] == "threatfox"


def test_a_cert_lookup_is_by_sha1(store):
    abusech.sync(store, FakeHttp())
    hit = store.abuse_cert("057B2084F877C8737E60DE6C07AD829EA411B9C6")
    assert hit and hit["malware"] == "Vidar", "fingerprint case must not matter"


def test_an_unknown_host_returns_nothing_rather_than_raising(store):
    abusech.sync(store, FakeHttp())
    assert store.abuse_urls_for_host("clean.example.org") == []
    assert store.abuse_cert("0" * 40) is None


# --- did we actually check? ------------------------------------------------

def test_a_never_synced_lake_reports_that_it_was_never_synced(store):
    """Every lookup on an empty lake returns nothing, which is indistinguishable
    from clean unless the store says so."""
    assert store.abuse_feed_synced_at("urlhaus") is None
    assert store.abuse_urls_for_host("anything.example") == []


def test_a_synced_feed_records_when(store):
    abusech.sync(store, FakeHttp())
    assert store.abuse_feed_synced_at("urlhaus")
    assert store.abuse_feed_synced_at("sslbl")


def test_stats_expose_the_lake_size_per_feed(store):
    abusech.sync(store, FakeHttp())
    stats = store.abuse_stats()
    assert stats["urls"] == 2
    assert stats["certs"] == 2
    assert stats["iocs"] == 3, "threatfox + feodo share the IOC table"
    assert set(stats["feeds"]) == {"urlhaus", "threatfox", "sslbl", "feodo"}


# --- egress ----------------------------------------------------------------

def test_every_feed_url_is_abuse_ch_over_https():
    for url in abusech.FEEDS.values():
        assert url.startswith("https://"), url
        assert url.split("/")[2].endswith("abuse.ch"), url
