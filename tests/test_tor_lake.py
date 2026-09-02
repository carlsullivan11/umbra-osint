"""Every Tor relay, not just the exits.

Umbra read `check.torproject.org/torbulkexitlist`, which is exits only.
Measured against the full consensus on 2026-09-01:

    relays        15,794
    Exit flag      6,021
    everything else 9,773   — 62%, invisible to the exit list

An operator looking up a guard relay got nothing back, and nothing reads like
a clean answer. That is the bug this closes.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from umbra.lake.tor import MIN_FETCH_INTERVAL, TorLake, describe_flags, parse_dan, sync

# Real shapes from the source document, including the messy contact field.
SAMPLE = """
1.161.170.240|MirukiiRelay|9001|0|FRDV|524423|Tor 0.4.9.9|AkiraZ@mail2tor.com<br>
1.201.176.169|AsianaOnionDurian|443|0|FRSV|64864|Tor 0.4.9.6|email:master[]a.org url:a.org
185.220.101.1|ExitRelayOne|9001|9030|FRSEDV|10000|Tor 0.4.8.1|abuse@example.org
203.0.113.7|GuardOnly|9001|0|FRSGDV|999|Tor 0.4.8.1|ops@example.org
198.51.100.9|MisbehavingExit|9001|0|FRSEBV|500|Tor 0.4.8.1|x@example.org
not-an-ip|Junk|1|0|FR|1|Tor|contact
"""


@pytest.fixture
def lake(tmp_path):
    lk = TorLake(tmp_path / "tor.sqlite")
    yield lk
    lk.close()


class FakeResp:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None


class FakeHttp:
    def __init__(self, text=SAMPLE):
        self.text, self.calls = text, 0

    def get(self, url, **kw):
        self.calls += 1
        return FakeResp(self.text)


# --- parsing ---------------------------------------------------------------

def test_relays_are_parsed_with_their_roles():
    rows = {r["ip"]: r for r in parse_dan(SAMPLE)}
    assert rows["185.220.101.1"]["is_exit"] == 1
    assert rows["203.0.113.7"]["is_guard"] == 1
    assert rows["203.0.113.7"]["is_exit"] == 0
    assert rows["185.220.101.1"]["nickname"] == "ExitRelayOne"
    assert rows["185.220.101.1"]["or_port"] == 9001


def test_a_non_exit_relay_is_still_a_relay():
    """The whole point: 62% of the consensus has no Exit flag and used to
    produce no answer at all."""
    rows = {r["ip"] for r in parse_dan(SAMPLE)}
    assert "1.161.170.240" in rows   # FRDV — middle relay, no E


def test_bad_exit_is_kept_distinct():
    """BadExit is the authorities marking a relay as misbehaving. That is a
    different statement from 'is an exit' and must not be merged into it."""
    rows = {r["ip"]: r for r in parse_dan(SAMPLE)}
    assert rows["198.51.100.9"]["is_bad_exit"] == 1
    assert rows["185.220.101.1"]["is_bad_exit"] == 0


def test_malformed_lines_are_skipped_not_fatal():
    """15,000 relays must not be lost to one bad row."""
    rows = parse_dan(SAMPLE)
    assert all(r["ip"] != "not-an-ip" for r in rows)
    assert len(rows) == 5


def test_contact_fields_with_stray_pipes_do_not_break_parsing():
    line = "9.9.9.9|Nick|9001|0|FRSEV|1|Tor 0.4|url:a.org|extra|pipes|here"
    assert parse_dan(line)[0]["is_exit"] == 1


def test_flags_get_human_names():
    assert "Exit" in describe_flags("FRSEDV")
    assert "Guard" in describe_flags("FRSGDV")
    assert "BadExit" in describe_flags("FRSEBV")


# --- the lake --------------------------------------------------------------

def test_lookup_returns_the_relay(lake):
    lake.replace_all(parse_dan(SAMPLE))
    r = lake.lookup("185.220.101.1")
    assert r and r["is_exit"] == 1 and r["nickname"] == "ExitRelayOne"


def test_an_address_that_is_not_a_relay_returns_none(lake):
    lake.replace_all(parse_dan(SAMPLE))
    assert lake.lookup("8.8.8.8") is None


def test_never_synced_is_distinguishable_from_not_a_relay(lake):
    """`lookup` is None in both cases; `status` is what tells them apart."""
    assert lake.lookup("185.220.101.1") is None
    assert lake.status()["synced"] is False
    lake.replace_all(parse_dan(SAMPLE))
    assert lake.status()["synced"] is True


def test_status_counts_the_roles(lake):
    lake.replace_all(parse_dan(SAMPLE))
    st = lake.status()
    assert st["relays"] == 5
    assert st["exits"] == 2
    assert st["guards"] == 1
    assert st["bad_exits"] == 1


def test_a_relay_that_left_the_consensus_is_dropped(lake):
    """Replace, not merge — a stale relay would report a role it no longer
    has, and the consensus is the authority on who is in it."""
    lake.replace_all(parse_dan(SAMPLE))
    assert lake.lookup("185.220.101.1")
    lake.replace_all(parse_dan("9.9.9.9|Only|9001|0|FRSEV|1|Tor|c@e.org"))
    assert lake.lookup("185.220.101.1") is None
    assert lake.lookup("9.9.9.9")


# --- the source's rate limit ----------------------------------------------

def test_a_first_sync_fetches(lake):
    http = FakeHttp()
    out = sync(http, lake, source="dan")
    assert out["fetched"] is True and out["relays"] == 5
    assert http.calls == 1


def test_a_second_sync_inside_the_window_does_not_fetch(lake):
    """dan.me.uk blocks callers who fetch more often than every 30 minutes."""
    http = FakeHttp()
    sync(http, lake, source="dan")
    out = sync(http, lake, source="dan")
    assert out["fetched"] is False
    assert http.calls == 1, "must not hit the source again"
    assert "30" in out["reason"]


def test_force_overrides_the_window(lake):
    http = FakeHttp()
    sync(http, lake, source="dan")
    assert sync(http, lake, force=True, source="dan")["fetched"] is True
    assert http.calls == 2


def test_the_window_reopens(lake):
    lake.replace_all(parse_dan(SAMPLE))
    past = datetime.now(tz=timezone.utc) - MIN_FETCH_INTERVAL - timedelta(minutes=1)
    conn = lake.connect()
    with conn:
        conn.execute("UPDATE tor_sync SET synced_at=?", (past.isoformat(),))
    assert lake.due_for_fetch() is True


def test_an_empty_document_does_not_wipe_the_lake(lake):
    """A bad fetch must not turn 15,000 relays into zero."""
    lake.replace_all(parse_dan(SAMPLE))
    out = sync(FakeHttp(text="<html>maintenance</html>"), lake, force=True, source="dan")
    assert out["fetched"] is False
    assert lake.status()["relays"] == 5


# --- the official source ---------------------------------------------------

ONIONOO = {"relays": [
    {"nickname": "Quintex152", "or_addresses": ["204.8.96.141:444", "[2620:7:6003::141]:81"],
     "flags": ["Exit", "Fast", "Guard", "Running", "Stable", "Valid"]},
    {"nickname": "MiddleOnly", "or_addresses": ["198.51.100.20:9001"],
     "flags": ["Fast", "Running", "Valid"]},
    {"nickname": "Naughty", "or_addresses": ["203.0.113.55:9001"],
     "flags": ["Exit", "BadExit", "Running", "Valid"]},
]}


class OnionooHttp:
    def __init__(self, payload=None):
        self.payload = payload if payload is not None else ONIONOO
        self.calls = 0

    def get(self, url, **kw):
        self.calls += 1
        outer = self

        class R:
            def raise_for_status(self):
                return None

            def json(self):
                return outer.payload
        return R()


def test_onionoo_is_selectable(lake):
    out = sync(OnionooHttp(), lake, source="onionoo")
    assert out["fetched"] is True
    assert out["source"] == "onionoo"


def test_onionoo_roles_are_read_correctly(lake):
    sync(OnionooHttp(), lake, source="onionoo")
    assert lake.lookup("204.8.96.141")["is_exit"] == 1
    assert lake.lookup("198.51.100.20")["is_exit"] == 0      # middle relay
    assert lake.lookup("203.0.113.55")["is_bad_exit"] == 1


def test_onionoo_flags_are_stored_in_the_same_form_as_dan(lake):
    """One storage format whichever source filled the lake."""
    sync(OnionooHttp(), lake, source="onionoo")
    flags = lake.lookup("204.8.96.141")["flags"]
    assert "E" in flags and "G" in flags
    assert "Exit" in describe_flags(flags)


def test_onionoo_is_not_subject_to_the_dan_window(lake):
    """The official API has no such trap, so back-to-back syncs are fine."""
    http = OnionooHttp()
    sync(http, lake, source="onionoo")
    assert sync(http, lake, source="onionoo")["fetched"] is True
    assert http.calls == 2


def test_a_source_error_keeps_the_previous_consensus(lake):
    sync(OnionooHttp(), lake, source="onionoo")
    before = lake.status()["relays"]

    class Boom:
        def get(self, *a, **k):
            raise RuntimeError("connection reset")

    out = sync(Boom(), lake, source="onionoo")
    assert out["fetched"] is False
    assert lake.status()["relays"] == before


# --- the authoritative source and its redundancy ---------------------------

CONSENSUS = """network-status-version 3
vote-status consensus
valid-after 2026-09-01 23:00:00
fresh-until 2026-09-02 00:00:00
r Quintex152 AAjZ ZFqz 2026-09-01 20:57:39 204.8.96.141 444 0
s Exit Fast Guard Running Stable Valid
v Tor 0.4.9.11
p accept 43,53,80,443
r FlaggedButShut BBBB CCCC 2026-09-01 20:00:00 198.51.100.30 9001 0
s Exit Fast Running Valid
p reject 1-65535
r MiddleOnly DDDD EEEE 2026-09-01 20:00:00 203.0.113.44 9001 0
s Fast Running Valid
p reject 1-65535
"""

# What two directory authorities actually returned from this network.
ISP_BLOCK_PAGE = ('<!doctype html><html><head><title></title>'
                  '<script>var reason=["malware","phishing"];</script></head></html>')


class AuthHttp:
    """Serves a chosen body per authority host, plus an Onionoo response."""

    def __init__(self, bodies):
        self.bodies, self.tried = bodies, []

    def get(self, url, **kw):
        outer = self
        if "onionoo" in url:
            class R:
                status_code = 200

                def raise_for_status(self):
                    return None

                def json(self):
                    return {"relays": []}
            return R()
        host = url.split("//", 1)[1].split("/", 1)[0]
        outer.tried.append(host)
        body = outer.bodies.get(host, "")

        class R:
            status_code = 200
            text = body

            def raise_for_status(self):
                return None
        return R()


def test_the_consensus_is_the_default_source(lake):
    from umbra.lake.tor import DIRECTORY_AUTHORITIES

    first = DIRECTORY_AUTHORITIES[0][1]
    out = sync(AuthHttp({first: CONSENSUS}), lake)
    assert out["fetched"] is True
    assert out["source"] == "consensus"
    assert out["valid_after"] == "2026-09-01 23:00:00"


def test_an_isp_block_page_is_not_a_consensus(lake):
    """Two authorities answered HTTP 200 with an AT&T interstitial. Parsing
    that as a consensus would have emptied the lake."""
    from umbra.lake.tor import parse_consensus

    relays, valid_after = parse_consensus(ISP_BLOCK_PAGE)
    assert relays == [] and valid_after is None


def test_it_fails_over_to_the_next_authority(lake):
    """Nine servers publish the same document; one bad answer is not an outage."""
    from umbra.lake.tor import DIRECTORY_AUTHORITIES

    a1, a2, a3 = (h for _, h in DIRECTORY_AUTHORITIES[:3])
    http = AuthHttp({a1: ISP_BLOCK_PAGE, a2: "", a3: CONSENSUS})
    out = sync(http, lake)
    assert out["fetched"] is True
    assert http.tried[:3] == [a1, a2, a3], "must try them in order"
    assert lake.lookup("204.8.96.141")


def test_the_exit_policy_overrides_the_exit_flag(lake):
    """A relay can hold the Exit flag and reject every port. The flag says the
    authorities may use it as an exit; the policy says what it will carry."""
    from umbra.lake.tor import DIRECTORY_AUTHORITIES

    sync(AuthHttp({DIRECTORY_AUTHORITIES[0][1]: CONSENSUS}), lake)
    assert lake.lookup("204.8.96.141")["is_exit"] == 1
    shut = lake.lookup("198.51.100.30")
    assert shut["is_exit"] == 0, "Exit flag but reject 1-65535"
    assert "E" in shut["flags"], "the flag is still recorded"


def test_the_exit_policy_is_kept(lake):
    from umbra.lake.tor import DIRECTORY_AUTHORITIES

    sync(AuthHttp({DIRECTORY_AUTHORITIES[0][1]: CONSENSUS}), lake)
    assert lake.lookup("204.8.96.141")["exit_policy"].startswith("accept")


def test_every_authority_failing_keeps_the_previous_lake(lake):
    from umbra.lake.tor import DIRECTORY_AUTHORITIES

    sync(AuthHttp({DIRECTORY_AUTHORITIES[0][1]: CONSENSUS}), lake)
    before = lake.status()["relays"]
    out = sync(AuthHttp({h: ISP_BLOCK_PAGE for _, h in DIRECTORY_AUTHORITIES}), lake)
    assert out["fetched"] is False
    assert lake.status()["relays"] == before


def test_an_older_lake_is_rebuilt_rather_than_erroring(tmp_path):
    """`CREATE TABLE IF NOT EXISTS` leaves an old table alone, so adding a
    column broke every lake created before it — which is every real install.
    Safe to drop here because the lake is derived and the next sync refills it."""
    import sqlite3

    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE tor_relay (ip TEXT PRIMARY KEY, nickname TEXT, or_port INTEGER,"
        " dir_port INTEGER, flags TEXT, is_exit INTEGER, is_guard INTEGER,"
        " is_bad_exit INTEGER, version TEXT, seen_at TEXT);"
        "CREATE TABLE tor_sync (source TEXT PRIMARY KEY, synced_at TEXT, rows INTEGER);"
        "INSERT INTO tor_relay VALUES ('1.2.3.4','Old',9001,0,'ER',1,0,0,'Tor','x');"
        "INSERT INTO tor_sync VALUES ('dan','x',1);")
    conn.commit()
    conn.close()

    lake = TorLake(path)
    try:
        cols = {r[1] for r in lake.connect().execute("PRAGMA table_info(tor_relay)")}
        assert "exit_policy" in cols
        # Rebuilt, so it reports never-synced rather than serving a stale row
        # as though it were current.
        assert lake.status()["synced"] is False
        lake.replace_all(parse_dan(SAMPLE))
        assert lake.lookup("185.220.101.1")
    finally:
        lake.close()
