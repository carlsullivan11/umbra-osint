"""Fingerprinting the things that scan us (Carl, 2026-08-20).

> "I want to run a search on IPs that connect to Umbra. the searches should be
> automated in the background and should count towards the search counters on
> the homepage. so if Google scans Umbra, Umbra fingerprints Google back."

Umbra is a public OSINT site, so a steady share of its traffic is other
people's automation: Googlebot working the wiki corpus, and a drizzle of
WordPress scanners probing a site that has never run WordPress. Asking who they
are is ordinary defensive work on our own asset, and Umbra already owns every
tool for it.

Three constraints shape the whole module.

**Passive only.** Fingerprinting means asking public registries and our own
lakes who an address belongs to — RDAP, ASN, geolocation, blocklists. It does
**not** mean connecting back to it. Probing a host because it touched our web
server is an unauthorised active scan (`AGENTS.md` #1) and would point Umbra's
egress at whoever happened to visit.

**Scanners only.** A person reading the guide is not scanned back. `PageView`
deliberately stores no raw IP, and this must not become the loophole that
reintroduces one — a row is written only when the request already looked like
automation.

**Bounded.** Capped per tick, one case per address per cooldown window, and
private, loopback and unroutable space skipped entirely.
"""
from __future__ import annotations

import warnings
from datetime import timedelta

import pytest

warnings.filterwarnings("ignore")

from umbra.core.config import Settings  # noqa: E402
from umbra.core.models import EntityType, utcnow  # noqa: E402
from umbra.db.repository import Repository  # noqa: E402
from umbra.db.schema import (  # noqa: E402
    Case,
    Entity,
    SentinelObservation,
    get_session,
    init_db,
)
from umbra import sentinel  # noqa: E402

GOOGLEBOT = ("Mozilla/5.0 (compatible; Googlebot/2.1; "
             "+http://www.google.com/bot.html)")
BROWSER = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path)
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)

    # Collectors are passive lookups, but they are still network calls. The unit
    # under test is which addresses get chosen and what is recorded, not whether
    # RDAP is reachable.
    from umbra.core.orchestrator import Orchestrator

    monkeypatch.setattr(Orchestrator, "run",
                        lambda self, case_id, **kw: {"entities": 1,
                                                     "collectors": kw.get("collectors")})
    return repo, session


def observe(session, ip, *, reason="bot_ua", ua=GOOGLEBOT, path="/",
            status=200, ago_hours=0.0, count=1):
    from uuid import uuid4

    for _ in range(count):
        session.add(SentinelObservation(
            id=uuid4().hex[:16],
            ts=utcnow() - timedelta(hours=ago_hours),
            ip=ip, reason=reason, path=path, status=status, user_agent=ua))
    session.commit()


def cases(session):
    return session.query(Case).all()


# --- what gets observed at all --------------------------------------------

def test_a_crawler_is_worth_observing():
    assert sentinel.classify("/wiki/tls", GOOGLEBOT, 200) == "bot_ua"


def test_a_wordpress_probe_is_worth_observing():
    """This site has never run WordPress."""
    assert sentinel.classify("/wp-admin/setup-config.php", BROWSER, 404) == "probe_path"


def test_a_person_reading_the_guide_is_not_observed():
    """The whole privacy position of this module. `PageView` stores no raw IP,
    and this must not be the loophole that reintroduces one."""
    assert sentinel.classify("/guide", BROWSER, 200) is None


def test_a_person_running_a_search_is_not_observed():
    assert sentinel.classify("/search", BROWSER, 200) is None


def test_our_own_health_check_is_not_observed():
    """The health watcher polls every 30s. Fingerprinting ourselves forever is
    not intelligence."""
    assert sentinel.classify("/health", "", 200) is None


def test_a_missing_user_agent_counts_as_automation():
    assert sentinel.classify("/", "", 200) == "bot_ua"


# --- which addresses are eligible -----------------------------------------

def test_a_private_address_is_never_fingerprinted():
    """Docker and the tunnel talk to the origin over RFC1918. `http_guard`
    would refuse them anyway; this refuses to even make the case."""
    for ip in ("10.0.0.5", "192.168.1.1", "172.16.4.4", "127.0.0.1", "::1"):
        assert sentinel.eligible(ip) is False


def test_a_cloudflare_edge_address_is_not_fingerprinted():
    """If `CF-Connecting-IP` is ever missing we see Cloudflare's own edge. A
    case per Cloudflare PoP is noise, not a finding."""
    assert sentinel.eligible("103.21.244.10") is False


def test_a_public_address_is_eligible():
    assert sentinel.eligible("66.249.66.1") is True


def test_junk_is_not_eligible():
    for value in ("", "not-an-ip", "999.999.999.999", None):
        assert sentinel.eligible(value) is False


# --- the tick --------------------------------------------------------------

def test_a_repeat_scanner_gets_fingerprinted(env):
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    result = sentinel.tick(repo)
    assert result["fingerprinted"] == 1
    assert len(cases(session)) == 1


def test_the_address_becomes_the_seed(env):
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    entity = session.query(Entity).one()
    assert entity.value == "66.249.66.1"
    assert entity.type == EntityType.IP.value


def test_a_single_stray_request_is_not_enough(env):
    """One crawler hit is a visit. A pattern is a pattern."""
    repo, session = env
    observe(session, "66.249.66.1", count=1)
    assert sentinel.tick(repo)["fingerprinted"] == 0


def test_the_case_says_why_it_exists(env):
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS, path="/wiki/tls")
    sentinel.tick(repo)
    case = cases(session)[0]
    assert "66.249.66.1" in case.name
    assert case.authorization_basis == "own_asset"
    assert "umbra" in (case.authorization_note or "").lower()


def test_the_evidence_is_recorded_in_the_audit_trail(env):
    """Every case needs a basis, and this one's basis is an observation we made.
    An analyst has to be able to see what the address actually did."""
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS, path="/wp-admin",
            reason="probe_path")
    sentinel.tick(repo)
    from umbra.db.schema import AuditEvent

    events = session.query(AuditEvent).all()
    blob = " ".join(str(e.detail) for e in events)
    assert "probe_path" in blob
    assert "/wp-admin" in blob


# --- passive only ----------------------------------------------------------

def test_only_passive_collectors_are_used():
    """The line that keeps this defensive. Fingerprinting is asking registries
    who an address belongs to — not connecting back to it."""
    active = {"http_probe", "html_links", "tech_fingerprint", "security_txt",
              "crtsh", "tls_cert", "wayback_cdx", "ddg_search",
              "username_presence", "github_user"}
    assert not set(sentinel.COLLECTORS) & active


def test_the_collectors_all_accept_an_ip():
    """A collector that cannot take an IP would silently contribute nothing."""
    from umbra.collectors.base import default_registry

    registry = {c.name: c for c in default_registry().list()}
    for name in sentinel.COLLECTORS:
        assert name in registry, f"{name} is not registered"
        assert EntityType.IP in registry[name].inputs, f"{name} does not take an IP"


def test_the_run_only_asks_for_those_collectors(env):
    repo, session = env
    seen = {}
    from umbra.core.orchestrator import Orchestrator

    def capture(self, case_id, **kw):
        seen.update(kw)
        return {"entities": 1}

    Orchestrator.run = capture  # type: ignore[method-assign]
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    assert set(seen["collectors"]) == set(sentinel.COLLECTORS)


def test_the_expansion_depth_is_zero(env):
    """Depth 1 would pivot off whatever the lookups return and start walking
    somebody else's estate. The question is "who is this", once."""
    repo, session = env
    seen = {}
    from umbra.core.orchestrator import Orchestrator

    Orchestrator.run = lambda self, case_id, **kw: (seen.update(kw),
                                                    {"entities": 1})[1]
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    assert seen["depth"] == 0


# --- it must not become a flood -------------------------------------------

def test_the_same_address_is_not_fingerprinted_twice(env):
    """Googlebot hits this site all day. A case every half hour is a denial of
    service against our own database."""
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    assert sentinel.tick(repo)["fingerprinted"] == 0
    assert len(cases(session)) == 1


def test_the_cooldown_eventually_expires(env):
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    case = cases(session)[0]
    case.created_at = utcnow() - timedelta(days=sentinel.COOLDOWN_DAYS + 1)
    session.commit()
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS, ago_hours=0.1)
    assert sentinel.tick(repo)["fingerprinted"] == 1


def test_a_tick_is_capped(env):
    repo, session = env
    for i in range(sentinel.MAX_PER_TICK * 3):
        observe(session, f"66.249.66.{i + 1}", count=sentinel.MIN_HITS)
    result = sentinel.tick(repo)
    assert result["fingerprinted"] <= sentinel.MAX_PER_TICK


def test_the_cap_says_what_it_deferred(env):
    """A silent cap reads as "that was everyone who scanned us"."""
    repo, session = env
    for i in range(sentinel.MAX_PER_TICK * 3):
        observe(session, f"66.249.66.{i + 1}", count=sentinel.MIN_HITS)
    result = sentinel.tick(repo)
    assert result["deferred"] > 0


def test_the_busiest_scanner_goes_first(env):
    """When the cap bites, the address that hit us hardest is the one worth
    knowing about."""
    repo, session = env
    observe(session, "66.249.66.9", count=sentinel.MIN_HITS)
    observe(session, "66.249.66.7", count=sentinel.MIN_HITS + 40)
    for i in range(sentinel.MAX_PER_TICK * 2):
        observe(session, f"66.249.70.{i + 1}", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    assert any("66.249.66.7" in c.name for c in cases(session))


def test_stale_observations_are_ignored(env):
    """A scan last month is not a reason to open a case today."""
    repo, session = env
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS,
            ago_hours=sentinel.WINDOW_HOURS + 5)
    assert sentinel.tick(repo)["fingerprinted"] == 0


def test_nothing_to_do_is_quiet(env):
    repo, session = env
    assert sentinel.tick(repo) == {"candidates": 0, "fingerprinted": 0,
                                   "deferred": 0, "cases": []}


# --- the counters Carl asked about ----------------------------------------

def test_a_fingerprint_counts_as_a_search(env):
    """The homepage counts cases. Carl asked for these to show up there, and
    they do because they are real cases — nothing special is needed."""
    repo, session = env
    before = repo.count_since()["searches"]
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    assert repo.count_since()["searches"] == before + 1


def test_the_entities_count_too(env):
    repo, session = env
    before = repo.count_since()["entities"]
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    sentinel.tick(repo)
    assert repo.count_since()["entities"] > before


# --- retention -------------------------------------------------------------

def test_old_observations_are_purged(env):
    """Held to notice a pattern over days, not to keep a visitor log."""
    repo, session = env
    observe(session, "66.249.66.1",
            ago_hours=(sentinel.PURGE_DAYS + 2) * 24, count=3)
    observe(session, "66.249.66.2", count=3, ago_hours=1)
    removed = sentinel.purge_observations(session)
    assert removed == 3
    assert {o.ip for o in session.query(SentinelObservation).all()} == {"66.249.66.2"}


def test_purging_an_empty_table_is_fine(env):
    repo, session = env
    assert sentinel.purge_observations(session) == 0


# --- failure ---------------------------------------------------------------

def test_a_collector_failure_does_not_stop_the_tick(env):
    repo, session = env
    from umbra.core.orchestrator import Orchestrator

    Orchestrator.run = lambda self, case_id, **kw: (_ for _ in ()).throw(
        RuntimeError("rdap down"))
    observe(session, "66.249.66.1", count=sentinel.MIN_HITS)
    observe(session, "66.249.66.2", count=sentinel.MIN_HITS)
    result = sentinel.tick(repo)
    assert result["fingerprinted"] == 0
    assert len(cases(session)) == 2  # the cases exist; the lookups failed


def test_recording_an_observation_never_raises():
    for args in ((None, None, None, 0), ("", "", "", 0), ("/", "x" * 5000, "u", 999)):
        sentinel.classify(*args[:3], args[3]) if len(args) == 4 else None
