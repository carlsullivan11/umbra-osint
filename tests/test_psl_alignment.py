"""The organisation boundary, and the spoofing verdict that rides on it.

`org_domain` decides whether two hostnames belong to the same organisation, and
DMARC alignment is defined in exactly those terms. It was doing that with 25
hardcoded registry suffixes, which meant every *shared hosting* namespace
collapsed into a single organisation:

    attacker.github.io      vs victim.github.io       → both "github.io"
    evil.herokuapp.com      vs bank.herokuapp.com     → both "herokuapp.com"
    evil.s3.amazonaws.com   vs corp.s3.amazonaws.com  → both "amazonaws.com"

Each is a false **alignment** — a DKIM signature from one tenant authenticating
a From: on another. A spoofing check that errs toward "authenticated" is the
wrong direction to be wrong in, so these are the tests that matter most.
"""
from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

from umbra.email.parse import org_domain  # noqa: E402
from umbra.email.verdict import _aligned  # noqa: E402
from umbra.lake.psl import PublicSuffixList, parse, sync  # noqa: E402

SHARED_HOSTS = [
    ("attacker.github.io", "victim.github.io"),
    ("evil.herokuapp.com", "bank.herokuapp.com"),
    ("phish.web.app", "realco.web.app"),
    ("bad.azurewebsites.net", "good.azurewebsites.net"),
    ("evil.s3.amazonaws.com", "corp.s3.amazonaws.com"),
    ("evil.pages.dev", "corp.pages.dev"),
    ("evil.netlify.app", "corp.netlify.app"),
    ("evil.vercel.app", "corp.vercel.app"),
]


class TestTheBugThatMattered:
    @pytest.mark.parametrize("attacker,victim", SHARED_HOSTS)
    def test_two_tenants_of_a_shared_host_never_align(self, attacker, victim):
        assert not _aligned(attacker, victim), (
            f"{attacker} was judged the same organisation as {victim} — that is a "
            "DKIM signature from one tenant authenticating another tenant's mail"
        )

    @pytest.mark.parametrize("attacker,victim", SHARED_HOSTS)
    def test_each_tenant_gets_its_own_org_domain(self, attacker, victim):
        assert org_domain(attacker) != org_domain(victim)
        assert org_domain(attacker) == attacker


class TestLegitimateAlignmentStillWorks:
    """Over-correcting would break real mail, which is the other way to be wrong."""

    @pytest.mark.parametrize("a,b", [
        ("mail.example.com", "example.com"),
        ("mx1.example.co.uk", "example.co.uk"),
        ("bounce.mail.example.com", "example.com"),
        ("example.com", "example.com"),
    ])
    def test_subdomains_align_with_their_parent(self, a, b):
        assert _aligned(a, b)

    @pytest.mark.parametrize("a,b", [
        ("example.com", "example.net"),
        ("example.co.uk", "other.co.uk"),
        ("evil-example.com", "example.com"),
    ])
    def test_unrelated_domains_do_not_align(self, a, b):
        assert not _aligned(a, b)


class TestPslParsing:
    LIST = """// ===BEGIN ICANN DOMAINS===
com
co.uk
*.ck
!www.ck
// ===BEGIN PRIVATE DOMAINS===
github.io
"""

    def test_the_three_rule_shapes(self):
        rules, wildcards, exceptions = parse(self.LIST)
        assert "com" in rules and "co.uk" in rules and "github.io" in rules
        assert "ck" in wildcards
        assert "www.ck" in exceptions

    def test_comments_and_blanks_are_ignored(self):
        rules, _, _ = parse("// a comment\n\n   \ncom\n")
        assert rules == {"com"}

    @pytest.fixture
    def psl(self, tmp_path):
        path = tmp_path / "psl.dat"
        path.write_text(self.LIST)
        return PublicSuffixList(path)

    def test_ordinary_suffix(self, psl):
        assert psl.public_suffix("example.co.uk") == "co.uk"
        assert psl.registrable("mail.example.co.uk") == "example.co.uk"

    def test_wildcard_makes_every_label_a_suffix(self, psl):
        assert psl.public_suffix("foo.ck") == "foo.ck"
        assert psl.registrable("bar.foo.ck") == "bar.foo.ck"

    def test_exception_beats_the_wildcard(self, psl):
        """`!www.ck` makes www.ck registrable even though `*.ck` would swallow it."""
        assert psl.registrable("www.ck") == "www.ck"

    def test_a_bare_public_suffix_has_no_registrable_domain(self, psl):
        # "github.io" belongs to nobody; inventing an organisation for it is how
        # the false alignments happened.
        assert psl.registrable("github.io") is None

    def test_private_section_counts_the_same_as_icann(self, psl):
        assert psl.registrable("attacker.github.io") == "attacker.github.io"

    def test_an_absent_list_returns_none_rather_than_guessing(self, tmp_path):
        psl = PublicSuffixList(tmp_path / "missing.dat")
        assert psl.public_suffix("example.co.uk") is None
        assert psl.registrable("example.co.uk") is None
        assert not psl.available


class TestSync:
    class Resp:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

    class Http:
        def __init__(self, resp):
            self._resp = resp

        def get(self, url, **kw):
            return self._resp

    def test_a_short_parse_refuses_to_overwrite(self, tmp_path):
        """A captive portal or error page parses to a handful of rules. Writing
        that over a good list silently restores the false-alignment behaviour."""
        path = tmp_path / "psl.dat"
        path.write_text("\n".join(f"suffix{i}.example" for i in range(2000)))
        psl = PublicSuffixList(path)
        before = path.read_text()

        with pytest.raises(ValueError, match="refusing to replace"):
            sync(psl, self.Http(self.Resp("com\nco.uk\n")))

        assert path.read_text() == before

    def test_a_real_list_replaces(self, tmp_path):
        psl = PublicSuffixList(tmp_path / "psl.dat")
        body = "\n".join(f"suffix{i}.example" for i in range(1500))
        out = sync(psl, self.Http(self.Resp(body)))
        assert out["rules"] == 1500
        assert psl.available


class TestUnknownTlds:
    """The regression I introduced, and the one it exposed underneath.

    When the PSL is loaded but the TLD is not in it — a brand-new gTLD, or the
    reserved test names fixtures are full of — the first version of this change
    returned None. Callers comparing `org_domain(a) == org_domain(b)` then read
    `None == None` as **aligned**, which is strictly worse than the heuristic it
    replaced. `tests/email/test_plan.py` caught it.
    """

    @pytest.mark.parametrize("host,expected", [
        ("mailer.random-vps.tld", "random-vps.tld"),
        ("mail.yourbank.example", "yourbank.example"),
        ("host.some.invalid", "some.invalid"),
    ])
    def test_an_unknown_tld_falls_back_rather_than_returning_none(self, host, expected):
        assert org_domain(host) == expected

    def test_unknown_tlds_on_different_domains_do_not_align(self):
        assert not _aligned("mailer.random-vps.tld", "yourbank.example")

    def test_two_unknowns_never_align_through_none(self):
        """`None == None` must never be an alignment. Not knowing the
        organisation is the one case where alignment cannot be claimed."""
        assert not _aligned(None, None)
        assert not _aligned("", "")

    def test_a_bare_public_suffix_has_no_org_when_the_list_is_loaded(self, tmp_path):
        """Asserted against an explicit list, not the ambient one.

        This test first read `org_domain("github.io") is None`, which is only
        true where `umbra psl sync` has run. It passed on my machine and blocked
        every production deploy, because the build image has no lake — the third
        environment-dependent gate test I have written this session, against a
        rule I wrote into docs/DEPLOYMENT.md myself.

        The two answers are both defensible and they differ by mode:
          list loaded   → None      ("github.io" is a suffix, owned by nobody)
          fallback only → github.io (the heuristic cannot know that)
        So the mode has to be pinned rather than inherited.
        """
        path = tmp_path / "psl.dat"
        path.write_text("// ===BEGIN PRIVATE DOMAINS===\ngithub.io\ncom\n")
        psl = PublicSuffixList(path)
        assert psl.registrable("github.io") is None
        assert psl.registrable("attacker.github.io") == "attacker.github.io"

    def test_the_fallback_never_merges_two_tenants(self):
        """What must hold in *either* mode: the security property.

        Whatever org_domain returns for the bare suffix, two tenants under it
        must never collapse together — that is the false alignment.
        """
        assert org_domain("attacker.github.io") != org_domain("victim.github.io")


class TestBothSurfacesAgree:
    """plan.py computed alignment with a raw `==` while verdict.py guarded for
    None. One rule, two implementations, and they disagreed the moment None
    became possible."""

    def test_plan_and_verdict_agree_on_a_mismatch(self):
        from umbra.email.parse import org_domain as od

        sig, frm = "mailer.random-vps.tld", "yourbank.example"
        plan_style = bool(od(sig) and od(frm) and od(sig) == od(frm))
        assert plan_style is _aligned(sig, frm) is False

    def test_plan_and_verdict_agree_on_a_match(self):
        from umbra.email.parse import org_domain as od

        sig, frm = "mail.example.com", "example.com"
        plan_style = bool(od(sig) and od(frm) and od(sig) == od(frm))
        assert plan_style is _aligned(sig, frm) is True
