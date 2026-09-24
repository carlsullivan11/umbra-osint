"""An email at Yahoo is not a reason to investigate Yahoo.

`darkbird232006@yahoo.com` was searched on production and came back with 55
evidence rows:

    ip_reputation 18 · asn_cymru 12 · ip_geo 12 · rdap_ip 9   = 51 about Yahoo
    gravatar 1 · email_split 1                                =  2 about the address

Every fact true; almost none of it about the thing asked for. Somebody looking
up an address got a report on Yahoo Inc.'s hosting.

The chain, and every link looked reasonable on its own:

1. `intent.extract` already refuses to seed a free-mail domain — `bob@yahoo.com`
   plans 4 collectors, `bob@acme-corp.example` plans 23. That guard works.
2. `email_split` then emits the domain as an entity anyway. Correct in itself:
   the address really does belong to that domain, and the edge is worth having.
3. `Orchestrator._seed_apexes` adds an **email seed's domain** to the pivot
   apexes, so `_should_pivot` says yes to yahoo.com …
4. … which pulls the whole domain bundle, which resolves to Yahoo's MX
   addresses, which pulls the IP core on each.

`umbra.email.plan.FREE_MAIL` already exists and already says why this is wrong:

    Seeding these is not an investigation — it is a scan of a mail provider
    that happens to have a billion other customers.

The fix applies that judgement one layer down, where the pivot is actually
decided. A *corporate* mail domain still pivots, because there the domain is the
organisation and that is the whole point.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from umbra.core.orchestrator import Orchestrator


def _seed(kind: str, value: str):
    return SimpleNamespace(type=kind, value=value, is_seed=True, id="e1")


def _apexes(*seeds):
    return Orchestrator._seed_apexes(None, list(seeds))


FREE = ["yahoo.com", "gmail.com", "outlook.com", "proton.me", "icloud.com",
        "hotmail.com", "aol.com", "gmx.net", "fastmail.com"]


@pytest.mark.parametrize("provider", FREE)
def test_a_free_mail_domain_is_not_an_apex(provider):
    assert _apexes(_seed("email", f"someone@{provider}")) == set()


def test_a_corporate_mail_domain_is_still_an_apex():
    """The opposite case, and the reason this is a filter and not a removal:
    an address at a company domain says something about the company."""
    assert "acme-corp.example" in _apexes(_seed("email", "bob@acme-corp.example"))


def test_a_subdomain_of_a_corporate_mail_domain_resolves_to_its_apex():
    assert "acme-corp.example" in _apexes(_seed("email", "bob@mail.acme-corp.example"))


def test_a_domain_seed_is_unaffected():
    """Searching yahoo.com deliberately must still investigate yahoo.com."""
    assert "yahoo.com" in _apexes(_seed("domain", "yahoo.com"))


def test_case_is_ignored():
    assert _apexes(_seed("email", "Someone@YAHOO.COM")) == set()


def test_mixed_seeds_keep_the_corporate_one():
    got = _apexes(_seed("email", "a@gmail.com"), _seed("email", "b@acme-corp.example"))
    assert got == {"acme-corp.example"}


# --- and the pivot decision itself -----------------------------------------

def _ent(kind: str, value: str):
    return SimpleNamespace(type=kind, value=value, is_seed=False, id="e2")


def test_the_free_mail_domain_does_not_pivot():
    seeds = [_seed("email", "darkbird232006@yahoo.com")]
    apexes = _apexes(*seeds)
    assert Orchestrator._should_pivot(None, _ent("domain", "yahoo.com"), seeds, apexes) is False


def test_the_corporate_mail_domain_does_pivot():
    seeds = [_seed("email", "bob@acme-corp.example")]
    apexes = _apexes(*seeds)
    assert Orchestrator._should_pivot(None, _ent("domain", "acme-corp.example"), seeds, apexes) is True


def test_the_email_itself_is_still_collected():
    """Narrowing the pivot must not stop the address being looked at."""
    seeds = [_seed("email", "darkbird232006@yahoo.com")]
    assert Orchestrator._should_pivot(None, seeds[0], seeds, _apexes(*seeds)) is True
