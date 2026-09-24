"""What can be said about an address without asking anyone.

After scoping the pivot, a free-mail search is honest and thin: `email_split`
and `gravatar`, two rows. U6's other half is giving it something real to say.

Everything here is a property of the string, so it costs no request, needs no
key, and cannot be rate limited or blocked. It answers the questions an
investigator actually opens with:

- Is this a person or a mailbox? `security@` is a function, not a human, and
  treating it as one is how a role account ends up in a report as a suspect.
- Is this throwaway? A mailinator address is a deliberate non-identity.
- Is this the *same* address as one already seen? `a.b+tag@gmail.com` and
  `ab@gmail.com` deliver to one inbox, and an investigator comparing two lists
  by string will miss it.
- Is the domain a provider or an organisation? It decides whether the domain
  says anything about the person.

**Canonicalisation is provider-specific and must stay that way.** Gmail ignores
dots; most providers do not, and `j.smith@fastmail.com` is a different mailbox
from `jsmith@fastmail.com`. Applying Gmail's rule everywhere would merge two
people.
"""
from __future__ import annotations

import pytest

from umbra.email.profile import (
    ROLE_LOCALS,
    canonical_address,
    is_disposable,
    is_role_account,
    profile_email,
    provider_class,
)


# --- role accounts ----------------------------------------------------------

@pytest.mark.parametrize("local", sorted(ROLE_LOCALS)[:8])
def test_known_role_locals(local):
    assert is_role_account(f"{local}@example.com") is True


@pytest.mark.parametrize("addr", [
    "noreply@example.com", "no-reply@example.com", "NoReply@example.com",
    "postmaster@example.com", "abuse@example.com", "security@example.com",
])
def test_role_variants(addr):
    assert is_role_account(addr) is True


@pytest.mark.parametrize("addr", [
    "jsmith@example.com", "carl@example.com", "darkbird232006@yahoo.com",
    "information.architect@example.com",
])
def test_people_are_not_role_accounts(addr):
    assert is_role_account(addr) is False


def test_a_role_word_inside_a_longer_local_is_not_a_role():
    """`information@` is a role; `information.architect@` is somebody's job."""
    assert is_role_account("info@example.com") is True
    assert is_role_account("infodev@example.com") is False


# --- provider class ---------------------------------------------------------

@pytest.mark.parametrize("addr,expected", [
    ("a@gmail.com", "free_mail"),
    ("a@yahoo.com", "free_mail"),
    ("a@proton.me", "free_mail"),
    ("a@mailinator.com", "disposable"),
    ("a@acme-corp.example", "other"),
])
def test_provider_class(addr, expected):
    assert provider_class(addr) == expected


def test_disposable_beats_free_mail():
    """A throwaway is a stronger statement than 'free provider'."""
    assert provider_class("a@guerrillamail.com") == "disposable"


@pytest.mark.parametrize("addr", ["a@mailinator.com", "a@guerrillamail.com",
                                 "a@10minutemail.com", "a@yopmail.com"])
def test_disposable_detection(addr):
    assert is_disposable(addr) is True


def test_a_real_provider_is_not_disposable():
    assert is_disposable("a@gmail.com") is False


# --- canonical form ---------------------------------------------------------

@pytest.mark.parametrize("addr,expected", [
    ("a.b+tag@gmail.com", "ab@gmail.com"),
    ("A.B@googlemail.com", "ab@gmail.com"),
    ("first.last+shopping@gmail.com", "firstlast@gmail.com"),
])
def test_gmail_dots_and_plus_are_normalised(addr, expected):
    assert canonical_address(addr) == expected


def test_dots_are_kept_where_they_are_significant():
    """Only Gmail ignores dots. Stripping them elsewhere merges two people."""
    assert canonical_address("j.smith@fastmail.com") == "j.smith@fastmail.com"


def test_plus_tags_are_stripped_where_the_provider_supports_them():
    assert canonical_address("carl+umbra@fastmail.com") == "carl@fastmail.com"


def test_case_is_normalised():
    assert canonical_address("Carl@Example.COM") == "carl@example.com"


def test_a_plain_address_is_unchanged():
    assert canonical_address("carl@example.com") == "carl@example.com"


# --- the whole profile ------------------------------------------------------

def test_profile_of_a_free_mail_person():
    p = profile_email("darkbird232006@yahoo.com")
    assert p["provider_class"] == "free_mail"
    assert p["role_account"] is False
    assert p["disposable"] is False
    assert p["canonical"] == "darkbird232006@yahoo.com"


def test_profile_of_a_role_account():
    p = profile_email("security@acme-corp.example")
    assert p["role_account"] is True
    assert p["provider_class"] == "other"


def test_profile_says_the_domain_is_uninformative_for_free_mail():
    """The note is the point: it explains why the report is short."""
    note = profile_email("a@gmail.com")["note"].lower()
    assert "provider" in note


def test_profile_never_raises_on_junk():
    for junk in ("", "not-an-email", "@", "a@", "@b.com"):
        assert isinstance(profile_email(junk), dict)


# --- the collector ----------------------------------------------------------

def _run(addr: str):
    from types import SimpleNamespace

    from umbra.collectors.email_profile import EmailProfileCollector

    ent = SimpleNamespace(value=addr, norm_key=f"email:{addr}")
    return EmailProfileCollector().collect(
        ent, SimpleNamespace(http=None, settings=None))


def test_the_collector_needs_no_http_client():
    """Offline like mac_oui and iana_port — ctx.http is None here on purpose."""
    assert _run("a@gmail.com").evidence


def test_disposable_is_not_said_twice():
    s = _run("throwaway@mailinator.com").evidence[0].summary
    assert s.count("disposable") == 1


def test_a_role_account_is_called_out():
    assert "role account" in _run("security@acme-corp.example").evidence[0].summary


def test_the_delivery_form_becomes_an_entity():
    """So two spellings of one mailbox converge in the graph."""
    from umbra.core.models import EntityType

    res = _run("first.last+shopping@gmail.com")
    vals = [e.value for e in res.entities if e.type == EntityType.EMAIL]
    assert "firstlast@gmail.com" in vals


def test_a_plain_address_creates_no_duplicate_entity():
    assert _run("carl@example.com").entities == []


def test_junk_is_a_note_not_a_finding():
    res = _run("not-an-address")
    assert res.evidence == []
    assert res.notes
