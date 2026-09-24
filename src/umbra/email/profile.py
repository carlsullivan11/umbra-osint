"""What an address says about itself, before anybody is asked.

U6. Three collectors accepted `EMAIL` — `email_split`, `gravatar` and the
key-gated `hibp_breach` — and a production search of a yahoo.com address
returned 51 rows about Yahoo's hosting and 2 about the address. Scoping the
pivot removed the 51. This is what replaces them.

Everything here is a property of the string. No request, no key, nothing to rate
limit, nothing to be blocked by — the same shape as the OUI and IANA port tables
and for the same reason: the answer was always derivable and was being fetched
or skipped instead.

It answers what an investigator opens with:

- **Is this a person or a function?** `security@` is a mailbox a team shares.
  Carrying it through a report as an individual is a category error that gets
  someone's name attached to an alias.
- **Is this throwaway?** A mailinator address is a deliberate non-identity, and
  saying so is more useful than any lookup against it.
- **Is this the same address as one already seen?** `a.b+tag@gmail.com` and
  `ab@gmail.com` are one inbox. Two lists compared by string will miss it.
- **Does the domain mean anything?** For a provider with a billion customers it
  does not, and that is why the rest of the report is short.

None of this identifies anybody. It describes the address.
"""
from __future__ import annotations

from umbra.email.plan import FREE_MAIL

#: Local parts that name a function rather than a person. Deliberately short and
#: matched **exactly** — `info@` is a role, `infodev@` is somebody's mailbox, and
#: a substring test would collapse the two.
ROLE_LOCALS = frozenset({
    "abuse", "admin", "administrator", "billing", "compliance", "contact",
    "dmarc", "help", "hello", "hostmaster", "info", "information", "legal",
    "mail", "marketing", "news", "newsletter", "noc", "noreply", "no-reply",
    "notifications", "office", "postmaster", "press", "privacy", "root",
    "sales", "security", "security-reports", "soc", "support", "sysadmin",
    "team", "webmaster", "welcome",
})

#: Throwaway providers. A short curated list, not an attempt at completeness —
#: there are thousands of these and a stale list that claims to be exhaustive is
#: worse than a short one that does not.
DISPOSABLE_DOMAINS = frozenset({
    "10minutemail.com", "20minutemail.com", "33mail.com", "dispostable.com",
    "fakeinbox.com", "getairmail.com", "getnada.com", "guerrillamail.com",
    "guerrillamail.net", "guerrillamail.org", "mailcatch.com", "maildrop.cc",
    "mailinator.com", "mailnesia.com", "mintemail.com", "mohmal.com",
    "sharklasers.com", "spam4.me", "temp-mail.org", "tempmail.com",
    "tempr.email", "throwawaymail.com", "trashmail.com", "yopmail.com",
})

#: Providers that ignore dots in the local part. **Gmail and only Gmail** — this
#: is not a general email rule. `j.smith@fastmail.com` and `jsmith@fastmail.com`
#: are different mailboxes, and applying Gmail's behaviour to them merges two
#: people into one.
_DOT_INSENSITIVE = frozenset({"gmail.com", "googlemail.com"})

#: Providers whose canonical spelling differs from what people type.
_DOMAIN_ALIASES = {"googlemail.com": "gmail.com"}


def _split(address: str) -> tuple[str, str]:
    text = (address or "").strip().lower()
    if "@" not in text:
        return "", ""
    local, _, domain = text.rpartition("@")
    return local.strip(), domain.strip()


def is_role_account(address: str) -> bool:
    """True when the local part names a function rather than a person."""
    local, _domain = _split(address)
    if not local:
        return False
    # A plus tag does not change what the mailbox is for.
    base = local.split("+", 1)[0]
    return base in ROLE_LOCALS


def is_disposable(address: str) -> bool:
    _local, domain = _split(address)
    return bool(domain) and domain in DISPOSABLE_DOMAINS


def provider_class(address: str) -> str:
    """``disposable`` | ``free_mail`` | ``other``.

    Disposable outranks free-mail: both are true of a throwaway address, and the
    throwaway part is the stronger statement.
    """
    _local, domain = _split(address)
    if not domain:
        return "other"
    if domain in DISPOSABLE_DOMAINS:
        return "disposable"
    if domain in FREE_MAIL:
        return "free_mail"
    return "other"


def canonical_address(address: str) -> str:
    """The address as its provider would deliver it.

    Plus tags are stripped everywhere — sub-addressing is near-universal and a
    tag is a label the sender chose, not part of the mailbox. Dots are stripped
    **only** for Gmail, because only Gmail ignores them.

    Returns the input lowercased when it cannot be parsed; this is a
    normalisation, not a validator.
    """
    local, domain = _split(address)
    if not local or not domain:
        return (address or "").strip().lower()

    domain = _DOMAIN_ALIASES.get(domain, domain)
    local = local.split("+", 1)[0]
    if domain in _DOT_INSENSITIVE:
        local = local.replace(".", "")
    if not local:
        return f"{domain}"
    return f"{local}@{domain}"


def profile_email(address: str) -> dict:
    """Everything derivable from the address, with a note explaining the scope."""
    local, domain = _split(address)
    cls = provider_class(address)
    role = is_role_account(address)
    disposable = is_disposable(address)
    canonical = canonical_address(address)

    notes: list[str] = []
    if cls == "disposable":
        notes.append(
            "Disposable provider — this address is a deliberate non-identity "
            "and is unlikely to be reachable or to belong to anyone for long."
        )
    elif cls == "free_mail":
        notes.append(
            "Free-mail provider. The domain is shared with millions of "
            "unrelated people, so nothing about the provider is a fact about "
            "this address — which is why this report is about the address alone."
        )
    elif domain:
        notes.append(
            f"{domain} is not a known consumer provider, so the domain may be "
            "an organisation worth looking at in its own right."
        )
    if role:
        notes.append(
            "Role account — a mailbox for a function, usually shared by a team. "
            "Not a person, and must not be reported as one."
        )
    if canonical != (address or "").strip().lower():
        notes.append(f"Delivers to {canonical}; compare addresses in that form.")

    return {
        "address": (address or "").strip().lower(),
        "local": local,
        "domain": domain,
        "canonical": canonical,
        "provider_class": cls,
        "role_account": role,
        "disposable": disposable,
        "note": " ".join(notes),
    }
