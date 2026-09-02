"""Header block → structure, with a trust-marked Received chain.

**The whole reason this module is careful.** Each MTA *prepends* a `Received:`
header, so the chain reads newest-first, and everything below the first hop the
recipient does not control was supplied by whoever sent the message. It can be
entirely fabricated. A parser that reads the bottom of the chain and calls it
"the originating IP" will confidently report an innocent third party as the
source of a phishing campaign.

That is the same failure the rest of the codebase is built against — a DNSBL
error rendered as clean, an unsynced lake rendered as no sanctions — except
here the wrong answer *accuses somebody*.

So: every hop is marked `trusted` / `untrusted` / `unknown`, an origin is named
only when the chain justifies it, and `boundary_basis` records which hop the
decision was anchored on so an analyst can check it.

**How the boundary is found.** The topmost hop naming a real hostname in its
`by` clause is the anchor. Anything above it was prepended later — by
infrastructure closer to the recipient — so it is at least as trustworthy.
Trust then extends downward for as long as the `by` host stays inside the same
organisation.

"Same organisation" is not a plain domain match, because Microsoft 365 legitimately
hands a message between `outlook.com`, `office365.com` and
`protection.outlook.com`. `_PROVIDER_FAMILIES` is a curated table of those
groupings — a fact we assert, with the same discipline as the verified-token
list in `umbra.crypto.providers.trongrid`: a curated claim may be trusted, a
counterparty's self-description may not. An operator who knows their own
perimeter should pass `trusted_domains` and skip the inference entirely.

No network, no I/O, no dependency beyond the standard library.
"""
from __future__ import annotations

import email.utils
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.parser import Parser
from enum import Enum

# A message with ten thousand Received headers is not an investigation, it is a
# denial-of-service. Real chains run to a dozen.
MAX_HOPS = 200

# Long enough for any legitimate header, short enough that a megabyte of
# padding cannot ride along into the plan and out to a template.
MAX_HEADER_LEN = 4000

# Sibling domains one provider legitimately routes between. Without this the
# boundary cuts at the first hand-off inside Microsoft's own estate and the only
# IP worth having — the one that actually connected from outside — is lost.
_PROVIDER_FAMILIES: dict[str, str] = {
    "outlook.com": "microsoft365",
    "office365.com": "microsoft365",
    "microsoft.com": "microsoft365",
    "google.com": "google",
    "googlemail.com": "google",
    "gmail.com": "google",
    "amazonses.com": "amazon-ses",
    "amazonaws.com": "amazon-ses",
    "pphosted.com": "proofpoint",
    "proofpoint.com": "proofpoint",
    "mimecast.com": "mimecast",
    "messagelabs.com": "broadcom-cloud",
    "barracudanetworks.com": "barracuda",
    "protonmail.ch": "proton",
    "proton.me": "proton",
    "icloud.com": "apple",
    "me.com": "apple",
    "apple.com": "apple",
    "zoho.com": "zoho",
    "fastmail.com": "fastmail",
    "messagingengine.com": "fastmail",
}

# The fallback when the Public Suffix List has not been synced. `umbra psl sync`
# loads the real thing (~6,900 rules) and org_domain prefers it.
#
# This set used to hold only registry suffixes, which meant every *shared
# hosting* namespace collapsed to one organisation:
#
#     attacker.github.io  and  victim.github.io   → both "github.io"
#     evil.herokuapp.com  and  bank.herokuapp.com → both "herokuapp.com"
#
# For DMARC that is a false *alignment* — a DKIM signature from one tenant
# authenticating a From: on another — which is the failure direction that
# actually matters in spoofing detection. The PRIVATE half of the PSL exists for
# exactly these, so the highest-traffic ones are carried here too, and a fresh
# install with no sync is no longer wrong about them.
_MULTI_LABEL_SUFFIXES = {
    # ICANN — registry suffixes
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "com.br", "com.mx", "com.ar", "co.za", "co.in", "com.sg",
    "com.tr", "com.cn", "com.hk", "com.tw",
    # PRIVATE — one company's namespace, many unrelated tenants
    "github.io", "gitlab.io", "herokuapp.com", "herokudns.com",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net",
    "web.app", "firebaseapp.com", "appspot.com", "run.app",
    "pages.dev", "workers.dev", "r2.dev",
    "amazonaws.com", "elasticbeanstalk.com", "cloudfront.net",
    "netlify.app", "vercel.app", "onrender.com", "fly.dev",
    "githubusercontent.com", "blogspot.com", "wordpress.com",
    "myshopify.com", "squarespace.com", "wixsite.com", "weebly.com",
    "zendesk.com", "freshdesk.com", "atlassian.net", "sharepoint.com",
    "s3.amazonaws.com", "blob.core.windows.net", "core.windows.net",
}

# Address space that means "this hop was internal plumbing", so a handoff from
# it is not an external origin. Deliberately narrower than `is_private`.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("fc00::/7"),        # unique local
]

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\.?$"
)

# Keywords that separate the clauses of a Received header (RFC 5321 §4.4).
_HOP_KEYWORDS = ("from", "by", "with", "id", "for", "via", "using")

_TAG_RE = re.compile(r"\b([a-z][a-z0-9_]*)\s*=\s*([^;]+)")
_ANGLE_URL_RE = re.compile(r"<\s*([^>]{1,600})\s*>")


class Trust(str, Enum):
    """Whether a hop's contents are evidence or merely a claim."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass
class Hop:
    """One `Received:` header. `index` 0 is the most recent."""

    index: int
    raw: str
    from_host: str | None = None
    from_ip: str | None = None
    rdns: str | None = None
    helo: str | None = None
    by: str | None = None
    by_ip: str | None = None
    protocol: str | None = None
    when: datetime | None = None
    trust: Trust = Trust.UNKNOWN


@dataclass
class AuthResult:
    """One `Authentication-Results:` header.

    `trusted` is tri-state on purpose. `True` means the `authserv-id` names a
    host inside the trust boundary. `False` means it names somebody else, which
    makes the verdicts worthless. `None` means the header carried no
    `authserv-id` at all — common from Microsoft 365 — so its position in the
    block is the only thing vouching for it.
    """

    raw: str
    authserv_id: str | None = None
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    compauth: str | None = None
    header_d: str | None = None
    header_from: str | None = None
    smtp_mailfrom: str | None = None
    trusted: bool | None = None


@dataclass
class ParsedEmail:
    headers: list[tuple[str, str]] = field(default_factory=list)

    # The claim being tested
    from_addr: str | None = None
    from_domain: str | None = None
    display_name: str | None = None
    sender: str | None = None
    reply_to: str | None = None
    return_path: str | None = None

    # The recipient side — present because an analyst needs it to read the
    # chain, kept separate because it is the victim's own infrastructure.
    recipients: list[str] = field(default_factory=list)

    subject: str = ""
    date: datetime | None = None
    message_id: str | None = None
    message_id_domain: str | None = None

    hops: list[Hop] = field(default_factory=list)
    auth: list[AuthResult] = field(default_factory=list)
    dkim_signatures: list[dict[str, str]] = field(default_factory=list)

    x_originating_ip: str | None = None
    x_mailer: str | None = None
    list_unsubscribe: list[str] = field(default_factory=list)

    origin_ip: str | None = None
    origin_note: str = ""
    boundary_basis: str = ""
    trusted_domains: list[str] = field(default_factory=list)

    notes: list[str] = field(default_factory=list)

    @property
    def dkim_domains(self) -> list[str]:
        seen: list[str] = []
        for sig in self.dkim_signatures:
            d = (sig.get("d") or "").strip().lower().rstrip(".")
            if d and d not in seen:
                seen.append(d)
        return seen


# --- small helpers --------------------------------------------------------


def _unfold(value: str) -> str:
    return re.sub(r"[ \t]*\r?\n[ \t]+", " ", value or "").strip()


def _clip(value: str, limit: int = MAX_HEADER_LEN) -> str:
    value = value or ""
    return value if len(value) <= limit else value[:limit] + "…"


def _decode(value: str) -> str:
    """RFC 2047 encoded words → text. A malformed encoding is not a crash."""
    try:
        return str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001 - hostile input; the raw value still helps
        return value


def org_domain(host: str | None) -> str | None:
    """The registrable domain — the organisation boundary DMARC aligns on.

    Prefers the synced Public Suffix List; falls back to the built-in set above
    when it has not been fetched. The fallback is deliberately generous about
    shared-hosting namespaces, because getting those wrong produces a false
    *alignment*, and a spoofing check that errs toward "authenticated" is worse
    than one that errs toward "unknown".
    """
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if not host or ":" in host:
        return None

    psl = _psl()
    if psl is not None:
        registrable = psl.registrable(host)
        if registrable:
            return registrable
        # The list loaded but produced nothing. Two very different reasons:
        #
        #   1. the host IS a public suffix — "github.io" belongs to nobody, and
        #      inventing an organisation for it is how the false alignments
        #      happened;
        #   2. the TLD is simply not in the list — a brand-new gTLD, or one of
        #      the reserved test names (.example, .invalid, .tld) that fixtures
        #      are full of.
        #
        # Only the first is an answer. Returning None for the second broke
        # alignment for every unknown TLD at once, and callers that compared
        # org_domain(a) == org_domain(b) then read None == None as *aligned* —
        # strictly worse than the heuristic it replaced.
        if psl.public_suffix(host) is not None:
            return None

    labels = host.split(".")
    if len(labels) < 2:
        return None
    for size in (3, 2):
        if len(labels) > size:
            tail = ".".join(labels[-size:])
            if tail in _MULTI_LABEL_SUFFIXES:
                return ".".join(labels[-(size + 1):])
    tail2 = ".".join(labels[-2:])
    if tail2 in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail2


_PSL_CACHE: list = []


def _psl():
    """The synced list, or None. Loaded once per process."""
    if _PSL_CACHE:
        return _PSL_CACHE[0]
    try:
        from umbra.core.config import get_settings
        from umbra.lake.psl import PublicSuffixList

        psl = PublicSuffixList.from_settings(get_settings())
        if not psl.available:
            _PSL_CACHE.append(None)
            return None
        _PSL_CACHE.append(psl)
        return psl
    except Exception:  # noqa: BLE001 — parsing an email must never need a lake
        _PSL_CACHE.append(None)
        return None


def _family(host: str | None) -> str | None:
    org = org_domain(host)
    if not org:
        return None
    return _PROVIDER_FAMILIES.get(org, org)


def _is_hostname(token: str) -> bool:
    token = (token or "").strip().strip("[]()<>,;")
    if not token or ":" in token:
        return False
    return bool(_HOSTNAME_RE.match(token))


def _as_ip(token: str) -> str | None:
    token = (token or "").strip().strip("[]()<>,;'\"")
    if not token:
        return None
    if token.lower().startswith("ipv6:"):
        token = token[5:]
    token = token.split("%", 1)[0]  # link-local zone index
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def _find_ips(text: str) -> list[str]:
    out: list[str] = []
    for token in re.split(r"[\s,;]+", text or ""):
        ip = _as_ip(token)
        if ip and ip not in out:
            out.append(ip)
    return out


def is_routable(ip: str | None) -> bool:
    """Is this an address that could have connected from outside?

    Spelled out rather than using `is_private`, which also covers the
    documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Those
    are not internal routing — a message really claiming to arrive from one is
    odd and worth showing, and silently dropping it would render "no origin"
    for a message that has one. The question here is only "was this internal
    plumbing rather than a handoff", so only internal plumbing is excluded.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return False
    return not any(addr in net for net in _INTERNAL_NETWORKS
                   if net.version == addr.version)


def _domain_of(addr: str | None) -> str | None:
    if not addr or "@" not in addr:
        return None
    dom = addr.rsplit("@", 1)[1].strip().lower().rstrip(".>")
    return dom or None


def _tags(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, raw in _TAG_RE.findall(value or ""):
        out.setdefault(key.lower(), raw.strip())
    return out


# --- Received parsing -----------------------------------------------------


def _split_clauses(value: str) -> dict[str, str]:
    """Slice a Received value at its keywords, ignoring anything in brackets.

    `with Microsoft SMTP Server (cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)`
    contains the word `with` inside the parenthesised comment, which is why the
    scan tracks depth rather than using a regex.
    """
    marks: list[tuple[str, int, int]] = []
    depth = 0
    i, n = 0, len(value)
    while i < n:
        char = value[i]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth = max(0, depth - 1)
        elif depth == 0:
            before_ok = i == 0 or not (value[i - 1].isalnum() or value[i - 1] in "-._")
            if before_ok:
                for keyword in _HOP_KEYWORDS:
                    end = i + len(keyword)
                    if value[i:end].lower() != keyword:
                        continue
                    after_ok = end >= n or not (
                        value[end].isalnum() or value[end] in "-._"
                    )
                    if after_ok:
                        marks.append((keyword, i, end))
                        i = end - 1
                        break
        i += 1

    out: dict[str, str] = {}
    for position, (keyword, _start, end) in enumerate(marks):
        stop = marks[position + 1][1] if position + 1 < len(marks) else n
        out.setdefault(keyword, value[end:stop].strip())
    return out


def _parse_hop(index: int, raw_value: str) -> Hop:
    value = _clip(_unfold(raw_value))
    hop = Hop(index=index, raw=value)

    body = value
    if ";" in value:
        head, _, tail = value.rpartition(";")
        try:
            hop.when = email.utils.parsedate_to_datetime(tail.strip())
            body = head
        except (TypeError, ValueError, IndexError):
            hop.when = None

    clauses = _split_clauses(body)

    from_clause = clauses.get("from", "")
    if from_clause:
        first = from_clause.split("(")[0].split()
        if first and _is_hostname(first[0]):
            hop.from_host = first[0].strip(".").lower()
        helo = re.search(r"(?i)\bhelo[=\s]+([A-Za-z0-9.\-]+)", from_clause)
        if helo and _is_hostname(helo.group(1)):
            hop.helo = helo.group(1).strip(".").lower()
        for chunk in re.findall(r"\(([^)]*)\)", from_clause):
            for token in re.split(r"[\s\[\]]+", chunk):
                if _is_hostname(token) and not hop.rdns:
                    lowered = token.strip(".").lower()
                    if lowered != hop.helo:
                        hop.rdns = lowered
        ips = _find_ips(from_clause)
        if ips:
            hop.from_ip = ips[0]

    by_clause = clauses.get("by", "")
    if by_clause:
        first = by_clause.split("(")[0].split()
        if first:
            if _is_hostname(first[0]):
                hop.by = first[0].strip(".").lower()
            else:
                ip = _as_ip(first[0])
                if ip:
                    hop.by_ip = ip
        ips = _find_ips(by_clause)
        if ips and not hop.by_ip:
            hop.by_ip = ips[0]

    protocol = clauses.get("with")
    if protocol:
        hop.protocol = protocol.split("(")[0].strip()[:80] or None

    return hop


def _mark_chain(
    hops: list[Hop], trusted_domains: set[str] | None
) -> tuple[str | None, str, str]:
    """Assign trust, then name the handoff IP if — and only if — one is justified.

    Returns `(origin_ip, origin_note, boundary_basis)`.
    """
    if not hops:
        return None, ("No Received headers, so there is no chain to read and no "
                      "origin to report. This is not the same as the message "
                      "having no origin."), ""

    anchor = next((h.index for h in hops if h.by), None)
    if anchor is None:
        for hop in hops:
            hop.trust = Trust.UNKNOWN
        return None, ("No hop names the server that received it, so the trust "
                      "boundary cannot be established and no hop's contents can "
                      "be treated as evidence."), ""

    if trusted_domains:
        wanted = {d.strip().lower().rstrip(".") for d in trusted_domains if d}

        def ours(host: str | None) -> bool:
            host = (host or "").lower().rstrip(".")
            return bool(host) and any(
                host == d or host.endswith("." + d) for d in wanted
            )

        basis = ("trust declared by the operator over " + ", ".join(sorted(wanted)))
    else:
        anchor_family = _family(hops[anchor].by)

        def ours(host: str | None) -> bool:
            return bool(host) and _family(host) == anchor_family

        basis = (
            f"hop {anchor} was recorded by {hops[anchor].by}; trust extends over "
            f"{anchor_family} and no further"
        )

    last_trusted = anchor - 1
    for hop in hops[anchor:]:
        if ours(hop.by):
            last_trusted = hop.index
        else:
            break

    for hop in hops:
        hop.trust = Trust.TRUSTED if hop.index <= last_trusted else Trust.UNTRUSTED

    if last_trusted < 0:
        return None, ("The first hop that names a receiving server is already "
                      "outside the trust boundary, so nothing in this chain is "
                      "evidence."), basis

    handoff = hops[last_trusted]
    # There used to be a check here for "the last trusted hop is also the last
    # hop", returning no origin on the theory that the message never left the
    # building. That is only true when the address it received *from* is
    # internal, which the routability check below already establishes — and the
    # theory is wrong for the commonest shape of all, a single hop reading
    # `from sender.example [198.51.100.30] by mx.ours.com`. One hop, ours,
    # naming exactly who connected. It was refusing to report the origin for
    # every small mail server on the internet.
    if not handoff.from_ip:
        return None, (
            f"Hop {last_trusted} is the last one recorded by infrastructure "
            "inside the boundary, but it did not record the address it received "
            "from. Everything below it is the sender's own claim."
        ), basis

    if not is_routable(handoff.from_ip):
        return None, (
            f"The last trusted hop received from {handoff.from_ip}, which is a "
            "private or link-local address. That is internal routing, not an "
            "external origin."
        ), basis

    return handoff.from_ip, (
        f"{handoff.from_ip} connected to {handoff.by}, which is inside the trust "
        f"boundary. Every hop below hop {last_trusted} was supplied by the sender "
        "and may be fabricated."
    ), basis


# --- entry point ----------------------------------------------------------


def parse_headers(
    blob: str,
    trusted_domains: set[str] | None = None,
) -> ParsedEmail:
    """Parse a header block. Never raises on hostile or malformed input."""
    parsed = ParsedEmail()
    parsed.trusted_domains = sorted(trusted_domains or [])
    blob = (blob or "").replace("\r\n", "\n")
    if not blob.strip():
        parsed.origin_note = ("Nothing to parse. An empty block is not a clean "
                              "message.")
        return parsed

    try:
        message = Parser(policy=policy.compat32).parsestr(blob, headersonly=True)
    except Exception as exc:  # noqa: BLE001 - the input is untrusted by design
        parsed.notes.append(f"header block could not be parsed ({exc})")
        parsed.origin_note = "The header block could not be parsed."
        return parsed

    def all_of(name: str) -> list[str]:
        try:
            return [str(v) for v in (message.get_all(name) or [])]
        except Exception:  # noqa: BLE001
            return []

    def one(name: str) -> str | None:
        values = all_of(name)
        if len(values) > 1:
            parsed.notes.append(
                f"{len(values)} {name} headers — mail clients disagree about "
                f"which one to render, and that disagreement is itself an "
                f"evasion technique. Reading the first."
            )
        return _clip(_unfold(values[0])) if values else None

    try:
        parsed.headers = [(k, _clip(_unfold(str(v)))) for k, v in message.items()]
    except Exception:  # noqa: BLE001
        parsed.headers = []

    # --- the claim ---
    raw_from = one("From")
    if raw_from:
        name, addr = email.utils.parseaddr(_decode(raw_from))
        parsed.display_name = (name or "").strip()[:200] or None
        parsed.from_addr = (addr or "").strip().lower() or None
        parsed.from_domain = _domain_of(parsed.from_addr)

    for attr, header in (("sender", "Sender"), ("reply_to", "Reply-To"),
                         ("return_path", "Return-Path")):
        raw = one(header)
        if raw:
            _, addr = email.utils.parseaddr(_decode(raw))
            setattr(parsed, attr, (addr or "").strip().lower() or None)

    # --- the recipient side ---
    recipients: list[str] = []
    for header in ("To", "Cc", "Delivered-To", "X-Original-To", "Envelope-To"):
        for raw in all_of(header):
            for _n, addr in email.utils.getaddresses([_unfold(raw)]):
                addr = (addr or "").strip().lower()
                if addr and "@" in addr and addr not in recipients:
                    recipients.append(addr)
    parsed.recipients = recipients[:50]

    parsed.subject = _clip(_decode(one("Subject") or ""))
    raw_date = one("Date")
    if raw_date:
        try:
            parsed.date = email.utils.parsedate_to_datetime(raw_date)
        except (TypeError, ValueError, IndexError):
            parsed.notes.append("Date header could not be parsed")

    message_id = one("Message-ID") or one("Message-Id")
    if message_id:
        parsed.message_id = message_id.strip("<> ")[:300]
        parsed.message_id_domain = _domain_of(parsed.message_id)

    # --- the chain ---
    received = all_of("Received")
    if len(received) > MAX_HOPS:
        parsed.notes.append(
            f"chain truncated to the {MAX_HOPS} most recent of {len(received)} "
            f"Received headers"
        )
        received = received[:MAX_HOPS]
    parsed.hops = [_parse_hop(i, value) for i, value in enumerate(received)]

    origin_ip, origin_note, basis = _mark_chain(parsed.hops, trusted_domains)
    parsed.origin_ip = origin_ip
    parsed.origin_note = origin_note
    parsed.boundary_basis = basis

    trusted_hosts = {h.by for h in parsed.hops if h.trust is Trust.TRUSTED and h.by}

    # --- authentication ---
    for raw in all_of("Authentication-Results")[:10]:
        value = _clip(_unfold(raw))
        result = AuthResult(raw=value)
        head = value.split(";", 1)[0].strip()
        if head and "=" not in head:
            result.authserv_id = head.split()[0].strip().lower()[:253] or None
        tags = _tags(value)
        result.spf = (tags.get("spf") or "").split()[0].lower() or None if tags.get("spf") else None
        result.dkim = (tags.get("dkim") or "").split()[0].lower() or None if tags.get("dkim") else None
        result.dmarc = (tags.get("dmarc") or "").split()[0].lower() or None if tags.get("dmarc") else None
        result.compauth = (tags.get("compauth") or "").split()[0].lower() or None if tags.get("compauth") else None
        for tag, attr in (("header.d", "header_d"), ("header.from", "header_from"),
                          ("smtp.mailfrom", "smtp_mailfrom")):
            found = re.search(rf"(?i){re.escape(tag)}\s*=\s*([^\s;]+)", value)
            if found:
                setattr(result, attr, found.group(1).strip().lower().strip("<>")[:253])
        if result.header_d is None and tags.get("header"):
            pass
        if result.authserv_id:
            if trusted_domains:
                wanted = {d.lower().rstrip(".") for d in trusted_domains}
                result.trusted = any(
                    result.authserv_id == d or result.authserv_id.endswith("." + d)
                    for d in wanted
                )
            else:
                result.trusted = any(
                    _family(result.authserv_id) == _family(host)
                    for host in trusted_hosts
                ) if trusted_hosts else None
        parsed.auth.append(result)

    for raw in all_of("DKIM-Signature")[:20]:
        parsed.dkim_signatures.append(_tags(_clip(_unfold(raw))))

    # --- low-trust extras ---
    for header in ("X-Originating-IP", "X-Sender-IP", "X-Source-IP"):
        raw = one(header)
        if raw:
            ips = _find_ips(raw)
            if ips:
                parsed.x_originating_ip = ips[0]
                break

    parsed.x_mailer = one("X-Mailer") or one("User-Agent")

    for raw in all_of("List-Unsubscribe")[:5]:
        for url in _ANGLE_URL_RE.findall(_unfold(raw)):
            url = url.strip()
            if url and url not in parsed.list_unsubscribe:
                parsed.list_unsubscribe.append(url[:600])

    return parsed
