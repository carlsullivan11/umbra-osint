"""Parsed headers → `IntentPlan`, which is where this feature stops being new.

Carl's design for the feature: extract the entities, then let the analyst choose
which ones go to the recon workers. That step already exists. `results.html`
renders a checkbox per seed under *"Uncheck anything the extractor got wrong"*,
and `umbra.web.routes._apply_plan_edits` enforces that edits may only
**narrow** — a collector that was not in the plan is dropped rather than run.
That narrowing rule is the security property, and it is already tested.

So the entire integration is this module: emit an `IntentPlan` and the confirm
page, worker dispatch, budgets, case creation and audit all apply unchanged.
`IntentSeed` happens to carry exactly the four fields needed — `include` for
the default check state, `notes` for the reason, `source_span` for the header a
claim came from, and `confidence` so a trusted Received hop outranks a
sender-supplied `X-Originating-IP`.

**Two rules do the real work here.**

*Everything is shown.* An earlier draft of `docs/EMAIL-HEADERS.md` proposed not
extracting recipient-side identifiers at all, for privacy. That was wrong: an
analyst needs the recipient's own relays visible to find the trust boundary,
and hiding them breaks the analysis.

*Almost nothing is armed.* Recipient addresses, the recipient's own relays, and
every hop below the trust boundary are present and unchecked. Those lower hops
are especially important to leave off — they are strings the **attacker chose**,
so running collectors against them means investigating whoever the attacker
decided to name.

**And the block itself never travels.** An `IntentPlan` is persisted as a case.
The header block is the most sensitive artifact in this feature and has no
investigative value once parsed, so `raw_intent` gets a description of the
message rather than the message.
"""
from __future__ import annotations

from umbra.core.models import EntityType
from umbra.email.parse import (
    ParsedEmail,
    Trust,
    is_routable,
    org_domain,
    parse_headers,
)
from umbra.email.verdict import Finding, judge
from umbra.intent.plan import select_collectors
from umbra.intent.schema import IntentFlags, IntentPlan, IntentSeed

# Seeding these is not an investigation — it is a scan of a mail provider that
# happens to have a billion other customers. `umbra.intent.extract` draws the
# same line for the same reason.
FREE_MAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "proton.me", "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com",
    "zoho.com", "yandex.com", "fastmail.com", "tutanota.com", "hey.com",
}

# Infrastructure hostnames belonging to the big providers. A hop through
# `mail-pj1-f172.google.com` is Google being Google, not a lead.
_INFRA_SUFFIXES = (
    "google.com", "googlemail.com", "outlook.com", "office365.com",
    "protection.outlook.com", "microsoft.com", "amazonses.com", "amazonaws.com",
    "pphosted.com", "mimecast.com", "messagelabs.com", "icloud.com",
    "messagingengine.com", "sendgrid.net", "mailgun.org", "mandrillapp.com",
)


def _is_infra(host: str | None) -> bool:
    org = org_domain(host)
    return bool(org and (org in _INFRA_SUFFIXES or org in FREE_MAIL))


class _Builder:
    """Collects seeds, keeping the first reason given for each one."""

    def __init__(self) -> None:
        self.seeds: list[IntentSeed] = []
        self._seen: set[tuple[str, str]] = set()

    def add(self, kind: EntityType, value: str | None, *, include: bool,
            confidence: float, source: str, notes: str | None = None) -> None:
        if not value:
            return
        value = value.strip().strip("<>").lower() if kind is not EntityType.URL else value.strip()
        if not value:
            return
        key = (kind.value, value)
        if key in self._seen:
            return
        self._seen.add(key)
        self.seeds.append(IntentSeed(
            type=kind, value=value, confidence=round(confidence, 2),
            include=include, source_span=source, notes=notes,
        ))

    def domain_and_address(self, address: str | None, *, include: bool,
                           confidence: float, source: str,
                           notes: str | None = None,
                           domain_notes: str | None = None) -> None:
        if not address or "@" not in address:
            return
        self.add(EntityType.EMAIL, address, include=include,
                 confidence=confidence, source=source, notes=notes)
        domain = address.rsplit("@", 1)[1]
        if domain in FREE_MAIL:
            self.add(EntityType.DOMAIN, domain, include=False,
                     confidence=0.3, source=source,
                     notes="a free-mail provider — investigating it would scan a "
                           "billion other people's mailboxes")
            return
        self.add(EntityType.DOMAIN, domain, include=include,
                 confidence=confidence - 0.05, source=source,
                 notes=domain_notes or notes)


def seeds_from_parse(parsed: ParsedEmail) -> list[IntentSeed]:
    """Every identifier in the block, with the sender side armed and the rest not."""
    builder = _Builder()
    signing = parsed.dkim_domains

    # --- the address being claimed ---
    builder.domain_and_address(
        parsed.from_addr, include=True, confidence=0.9, source="From",
        notes="the sender the message claims to be",
    )

    # --- the domain that actually signed it ---
    for domain in signing:
        # `org_domain(a) == org_domain(b)` reads None == None as aligned, which
        # is exactly backwards: not knowing the organisation is the one case
        # where alignment must never be claimed. verdict._aligned already got
        # this right; two implementations of one rule is how they disagree.
        _sig_org = org_domain(domain)
        _from_org = org_domain(parsed.from_domain or "")
        aligned = bool(_sig_org and _from_org and _sig_org == _from_org)
        note = ("the domain that actually signed this message — it is not "
                f"{parsed.from_domain}, which is what makes the From address a "
                "claim rather than a fact") if not aligned else (
            "the signing domain, which lines up with the From address")
        builder.add(EntityType.DOMAIN, domain, include=True,
                    confidence=0.88 if not aligned else 0.8,
                    source="DKIM-Signature d=", notes=note)

    # --- where bounces and replies really go ---
    builder.domain_and_address(
        parsed.return_path, include=True, confidence=0.85, source="Return-Path",
        notes="the envelope sender — where bounces go, and what SPF actually "
              "covers",
    )
    builder.domain_and_address(
        parsed.reply_to, include=True, confidence=0.82, source="Reply-To",
        notes="where a reply would actually go",
    )
    builder.domain_and_address(
        parsed.sender, include=True, confidence=0.8, source="Sender",
        notes="the Sender header, used when a message is submitted on someone "
              "else's behalf",
    )

    # --- the sending host naming itself ---
    if parsed.message_id_domain and not _is_infra(parsed.message_id_domain):
        builder.add(EntityType.DOMAIN, parsed.message_id_domain, include=True,
                    confidence=0.7, source="Message-ID",
                    notes="the host that generated the Message-ID, which is "
                          "often the true sending system")

    # --- the one address the chain justifies naming ---
    if parsed.origin_ip:
        builder.add(EntityType.IP, parsed.origin_ip, include=True,
                    confidence=0.95, source="Received (trusted hop)",
                    notes="the address that connected to a server inside the "
                          "trust boundary — the only origin this block supports")

    # --- links ---
    for url in parsed.list_unsubscribe:
        if url.lower().startswith("http"):
            builder.add(EntityType.URL, url, include=True, confidence=0.8,
                        source="List-Unsubscribe",
                        notes="unsubscribe links are frequently the campaign's "
                              "real infrastructure")
            host = url.split("//", 1)[-1].split("/")[0].split(":")[0]
            if host and not _is_infra(host):
                builder.add(EntityType.DOMAIN, host, include=True,
                            confidence=0.75, source="List-Unsubscribe",
                            notes="host of the unsubscribe link")

    # --- shown, not armed: the recipient side ---
    for address in parsed.recipients:
        builder.domain_and_address(
            address, include=False, confidence=0.9, source="To/Delivered-To",
            notes="the recipient — their own address, shown so the chain can be "
                  "read, off so it is not scanned by accident",
            domain_notes="the recipient's own mail domain — this is the victim's "
                         "infrastructure, not the sender's",
        )

    # --- the machine that actually connected to us ---
    #
    # On the boundary hop the two clauses belong to different parties: `by` is
    # our server, `from` is *theirs*. Treating the whole hop as ours labelled
    # the sender's own host "the recipient's infrastructure" and left it
    # unchecked — wrong twice over, because the connecting host's name is one of
    # the better leads in a header block and frequently differs from the From
    # domain. Gated on an origin actually having been established: with no
    # external handoff (an all-internal chain) every hop really is ours.
    trusted = [h for h in parsed.hops if h.trust is Trust.TRUSTED]
    handoff = trusted[-1] if (trusted and parsed.origin_ip) else None
    if handoff is not None:
        for host in (handoff.rdns, handoff.from_host, handoff.helo):
            if host and not _is_infra(host):
                builder.add(EntityType.DOMAIN, host, include=True,
                            confidence=0.78,
                            source=f"Received hop {handoff.index} (connecting host)",
                            notes="the machine that connected to a server inside "
                                  "the trust boundary, and the name it gave for "
                                  "itself — sender-side, and recorded by us "
                                  "rather than claimed by them")

    # --- shown, not armed: our own hops ---
    for hop in parsed.hops:
        if hop.trust is not Trust.TRUSTED:
            continue
        for host in (hop.by, hop.from_host):
            if host and not _is_infra(host):
                builder.add(EntityType.DOMAIN, host, include=False,
                            confidence=0.85, source=f"Received hop {hop.index}",
                            notes="a mail server inside the trust boundary — "
                                  "the recipient's own infrastructure")

    # --- shown, not armed: everything the sender wrote ---
    for hop in parsed.hops:
        if hop.trust is Trust.TRUSTED:
            continue
        reason = ("below the trust boundary — this hop was written by the "
                  "sender and can say anything, so it is a string the attacker "
                  "chose rather than a lead")
        for host in (hop.from_host, hop.rdns, hop.helo, hop.by):
            if host and not _is_infra(host):
                builder.add(EntityType.DOMAIN, host, include=False,
                            confidence=0.3,
                            source=f"Received hop {hop.index} ({hop.trust.value})",
                            notes=reason)
        # Loopback and RFC1918 addresses turn up constantly in forged chains
        # (`from localhost (localhost [127.0.0.1])` is boilerplate). They are
        # not investigable — `umbra.core.http_guard` refuses them outright — so
        # offering them as seeds is a checkbox that can never do anything.
        if hop.from_ip and is_routable(hop.from_ip):
            builder.add(EntityType.IP, hop.from_ip, include=False,
                        confidence=0.3,
                        source=f"Received hop {hop.index} ({hop.trust.value})",
                        notes=reason)

    if parsed.x_originating_ip:
        builder.add(EntityType.IP, parsed.x_originating_ip, include=False,
                    confidence=0.4, source="X-Originating-IP",
                    notes="vendor-specific and supplied by the sending system, "
                          "so it is a claim rather than a record"
                          + (" — and it disagrees with the trusted hop"
                             if parsed.origin_ip
                             and parsed.origin_ip != parsed.x_originating_ip
                             else ""))

    seeds = builder.seeds
    seeds.sort(key=lambda s: (-int(s.include), -s.confidence, s.type.value, s.value))
    return seeds


def _origin_line(parsed: ParsedEmail) -> str:
    """The origin conclusion, with the recipient's own hosts left out.

    `parsed.origin_note` names the server that anchored the trust boundary,
    which is exactly what an analyst needs in order to check the reasoning — and
    it is the recipient's own MX. The parse is ephemeral, so the full note goes
    to the screen. The plan is persisted as a case and rendered on a page, so it
    gets the conclusion without the victim's infrastructure in it.
    """
    if parsed.origin_ip:
        return (f"The chain supports naming {parsed.origin_ip} as the address "
                f"that reached the trust boundary; every hop below it is the "
                f"sender's own claim.")
    if not parsed.hops:
        return ("No Received headers, so there is no chain to read and no origin "
                "to report.")
    return ("The chain does not support naming where this message came from. "
            "That is a limit of the evidence, not a finding about the sender.")


def _describe(parsed: ParsedEmail) -> str:
    """A short description of the message — never the message itself."""
    parts = [f"{len(parsed.hops)} Received hop(s)"]
    if parsed.from_domain:
        parts.append(f"From {parsed.from_domain}")
    if parsed.origin_ip:
        parts.append(f"handoff from {parsed.origin_ip}")
    else:
        parts.append("no provable origin")
    if parsed.auth:
        parts.append("authentication results present")
    else:
        parts.append("no authentication results recorded")
    return "Email header block — " + "; ".join(parts)


def plan_from_parsed(
    parsed: ParsedEmail,
    findings: list[Finding],
    *,
    authorization_basis: str = "own_asset",
    authorization_note: str = "",
    depth: int = 1,
    max_entities: int = 200,
) -> IntentPlan:
    """Build the plan from work already done.

    Split out from `plan_from_headers` so nothing has to parse a message twice
    to get both the findings and the plan — see `analyze`.

    `own_asset` is the default basis because the ordinary case is an analyst
    looking at a message that was delivered to them. Callers with a different
    situation — a client engagement, a public sample — should say so.
    """
    seeds = seeds_from_parse(parsed)

    plan = IntentPlan(
        case_name=(f"Email from {parsed.from_domain}" if parsed.from_domain
                   else "Email header analysis")[:120],
        authorization_basis=authorization_basis,  # type: ignore[arg-type]
        authorization_note=authorization_note,
        seeds=seeds,
        depth=max(0, min(3, depth)),
        max_entities=max_entities,
        flags=IntentFlags(),
        extractor="email_headers_v1",
        # Deliberately a description, not the block. See the module docstring.
        raw_intent=_describe(parsed)[:280],
    )

    plan.collectors = select_collectors(seeds, plan.flags)
    plan.playbook = "email_triage"

    loud = [f for f in findings if f.severity in {"high", "medium"}]
    plan.warnings = [f"{f.title}. {f.detail}" for f in loud][:10]

    armed = [s for s in seeds if s.include]
    plan.summary = (
        f"{len(armed)} of {len(seeds)} extracted identifiers selected to run; "
        f"{len(loud)} finding(s) worth reading. " + _origin_line(parsed)
    )[:500]

    if not seeds:
        plan.warnings.append(
            "No identifiers could be extracted from this block. That means the "
            "paste did not parse as mail headers, not that the message is clean."
        )
        plan.clarifying_questions.append(
            "Paste the full header block — in Gmail, Show original; in Outlook, "
            "File → Properties → Internet headers."
        )
    elif not armed:
        plan.warnings.append(
            "Every identifier in this block is recipient-side or below the trust "
            "boundary, so nothing is selected by default. Tick anything you "
            "intend to investigate."
        )

    return plan


def plan_from_headers(
    blob: str,
    *,
    trusted_domains: set[str] | None = None,
    **kwargs,
) -> IntentPlan:
    """Parse a header block and return a plan the confirm page can run."""
    parsed = parse_headers(blob, trusted_domains=trusted_domains)
    return plan_from_parsed(parsed, judge(parsed), **kwargs)


def analyze(
    blob: str,
    *,
    trusted_domains: set[str] | None = None,
    **kwargs,
) -> tuple[ParsedEmail, list[Finding], IntentPlan]:
    """Parse, judge and plan in **one** pass — the shape the CLI and web want.

    Both callers need all three results. Reaching for them separately meant the
    web endpoint parsed and judged every upload twice and `umbra email` parsed
    three times, which on a public rate-limited route is double the CPU per
    request for identical output.
    """
    parsed = parse_headers(blob, trusted_domains=trusted_domains)
    findings = judge(parsed)
    return parsed, findings, plan_from_parsed(parsed, findings, **kwargs)
