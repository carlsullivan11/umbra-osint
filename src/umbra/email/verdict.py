"""Judging a parsed header block — alignment, not pass/fail.

`dkim=pass` means somebody signed the message. It does not mean the sender is
who `From:` claims. What matters is **alignment**: whether the `From:` domain
matches the domain that signed (DKIM `d=`) and the domain that owns the
envelope sender (`Return-Path`). A message from `security@yourbank.example`,
validly signed for `d=mailer.random-vps.tld`, with SPF passing for that same
stranger, passes all three checks read individually and is a textbook spoof.

The second job is refusing to overstate. Absent `Authentication-Results` means
the receiving server did not check, or did not record it. Reporting that as a
failed check invents a finding — the same mistake as rendering a DNSBL timeout
as clean, pointed the other way. So there are three outcomes here, never two:
aligned, misaligned, and not checked.

Pure. No network, no database, no I/O.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from umbra.email.parse import ParsedEmail, Trust, org_domain

SEVERITY_ORDER = ("high", "medium", "low", "info")


@dataclass
class Finding:
    """One thing worth saying about a message.

    `evidence` is not decoration. A finding an analyst cannot check is an
    assertion, and this codebase does not ship assertions — the same reason
    every collector result carries its provenance.
    """

    key: str
    severity: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)


def _aligned(claim: str | None, other: str | None) -> bool:
    """Relaxed alignment, which is what nearly every real sender uses.

    Strict alignment demands an exact match. Relaxed accepts an organisational
    match, so `d=mail.example.com` signing for `From: x@example.com` counts —
    and it has to, or every bulk sender in the world is reported as a spoof.
    """
    if not claim or not other:
        return False
    claim, other = claim.lower().rstrip("."), other.lower().rstrip(".")
    if claim == other:
        return True
    left, right = org_domain(claim), org_domain(other)
    return bool(left and right and left == right)


def _usable_auth(parsed: ParsedEmail):
    """The topmost `Authentication-Results` that is worth reading, if any.

    Headers are prepended, so the receiving server's own results header sits
    above anything the sender wrote. `trusted is False` means the header names
    an `authserv-id` outside the boundary and its verdicts are worthless.
    `None` means no `authserv-id` was given at all — common from Microsoft 365 —
    so position is the only thing vouching for it, which is weak but not
    nothing.
    """
    if not parsed.auth:
        return None
    topmost = parsed.auth[0]
    return None if topmost.trusted is False else topmost


def judge(parsed: ParsedEmail) -> list[Finding]:
    """Findings for one parsed header block, worst first."""
    out: list[Finding] = []

    def add(key: str, severity: str, title: str, detail: str, **evidence) -> None:
        out.append(Finding(key=key, severity=severity, title=title,
                           detail=detail, evidence=evidence))

    from_domain = parsed.from_domain
    auth = _usable_auth(parsed)

    # --- was anything actually checked? ---
    #
    # Only the topmost header decides. MTAs prepend, so the receiving server's
    # own results sit above anything the sender wrote, and a sender that
    # appends a decorative `Authentication-Results` of its own cannot displace
    # the real one. Judging the whole list instead meant a legitimate, aligned,
    # DMARC-passing message earned a `high` finding — the loudest thing on the
    # page — over a header nothing here was relying on.
    topmost = parsed.auth[0] if parsed.auth else None
    planted = [r for r in parsed.auth[1:] if r.trusted is False]

    if topmost is not None and topmost.trusted is False:
        add("auth_untrusted", "high",
            "Authentication results were written by a server outside the trust "
            "boundary",
            f"The Authentication-Results header names "
            f"{topmost.authserv_id!r} as the checking server, which is not "
            f"inside the boundary established by the Received chain. Anyone can "
            f"add this header and claim every check passed, so these verdicts "
            f"are not evidence.",
            authserv_id=topmost.authserv_id, raw=topmost.raw[:400])
    elif planted:
        # Worth pointing out, not worth condemning: the verdicts being used
        # came from the trusted header above these.
        add("auth_self_asserted", "low",
            "The message carries authentication results it wrote for itself",
            f"Below the receiving server's own header, this message includes "
            f"{len(planted)} more Authentication-Results claiming to come from "
            f"{', '.join(str(r.authserv_id) for r in planted[:3])}. They are "
            f"not what Umbra read — the topmost header is — but senders with "
            f"nothing to hide do not usually grade their own homework.",
            authserv_ids=[r.authserv_id for r in planted[:3]],
            count=len(planted))

    if not parsed.auth:
        add("auth_not_checked", "info",
            "SPF, DKIM and DMARC results were not recorded",
            "This block carries no Authentication-Results header, so the "
            "receiving server either did not check the message or did not write "
            "the outcome down. That is an absence of evidence, not a failed "
            "check — nothing here says the message is unauthenticated.")

    # --- alignment, the actual spoofing signal ---
    dkim_domains = parsed.dkim_domains
    if auth and auth.header_d and auth.header_d not in dkim_domains:
        dkim_domains = [auth.header_d, *dkim_domains]

    dkim_checked = bool(auth and auth.dkim)
    if from_domain and dkim_domains:
        matching = [d for d in dkim_domains if _aligned(d, from_domain)]
        if matching:
            if dkim_checked and auth.dkim != "pass":
                add("dkim_fail", "medium",
                    f"DKIM signature for {from_domain} did not verify",
                    f"The signature aligns with the From domain but the "
                    f"receiving server recorded dkim={auth.dkim}.",
                    from_domain=from_domain, dkim=auth.dkim)
            else:
                add("dkim_aligned", "info",
                    "DKIM signing domain lines up with the From address",
                    f"The message is signed by {matching[0]}, which belongs to "
                    f"the same organisation as the From domain {from_domain}. "
                    + ("The receiving server verified the signature."
                       if dkim_checked and auth.dkim == "pass"
                       else "Alignment is a property of the headers; whether the "
                            "signature itself verified was not recorded here."),
                    from_domain=from_domain, dkim_domain=matching[0],
                    dkim_result=auth.dkim if auth else None)
        else:
            verified = " and the receiving server confirmed it verified" if (
                dkim_checked and auth.dkim == "pass") else ""
            add("dkim_unaligned", "high",
                "The message is signed by a domain that is not the sender it "
                "claims to be",
                f"The From address claims {from_domain}, but the DKIM signature "
                f"is for {dkim_domains[0]}{verified}. A valid signature proves "
                f"someone signed this message — it does not make them "
                f"{from_domain}. This mismatch is the ordinary shape of a "
                f"spoofed sender.",
                from_domain=from_domain, dkim_domain=dkim_domains[0],
                dkim_result=auth.dkim if auth else None)

    envelope = parsed.return_path or (auth.smtp_mailfrom if auth else None)
    envelope_domain = None
    if envelope:
        envelope_domain = envelope.rsplit("@", 1)[-1].strip("<> ").lower() or None
    if from_domain and envelope_domain:
        if _aligned(envelope_domain, from_domain):
            add("spf_aligned", "info",
                "The envelope sender matches the From domain",
                f"Bounces for this message go to {envelope_domain}, the same "
                f"organisation the From address claims.",
                from_domain=from_domain, envelope_domain=envelope_domain)
        else:
            add("spf_unaligned", "medium",
                "The envelope sender is a different domain from the visible "
                "sender",
                f"The message displays as coming from {from_domain}, but bounces "
                f"go to {envelope_domain}. An SPF pass covers "
                f"{envelope_domain} — it says nothing about {from_domain}. "
                f"Legitimate bulk mail does this too, so read it alongside DKIM "
                f"alignment rather than on its own.",
                from_domain=from_domain, envelope_domain=envelope_domain)

    if auth and auth.dmarc and auth.dmarc not in {"pass", "none", "bestguesspass"}:
        add("dmarc_fail", "high",
            "DMARC failed at the receiving server",
            f"The receiving server recorded dmarc={auth.dmarc} for "
            f"{auth.header_from or from_domain}. DMARC is the check that ties "
            f"SPF and DKIM back to the visible From domain, so a failure here "
            f"means neither one vouched for the sender the reader sees.",
            dmarc=auth.dmarc, from_domain=from_domain)

    if auth and auth.compauth and auth.compauth != "pass":
        add("compauth_fail", "medium",
            "Microsoft composite authentication failed",
            f"compauth={auth.compauth}. Microsoft applies this when a message "
            f"fails its combined sender checks, and it commonly accompanies "
            f"outright impersonation.",
            compauth=auth.compauth)

    # --- the chain ---
    if parsed.origin_ip:
        add("origin_established", "info",
            f"The message reached us from {parsed.origin_ip}",
            parsed.origin_note,
            origin_ip=parsed.origin_ip, basis=parsed.boundary_basis)
    else:
        add("origin_unproven", "info",
            "No origin address could be established from this block",
            parsed.origin_note or
            "The Received chain does not support naming where the message came "
            "from. That is a limit of the evidence, not a finding about the "
            "sender.",
            basis=parsed.boundary_basis)

    untrusted = [h for h in parsed.hops if h.trust is Trust.UNTRUSTED]
    if parsed.origin_ip and untrusted:
        claimed_hosts = [h.from_host or h.by for h in untrusted if (h.from_host or h.by)]
        claimed_orgs = {org_domain(h) for h in claimed_hosts}
        claimed_orgs.discard(None)
        handoff_org = org_domain(
            next((h.rdns or h.helo or h.from_host for h in parsed.hops
                  if h.trust is Trust.TRUSTED and (h.rdns or h.helo or h.from_host)
                  and h.from_ip == parsed.origin_ip), None)
        )
        alien = {o for o in claimed_orgs if o != handoff_org}
        if alien and from_domain and org_domain(from_domain) in alien:
            named = sorted(alien)[:4]
            add("chain_claims_another_origin", "high",
                "The chain claims an origin our own servers did not see",
                f"Hops below the trust boundary say the message started at "
                f"{', '.join(named)}, but the last server inside the boundary "
                f"received it from {parsed.origin_ip}"
                + (f" ({handoff_org})" if handoff_org else "")
                + ". Those lower hops were supplied by the sender and can be "
                  "written to say anything. Treat the claimed hosts as part of "
                  "the message, not as victims or as the source.",
                claimed=named, origin_ip=parsed.origin_ip,
                handoff_org=handoff_org)
        elif alien:
            add("chain_below_boundary", "low",
                f"{len(untrusted)} hop(s) below the trust boundary cannot be "
                f"verified",
                f"They name {', '.join(sorted(alien)[:4])}. Everything below the "
                f"boundary was written by the sender's own infrastructure, so it "
                f"is a claim rather than a record.",
                claimed=sorted(alien)[:4], hops=len(untrusted))

    if (parsed.x_originating_ip and parsed.origin_ip
            and parsed.x_originating_ip != parsed.origin_ip):
        add("originating_ip_disagrees", "low",
            "X-Originating-IP does not match the address we actually saw",
            f"The header claims {parsed.x_originating_ip}; the last server "
            f"inside the boundary recorded {parsed.origin_ip}. X-Originating-IP "
            f"is vendor-specific and sender-supplied, so where they disagree the "
            f"chain wins.",
            claimed=parsed.x_originating_ip, observed=parsed.origin_ip)

    # --- the visible bits a human reads ---
    if parsed.reply_to and from_domain:
        reply_domain = parsed.reply_to.rsplit("@", 1)[-1].lower()
        if not _aligned(reply_domain, from_domain):
            add("reply_to_mismatch", "medium",
                "Replies would go to a different domain than the sender",
                f"The message displays as {from_domain} but a reply is "
                f"addressed to {reply_domain}. That redirection is how a "
                f"conversation gets moved somewhere the real sender cannot see "
                f"it.",
                from_domain=from_domain, reply_to=parsed.reply_to,
                reply_domain=reply_domain)

    name = (parsed.display_name or "").strip()
    if name and from_domain:
        lowered = name.lower()
        impostor = None
        if "@" in lowered:
            candidate = lowered.rsplit("@", 1)[-1].strip("<>\"' ")
            if candidate and not _aligned(candidate, from_domain):
                impostor = candidate
        if impostor:
            add("display_name_spoof", "medium",
                "The display name contains an address that is not the sender",
                f"The name shown to the reader is {name!r}, which reads as an "
                f"address at {impostor}, but the message is actually from "
                f"{parsed.from_addr}. Most mail clients show the name and hide "
                f"the address.",
                display_name=name[:200], claimed_domain=impostor,
                actual=parsed.from_addr)

    if parsed.message_id_domain and from_domain:
        if not _aligned(parsed.message_id_domain, from_domain):
            add("message_id_mismatch", "low",
                "The Message-ID was generated on a different domain",
                f"Message-ID is stamped by {parsed.message_id_domain} while the "
                f"From address claims {from_domain}. Senders that relay through "
                f"a provider do this legitimately, but it is often the sending "
                f"host naming itself.",
                message_id_domain=parsed.message_id_domain,
                from_domain=from_domain)

    if parsed.date and parsed.hops:
        received_at = next((h.when for h in parsed.hops if h.when), None)
        if received_at and parsed.date.tzinfo and received_at.tzinfo:
            skew = abs((received_at - parsed.date).total_seconds())
            if skew > 86_400:
                add("date_skew", "low",
                    "The Date header is far from when the message was received",
                    f"Date says {parsed.date.isoformat()}; the top of the chain "
                    f"recorded {received_at.isoformat()}, about "
                    f"{skew / 3600:.0f} hours apart. Date is sender-supplied.",
                    date=parsed.date.isoformat(),
                    received=received_at.isoformat())

    for note in parsed.notes:
        add("parse_note", "low", "Something about this block is unusual", note,
            note=note)

    out.sort(key=lambda f: SEVERITY_ORDER.index(f.severity)
             if f.severity in SEVERITY_ORDER else len(SEVERITY_ORDER))
    return out
