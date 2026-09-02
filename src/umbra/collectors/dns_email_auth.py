"""DNS-based email authentication, security posture & provider inference.

No third-party API — everything is derived from DNS (plus a best-effort HTTPS
fetch of the MTA-STS policy). Covers the full modern email-security surface:

- **SPF** — record, qualifier (`-all`/`~all`/`?all`/`+all`), include/ip pivots,
  and a shallow DNS-lookup count vs the RFC 7208 limit of 10.
- **DMARC** — every tag (p, sp, pct, adkim, aspf, fo, rua, ruf); reporting
  addresses become graph pivots and reveal third-party DMARC processors.
- **DKIM** — probes common selectors (no external key intel).
- **MX** + mail-provider inference.
- **MTA-STS** (`_mta-sts` TXT + policy `mode:`), **TLS-RPT** (`_smtp._tls`),
  **BIMI** (`default._bimi`: logo + VMC), **DNSSEC** (DNSKEY presence).
- A **spoofability grade** — the actionable "so what": is this domain
  impersonatable?

Parsing lives in pure functions (`parse_spf`, `parse_dmarc`, `parse_bimi`,
`assess_email_posture`) that are unit-testable without network.
"""
from __future__ import annotations

import re
from typing import Any

import dns.exception
import dns.resolver

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.dns import get_resolver
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

# Common DKIM selectors to probe (no external intel service)
_DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2",
    "dkim", "mail", "smtp", "cm", "mandrill", "everlytickey1", "everlytickey2",
    "mxvault", "sig1", "ctct1", "ctct2", "litesrv", "pm", "protonmail",
    "fastmail", "fm1", "fm2", "fm3", "zendesk1", "zendesk2", "s1024", "s2048",
)

_PROVIDER_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"google\.com|googlemail|aspmx", re.I), "google_workspace"),
    (re.compile(r"outlook\.com|protection\.outlook|microsoft", re.I), "microsoft_365"),
    (re.compile(r"pphosted\.com|proofpoint", re.I), "proofpoint"),
    (re.compile(r"mimecast", re.I), "mimecast"),
    (re.compile(r"mailgun|mxa\.mailgun|mxb\.mailgun", re.I), "mailgun"),
    (re.compile(r"sendgrid\.net", re.I), "sendgrid"),
    (re.compile(r"amazonses\.com|aws", re.I), "amazon_ses"),
    (re.compile(r"zoho", re.I), "zoho"),
    (re.compile(r"protonmail|proton\.me", re.I), "proton"),
    (re.compile(r"fastmail", re.I), "fastmail"),
    (re.compile(r"cloudflare\.net|email\.cloudflare", re.I), "cloudflare_email"),
    (re.compile(r"secureserver\.net|godaddy", re.I), "godaddy"),
    (re.compile(r"emailsrvr\.com|rackspace", re.I), "rackspace"),
    (re.compile(r"messagingengine\.com", re.I), "fastmail"),
    (re.compile(r"yandex", re.I), "yandex"),
    (re.compile(r"icloud|apple\.com", re.I), "apple_icloud"),
]

# Third-party DMARC aggregate/forensic report processors, inferred from the
# domain of a rua/ruf address — a useful "who runs their DMARC" signal.
_DMARC_PROCESSOR_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"dmarcian", re.I), "dmarcian"),
    (re.compile(r"agari", re.I), "agari"),
    (re.compile(r"valimail|vali\.email", re.I), "valimail"),
    (re.compile(r"proofpoint|dmarc-report", re.I), "proofpoint"),
    (re.compile(r"redsift|ondmarc", re.I), "redsift_ondmarc"),
    (re.compile(r"easydmarc", re.I), "easydmarc"),
    (re.compile(r"powerdmarc", re.I), "powerdmarc"),
    (re.compile(r"sendmarc", re.I), "sendmarc"),
    (re.compile(r"uriports", re.I), "uriports"),
    (re.compile(r"mailhardener", re.I), "mailhardener"),
    (re.compile(r"fraudmarc", re.I), "fraudmarc"),
    (re.compile(r"postmarkapp", re.I), "postmark"),
    (re.compile(r"mxtoolbox", re.I), "mxtoolbox"),
    (re.compile(r"250ok|validity", re.I), "validity_250ok"),
]

_SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4


# --- pure parsers (unit-tested without network) ---------------------------

def parse_spf(record: str) -> dict[str, Any]:
    """Parse an SPF record into its qualifier, pivots, and DNS-lookup count.

    The lookup count is *shallow* (mechanisms in this record only — it does not
    recurse into includes), so `exceeds_lookup_limit` is a lower-bound signal.
    """
    tokens = record.strip().split()
    all_qual: str | None = None
    includes: list[str] = []
    ip4s: list[str] = []
    ip6s: list[str] = []
    redirect: str | None = None
    lookups = 0
    for tok in tokens:
        low = tok.lower()
        if low in ("v=spf1", ""):
            continue
        qual = "+"
        t = tok
        if t[0] in "+-~?":
            qual, t = t[0], t[1:]
        lt = t.lower()
        if lt == "all":
            all_qual = qual
        elif lt.startswith("include:"):
            includes.append(t.split(":", 1)[1]); lookups += 1
        elif lt.startswith("redirect="):
            redirect = t.split("=", 1)[1]; lookups += 1
        elif lt.startswith("ip4:"):
            ip4s.append(t.split(":", 1)[1])
        elif lt.startswith("ip6:"):
            ip6s.append(t.split(":", 1)[1])
        elif lt == "a" or lt.startswith(("a:", "a/")):
            lookups += 1
        elif lt == "mx" or lt.startswith(("mx:", "mx/")):
            lookups += 1
        elif lt == "ptr" or lt.startswith("ptr:"):
            lookups += 1
        elif lt.startswith("exists:"):
            lookups += 1
    return {
        "all": all_qual,
        "includes": includes,
        "ip4": ip4s,
        "ip6": ip6s,
        "redirect": redirect,
        "dns_lookups": lookups,
        "exceeds_lookup_limit": lookups > _SPF_LOOKUP_LIMIT,
    }


def _report_addresses(uri_list: str) -> list[str]:
    """Extract email addresses from a DMARC rua/ruf value (mailto: URIs)."""
    out: list[str] = []
    for part in (uri_list or "").split(","):
        p = part.strip()
        if p.lower().startswith("mailto:"):
            p = p[len("mailto:"):]
        p = p.split("!", 1)[0].strip()  # drop the optional !size limit
        if "@" in p:
            out.append(p.lower())
    return out


def parse_dmarc(record: str) -> dict[str, Any]:
    """Parse a DMARC record into all tags, with rua/ruf resolved to addresses."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {
        "policy": (tags.get("p") or "").lower() or None,
        "subdomain_policy": (tags.get("sp") or "").lower() or None,
        "pct": tags.get("pct"),
        "adkim": tags.get("adkim"),
        "aspf": tags.get("aspf"),
        "fo": tags.get("fo"),
        "rua": _report_addresses(tags.get("rua", "")),
        "ruf": _report_addresses(tags.get("ruf", "")),
        "tags": tags,
    }


def parse_bimi(record: str) -> dict[str, Any]:
    """Parse a BIMI record: logo (l=) and VMC certificate (a=) URLs."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {"logo_url": tags.get("l") or None, "vmc_url": tags.get("a") or None}


def assess_email_posture(
    spf: dict | None,
    dmarc: dict | None,
    dkim_present: bool,
    mta_sts_mode: str | None,
    dnssec: bool,
) -> dict[str, Any]:
    """Grade impersonation resistance from the parsed records.

    `spoofable` is the headline: a domain whose DMARC policy is not
    quarantine/reject does not instruct receivers to reject forged mail.
    """
    reasons: list[str] = []
    dmarc_p = (dmarc or {}).get("policy")
    spf_all = (spf or {}).get("all")

    spoofable = dmarc_p not in ("quarantine", "reject")

    if not spf:
        reasons.append("no SPF record")
    else:
        if spf_all == "+":
            reasons.append("SPF +all accepts ALL senders (dangerous)")
        elif spf_all not in ("-", "~"):
            reasons.append(f"SPF lacks a restrictive all (all={spf_all})")
        if spf.get("exceeds_lookup_limit"):
            reasons.append("SPF exceeds 10 DNS lookups (permerror risk)")

    if not dmarc:
        reasons.append("no DMARC record — domain is spoofable")
    elif dmarc_p == "none":
        reasons.append("DMARC p=none (monitoring only, not enforced)")
    elif dmarc_p == "quarantine":
        reasons.append("DMARC p=quarantine")
    elif dmarc_p == "reject":
        reasons.append("DMARC p=reject (strongest)")
    if dmarc and dmarc.get("subdomain_policy") in ("none", None) and dmarc_p in ("quarantine", "reject"):
        reasons.append("DMARC sp not set to quarantine/reject (subdomains weaker)")

    if not dkim_present:
        reasons.append("no common DKIM selector found (may use a custom one)")
    if mta_sts_mode:
        reasons.append(f"MTA-STS mode={mta_sts_mode}")
    if dnssec:
        reasons.append("DNSSEC enabled")

    if dmarc_p == "reject" and spf_all in ("-", "~") and dkim_present:
        grade = "strong"
    elif dmarc_p in ("reject", "quarantine"):
        grade = "moderate"
    elif dmarc_p == "none" or spf:
        grade = "weak"
    else:
        grade = "none"

    return {"grade": grade, "spoofable": spoofable, "reasons": reasons}


# --- collector ------------------------------------------------------------

class DnsEmailAuthCollector(BaseCollector):
    name = "dns_email_auth"
    timeout_s = 25
    inputs = {EntityType.DOMAIN}
    description = ("SPF/DMARC/DKIM/MX + MTA-STS/TLS-RPT/BIMI/DNSSEC, spoofability "
                  "grade & report-address pivots (no external API)")

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        domain = entity.value.strip(".").lower()
        src = entity.norm_key
        resolver = get_resolver()
        resolver.lifetime = min(8.0, ctx.settings.request_timeout_s)

        def txt(name: str) -> list[str]:
            try:
                ans = resolver.resolve(name, "TXT")
                out: list[str] = []
                for rr in ans:
                    if hasattr(rr, "strings"):
                        out.append(b"".join(rr.strings).decode("utf-8", "replace"))
                    else:
                        out.append(rr.to_text().strip('"'))
                return out
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                return []
            except dns.exception.DNSException:
                return []

        def mx(name: str) -> list[str]:
            try:
                ans = resolver.resolve(name, "MX")
                return sorted({rr.exchange.to_text().rstrip(".") for rr in ans})
            except Exception:  # noqa: BLE001
                return []

        def has_record(name: str, rtype: str) -> bool:
            try:
                return len(resolver.resolve(name, rtype)) > 0
            except Exception:  # noqa: BLE001
                return False

        # --- gather raw records ---
        spf_recs = [t for t in txt(domain) if t.lower().startswith("v=spf1")]
        dmarc_raw = [t for t in txt(f"_dmarc.{domain}") if "V=DMARC1" in t.upper()]
        mx_hosts = mx(domain)
        tlsrpt = [t for t in txt(f"_smtp._tls.{domain}") if "V=TLSRPTV1" in t.upper()]
        bimi_recs = [t for t in txt(f"default._bimi.{domain}") if "V=BIMI1" in t.upper()]
        dnssec = has_record(domain, "DNSKEY")

        dkim_found: dict[str, str] = {}
        for sel in _DKIM_SELECTORS:
            for t in txt(f"{sel}._domainkey.{domain}"):
                if "v=DKIM1" in t.upper() or "p=" in t.lower():
                    dkim_found[sel] = t[:300]
                    break

        # --- parse ---
        spf = parse_spf(spf_recs[0]) if spf_recs else None
        dmarc = parse_dmarc(dmarc_raw[0]) if dmarc_raw else None
        bimi = parse_bimi(bimi_recs[0]) if bimi_recs else None

        # MTA-STS: TXT record + best-effort policy fetch for the enforcement mode
        mta_sts_id: str | None = None
        mta_sts_mode: str | None = None
        mta_txt = [t for t in txt(f"_mta-sts.{domain}") if "V=STSV1" in t.upper()]
        if mta_txt:
            m = re.search(r"id=([^;\s]+)", mta_txt[0])
            mta_sts_id = m.group(1) if m else None
            try:
                r = ctx.http.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                                 timeout=6.0)
                if r.status_code == 200:
                    mm = re.search(r"mode:\s*(\w+)", r.text, re.I)
                    mta_sts_mode = mm.group(1).lower() if mm else None
            except Exception:  # noqa: BLE001
                pass

        # --- provider inference ---
        providers: list[str] = []
        blob = " ".join(spf_recs + mx_hosts + list(dkim_found.values()))
        for pat, label in _PROVIDER_HINTS:
            if pat.search(blob) and label not in providers:
                providers.append(label)

        # --- SPF pivots (ip4 + includes) ---
        if spf:
            for ip4 in spf["ip4"]:
                if "/" not in ip4:
                    result.entities.append(EntityIn(type=EntityType.IP, value=ip4, confidence=0.6))
                    result.edges.append(EdgeIn(source_key=src,
                        target_key=entity_key(EntityType.IP, ip4),
                        rel=EdgeType.ASSOCIATED_WITH, confidence=0.55, props={"via": "spf"}))
            for inc in spf["includes"][:20]:
                host = inc.strip().rstrip(".")
                if host and "." in host and ":" not in host and " " not in host:
                    try:
                        result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host,
                            confidence=0.5, props={"role": "spf_include"}))
                        result.edges.append(EdgeIn(source_key=src,
                            target_key=entity_key(EntityType.DOMAIN, host),
                            rel=EdgeType.ASSOCIATED_WITH, confidence=0.5, props={"via": "spf_include"}))
                    except ValueError:
                        continue

        # --- MX pivots ---
        for host in mx_hosts:
            host = (host or "").strip().rstrip(".")
            if not host or host == ".":
                continue
            try:
                result.entities.append(EntityIn(type=EntityType.DOMAIN, value=host,
                    confidence=0.85, props={"role": "mx"}))
                result.edges.append(EdgeIn(source_key=src,
                    target_key=entity_key(EntityType.DOMAIN, host),
                    rel=EdgeType.HAS_MX, confidence=0.85))
            except ValueError:
                continue

        # --- DMARC report-address pivots + processor inference ---
        dmarc_processors: list[str] = []
        if dmarc:
            for addr in dict.fromkeys(dmarc["rua"] + dmarc["ruf"]):
                rep_domain = addr.split("@", 1)[1] if "@" in addr else ""
                try:
                    result.entities.append(EntityIn(type=EntityType.EMAIL, value=addr,
                        confidence=0.7, props={"role": "dmarc_report"}))
                    result.edges.append(EdgeIn(source_key=src,
                        target_key=entity_key(EntityType.EMAIL, addr),
                        rel=EdgeType.ASSOCIATED_WITH, confidence=0.7, props={"via": "dmarc_rua_ruf"}))
                except ValueError:
                    pass
                if rep_domain and rep_domain != domain:
                    try:
                        result.entities.append(EntityIn(type=EntityType.DOMAIN, value=rep_domain,
                            confidence=0.5, props={"role": "dmarc_report_domain"}))
                    except ValueError:
                        pass
                for pat, label in _DMARC_PROCESSOR_HINTS:
                    if pat.search(rep_domain) and label not in dmarc_processors:
                        dmarc_processors.append(label)

        # --- technology entities (mail providers + DMARC processors) ---
        for prov in providers:
            result.entities.append(EntityIn(type=EntityType.TECHNOLOGY, value=f"mail:{prov}", confidence=0.7))
            result.edges.append(EdgeIn(source_key=src,
                target_key=entity_key(EntityType.TECHNOLOGY, f"mail:{prov}"),
                rel=EdgeType.USES_TECH, confidence=0.7))
        for proc in dmarc_processors:
            result.entities.append(EntityIn(type=EntityType.TECHNOLOGY, value=f"dmarc:{proc}", confidence=0.75))
            result.edges.append(EdgeIn(source_key=src,
                target_key=entity_key(EntityType.TECHNOLOGY, f"dmarc:{proc}"),
                rel=EdgeType.USES_TECH, confidence=0.75))

        # --- posture / spoofability ---
        posture = assess_email_posture(spf, dmarc, bool(dkim_found), mta_sts_mode, dnssec)

        result.entities.append(EntityIn(
            type=EntityType.DOMAIN, value=domain, confidence=0.95,
            props={
                # backward-compatible keys
                "spf": spf_recs[:5],
                "dmarc": dmarc_raw[:3],
                "dkim_selectors": list(dkim_found.keys()),
                "mail_providers": providers,
                # structured detail
                "spf_parsed": spf,
                "dmarc_parsed": {k: v for k, v in (dmarc or {}).items() if k != "tags"} or None,
                "dmarc_policy": (dmarc or {}).get("policy"),
                "dmarc_processors": dmarc_processors,
                "mx": mx_hosts,
                "mta_sts": {"id": mta_sts_id, "mode": mta_sts_mode} if mta_txt else None,
                "tls_rpt": bool(tlsrpt),
                "bimi": bimi,
                "dnssec": dnssec,
                "email_posture_grade": posture["grade"],
                "spoofable": posture["spoofable"],
                "email_posture_reasons": posture["reasons"],
            },
        ))
        result.evidence.append(EvidenceIn(
            collector=self.name, source_name="DNS",
            summary=(
                f"Email posture {domain}: grade={posture['grade']} "
                f"spoofable={posture['spoofable']} | SPF={bool(spf)}"
                f"({(spf or {}).get('all')}) DMARC={(dmarc or {}).get('policy') or 'none'} "
                f"DKIM={list(dkim_found.keys()) or 'none'} MTA-STS={mta_sts_mode or 'no'} "
                f"BIMI={bool(bimi)} DNSSEC={dnssec}"
            ),
            confidence=0.9,
            raw={"spf": spf_recs, "dmarc": dmarc_raw, "dkim": dkim_found, "mx": mx_hosts,
                 "mta_sts": mta_txt, "tls_rpt": tlsrpt, "bimi": bimi_recs,
                 "providers": providers, "posture": posture},
            entity_key=src,
        ))
        return result
