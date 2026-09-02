"""Generate and resolve lookalike / typosquat domains — no external API."""

from __future__ import annotations

import itertools

import dns.exception
import dns.resolver

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.dns import get_resolver
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

# adjacent keyboard typos (qwerty)
_ADJ = {
    "a": "sqwz",
    "b": "vghn",
    "c": "xdfv",
    "d": "sfcxe",
    "e": "wrsdf",
    "f": "dgcrt",
    "g": "fhvty",
    "h": "gjbyu",
    "i": "ujko",
    "j": "hkniu",
    "k": "jlmi",
    "l": "kop",
    "m": "njk",
    "n": "bhjm",
    "o": "iklp",
    "p": "ol",
    "q": "wa",
    "r": "edft",
    "s": "awedxz",
    "t": "rfgy",
    "u": "yhji",
    "v": "cfgb",
    "w": "qase",
    "x": "zsdc",
    "y": "tghu",
    "z": "asx",
    "0": "9",
    "1": "2",
    "2": "13",
    "3": "24",
    "4": "35",
    "5": "46",
    "6": "57",
    "7": "68",
    "8": "79",
    "9": "80",
}

_HOMO = {
    "a": ["à", "á", "â", "ä", "@"],
    "e": ["è", "é", "ê", "ë"],
    "i": ["ì", "í", "î", "ï", "l", "1"],
    "o": ["ò", "ó", "ô", "ö", "0"],
    "u": ["ù", "ú", "û", "ü"],
    "c": ["ç"],
    "n": ["ñ"],
    "s": ["$", "5"],
    "l": ["1", "i"],
    "0": ["o"],
    "1": ["l", "i"],
}

_TLDS = ("com", "net", "org", "io", "co", "info", "biz", "xyz", "online", "app", "dev", "us")


def generate_lookalikes(domain: str, limit: int = 80) -> list[tuple[str, str]]:
    """Return list of (variant, technique). ASCII-focused + simple homoglyphs."""
    domain = domain.lower().strip(".")
    if "." not in domain:
        return []
    name, _, tld = domain.rpartition(".")
    if not name:
        return []

    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(v: str, tech: str) -> None:
        v = v.strip(".-").lower()
        if not v or v == domain or v in seen:
            return
        if ".." in v or v.startswith(".") or v.endswith("."):
            return
        seen.add(v)
        out.append((v, tech))

    # High-signal first (so low limits still cover TLD swaps etc.)
    for alt in _TLDS:
        if alt != tld:
            add(name + "." + alt, "tld_swap")

    add(name.replace("-", "") + "." + tld, "strip_hyphen")
    if "-" not in name and len(name) > 4:
        mid = len(name) // 2
        add(name[:mid] + "-" + name[mid:] + "." + tld, "insert_hyphen")

    for i in range(len(name) - 1):
        chars = list(name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        add("".join(chars) + "." + tld, "transpose")

    for i in range(len(name)):
        add(name[:i] + name[i + 1 :] + "." + tld, "omit_char")

    add("www-" + name + "." + tld, "www_prefix")
    add(name + "-login." + tld, "login_suffix")
    add(name + "-secure." + tld, "secure_suffix")
    add("secure-" + name + "." + tld, "secure_prefix")
    add(name + "s." + tld, "plural")
    if name.endswith("s") and len(name) > 3:
        add(name[:-1] + "." + tld, "singular")

    for i, ch in enumerate(name):
        add(name[:i] + ch + name[i:] + "." + tld, "double_char")
        if i < len(name) - 1 and name[i] == name[i + 1]:
            add(name[:i] + name[i + 1 :] + "." + tld, "drop_double")

    # Cap noisy classes
    qwerty_n = 0
    for i, ch in enumerate(name):
        for rep in _ADJ.get(ch, ""):
            if qwerty_n >= 40:
                break
            add(name[:i] + rep + name[i + 1 :] + "." + tld, "qwerty_sub")
            qwerty_n += 1

    for i, ch in enumerate(name):
        for rep in _HOMO.get(ch, []):
            if rep.isascii() and rep.isalnum():
                add(name[:i] + rep + name[i + 1 :] + "." + tld, "homoglyph_ascii")

    return out[:limit]


class LookalikeDomainCollector(BaseCollector):
    name = "lookalike_domains"
    timeout_s = 45
    inputs = {EntityType.DOMAIN}
    description = "Generate typosquat/lookalike domains and check DNS resolution (no API)"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        domain = entity.value.lower()
        src = entity.norm_key
        # Prefer seeds; skip deep subdomains
        if not entity.is_seed and domain.count(".") > 1:
            result.notes.append("lookalike: skipped non-seed subdomain")
            return result
        if domain.count(".") > 2:
            result.notes.append("lookalike: skipped deep subdomain")
            return result

        max_check = int((entity.props or {}).get("lookalike_limit") or 60)
        variants = generate_lookalikes(domain, limit=max_check)
        # Ordinary A-record resolution of typosquat candidates → the general
        # resolver (configured primary + public failover is fine here).
        resolver = get_resolver(allow_public_failover=True)
        resolver.lifetime = 3.0
        resolver.timeout = 2.0

        resolved: list[dict] = []
        checked = 0
        for var, tech in variants:
            checked += 1
            ips: list[str] = []
            try:
                ans = resolver.resolve(var, "A")
                ips = sorted({rr.to_text() for rr in ans})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
            except dns.exception.DNSException:
                continue
            if not ips:
                continue

            result.entities.append(
                EntityIn(
                    type=EntityType.DOMAIN,
                    value=var,
                    confidence=0.7,
                    props={"lookalike_of": domain, "technique": tech, "resolved_ips": ips},
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=entity_key(EntityType.DOMAIN, var),
                    target_key=src,
                    rel=EdgeType.LOOKALIKE_OF,
                    confidence=0.75,
                    props={"technique": tech},
                )
            )
            for ip in ips[:4]:
                result.entities.append(EntityIn(type=EntityType.IP, value=ip, confidence=0.7))
                result.edges.append(
                    EdgeIn(
                        source_key=entity_key(EntityType.DOMAIN, var),
                        target_key=entity_key(EntityType.IP, ip),
                        rel=EdgeType.RESOLVES_TO,
                        confidence=0.75,
                    )
                )
            resolved.append({"domain": var, "technique": tech, "ips": ips})

        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="lookalike_dns",
                summary=(
                    f"Lookalikes for {domain}: checked={checked} resolved={len(resolved)} "
                    f"(potential typosquats)"
                ),
                confidence=0.8,
                raw={"checked": checked, "resolved": resolved, "sample_variants": variants[:20]},
                entity_key=src,
            )
        )
        return result
