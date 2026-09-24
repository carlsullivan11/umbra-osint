"""Deterministic extractors for intent text (no LLM)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from umbra.core.mac import find_macs
from umbra.core.models import EntityType
from umbra.core.normalize import is_email, normalize_value
from umbra.intent.schema import IntentFlags, IntentSeed

# --- patterns ---

_EMAIL_RE = re.compile(
    r"(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b"
)
_URL_RE = re.compile(
    r"(?i)\b((?:https?://)?(?:www\.)?[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+(?:/[^\s]*)?)"
)
_IPV4_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b"
)
_GH_URL_RE = re.compile(r"(?i)github\.com/([A-Za-z0-9](?:[A-Za-z0-9\-]{0,38}[A-Za-z0-9])?)")
_GH_SHORTHAND_RE = re.compile(
    r"(?i)\b(?:gh|github)\s*[:@\s]+([A-Za-z0-9](?:[A-Za-z0-9\-]{0,38}[A-Za-z0-9])?)\b"
)
_LI_URL_RE = re.compile(r"(?i)linkedin\.com/in/([A-Za-z0-9\-_%]+)")
_X_URL_RE = re.compile(r"(?i)(?:twitter|x)\.com/([A-Za-z0-9_]{1,15})")
_IG_URL_RE = re.compile(r"(?i)instagram\.com/([A-Za-z0-9_.]+)")
_REDDIT_URL_RE = re.compile(r"(?i)reddit\.com/u(?:ser)?/([A-Za-z0-9_\-]+)")
_HANDLE_AT_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])@([A-Za-z0-9_]{2,30})\b")
_PLATFORM_HANDLE_RE = re.compile(
    r"(?i)\b(github|gh|twitter|x|instagram|ig|reddit|linkedin|li|tiktok|youtube|yt)"
    r"\s*[:@]\s*@?([A-Za-z0-9._\-]{2,40})\b"
)
_REPO_RE = re.compile(r"(?i)\b([A-Za-z0-9\-]+/[A-Za-z0-9_.\-]+)\b")

# Words that look like domains but aren't
_DOMAIN_BLOCK = {
    "example.com",  # allow — useful in tests; don't block
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazonaws.com",
    "cloudflare.com",
    "github.com",
    "githubusercontent.com",
    "linkedin.com",
    "twitter.com",
    "instagram.com",
    "facebook.com",
    "reddit.com",
}

_TLD_OK = {
    "com", "org", "net", "io", "co", "us", "uk", "dev", "app", "ai", "info",
    "biz", "me", "tv", "cc", "xyz", "online", "site", "tech", "cloud", "gov",
    "edu", "mil", "ca", "de", "fr", "au", "nl", "eu",
}

# Flag keywords
_LOOKALIKE_KW = re.compile(
    r"(?i)\b(lookalike|typosquat|typo-?squat|brand.?abuse|phishing.?domain|"
    r"similar.?domain|domain.?watch|squatt)\w*\b"
)
_BREACH_KW = re.compile(
    r"(?i)\b(breach|breached|pwned|have.?i.?been|hibp|leaked?|leak|"
    r"compromised|credential|stuffed|infostealer|stealer)\w*\b"
)
_CORP_KW = re.compile(
    r"(?i)\b(edgar|sec\.gov|corporation|llc|inc\b|company.?record|"
    r"opencorporate|wikidata|filing|trademark)\w*\b"
)
_USERNAME_PROBE_KW = re.compile(
    r"(?i)\b(username.?probe|sherlock|everywhere|all.?platforms|"
    r"social.?presence|handle.?check)\b"
)
_WEB_KW = re.compile(r"(?i)\b(google|search.?web|web.?search|ddg|duckduckgo)\b")
_WAYBACK_KW = re.compile(r"(?i)\b(wayback|archive\.org|historical.?site|old.?website)\b")

# US aircraft registration ("tail number"). Bounded on both sides so it cannot
# fire inside a hostname, an email local part, or a longer hex run.
_N_NUMBER_RE = re.compile(
    r"(?<![A-Za-z0-9._@\-])([Nn]-?\d(?:-?[A-Za-z0-9]){0,4})(?![A-Za-z0-9._@\-])"
)

# Soft person: "Name Name" two capitalized tokens (conservative)
_PERSON_RE = re.compile(
    r"\b([A-Z][a-z]{1,20})\s+([A-Z][a-z]{1,20})(?:\s+([A-Z][a-z]{1,20}))?\b"
)
_PERSON_BLOCK = {
    "Certificate Transparency", "Team Cymru", "Have I", "Duck Duck",
    "United States", "New York", "Los Angeles", "San Francisco", "San Diego",
    "Internet Archive", "Open Corporates", "Cloud Flare",
}

# A corporate suffix is unambiguous wherever it appears — "Acme Inc" is a
# company in the middle of a sentence, with no "company" keyword needed.
_ORG_SUFFIX_RE = re.compile(
    r"\b((?:[A-Z][\w&.'\-]*\s+){0,3}[A-Z][\w&.'\-]*)\s+"
    r"(Inc\.?|LLC|Ltd\.?|Limited|GmbH|AG|PLC|S\.A\.|SA|N\.V\.|NV|"
    r"Corp\.?|Corporation|Co\.|Holdings|Group|SAS|Pty|B\.V\.|BV|Oy|AB)(?![\w])"
)

# Words that start sentences and are not companies.
_NOT_A_NAME = {
    "check", "find", "search", "look", "please", "help", "what", "who", "where",
    "why", "how", "the", "this", "that", "show", "tell", "give", "run", "scan",
    "investigate", "analyze", "analyse", "lookup", "test", "hello", "hi", "info",
    "information", "everything", "anything", "something", "all", "list", "me",
    "my", "about", "for", "of", "is", "it",
}
# Above this many words a query is a sentence, not a name someone typed.
_BARE_QUERY_MAX_WORDS = 3

#: Words that mark a bare query as an organisation rather than a person, so it
#: keeps running without an opt-in. Anything name-shaped and *without* one of
#: these is seeded as a person instead — see `_looks_like_a_person`.
_ORG_MARKER = {
    "inc", "inc.", "llc", "l.l.c.", "ltd", "ltd.", "limited", "corp", "corp.",
    "corporation", "co", "co.", "company", "plc", "gmbh", "ag", "sa", "nv",
    "bv", "pty", "llp", "lp", "holdings", "group", "partners", "ventures",
    "capital", "labs", "technologies", "technology", "systems", "solutions",
    "services", "industries", "foundation", "institute", "university",
    "college", "hospital", "bank", "insurance", "media", "studios", "games",
    "software", "security", "networks", "telecom", "energy", "motors", "&",
}


def _looks_like_a_person(words: list[str]) -> bool:
    """True when a bare query is name-shaped.

    The person consent gate used to be one keystroke wide. "Dustin Moore" hits
    the capitalized-name rule and is seeded PERSON at 0.6 — below the inclusion
    threshold, so N1's declaration is required. "dustin moore" misses that rule,
    falls to the bare-query fallback, and was seeded ORG at 0.55, which is
    exactly the include threshold. Organisations need no opt-in, so the same
    person ran immediately depending on the shift key.

    Two or three alphabetic words with no corporate marker is the shape of a
    name. One word is a brand — `Cloudflare` is the query the bare fallback was
    written for.

    **This errs toward the gate.** "united airlines" will be read as a person
    and asked for a basis. Being asked to declare before searching an airline is
    a smaller harm than searching a person without declaring, which is the error
    this project said it would not make.
    """
    if not 2 <= len(words) <= _BARE_QUERY_MAX_WORDS:
        return False
    if any(w.lower().strip(".,") in _ORG_MARKER for w in words):
        return False
    # Initials are ordinary in a name ("janice m miller") and rare in a brand.
    return all(w.replace("'", "").replace("-", "").replace(".", "").isalpha()
               for w in words)

_ORG_HINT_RE = re.compile(
    r"(?i)\b(?:company|org|organization|employer|corp(?:oration)?)\s*[:\-]?\s+"
    r"([A-Z][\w&.\'\-]+(?:\s+[A-Z][\w&.\'\-]+){0,4})"
)


@dataclass
class _Hit:
    type: EntityType
    value: str
    confidence: float
    span: str
    notes: str | None = None
    props: dict | None = None


def _safe_norm(t: EntityType, value: str) -> str | None:
    try:
        return normalize_value(t, value)
    except ValueError:
        return None


def extract_flags(text: str) -> IntentFlags:
    return IntentFlags(
        want_lookalikes=bool(_LOOKALIKE_KW.search(text)),
        want_breaches=bool(_BREACH_KW.search(text)),
        want_corp_records=bool(_CORP_KW.search(text)),
        aggressive_username_probe=bool(_USERNAME_PROBE_KW.search(text)),
        want_web_search=bool(_WEB_KW.search(text)),
        want_wayback=bool(_WAYBACK_KW.search(text)),
    )


def _is_plausible_domain(d: str) -> bool:
    d = d.lower().rstrip(".")
    if d in _DOMAIN_BLOCK and d not in {"example.com", "example.org", "example.net"}:
        # free-mail / mega-platforms as domains alone are weak seeds
        if d in {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}:
            return False
    parts = d.split(".")
    if len(parts) < 2:
        return False
    tld = parts[-1]
    if tld not in _TLD_OK and len(tld) < 2:
        return False
    if any(p.startswith("-") or p.endswith("-") or not p for p in parts):
        return False
    # skip version-like 1.2.3
    if all(p.isdigit() for p in parts):
        return False
    return True


def extract_hits(text: str) -> list[_Hit]:
    hits: list[_Hit] = []
    seen: set[tuple[str, str]] = set()

    def add(t: EntityType, value: str, conf: float, span: str, notes: str | None = None, **props: object) -> None:
        nv = _safe_norm(t, value)
        if not nv:
            return
        key = (t.value, nv)
        if key in seen:
            # keep higher confidence / better span
            for existing in hits:
                ev = existing.value
                if existing.type == t and ev == nv:
                    if conf > existing.confidence:
                        existing.confidence = conf
                        existing.span = span[:120]
                        if notes:
                            existing.notes = notes
                    return
            return
        seen.add(key)
        hits.append(
            _Hit(
                type=t,
                value=nv if t != EntityType.USERNAME else nv,
                confidence=conf,
                span=span[:120],
                notes=notes,
                props=dict(props) if props else None,
            )
        )
    # Emails first
    for m in _EMAIL_RE.finditer(text):
        em = m.group(1)
        if is_email(em):
            add(EntityType.EMAIL, em, 0.95, m.group(0))
            # domain from email as weaker seed
            dom = em.split("@", 1)[1].lower()
            if _is_plausible_domain(dom) and dom not in {
                "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                "icloud.com", "proton.me", "protonmail.com",
            }:
                add(EntityType.DOMAIN, dom, 0.75, dom, notes="from email")

    # IPs
    for m in _IPV4_RE.finditer(text):
        add(EntityType.IP, m.group(1), 0.9, m.group(0))

    # MAC addresses — separated forms only. A bare 12-hex run is the same shape
    # as a commit SHA or a build id, so matching it would turn ordinary notes
    # into MAC seeds.
    for mac in find_macs(text):
        add(EntityType.MAC, mac, 0.95, mac)

    # US aircraft registrations. N + a digit + up to four more alphanumerics,
    # hyphens optional. The lookarounds are the whole difficulty: without them
    # "n123ab.example.com" and "n123ab@example.com" both yield an aircraft, and
    # a 12-hex commit prefix yields one too. Requiring a *digit* after the N is
    # what keeps "NASA", "Nginx" and "November" out.
    for m in _N_NUMBER_RE.finditer(text):
        tail = _safe_norm(EntityType.AIRCRAFT, m.group(0))
        if tail:
            add(EntityType.AIRCRAFT, tail, 0.9, m.group(0))

    # Phone numbers (libphonenumber matcher). Before domain-ish tokens so a
    # bare NANP paste becomes PHONE, not a failed bare-org fallback.
    from umbra.phone.normalize import find_phones

    for e164 in find_phones(text):
        add(EntityType.PHONE, e164, 0.92, e164)

    # Companies with a legal suffix — unambiguous anywhere in the text.
    for m in _ORG_SUFFIX_RE.finditer(text):
        add(EntityType.ORG, f"{m.group(1)} {m.group(2)}".strip(), 0.8, m.group(0))

    # Platform URLs
    for m in _GH_URL_RE.finditer(text):
        handle = m.group(1)
        if handle.lower() not in {"settings", "orgs", "marketplace", "topics", "about", "login"}:
            add(EntityType.USERNAME, f"github:{handle}", 0.95, m.group(0))
    for m in _GH_SHORTHAND_RE.finditer(text):
        add(EntityType.USERNAME, f"github:{m.group(1)}", 0.9, m.group(0))
    for m in _LI_URL_RE.finditer(text):
        add(EntityType.USERNAME, f"linkedin:{m.group(1)}", 0.95, m.group(0))
    for m in _X_URL_RE.finditer(text):
        h = m.group(1)
        if h.lower() not in {"intent", "share", "home", "i", "search"}:
            add(EntityType.USERNAME, f"twitter:{h}", 0.9, m.group(0))
    for m in _IG_URL_RE.finditer(text):
        add(EntityType.USERNAME, f"instagram:{m.group(1)}", 0.9, m.group(0))
    for m in _REDDIT_URL_RE.finditer(text):
        add(EntityType.USERNAME, f"reddit:{m.group(1)}", 0.9, m.group(0))

    for m in _PLATFORM_HANDLE_RE.finditer(text):
        plat = m.group(1).lower()
        handle = m.group(2)
        plat_map = {
            "gh": "github",
            "ig": "instagram",
            "li": "linkedin",
            "x": "twitter",
            "yt": "youtube",
        }
        plat = plat_map.get(plat, plat)
        if plat == "twitter":
            plat = "twitter"
        add(EntityType.USERNAME, f"{plat}:{handle}", 0.88, m.group(0))

    # URLs / domains
    for m in _URL_RE.finditer(text):
        raw = m.group(1).rstrip(".,);]")
        # skip if it's an email false positive (already handled)
        if "@" in raw and not raw.startswith("http"):
            continue
        lower = raw.lower()
        # platform hosts already handled
        if any(
            x in lower
            for x in (
                "github.com/",
                "linkedin.com/",
                "twitter.com/",
                "x.com/",
                "instagram.com/",
                "reddit.com/",
            )
        ):
            continue
        if lower.startswith("http://") or lower.startswith("https://") or "/" in raw.split("://")[-1]:
            # full URL
            url_val = raw if "://" in raw else f"https://{raw}"
            add(EntityType.URL, url_val, 0.85, m.group(0))
            # also domain
            host = re.sub(r"(?i)^https?://", "", raw).split("/")[0].split(":")[0]
            if _is_plausible_domain(host):
                add(EntityType.DOMAIN, host, 0.9, host)
        else:
            if _is_plausible_domain(raw):
                add(EntityType.DOMAIN, raw, 0.92, m.group(0))

    # Bare @handles → unknown platform (lower conf)
    for m in _HANDLE_AT_RE.finditer(text):
        h = m.group(1)
        if "." in h:  # likely email already
            continue
        add(EntityType.USERNAME, f"unknown:{h}", 0.55, m.group(0), notes="bare @handle")

    # org hints
    for m in _ORG_HINT_RE.finditer(text):
        org = m.group(1).strip()
        if len(org) >= 2:
            add(EntityType.ORG, org, 0.7, m.group(0))

    # person names — conservative
    for m in _PERSON_RE.finditer(text):
        parts = [p for p in m.groups() if p]
        name = " ".join(parts)
        if name in _PERSON_BLOCK:
            continue
        # skip if looks like start of sentence with common words
        if parts[0].lower() in {
            "the", "this", "that", "with", "from", "check", "need", "also",
            "domain", "email", "please", "using", "about",
        }:
            continue
        add(EntityType.PERSON, name, 0.6, m.group(0), notes="capitalized name guess")

    # Explicit person: / name: prefix — high confidence (web + CLI match)
    for m in re.finditer(
        r"(?i)\b(?:person|name|decedent)\s*[:]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z'.\-]+){1,4})\b",
        text,
    ):
        add(EntityType.PERSON, m.group(1), 0.9, m.group(0), notes="explicit person: prefix")

    # Crypto addresses (unambiguous BTC/ETH/TRON forms). Same detector as
    # `umbra crypto screen` / `/crypto`.
    from umbra.crypto.normalize import detect_and_normalize

    for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9._\-:]{15,90}", text):
        n = detect_and_normalize(tok)
        if n:
            add(
                EntityType.CRYPTO_ADDRESS,
                f"{n.chain}:{n.address}",
                0.93,
                tok,
                notes=f"chain={n.chain}",
                chain=n.chain,
            )

    # Last resort: the whole query is a short name and nothing else matched.
    #
    # "Cloudflare" used to extract nothing at all — the one-box promise is that a
    # seed you paste does *something*. This fires only when the query IS the
    # name, so "Check this domain" cannot become a case about a company called
    # Check, and it seeds at low confidence with a note so the plan page shows it
    # as a chip to uncheck rather than as a finding.
    if not hits:
        words = [w for w in re.split(r"\s+", (text or "").strip()) if w]
        if 1 <= len(words) <= _BARE_QUERY_MAX_WORDS:
            plain = re.sub(r"[^A-Za-z0-9&.\'\- ]", "", " ".join(words)).strip()
            if (
                plain
                and any(c.isalpha() for c in plain)
                and all(w.lower() not in _NOT_A_NAME for w in plain.split())
            ):
                # Below the include threshold, typing "Cloudflare" produced a
                # plan with nothing selected — which is what it did before this
                # fallback existed.
                if _looks_like_a_person(plain.split()):
                    # 0.6 matches the capitalized-name rule, which is the point:
                    # the same query must meet the same gate however it was
                    # typed. Below the inclusion threshold, so the plan asks.
                    add(EntityType.PERSON, plain, 0.6, plain,
                        notes="name-shaped bare query — declare a basis to run")
                else:
                    # 0.55 is exactly the include threshold: the seed is
                    # runnable, and it is still the least confident thing the
                    # extractor emits.
                    add(EntityType.ORG, plain, 0.55, plain,
                        notes="assumed from a bare query — uncheck if wrong")

    return hits


def hits_to_seeds(hits: list[_Hit]) -> list[IntentSeed]:
    seeds: list[IntentSeed] = []
    for h in hits:
        include = h.confidence >= 0.55
        # person guesses default off unless conf high
        if h.type == EntityType.PERSON and h.confidence < 0.8:
            include = False
        if h.type == EntityType.USERNAME and h.value.startswith("unknown:") and h.confidence < 0.7:
            include = False
        seeds.append(
            IntentSeed(
                type=h.type,
                value=h.value,
                confidence=round(h.confidence, 2),
                source_span=h.span,
                include=include,
                notes=h.notes,
                props=h.props or {},
            )
        )
    # sort: include first, then confidence
    seeds.sort(key=lambda s: (-int(s.include), -s.confidence, s.type.value, s.value))
    return seeds
