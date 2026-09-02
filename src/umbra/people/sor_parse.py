"""Parse *candidates* from public sex-offender registry HTML.

Government registries are high-signal when the **first and last** name both
appear on the page. That is still not identity (common names). No captcha
bypass, no photo bulk dump, no victim names.
"""

from __future__ import annotations

import re
from typing import Any

from umbra.people.obituary_parse import strip_html

_AKA_RE = re.compile(
    r"\b(?:a\.?k\.?a\.?|also known as|aliases?)\s*[:\-]?\s*([A-Za-z][A-Za-z0-9.',\- ]{1,80})",
    re.I,
)
_DOB_RE = re.compile(
    r"\b(?:DOB|date of birth|born)\s*[:\-]?\s*"
    r"((?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4})|(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}))",
    re.I,
)
_ADDR_RE = re.compile(
    r"\b(\d{1,6}\s+[A-Za-z0-9.'\-]+(?:\s+[A-Za-z0-9.'\-]+){0,4}"
    r"\s(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|"
    r"Way|Ct|Court|Hwy|Highway|Pkwy|Parkway|Cir|Circle|Pl|Place))\b\.?",
    re.I,
)
_ID_RE = re.compile(
    r"\b(?:offender(?:\s*id)?|registry(?:\s*id)?|DOC(?:\s*#)?|SID)\s*[:#]?\s*([A-Z0-9\-]{4,20})",
    re.I,
)
_TIER_RE = re.compile(r"\b(?:tier|risk(?:\s*level)?|level)\s*[:\-]?\s*([123]|high|moderate|low)\b", re.I)
_OFFENSE_WORDS = (
    "sexual assault",
    "rape",
    "lewd",
    "molest",
    "indecent",
    "exploitation",
    "pornography",
    "kidnapping",
    "unlawful sexual",
    "sex offender",
)


def _tokens(name: str) -> tuple[str, str]:
    parts = [p.lower() for p in re.findall(r"[A-Za-z']+", name or "") if len(p) >= 2]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], parts[0]
    return parts[0], parts[-1]


def parse_sor_html(
    text: str,
    *,
    person_name: str = "",
    source_url: str = "",
    region: str = "",
) -> dict[str, Any]:
    body = strip_html(text or "")
    first, last = _tokens(person_name)
    toks = set(re.findall(r"[a-z0-9']+", body.lower()))
    first_hit = bool(first and first in toks)
    last_hit = bool(last and last in toks and len(last) >= 3)
    name_hit = first_hit and last_hit and first != last
    if first and first == last:
        name_hit = last_hit

    aliases: list[str] = []
    for m in _AKA_RE.finditer(body):
        a = m.group(1).strip(" .;," )
        if a and a.lower() not in {person_name.lower(), first, last}:
            aliases.append(a[:80])
        if len(aliases) >= 4:
            break

    dob = None
    dm = _DOB_RE.search(body)
    if dm:
        dob = dm.group(1).strip()

    addresses: list[str] = []
    for m in _ADDR_RE.finditer(body[:6000]):
        a = m.group(1).strip()
        if a.lower() not in {x.lower() for x in addresses}:
            addresses.append(a)
        if len(addresses) >= 3:
            break

    rid = None
    im = _ID_RE.search(body)
    if im:
        rid = im.group(1).strip()

    tier = None
    tm = _TIER_RE.search(body)
    if tm:
        tier = tm.group(1).lower()

    low = body.lower()
    offenses = [w for w in _OFFENSE_WORDS if w in low][:6]

    excerpt = body[:400].strip() if name_hit else ""
    return {
        "name_hit": name_hit,
        "first_hit": first_hit,
        "last_hit": last_hit,
        "aliases": aliases,
        "dob": dob,
        "addresses": addresses,
        "registry_id": rid,
        "tier": tier,
        "offenses": offenses,
        "excerpt": excerpt,
        "source_url": source_url,
        "region": region,
    }
