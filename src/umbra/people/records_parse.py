"""Parse land / corporation *candidates* from public county/SOS HTML.

Never treat a hit as identity. Last-name token should already be on the page
before we keep a fact. No PACER, no login bodies.
"""

from __future__ import annotations

import re
from typing import Any

from umbra.people.obituary_parse import strip_html

_APN_RE = re.compile(
    r"\b(?:APN|assessor'?s?\s*parcel(?:\s*(?:number|no\.?|#))?|parcel(?:\s*(?:id|no\.?|number|#))?)"
    r"\s*[:#]?\s*([0-9][0-9A-Z\-\.]{4,24})",
    re.I,
)
_SITUS_RE = re.compile(
    r"\b(\d{1,6}\s+[A-Za-z0-9.'\-]+(?:\s+[A-Za-z0-9.'\-]+){0,4}"
    r"\s(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Dr|Drive|Ln|Lane|"
    r"Way|Ct|Court|Hwy|Highway|Pkwy|Parkway|Cir|Circle|Pl|Place))\b\.?",
    re.I,
)
_CORP_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.,'’\- ]{1,70}?\s(?:LLC|L\.L\.C\.|Inc\.?|Incorporated|"
    r"Corp\.?|Corporation|LP|L\.P\.|LLP|Ltd\.?|Limited))\b"
)
_FILE_RE = re.compile(
    r"\b(?:file(?:\s*no\.?| number)|entity(?:\s*(?:no\.?|number|#))|sos(?:\s*id)?|"
    r"charter(?:\s*no\.?)?)\s*[:#]?\s*([A-Z0-9\-]{4,24})",
    re.I,
)


def _last_token(person: str) -> str:
    parts = [p for p in (person or "").replace(",", " ").split() if p]
    return (parts[-1] if parts else "").lower()


def parse_public_records_text(
    text: str,
    *,
    person_name: str = "",
    kind: str = "",
    source_url: str = "",
    region: str = "",
) -> dict[str, Any]:
    """Return land/corp candidate dicts. Empty if the page is just a portal shell."""
    body = strip_html(text or "")
    last = _last_token(person_name)
    if last and len(last) >= 3:
        tokens = set(re.findall(r"[a-z0-9']+", body.lower()))
        if last not in tokens:
            return {"land": [], "corps": [], "name_hit": False}

    land: list[dict[str, Any]] = []
    seen_apn: set[str] = set()
    if kind in {"", "property", "land", "vital"}:
        for m in _APN_RE.finditer(body):
            apn = m.group(1).strip(" .")
            if apn.lower() in seen_apn:
                continue
            seen_apn.add(apn.lower())
            window = body[max(0, m.start() - 80) : m.end() + 120]
            sm = _SITUS_RE.search(window) or _SITUS_RE.search(body[:2500])
            land.append(
                {
                    "apn": apn,
                    "situs": sm.group(1).strip() if sm else None,
                    "source_url": source_url,
                    "region": region,
                    "kind": "property",
                }
            )
            if len(land) >= 5:
                break
        if not land:
            for sm in _SITUS_RE.finditer(body[:4000]):
                land.append(
                    {
                        "apn": None,
                        "situs": sm.group(1).strip(),
                        "source_url": source_url,
                        "region": region,
                        "kind": "property",
                    }
                )
                if len(land) >= 3:
                    break

    corps: list[dict[str, Any]] = []
    seen_org: set[str] = set()
    if kind in {"", "business", "government_contracting"}:
        for m in _CORP_RE.finditer(body):
            org = re.sub(r"\s+", " ", m.group(1)).strip(" ,.")
            key = org.lower()
            if key in seen_org or len(org) < 5:
                continue
            if last and last not in key and last not in body[max(0, m.start() - 40) : m.end() + 40].lower():
                # Keep only orgs near the subject name, or whose legal name includes it.
                continue
            seen_org.add(key)
            window = body[max(0, m.start() - 60) : m.end() + 80]
            fm = _FILE_RE.search(window)
            corps.append(
                {
                    "org_name": org,
                    "file_number": fm.group(1) if fm else None,
                    "source_url": source_url,
                    "region": region,
                    "kind": "business",
                }
            )
            if len(corps) >= 5:
                break

    return {"land": land, "corps": corps, "name_hit": True}


def parse_index_json(
    text: str,
    *,
    person_name: str = "",
    source_url: str = "",
) -> dict[str, Any]:
    """CourtListener / FEC public JSON indexes — extra URLs, not identity."""
    import json

    last = _last_token(person_name)
    out_urls: list[str] = []
    names: list[str] = []
    try:
        data = json.loads(text or "")
    except (json.JSONDecodeError, TypeError, ValueError):
        return {"urls": [], "names": [], "name_hit": False}
    if not isinstance(data, dict):
        return {"urls": [], "names": [], "name_hit": False}

    rows = data.get("results")
    if not isinstance(rows, list):
        rows = []
    blob = (text or "").lower()
    name_hit = bool(last and len(last) >= 3 and last in blob)

    for row in rows[:8]:
        if not isinstance(row, dict):
            continue
        abs_url = row.get("absolute_url") or row.get("url")
        if isinstance(abs_url, str) and abs_url.startswith("http"):
            out_urls.append(abs_url)
        elif isinstance(abs_url, str) and abs_url.startswith("/") and "courtlistener" in (source_url or ""):
            out_urls.append("https://www.courtlistener.com" + abs_url)
        nm = row.get("caseName") or row.get("name") or row.get("candidate_name")
        if isinstance(nm, str) and nm.strip():
            names.append(nm.strip()[:120])
    return {"urls": out_urls[:8], "names": names[:8], "name_hit": name_hit}
