"""Parse *candidates* from the BOP inmate locator JSON response.

Federal register is high-signal when the **first and last** name both appear
on the same record. That is still not identity — common names, and a hit
names someone convicted, someone acquitted on appeal, or a namesake. No
photo, no captcha bypass, no scraping the rendered page.
"""

from __future__ import annotations

import re
from typing import Any

_MAX_MATCHES = 5


def _norm_token(s: str) -> str:
    return re.sub(r"[^a-z']", "", (s or "").lower())


def _tokens(name: str) -> tuple[str, str]:
    parts = [p.lower() for p in re.findall(r"[A-Za-z']+", name or "") if len(p) >= 2]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], parts[0]
    return parts[0], parts[-1]


def parse_inmate_json(
    payload: Any,
    *,
    person_name: str = "",
    source_url: str = "",
) -> dict[str, Any]:
    """Return name-hit candidates from a BOP ``InmateLocator`` JSON payload.

    ``payload`` is the raw dict the BOP search endpoint returns:
    ``{"Captcha": bool, "Messages": {...}, "InmateLocator": [ {...}, ... ]}``.
    A record counts as a hit only when **both** the first and last name tokens
    of ``person_name`` match that record's ``nameFirst``/``nameLast`` fields —
    a shared last name alone (e.g. every "Smith") is not a hit.
    """
    first, last = _tokens(person_name)
    rows = []
    if isinstance(payload, dict):
        rows = payload.get("InmateLocator") or []
    if not isinstance(rows, list):
        rows = []

    matches: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        r_first = _norm_token(row.get("nameFirst") or "")
        r_last = _norm_token(row.get("nameLast") or "")
        first_hit = bool(first and first == r_first)
        last_hit = bool(last and last == r_last and len(last) >= 2)
        if not (first_hit and last_hit):
            continue
        matches.append(
            {
                "register_number": (row.get("inmateNum") or "").strip() or None,
                "name_first": row.get("nameFirst"),
                "name_middle": row.get("nameMiddle"),
                "name_last": row.get("nameLast"),
                "age": row.get("age") or None,
                "race": row.get("race") or None,
                "sex": row.get("sex") or None,
                "release_code": row.get("releaseCode") or None,
                "facility_name": row.get("faclName") or None,
                "facility_code": row.get("faclCode") or None,
                "facility_type": row.get("faclType") or None,
                "facility_url": row.get("faclURL") or None,
                "proj_release_date": row.get("projRelDate") or None,
                "act_release_date": row.get("actRelDate") or None,
            }
        )
        if len(matches) >= _MAX_MATCHES:
            break

    return {
        "name_hit": bool(matches),
        "matches": matches,
        "total_rows": len(rows),
        "captcha": bool(payload.get("Captcha")) if isinstance(payload, dict) else False,
        "source_url": source_url,
    }
