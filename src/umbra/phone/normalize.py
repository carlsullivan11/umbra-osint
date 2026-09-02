"""Phone number normalize + facts (libphonenumber).

Offline numbering-plan validation only. This is not live HLR, not CNAM, and
not proof of who answers the phone. US/CA mobile *type* metadata is often weak
after number portability — surface that in notes rather than inventing a carrier.
"""
from __future__ import annotations

from typing import Any

import phonenumbers
from phonenumbers import NumberParseException, PhoneNumberFormat, PhoneNumberType
from phonenumbers.phonenumberutil import number_type

DEFAULT_REGION = "US"

# Readable labels for PhoneNumberType enum values we care about.
_TYPE_LABEL: dict[int, str] = {
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}

_TYPE_CAVEAT_US = (
    "Numbering-plan type only — after mobile number portability the offline "
    "type is often fixed_line_or_mobile / unknown for North American numbers."
)


def normalize_phone(raw: str, default_region: str = DEFAULT_REGION) -> str | None:
    """Return E.164 (+14155550134) or None if not a possible phone number."""
    facts = phone_facts(raw, default_region=default_region)
    if not facts.get("possible"):
        return None
    return facts.get("e164")


def phone_facts(raw: str, default_region: str = DEFAULT_REGION) -> dict[str, Any]:
    """Parse one candidate. Never raises for bad input — empty/invalid → possible=False."""
    text = (raw or "").strip()
    empty: dict[str, Any] = {
        "input": text,
        "possible": False,
        "valid": False,
        "e164": None,
        "notes": [],
    }
    if not text:
        return empty

    region = (default_region or DEFAULT_REGION).upper()
    try:
        # Keep a leading + so international form is not forced through default region.
        num = phonenumbers.parse(text, None if text.lstrip().startswith("+") else region)
    except NumberParseException as exc:
        out = dict(empty)
        out["notes"] = [f"parse_failed: {exc}"]
        return out

    possible = phonenumbers.is_possible_number(num)
    valid = phonenumbers.is_valid_number(num)
    notes: list[str] = []
    if possible and not valid:
        notes.append(
            "Possible under the numbering plan but not a fully valid number "
            "(wrong length or invalid prefix for the region)."
        )

    ntype = number_type(num) if possible else PhoneNumberType.UNKNOWN
    type_label = _TYPE_LABEL.get(ntype, "unknown")
    region_code = phonenumbers.region_code_for_number(num) if possible else None
    if region_code in {"US", "CA", "PR"} and type_label in {
        "fixed_line_or_mobile",
        "unknown",
        "fixed_line",
        "mobile",
    }:
        notes.append(_TYPE_CAVEAT_US)

    e164 = (
        phonenumbers.format_number(num, PhoneNumberFormat.E164) if possible else None
    )
    national = (
        phonenumbers.format_number(num, PhoneNumberFormat.NATIONAL) if possible else None
    )
    international = (
        phonenumbers.format_number(num, PhoneNumberFormat.INTERNATIONAL)
        if possible
        else None
    )

    return {
        "input": text,
        "possible": possible,
        "valid": valid,
        "e164": e164,
        "country_code": num.country_code if possible else None,
        "region": region_code,
        "national_format": national,
        "international_format": international,
        "number_type": type_label,
        "notes": notes,
    }


def find_phones(text: str, default_region: str = DEFAULT_REGION) -> list[str]:
    """Unique E.164 numbers found in free text (order of first appearance)."""
    body = text or ""
    region = (default_region or DEFAULT_REGION).upper()
    found: list[str] = []
    seen: set[str] = set()

    # Whole-string parse first — reputation form and single-token pastes.
    whole = normalize_phone(body.strip(), default_region=region)
    if whole and whole not in seen:
        seen.add(whole)
        found.append(whole)

    try:
        matcher = phonenumbers.PhoneNumberMatcher(body, region)
    except Exception:  # noqa: BLE001 — never break intent extract
        return found

    for match in matcher:
        num = match.number
        if not phonenumbers.is_possible_number(num):
            continue
        e164 = phonenumbers.format_number(num, PhoneNumberFormat.E164)
        if e164 not in seen:
            seen.add(e164)
            found.append(e164)
    return found
