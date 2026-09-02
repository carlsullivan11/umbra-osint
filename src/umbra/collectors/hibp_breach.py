"""Breach exposure checks via legitimate APIs (Have I Been Pwned).

Dark-web marketplace scraping is intentionally NOT implemented.
HIBP and similar services already aggregate leak data from breaches
(including many that first appeared on criminal forums) into a lawful API.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from umbra.collectors.base import BaseCollector, CollectorContext
from umbra.core.models import CollectorResult, EdgeIn, EdgeType, EntityIn, EntityType, EvidenceIn
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

# Remediation templates keyed by rough breach data classes
_REMEDIATION_BY_DATA_CLASS: dict[str, list[str]] = {
    "passwords": [
        "Change the password on this account immediately if still in use.",
        "If you reused that password anywhere else, change those accounts too (unique passwords).",
        "Enable a password manager and generate a long unique password.",
        "Turn on MFA (prefer app/hardware key over SMS when possible).",
    ],
    "password hints": [
        "Review and remove password hints where the service allows.",
        "Assume hints are public; do not use guessable recovery answers.",
    ],
    "email addresses": [
        "Watch for targeted phishing referencing this breach.",
        "Consider a mail-filter rule for spoofed messages claiming to be the breached brand.",
    ],
    "usernames": [
        "If the username is reused, review profile privacy on other sites.",
    ],
    "phone numbers": [
        "Enable carrier PIN / port-out protection.",
        "Be alert for SIM-swap and vishing attempts.",
    ],
    "credit cards": [
        "Contact your bank/card issuer; request a new card number if the card was active at breach time.",
        "Monitor statements for unauthorized charges.",
    ],
    "partial credit card data": [
        "Monitor statements; ask issuer about additional monitoring if concerned.",
    ],
    "social security numbers": [
        "Consider a fraud alert or credit freeze with major bureaus (Equifax, Experian, TransUnion).",
        "File an IRS identity-theft PIN if in the US and SSN was exposed.",
    ],
    "physical addresses": [
        "Be cautious of physical mail / spearphish that reference your address.",
    ],
    "dates of birth": [
        "Do not use DOB as a password or recovery answer.",
        "Watch for identity-verification social engineering.",
    ],
    "ip addresses": [
        "No password change required solely for IP exposure; review account login history if available.",
    ],
    "names": [
        "Low direct risk alone; combine with phishing vigilance if email/password also exposed.",
    ],
}

_DEFAULT_REMEDIATION = [
    "Treat the account as potentially compromised until you verify otherwise.",
    "Change the password if you still use the service (or delete unused accounts).",
    "Enable MFA on important accounts (email, banking, cloud, password manager).",
    "Use unique passwords per site via a password manager.",
    "Review account recovery options (backup email/phone) for hijack risk.",
    "Watch email for phishing that references the breached service.",
]


def remediation_for_data_classes(data_classes: list[str] | None) -> list[str]:
    steps: list[str] = []
    seen: set[str] = set()
    for dc in data_classes or []:
        key = dc.strip().lower()
        for step in _REMEDIATION_BY_DATA_CLASS.get(key, []):
            if step not in seen:
                steps.append(step)
                seen.add(step)
    for step in _DEFAULT_REMEDIATION:
        if step not in seen:
            steps.append(step)
            seen.add(step)
    return steps


def severity_for_breach(breach: dict[str, Any]) -> str:
    classes = {c.lower() for c in (breach.get("DataClasses") or [])}
    if any(x in classes for x in ("passwords", "password hints", "credit cards", "social security numbers")):
        return "high"
    if any(x in classes for x in ("email addresses", "phone numbers", "partial credit card data", "dates of birth")):
        return "medium"
    return "low"


class HibpBreachCollector(BaseCollector):
    """Check email exposure via Have I Been Pwned v3 (requires UMBRA_HIBP_API_KEY)."""

    name = "hibp_breach"
    timeout_s = 25
    inputs = {EntityType.EMAIL}
    description = "Have I Been Pwned breach check for authorized email monitoring"

    def collect(self, entity: Entity, ctx: CollectorContext) -> CollectorResult:
        result = CollectorResult()
        email = entity.value.strip().lower()
        src = entity.norm_key
        api_key = ctx.settings.hibp_api_key
        if not api_key:
            result.notes.append(
                "HIBP API key not set. Export UMBRA_HIBP_API_KEY=... "
                "(https://haveibeenpwned.com/API/Key). Password checks still work without a key."
            )
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="HIBP",
                    source_url="https://haveibeenpwned.com/API/Key",
                    summary="Skipped breach account lookup — no UMBRA_HIBP_API_KEY configured",
                    confidence=0.2,
                    raw={"skipped": True, "reason": "missing_api_key", "email": email},
                    entity_key=src,
                )
            )
            return result

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": api_key,
            "user-agent": ctx.settings.hibp_user_agent,
            "Accept": "application/json",
        }
        try:
            resp = ctx.http.get(url, headers=headers, params={"truncateResponse": "false"})
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"HIBP request error: {exc}")
            return result

        if resp.status_code == 404:
            result.evidence.append(
                EvidenceIn(
                    collector=self.name,
                    source_name="HIBP",
                    source_url="https://haveibeenpwned.com/",
                    summary=f"No breaches found for {email}",
                    confidence=0.85,
                    raw={"breached": False, "email": email},
                    entity_key=src,
                )
            )
            result.entities.append(
                EntityIn(
                    type=EntityType.EMAIL,
                    value=email,
                    confidence=0.9,
                    props={"hibp_breached": False, "hibp_count": 0},
                )
            )
            return result

        if resp.status_code == 401:
            result.notes.append("HIBP API key rejected (401)")
            return result
        if resp.status_code == 429:
            result.notes.append("HIBP rate limited (429) — retry later")
            return result
        if resp.status_code != 200:
            result.notes.append(f"HIBP HTTP {resp.status_code}: {resp.text[:200]}")
            return result

        breaches = resp.json()
        if not isinstance(breaches, list):
            result.notes.append("HIBP unexpected payload")
            return result

        all_steps: list[str] = []
        seen_steps: set[str] = set()
        high = med = low = 0

        for b in breaches:
            name = b.get("Name") or b.get("Title") or "unknown"
            title = b.get("Title") or name
            bid = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(name))[:80]
            sev = severity_for_breach(b)
            if sev == "high":
                high += 1
            elif sev == "medium":
                med += 1
            else:
                low += 1
            classes = b.get("DataClasses") or []
            steps = remediation_for_data_classes(classes)
            for s in steps:
                if s not in seen_steps:
                    all_steps.append(s)
                    seen_steps.add(s)

            result.entities.append(
                EntityIn(
                    type=EntityType.BREACH,
                    value=bid,
                    display_name=str(title),
                    confidence=0.95,
                    props={
                        "title": title,
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "added_date": b.get("AddedDate"),
                        "pwn_count": b.get("PwnCount"),
                        "data_classes": classes,
                        "is_verified": b.get("IsVerified"),
                        "is_sensitive": b.get("IsSensitive"),
                        "is_ransomware": b.get("IsRansomware"),
                        "severity": sev,
                        "description_html": (b.get("Description") or "")[:500],
                        "remediation": steps[:8],
                    },
                )
            )
            result.edges.append(
                EdgeIn(
                    source_key=src,
                    target_key=entity_key(EntityType.BREACH, bid),
                    rel=EdgeType.EXPOSED_IN,
                    confidence=0.95,
                    props={"severity": sev, "breach_date": b.get("BreachDate")},
                )
            )

        result.entities.append(
            EntityIn(
                type=EntityType.EMAIL,
                value=email,
                confidence=0.95,
                props={
                    "hibp_breached": True,
                    "hibp_count": len(breaches),
                    "hibp_severity": {"high": high, "medium": med, "low": low},
                    "remediation_priority": all_steps[:12],
                },
            )
        )
        result.evidence.append(
            EvidenceIn(
                collector=self.name,
                source_name="Have I Been Pwned",
                source_url=f"https://haveibeenpwned.com/account/{email}",
                summary=(
                    f"{email} appears in {len(breaches)} breach(es) "
                    f"(high={high}, medium={med}, low={low})"
                ),
                confidence=0.95,
                raw={"count": len(breaches), "names": [b.get("Name") for b in breaches]},
                entity_key=src,
            )
        )
        return result
