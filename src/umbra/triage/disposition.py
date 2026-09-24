"""The triage call: escalate, suggest close, or hand to an analyst.

Pure. The rules are docs/JEV-SOC.md §4.3; the numbers are the ones fitted on
held-out data in docs/JEV-EVAL.md. The invariants are tests in
`tests/test_triage_disposition.py`:

- **Nothing closes.** The best Umbra offers is `suggest_close`; a person decides.
- A **listing** Umbra found always escalates, whatever Jev says.
- Planted text addressed to a classifier **escalates**. It is evidence, not noise.
- **Without Jev**, a clean lookup is `needs_analyst`, never `suggest_close`:
  "no blocklist has it yet" is how most new infrastructure looks.
- A **critical asset**, an **un-enriched** indicator, and one whose blocklist check
  did not complete never get `suggest_close`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from umbra.jev.client import Answer
from umbra.jev.questions import INJECTION_CANARY_KEY

ESCALATE = "escalate"
SUGGEST_CLOSE = "suggest_close"
NEEDS_ANALYST = "needs_analyst"
RANK = {SUGGEST_CLOSE: 0, NEEDS_ANALYST: 1, ESCALATE: 2}

#: Fitted 2026-09-24 on soc_triage@1 against typesafe/jev-1.13-20260917
#: (docs/JEV-EVAL.md): zero missed threats on the held-out half at these values.
#: Refit before trusting them on another model build or question version.
FITTED_MODEL = "typesafe/jev-1.13-20260917"
CLOSE_MAX_P = 0.115
ESCALATE_MIN_P = 0.465
CANARY_AT = 0.5

MALICIOUS_ROLES = frozenset({"dedicated_malicious_infra", "compromised_legitimate_host"})
BENIGN_ROLES = frozenset({"clean", "scanner_or_research", "shared_platform_serving_bad_content",
                          "anonymity_network", "residential_noise"})


@dataclass
class Decision:
    disposition: str
    reasons: list[str] = field(default_factory=list)
    role: str | None = None
    role_confidence: float | None = None
    p_malicious: float | None = None
    p_business: float | None = None
    urgency: str | None = None
    injection_flag: bool = False

    def to_dict(self) -> dict[str, Any]:
        return dict(vars(self))


def _p(answers: dict[str, Answer], key: str) -> float | None:
    a = answers.get(key)
    return a.probability if a is not None and a.type == "noul" else None


def decide(
    listing: str,
    listed_by: list[str],
    answers: dict[str, Answer] | None,
    *,
    enriched: bool = True,
    critical_asset: bool = False,
    injection_suspected: bool = False,
) -> Decision:
    """One indicator's disposition.

    `listing` is Umbra's deterministic reputation verdict (clean / suspicious /
    malicious), or "unknown" when no reputation collector ran.
    """
    d = Decision(disposition=NEEDS_ANALYST)
    if answers:
        role = answers.get("role")
        if role is not None and role.value:
            d.role = role.value
            d.role_confidence = role.confidence
        d.p_malicious = _p(answers, "malware_or_c2")
        d.p_business = _p(answers, "ordinary_business")
        if (u := answers.get("urgency")) is not None:
            d.urgency = u.value
        canary = _p(answers, INJECTION_CANARY_KEY)
        d.injection_flag = injection_suspected or (canary is not None and canary >= CANARY_AT)

    # 1. Deterministic evidence accuses; nothing Jev says can undo it.
    if listing == "malicious":
        d.disposition = ESCALATE
        d.reasons.append("listed by " + (", ".join(listed_by) if listed_by else "a blocklist"))
        return d
    # 2. Somebody wrote to the classifier. That is a finding in itself.
    if d.injection_flag:
        d.disposition = ESCALATE
        d.reasons.append("its content addresses automated reviewers (likely evasion)")
        return d
    if not answers:
        d.reasons.append("no Jev answer; deterministic checks alone cannot clear an unlisted indicator"
                         if listing != "suspicious" else "partial listing: " + ", ".join(listed_by))
        return d
    # 3. Jev escalates on a malicious role or a high enough probability.
    p = d.p_malicious if d.p_malicious is not None else 0.5
    if d.role in MALICIOUS_ROLES or p >= ESCALATE_MIN_P:
        d.disposition = ESCALATE
        if d.role in MALICIOUS_ROLES:
            d.reasons.append(f"assessed as {d.role.replace('_', ' ')} (p={p:.2f}, Jev)")
        else:
            d.reasons.append(f"looks like malware delivery or C2 (p={p:.2f}, Jev)")
        return d
    # 4. Suggest close only when every guard agrees.
    blockers = []
    if listing == "suspicious":
        blockers.append("partially listed" + (f" ({', '.join(listed_by)})" if listed_by else ""))
    elif listing != "clean" and enriched:
        blockers.append("the blocklist check did not complete")
    if not enriched:
        blockers.append("not enriched, so there are too few facts to clear it")
    if critical_asset:
        blockers.append("critical asset")
    if d.role not in BENIGN_ROLES:
        blockers.append(f"role unclear ({(d.role or 'none').replace('_', ' ')})")
    if p > CLOSE_MAX_P:
        blockers.append(f"not confidently benign (p={p:.2f})")
    if blockers:
        d.reasons.append("needs a person: " + "; ".join(blockers))
        return d
    d.disposition = SUGGEST_CLOSE
    d.reasons.append(f"reads as {d.role.replace('_', ' ')} (p={p:.2f}, Jev); no listing")
    return d


def worst(dispositions: list[str]) -> str:
    """The alert takes its most serious indicator's disposition."""
    if not dispositions:
        return NEEDS_ANALYST
    return max(dispositions, key=RANK.__getitem__)
