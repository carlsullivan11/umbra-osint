"""The one place a Jev answer meets a verdict (docs/JEV.md §3).

Jev is an adjudicator, never an authority. The invariants, each a test in
`tests/test_jev_combine.py`:

- Jev **never lowers** a verdict. A listing Umbra found stays found.
- Jev **alone never produces "malicious"**. The most it can do to a clean
  result is "suspicious", flagged `ai_assessed` so the UI labels it.
- Below the confidence floor an answer is recorded but **not public**.
- An injection signal is evidence *for* malice, never against it.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from umbra.jev.client import Answer
from umbra.jev.questions import INJECTION_CANARY_KEY

_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}

#: Roles that, confidently asserted, justify raising clean -> suspicious.
ACCUSATORY_ROLES = frozenset({
    "dedicated_malicious_infra",
    "compromised_legitimate_host",
    "brand_impersonation",
})

#: Roles that say "nothing wrong here". Used only to flag disagreement with a
#: listing for analyst review — never to lower the verdict.
BENIGN_ROLES = frozenset({"clean", "unrelated_legitimate", "brand_owned_defensive"})

INJECTION_AT = 0.80
CREDENTIALS_AT = 0.80


@dataclass
class Adjudication:
    verdict: str
    deterministic_verdict: str
    role: str | None = None
    role_confidence: float | None = None
    #: the verdict was raised on Jev's word alone; render as AI-assessed
    ai_assessed: bool = False
    #: safe to show on a public page (confidence cleared the floor)
    public: bool = False
    injection_flag: bool = False
    #: Jev reads the host as benign while a blocklist lists it — route to review
    disagreement: bool = False
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _best_role(answers: dict[str, Answer]) -> tuple[str | None, float | None]:
    """The most confident Choice among the role-like questions."""
    best: tuple[str | None, float | None] = (None, None)
    for key in ("site_kind", "role"):
        a = answers.get(key)
        if a is None or a.type != "choice" or a.value is None:
            continue
        conf = a.confidence if a.confidence is not None else a.probabilities.get(a.value)
        if key == "site_kind" and a.value == "unknown":
            continue
        if best[1] is None or (conf or 0.0) > best[1]:
            best = (a.value, conf)
    return best


def combine(
    deterministic_verdict: str,
    answers: dict[str, Answer] | None,
    *,
    min_confidence: float = 0.70,
    injection_suspected: bool = False,
) -> Adjudication:
    det = deterministic_verdict if deterministic_verdict in _RANK else "clean"
    out = Adjudication(verdict=det, deterministic_verdict=det)
    if not answers:
        return out

    role, conf = _best_role(answers)
    out.role, out.role_confidence = role, conf
    confident = conf is not None and conf >= min_confidence
    out.public = confident

    canary = answers.get(INJECTION_CANARY_KEY)
    if injection_suspected or (canary and (canary.probability or 0.0) >= INJECTION_AT):
        out.injection_flag = True
        out.reasons.append("page content addresses automated classifiers")

    creds = answers.get("solicits_credentials")
    solicits = bool(creds and (creds.probability or 0.0) >= CREDENTIALS_AT)
    if solicits:
        out.reasons.append("asks for credentials on behalf of another brand")

    raise_to_suspicious = (
        (confident and role in ACCUSATORY_ROLES)
        or out.injection_flag
        or (solicits and role == "brand_impersonation")
    )
    if raise_to_suspicious and _RANK[det] < _RANK["suspicious"]:
        out.verdict = "suspicious"
        out.ai_assessed = True
        # An injection attempt is shown whatever the role confidence: it is an
        # observed fact about the page, not a guess.
        out.public = out.public or out.injection_flag
        if role in ACCUSATORY_ROLES:
            out.reasons.insert(0, f"assessed as {role.replace('_', ' ')}")

    if det != "clean" and confident and role in BENIGN_ROLES:
        out.disagreement = True
        out.reasons.append("model reads this as benign despite a listing; needs analyst review")

    # Belt and braces: whatever happened above, the invariants hold. Not an
    # `assert` — those vanish under `python -O`.
    if _RANK[out.verdict] < _RANK[det] or (out.verdict == "malicious" and det != "malicious"):
        raise RuntimeError(f"combine() broke an invariant: {det} -> {out.verdict}")
    return out
