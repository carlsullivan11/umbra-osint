"""Adjudicate entities with Jev after collection (docs/JEV.md §2, §4).

Runs as a post-collection pass, like scoring: it reads the props collectors
already wrote, asks Jev, and stores the answer under `props["jev"]`. It never
rewrites `reputation_verdict` — the public verdict is derived at render time
from both, through `combine()`.

**Dual ask (§4.3).** When the state carries untrusted text, the same questions
are asked twice: facts only, then facts + fenced text + the canary. If adding
the attacker's text moves the answer toward benign, that shift is treated as an
injection attempt, and the facts-only answer is the one used. Untrusted text
can therefore add suspicion but never remove it.

Synchronous by design. In the web app this runs inside the `umbra-worker` job,
never on the event loop (AGENTS.md §1.4).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from umbra.jev.client import Answer, JevClient, JevResult, JevUnavailable
from umbra.jev.combine import BENIGN_ROLES, Adjudication, combine
from umbra.jev.facts import Facts, facts_from_props, render_state
from umbra.jev.questions import INJECTION_CANARY, INJECTION_CANARY_KEY, Question, for_entity_type

#: How far the benign probability mass may rise when untrusted text is added
#: before the rise is read as manipulation rather than information.
BENIGN_SHIFT_AT = 0.25

_ROLE_KEYS = ("role", "site_kind")


def benign_mass(answers: dict[str, Answer]) -> float:
    """Total probability on benign options across the role-like questions."""
    total = 0.0
    for key in _ROLE_KEYS:
        a = answers.get(key)
        if a and a.type == "choice":
            total += sum(p for opt, p in a.probabilities.items() if opt in BENIGN_ROLES)
    return total


@dataclass
class JevOutcome:
    adjudication: Adjudication
    record: dict[str, Any]


def adjudicate(
    kind: str,
    value: str,
    props: dict[str, Any],
    client: JevClient,
    *,
    min_confidence: float = 0.70,
    now: datetime | None = None,
) -> JevOutcome | None:
    """Ask Jev about one entity. None when the type is out of scope.

    Raises `JevUnavailable`; callers keep the deterministic verdict on it.
    """
    sets = for_entity_type(kind)
    if not sets:
        return None
    facts: Facts = facts_from_props(kind, value, props, now=now)

    base_q: dict[str, Question] = {}
    for qs in sets:
        base_q.update(qs.questions)

    facts_only = client.ask(render_state(facts.without_untrusted()), base_q)
    answers = dict(facts_only.answers)
    full: JevResult | None = None
    injection_suspected = False
    shift = 0.0

    if facts.has_untrusted:
        full_q = dict(base_q)
        full_q[INJECTION_CANARY_KEY] = INJECTION_CANARY
        full = client.ask(render_state(facts), full_q)
        shift = benign_mass(full.answers) - benign_mass(facts_only.answers)
        if shift > BENIGN_SHIFT_AT:
            # The attacker's text argued the model toward "fine". Keep the
            # facts-only reading; record the attempt.
            injection_suspected = True
        else:
            answers = {k: v for k, v in full.answers.items() if k != INJECTION_CANARY_KEY}
        answers[INJECTION_CANARY_KEY] = full.answers[INJECTION_CANARY_KEY]

    det = str(props.get("reputation_verdict") or "clean")
    adj = combine(det, answers, min_confidence=min_confidence,
                  injection_suspected=injection_suspected)

    record = {
        "model": (full or facts_only).model,
        "question_sets": [qs.tag for qs in sets],
        "state_hash": facts_only.state_hash,
        "full_state_hash": full.state_hash if full else None,
        "answers": {k: vars(v) for k, v in answers.items()},
        "benign_shift": round(shift, 4),
        "adjudication": adj.to_dict(),
        "ts": (now or datetime.now(timezone.utc)).isoformat(),
    }
    return JevOutcome(adjudication=adj, record=record)


def adjudicate_case(repo: Any, case_id: str, client: JevClient, *,
                    min_confidence: float = 0.70, persist: bool = True,
                    now: datetime | None = None) -> list[dict[str, Any]]:
    """Run `adjudicate` over every in-scope entity on a case.

    Returns one row per entity considered. With `persist`, stores the record at
    `entity.props["jev"]` and writes one audit event; the caller commits.
    """
    rows: list[dict[str, Any]] = []
    for ent in repo.list_entities(case_id):
        if not for_entity_type(ent.type):
            continue
        row: dict[str, Any] = {"entity_id": ent.id, "type": ent.type, "value": ent.value}
        try:
            outcome = adjudicate(ent.type, ent.value, dict(ent.props or {}), client,
                                 min_confidence=min_confidence, now=now)
        except JevUnavailable as exc:
            row["error"] = str(exc)
            rows.append(row)
            continue
        if outcome is None:
            continue
        row.update(outcome.adjudication.to_dict())
        rows.append(row)
        if persist:
            props = dict(ent.props or {})
            props["jev"] = outcome.record
            ent.props = props
    if persist:
        repo.audit(case_id, "jev_adjudicate", {
            "entities": len(rows),
            "errors": sum(1 for r in rows if "error" in r),
            "raised": sum(1 for r in rows if r.get("ai_assessed")),
        })
    return rows
