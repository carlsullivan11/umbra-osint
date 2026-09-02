"""Aggregate community reports into a verdict.

Deliberately arithmetic rather than clever. Everything being aggregated is a
user allegation about a phone line somebody may own, use for work, or have been
reassigned after somebody else gave it up — so the rules have to be readable by
the person the verdict is about, and arguable by them.

Three of the rules exist to protect that person rather than the reader:

- one reporter is never a verdict (`unconfirmed`), because one motivated person
  is exactly how a personal number gets brigaded;
- disagreement renders as `disputed`, never resolved by majority;
- no reports is `unknown`, never "clean" — the same unchecked-is-not-clean rule
  the collectors follow.

Nothing here may produce a label that reads as a finding of fact or an
accusation of a crime. `likely_spam` is the strongest thing this can say.
"""
from __future__ import annotations

from typing import Any

# Fixed enum. "cheater", "ex", "neighbour" and the like are absent on purpose:
# they turn a spam database into a tool for interpersonal harassment.
CATEGORIES: dict[str, dict[str, Any]] = {
    "scam": {"label": "Scam / fraud attempt", "weight": 2.0},
    "spam": {"label": "Spam / unsolicited", "weight": 1.0},
    "robocall": {"label": "Robocall", "weight": 1.0},
    "telemarketing": {"label": "Telemarketing", "weight": 1.0},
    "debt_collection": {"label": "Debt collection", "weight": 1.0},
    "political": {"label": "Political", "weight": 0.5},
    "survey": {"label": "Survey", "weight": 0.5},
    "other": {"label": "Other", "weight": 0.5},
    "not_spam": {"label": "Not spam / legitimate", "weight": -1.0},
}

# Below this many distinct reporters nothing stronger than "unconfirmed" is
# available, whatever the votes say.
MIN_REPORTERS_FOR_A_VERDICT = 2

_SPAM_THRESHOLD = 5.0
_LEGIT_THRESHOLD = -3.0
# Below this share of one-sidedness the reports are treated as contested.
_CONSENSUS = 0.7

_NOTES = {
    "unknown": ("Nobody has reported this number here. That is not evidence the "
                "number is safe — it may simply never have been reported."),
    "unconfirmed": ("A single person has reported this number. One report is not "
                    "a verdict, and Umbra will not present it as one."),
    "mixed": ("Reports disagree about what this number is. Read the categories "
              "and dates rather than a single label."),
    "disputed": ("Reports directly contradict each other — some say spam, others "
                 "say legitimate. Umbra does not pick a winner."),
    "likely_spam": ("Several independent people have reported this number for "
                    "unwanted contact. These are community allegations, not a "
                    "finding of fact and not an accusation of a crime."),
    "likely_legit": ("People who looked this number up have mostly said it is "
                     "legitimate. That is community opinion, not verification."),
}

_LABELS = {
    "unknown": "No reports",
    "unconfirmed": "Unconfirmed — one report",
    "mixed": "Mixed reports",
    "disputed": "Disputed",
    "likely_spam": "Likely unwanted",
    "likely_legit": "Likely legitimate",
}


def _clean_counts(counts: dict[str, int] | None) -> dict[str, int]:
    out: dict[str, int] = {}
    for code, raw in (counts or {}).items():
        if code not in CATEGORIES:
            continue  # never render a category outside the fixed enum
        try:
            value = int(raw)
        except (TypeError, ValueError):
            continue
        if value > 0:
            out[code] = value
    return out


def compute_verdict(counts: dict[str, int] | None, *, agree: int = 0,
                    disagree: int = 0, reporters: int = 0) -> dict[str, Any]:
    """A verdict dict: code, label, note, score, reporters, categories."""
    clean = _clean_counts(counts)
    agree = max(0, int(agree or 0))
    disagree = max(0, int(disagree or 0))
    reporters = max(0, int(reporters or 0))

    spam_weight = sum(clean[c] * CATEGORIES[c]["weight"]
                      for c in clean if CATEGORIES[c]["weight"] > 0)
    legit_weight = clean.get("not_spam", 0) * 1.0
    score = round(spam_weight + agree - legit_weight - disagree, 2)

    total = spam_weight + legit_weight
    share = (spam_weight / total) if total else 0.0

    if reporters == 0:
        code = "unknown"
    elif reporters < MIN_REPORTERS_FOR_A_VERDICT:
        # However many agrees it has. A lone reporter plus votes is still a
        # lone reporter, and sockpuppet votes are cheap.
        code = "unconfirmed"
    elif legit_weight and spam_weight and 0.3 <= share <= 0.7:
        code = "disputed"
    elif score >= _SPAM_THRESHOLD and share > _CONSENSUS:
        code = "likely_spam"
    elif score <= _LEGIT_THRESHOLD and share < (1 - _CONSENSUS):
        code = "likely_legit"
    else:
        code = "mixed"

    categories = [
        {"code": c, "label": CATEGORIES[c]["label"], "count": clean[c]}
        for c in sorted(clean, key=lambda k: (-clean[k], k))
    ]
    return {
        "code": code,
        "label": _LABELS[code],
        "note": _NOTES[code],
        "score": score,
        "reporters": reporters,
        "agree": agree,
        "disagree": disagree,
        "categories": categories,
    }
