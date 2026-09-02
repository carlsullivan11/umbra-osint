"""Tell "we do not hold this" apart from "this does not exist".

The corpus answered three different questions with one sentence:

    umbra lookup RFC7231        → silently returned RFC9110, unexplained
    umbra lookup CVE-2014-3566  → "No wiki hits — Tip: umbra wiki update"
    umbra lookup RFC99999       → "No wiki hits — Tip: umbra wiki update"

Only the third is a miss. RFC 7231 is real and was obsoleted by 9110 — a good
answer, delivered as if it were the thing asked for. CVE-2014-3566 is POODLE:
real, famous, and scored **0.99999** by the EPSS lake sitting next to the wiki.
Telling someone there are "no hits" for POODLE, and blaming a stale corpus that
is not stale, is the lookup-shaped version of reporting an unreachable source as
clean.

The corpus is **deliberately scoped** — CISA KEV rather than all 384,910 CVEs, a
curated RFC set rather than all 9,834. Scope is a good decision. Silence about
scope is not.

So a well-formed identifier we do not hold gets an answer that says which of
these is true, and hands over whatever Umbra does know.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Identifier:
    """A recognised identifier and where its authority lives."""

    kind: str
    """cve · rfc · cwe · capec · attack"""
    canonical: str
    """Normalised form — 'CVE-2014-3566', 'RFC7231', 'CWE-79'."""
    upstream_url: str
    """Where the authoritative record lives, always."""
    scope_note: str = ""
    """Why the corpus may legitimately not hold it."""
    extra: dict[str, Any] = field(default_factory=dict)


_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("cve", re.compile(r"^\s*(CVE)[-\s]?(\d{4})[-\s]?(\d{4,7})\s*$", re.I)),
    ("cwe", re.compile(r"^\s*(CWE)[-\s]?(\d{1,4})\s*$", re.I)),
    ("capec", re.compile(r"^\s*(CAPEC)[-\s]?(\d{1,4})\s*$", re.I)),
    ("attack", re.compile(r"^\s*(T)(\d{4})(?:\.(\d{3}))?\s*$", re.I)),
    ("rfc", re.compile(r"^\s*(?:RFC)[-\s]?0*(\d{1,5})\s*$", re.I)),
    ("d3fend", re.compile(r"^\s*(D3)[-\s]?([A-Z]{2,8})\s*$", re.I)),
]

#: Why the corpus legitimately stops short, per identifier kind. Stated in the
#: answer so "not here" never reads as "not real".
SCOPE = {
    "cve": (
        "The wiki carries the CISA KEV catalogue — vulnerabilities known to be "
        "exploited — not all 384,910 published CVEs. Absence here means it is "
        "not in KEV, not that it does not exist."
    ),
    "rfc": (
        "The wiki carries a curated RFC set covering the protocols Umbra's "
        "collectors touch, not all 9,834 RFCs. Absence here is scope, not "
        "nonexistence."
    ),
    "cwe": "The wiki carries the full MITRE CWE list; a gap here is worth reporting.",
    "capec": ("The wiki carries the CAPEC attack-pattern catalogue "
              "(deprecated patterns excluded); a gap here is worth reporting."),
    "attack": "The wiki carries MITRE ATT&CK techniques; a gap here is worth reporting.",
    "d3fend": (
        "The wiki carries the MITRE D3FEND countermeasure catalogue; a gap here "
        "is worth reporting."
    ),
}


def recognise(query: str) -> Identifier | None:
    """Is this a well-formed identifier? None when it is free text."""
    text = (query or "").strip()
    if not text:
        return None

    for kind, pattern in _PATTERNS:
        m = pattern.match(text)
        if not m:
            continue

        if kind == "cve":
            canonical = f"CVE-{m.group(2)}-{m.group(3)}"
            return Identifier(
                kind, canonical,
                f"https://nvd.nist.gov/vuln/detail/{canonical}",
                SCOPE["cve"],
            )
        if kind == "cwe":
            num = int(m.group(2))
            return Identifier(
                kind, f"CWE-{num}",
                f"https://cwe.mitre.org/data/definitions/{num}.html",
                SCOPE["cwe"],
            )
        if kind == "capec":
            num = int(m.group(2))
            return Identifier(
                kind, f"CAPEC-{num}",
                f"https://capec.mitre.org/data/definitions/{num}.html",
                SCOPE["capec"],
            )
        if kind == "attack":
            tid = f"T{m.group(2)}" + (f".{m.group(3)}" if m.group(3) else "")
            path = tid.replace(".", "/")
            return Identifier(
                kind, tid, f"https://attack.mitre.org/techniques/{path}/",
                SCOPE["attack"],
            )
        if kind == "d3fend":
            ident_id = f"D3-{m.group(2).upper()}"
            return Identifier(
                kind, ident_id,
                f"https://d3fend.mitre.org/technique/{ident_id}/",
                SCOPE["d3fend"],
            )
        if kind == "rfc":
            num = int(m.group(1))
            # RFC numbering is sequential and currently ends around 9,834.
            # Anything far beyond that is a typo, not a document — and saying
            # so is more useful than a polite "no results".
            plausible = 1 <= num <= 9999
            return Identifier(
                kind, f"RFC{num}",
                f"https://www.rfc-editor.org/info/rfc{num}",
                SCOPE["rfc"],
                extra={"plausible": plausible, "number": num},
            )
    return None


def explain_miss(ident: Identifier, *, epss: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the answer for a recognised identifier the corpus does not hold.

    `epss` is passed in rather than looked up here so this module stays pure and
    the caller owns the lake handle.
    """
    if ident.kind == "rfc" and not ident.extra.get("plausible", True):
        return {
            "held": False,
            "verdict": "not_a_document",
            "canonical": ident.canonical,
            "headline": f"{ident.canonical} does not appear to exist.",
            "detail": (
                "RFC numbers are sequential and currently reach about 9,834. "
                f"{ident.canonical} is beyond that, so this is most likely a typo."
            ),
            "upstream_url": ident.upstream_url,
            "known": [],
        }

    known: list[str] = []
    if ident.kind == "cve" and epss:
        # The wiki does not hold it — but Umbra is not ignorant of it, and
        # saying "no hits" while a neighbouring lake holds a 0.99999 score
        # would be the failure this whole module exists to prevent.
        known.append(
            f"EPSS {epss['score']:.5f} ({epss['band']}) — {epss['meaning']}. "
            f"Model {epss['model_version']}, scored {epss['score_date']}."
        )
    elif ident.kind == "cve":
        known.append(
            "No EPSS score either — run `umbra epss sync` if that lake is empty. "
            "Unscored is not low."
        )

    return {
        "held": False,
        "verdict": "outside_scope",
        "canonical": ident.canonical,
        "headline": f"{ident.canonical} is not in this corpus — that is scope, not absence of the thing.",
        "detail": ident.scope_note,
        "upstream_url": ident.upstream_url,
        "known": known,
    }
