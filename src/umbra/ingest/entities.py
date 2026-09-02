"""Text, CSV and JSON → seeds, by reusing the extractor the intent box uses.

There is no second extractor here on purpose. `umbra.intent.extract` already
knows what an IP, a domain, an email, a URL, a MAC and a phone number look like,
and it already knows which of those are too weak to arm by default. A file of
indicators is the intent box with more lines in it.

What this module adds is structure-awareness, so the *shape* of the file does
not become the finding: a CSV's column headers are not indicators, and a JSON
document's keys are not indicators. Feeding the raw bytes through would mostly
work and would occasionally seed a case with `first_seen`.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from umbra.intent.extract import extract_hits
from umbra.intent.schema import AnalyzeRequest, IntentPlan
from umbra.intent.plan import analyze_intent


def _has_entities(text: str) -> bool:
    try:
        return bool(extract_hits(text))
    except Exception:  # noqa: BLE001
        return False


def csv_values(text: str) -> tuple[str, list[str]]:
    """Data cells only, plus a note about the header row that was dropped."""
    notes: list[str] = []
    try:
        sample = text[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel  # type: ignore[assignment]
        rows = list(csv.reader(io.StringIO(text), dialect))
    except Exception:  # noqa: BLE001 - a malformed CSV is still text
        return text, ["could not parse as CSV; read it as plain text instead"]

    if not rows:
        return "", notes

    # Drop the header row only when it holds no indicators of its own. A real
    # export sometimes puts data in row 1, and dropping it would silently lose
    # an indicator.
    body = rows
    header = " ".join(rows[0])
    if len(rows) > 1 and not _has_entities(header):
        body = rows[1:]
        notes.append(f"treated row 1 as column headers ({header[:120]})")

    return "\n".join(" ".join(cell for cell in row) for row in body), notes


def json_values(text: str) -> tuple[str, list[str]]:
    """Leaf values only. Keys name the schema; they are not indicators."""
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return text, ["not valid JSON; read it as plain text instead"]

    out: list[str] = []

    def walk(node: Any, depth: int = 0) -> None:
        if depth > 30 or len(out) > 100_000:
            return
        if isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for value in node:
                walk(value, depth + 1)
        elif isinstance(node, str):
            out.append(node)
        elif isinstance(node, (int, float)):
            out.append(str(node))

    walk(document)
    return "\n".join(out), []


def plan_from_text(
    text: str,
    *,
    case_name: str,
    authorization_basis: str = "training_lab",
    authorization_note: str = "",
    depth: int = 1,
    max_entities: int = 200,
) -> IntentPlan:
    """Run the deterministic intent extractor over a block of text.

    `use_llm=False` unconditionally: an uploaded file can be large and can be
    somebody else's confidential data, and neither belongs in a prompt to an
    external model.
    """
    plan = analyze_intent(AnalyzeRequest(
        text=text,
        authorization_basis=authorization_basis,  # type: ignore[arg-type]
        authorization_note=authorization_note,
        case_name=case_name,
        default_depth=depth,
        max_entities=max_entities,
        use_llm=False,
    ))
    plan.case_name = case_name[:120]
    return plan
