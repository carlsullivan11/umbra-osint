"""Render a finished run the way a person reads it.

Every command that runs the orchestrator used to end with

    rprint(f"[green]Run complete[/green] {stats}")

which prints a Python dict — including a `notes` list that, on a routine
three-seed run, was 33 strings long. Rich then soft-wraps it into a paragraph
with no line breaks between conditions. The information was all there and none
of it was legible.

Same numbers, one shape: what was found, then what qualifies it.
"""
from __future__ import annotations

from typing import Any

from rich import print as rprint

from umbra.core.notes import KIND_BLURB, KIND_LABEL, KIND_ORDER, NoteKind, summarize_by_kind

# The counters worth a headline, in the order they answer "did this work?".
_HEADLINE = [
    ("entities_added", "new"),
    ("scored_entities", "scored"),
    ("score_high", "high"),
    ("processed", "processed"),
    ("collector_runs", "collector runs"),
    ("errors", "errors"),
]

_KIND_STYLE = {
    NoteKind.LIMIT: "yellow",
    NoteKind.SOURCE_FAILED: "yellow",
    NoteKind.NOT_CONFIGURED: "cyan",
    NoteKind.RESULT: "dim",
}


def render_run_summary(stats: dict[str, Any], *, title: str = "Run complete") -> None:
    """Print the headline counters, then the notes grouped by what they mean."""
    parts = []
    for key, label in _HEADLINE:
        value = stats.get(key)
        if value is None:
            continue
        # Zero errors is worth saying; zero of anything else is just noise.
        if not value and key != "errors":
            continue
        style = "red" if key == "errors" and value else "bold"
        # "1 errors" is the kind of small wrongness that makes a tool feel
        # unfinished.
        text = label[:-1] if value == 1 and label.endswith("s") else label
        parts.append(f"[{style}]{value}[/{style}] {text}")

    rprint(f"\n[green]{title}[/green]  " + " · ".join(parts))

    # Where the wall clock actually went. Three lines, only when something took
    # long enough to be worth saying — a fast run should stay quiet.
    seconds = stats.get("collector_seconds") or {}
    slow = sorted(seconds.items(), key=lambda kv: -kv[1])[:3]
    if slow and slow[0][1] >= 5:
        total = sum(seconds.values())
        parts = " · ".join(f"{name} {secs:.0f}s" for name, secs in slow)
        rprint(f"[dim]{total:.0f}s in collectors — slowest: {parts}[/dim]")

    notes = stats.get("notes") or []
    if not notes:
        return

    by_kind = summarize_by_kind(list(notes))
    total = len(notes)
    distinct = sum(len(v) for v in by_kind.values())
    if total > distinct:
        rprint(f"[dim]{total} notes, {distinct} distinct conditions[/dim]")

    for kind in KIND_ORDER:
        groups = by_kind.get(kind)
        if not groups:
            continue
        style = _KIND_STYLE[kind]
        rprint(f"\n  [{style}]{KIND_LABEL[kind]}[/{style}] [dim]— {KIND_BLURB[kind]}[/dim]")
        for g in groups:
            # `x4` earns its place only when it is more than one.
            times = f" [dim]x{g.count}[/dim]" if g.count > 1 else ""
            rprint(f"    • {g.message}{times}")
            if g.detail:
                rprint(f"      [dim]{g.detail}[/dim]")
            if g.remedy:
                rprint(f"      [dim]fix:[/dim] [bold]{g.remedy}[/bold]")
