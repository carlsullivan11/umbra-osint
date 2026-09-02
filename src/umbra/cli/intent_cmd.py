"""CLI: umbra intent — Phase I deterministic dry-run (+ optional confirm to case)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from umbra.intent.plan import analyze_intent
from umbra.intent.schema import AnalyzeRequest, IntentPlan

# Single command group-less style is registered from main as @app.command
# This module exposes `register(app)` and the core handler.


def _print_plan(plan: IntentPlan) -> None:
    if plan.refuse:
        rprint(f"[red bold]REFUSE[/red bold]: {plan.refuse_reason}")
    rprint(
        Panel(
            f"[bold]{plan.case_name}[/bold]\n"
            f"{plan.summary}\n"
            f"basis={plan.authorization_basis} · playbook={plan.playbook} · "
            f"depth={plan.depth} · plan_id={plan.plan_id}\n"
            f"extractor={plan.extractor}",
            title="IntentPlan",
        )
    )
    flags = plan.flags.model_dump()
    on = [k for k, v in flags.items() if v]
    rprint(f"Flags: {', '.join(on) if on else '(none)'}")
    table = Table("In", "Type", "Value", "Conf", "Notes")
    for s in plan.seeds:
        table.add_row(
            "yes" if s.include else "no",
            s.type.value,
            s.value[:48],
            f"{s.confidence:.2f}",
            (s.notes or "")[:40],
        )
    rprint(table)
    rprint(f"Collectors ({len(plan.collectors)}): " + ", ".join(plan.collectors))
    if plan.warnings:
        rprint("[yellow]Warnings:[/yellow]")
        for w in plan.warnings:
            rprint(f"  • {w}")
    if plan.clarifying_questions:
        rprint("[cyan]Questions:[/cyan]")
        for q in plan.clarifying_questions:
            rprint(f"  • {q}")


def _load_text(text: Optional[str], file: Optional[str]) -> str:
    if file:
        return Path(file).read_text(encoding="utf-8")
    if text:
        return text
    raise typer.BadParameter("Provide TEXT or --file")


def intent_command(
    text: Optional[str] = typer.Argument(None, help="Free-text intent"),
    file: Optional[str] = typer.Option(None, "--file", "-f", help="Read intent from file"),
    basis: str = typer.Option(
        "training_lab",
        "--basis",
        "-b",
        help="own_asset|client_engagement|public_cti|training_lab|other",
    ),
    note: str = typer.Option("", "--note", "-n"),
    name: Optional[str] = typer.Option(None, "--name", help="Case name override"),
    depth: int = typer.Option(1, "--depth", "-d"),
    json_out: bool = typer.Option(False, "--json", help="Print IntentPlan JSON"),
    out: Optional[str] = typer.Option(None, "--out", "-o", help="Write plan JSON to path"),
    confirm: bool = typer.Option(
        False,
        "--confirm",
        help="Create case, seed included entities, run collectors",
    ),
    llm: bool = typer.Option(
        False,
        "--llm",
        help="Force LLM enrich (needs UMBRA_LLM_BASE_URL + UMBRA_LLM_MODEL)",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Force deterministic-only (ignore UMBRA_LLM_ENABLED)",
    ),
) -> None:
    """Analyze free text → IntentPlan (dry-run). Use --confirm to execute."""
    raw = _load_text(text, file)
    allowed = {"own_asset", "client_engagement", "public_cti", "training_lab", "other"}
    if basis not in allowed:
        raise typer.BadParameter(f"basis must be one of {sorted(allowed)}")
    if llm and no_llm:
        raise typer.BadParameter("Use only one of --llm / --no-llm")

    use_llm: bool | None
    if llm:
        use_llm = True
    elif no_llm:
        use_llm = False
    else:
        use_llm = None

    req = AnalyzeRequest(
        text=raw,
        authorization_basis=basis,  # type: ignore[arg-type]
        authorization_note=note,
        case_name=name,
        default_depth=depth,
        use_llm=use_llm,
    )
    plan = analyze_intent(req)

    if json_out:
        rprint(plan.model_dump_json(indent=2))
    else:
        _print_plan(plan)

    if out:
        path = Path(out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
        rprint(f"[green]Wrote plan[/green] {path}")

    if not confirm:
        rprint("[dim]Dry-run only. Re-run with --confirm to create case and execute.[/dim]")
        return

    from umbra.cli.plan_exec import confirm_and_run

    confirm_and_run(plan, source="cli", action="intent.confirm")
