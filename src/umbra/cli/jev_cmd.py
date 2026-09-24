"""CLI: `umbra jev` — Jev second-opinion verdicts (docs/JEV.md, slice J1).

- `status`     — is it configured, which model, today's token use.
- `state`      — print the exact state Umbra *would* send for a case's
                 entities. Offline: no key needed, no network. This is how you
                 check what leaves the machine before anything does.
- `adjudicate` — ask Jev about a case's IP/domain/URL entities and store the
                 answers at `props.jev`. Opt-in: needs UMBRA_JEV_ENABLED=true
                 and UMBRA_OPENROUTER_API_KEY (default provider).
"""
from __future__ import annotations

import json
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.jev.adjudicate import adjudicate_case
from umbra.jev.client import JevClient
from umbra.jev.facts import facts_from_props, render_state
from umbra.jev.questions import for_entity_type

jev_app = typer.Typer(help="Jev (TypeSafe AI) second-opinion verdicts — see docs/JEV.md.")


def _repo():
    from umbra.cli.case_cmd import _repo as case_repo
    return case_repo()


@jev_app.command("status")
def jev_status() -> None:
    """Show whether Jev is enabled and configured."""
    s = get_settings()
    client = JevClient.from_settings(s)
    table = Table(title="Jev")
    table.add_column("field")
    table.add_column("value")
    table.add_row("enabled", "yes" if s.jev_enabled else "no (UMBRA_JEV_ENABLED)")
    key_var = "UMBRA_OPENROUTER_API_KEY" if s.jev_provider == "openrouter" else "UMBRA_TYPESAFE_API_KEY"
    table.add_row("provider", s.jev_provider)
    table.add_row("endpoint", client.url)
    table.add_row("api key", "set" if s.jev_api_key else f"not set ({key_var})")
    table.add_row("model", s.jev_model)
    table.add_row("min confidence", f"{s.jev_min_confidence:.2f}")
    budget = s.jev_daily_token_budget or "unlimited"
    table.add_row("tokens today", f"{client.tokens_used_today()} / {budget}")
    rprint(table)


@jev_app.command("state")
def jev_state(
    case_id: str = typer.Argument(..., help="Case id"),
    value: Optional[str] = typer.Option(None, "--entity", help="Only this entity value"),
) -> None:
    """Print the state that would be sent for each in-scope entity. Offline."""
    repo, session = _repo()
    try:
        shown = 0
        for ent in repo.list_entities(case_id):
            if not for_entity_type(ent.type) or (value and ent.value != value):
                continue
            facts = facts_from_props(ent.type, ent.value, dict(ent.props or {}))
            rprint(f"[bold]── {ent.type} {ent.value}[/bold]")
            print(render_state(facts))
            print()
            shown += 1
        if not shown:
            rprint("[yellow]no IP/domain/URL entities in scope[/yellow]")
    finally:
        session.close()


@jev_app.command("adjudicate")
def jev_adjudicate(
    case_id: str = typer.Argument(..., help="Case id"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Ask, but do not store answers"),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable rows"),
) -> None:
    """Ask Jev about a case's IP/domain/URL entities."""
    s = get_settings()
    if not s.jev_configured:
        rprint("[red]Jev is off.[/red] Set UMBRA_JEV_ENABLED=true and "
               "UMBRA_OPENROUTER_API_KEY (or UMBRA_JEV_PROVIDER=typesafe + "
               "UMBRA_TYPESAFE_API_KEY). Check what would be sent first: "
               f"`umbra jev state {case_id}`.")
        raise typer.Exit(2)
    client = JevClient.from_settings(s)
    repo, session = _repo()
    try:
        if repo.get_case(case_id) is None:
            rprint(f"[red]no such case[/red] {case_id}")
            raise typer.Exit(1)
        rows = adjudicate_case(repo, case_id, client,
                               min_confidence=s.jev_min_confidence, persist=not dry_run)
        if not dry_run:
            session.commit()
    finally:
        session.close()

    if as_json:
        print(json.dumps(rows, indent=2, default=str))
        return
    table = Table(title=f"Jev adjudication · {case_id}")
    for col in ("entity", "verdict", "role", "conf", "flags"):
        table.add_column(col)
    for r in rows:
        if "error" in r:
            table.add_row(r["value"], "[dim]unchanged[/dim]", "—", "—", f"[yellow]{r['error']}[/yellow]")
            continue
        verdict = r["verdict"]
        if r["ai_assessed"]:
            verdict += " [magenta](AI)[/magenta]"
        flags = [f for f in ("injection_flag", "disagreement") if r.get(f)]
        if not r["public"]:
            flags.append("low-confidence")
        conf = f"{r['role_confidence']:.2f}" if r.get("role_confidence") is not None else "—"
        table.add_row(r["value"], verdict, r.get("role") or "—", conf, ", ".join(flags))
    rprint(table)
