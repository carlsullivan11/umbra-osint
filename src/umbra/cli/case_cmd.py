"""Case lifecycle CLI: create/list/seed, run, score, profile, entities, graph, audit.

This wires the documented CLI workflow (README "Quick start (CLI)" /
"Operator validation loop") onto the existing, already-tested primitives —
`Repository`, `Orchestrator`, `score_case`, `write_profile`/`export_graphml`.
No new business logic: every command below is a thin call into code the web
UI and `intent` already exercise.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.models import EntityIn, EntityType
from umbra.core.orchestrator import Orchestrator
from umbra.core.scoring import render_score_report, score_case
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.export.profile import export_graphml, write_profile
from umbra.cli.run_summary import render_run_summary

case_app = typer.Typer(help="Case management")

_BASES = ["own_asset", "client_engagement", "public_cti", "training_lab", "other"]


def _repo() -> tuple[Repository, any]:
    settings = get_settings()
    init_db(settings)
    session = get_session()
    return Repository(session, settings.raw_dir), session


@case_app.command("export")
def case_export(
    case_id: str = typer.Argument(..., help="Case id"),
    out: Optional[Path] = typer.Option(None, "-o", "--out", help="Write JSON here"),
) -> None:
    """Export a complete case bundle as JSON (entities, edges, evidence, runs)."""
    import json

    from umbra.export.bundle import build_bundle

    repo, session = _repo()
    try:
        bundle = build_bundle(repo, case_id)
        if bundle is None:
            rprint(f"[red]no such case[/red]: {case_id}")
            raise typer.Exit(code=1)
        text = json.dumps(bundle, indent=2)
        if out:
            Path(out).write_text(text, encoding="utf-8")
            rprint(f"[green]wrote[/green] {out} "
                   f"({len(bundle['entities'])} entities, {len(bundle['evidence'])} evidence)")
        else:
            print(text)
    finally:
        session.close()


@case_app.command("delete")
def case_delete(
    case_id: str = typer.Argument(..., help="Case id"),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation prompt"),
) -> None:
    """Delete a case, its graph, its evidence and its raw files. Permanent."""
    repo, session = _repo()
    try:
        case = repo.get_case(case_id)
        if case is None:
            rprint(f"[red]no such case[/red]: {case_id}")
            raise typer.Exit(code=1)
        if not yes:
            typer.confirm(f"Permanently delete {case_id} ({case.name})?", abort=True)
        report = repo.delete_case(case_id, reason="cli")
        rprint(f"[green]deleted[/green] {case_id}: " + ", ".join(
            f"{v} {k}" for k, v in (report or {}).items()))
    finally:
        session.close()


@case_app.command("purge")
def case_purge(
    days: Optional[int] = typer.Option(
        None, "--days",
        help="Retention window; defaults to UMBRA_CASE_RETENTION_DAYS (0 = keep everything)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="List what would go, delete nothing"),
) -> None:
    """Delete cases older than the retention window.

    Zero means *disabled*, not "everything is older than zero days". The sweep
    is opt-in so a self-hosted upgrade never silently destroys someone's work;
    the hosted service sets `UMBRA_CASE_RETENTION_DAYS`.
    """
    from datetime import timedelta

    from umbra.core.models import utcnow

    settings = get_settings()
    window = settings.case_retention_days if days is None else days
    repo, session = _repo()
    try:
        if not window or window <= 0:
            rprint("[yellow]retention disabled[/yellow] "
                   "(UMBRA_CASE_RETENTION_DAYS=0) — nothing purged")
            return
        if dry_run:
            cutoff = utcnow() - timedelta(days=window)
            stale = [c for c in repo.list_cases() if c.created_at < cutoff]
            rprint(f"[cyan]{len(stale)}[/cyan] case(s) older than {window}d would be deleted")
            for c in stale[:50]:
                rprint(f"  {c.id}  {c.created_at:%Y-%m-%d}")
            return
        removed = repo.purge_cases_older_than(window)
        rprint(f"[green]purged[/green] {len(removed)} case(s) older than {window}d")
        # A phone lookup is not a report: rows nobody reported are search
        # residue, and keeping them would make the table a log of every number
        # anyone typed. Reported numbers are never touched here.
        from umbra.phone import store as phone_store

        dropped = phone_store.purge_unreported(repo.session)
        if dropped:
            rprint(f"[green]purged[/green] {dropped} unreported phone lookup(s)")
        # A listing is a claim about now: numbers get reassigned, so one nobody
        # has reported in months comes off the active list. The reports and the
        # delisting stay on record.
        delisted = phone_store.expire_stale_listings(repo.session)
        if delisted:
            rprint(f"[green]delisted[/green] {delisted} stale phone listing(s)")
    finally:
        session.close()


@case_app.command("create")
def case_create(
    name: str = typer.Option(..., "-n", "--name"),
    basis: str = typer.Option(..., "-b", "--basis", help=f"one of: {', '.join(_BASES)}"),
    note: str = typer.Option("", "--note"),
) -> None:
    """Create a new case with a mandatory authorization basis."""
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {_BASES}")
    repo, session = _repo()
    try:
        case = repo.create_case(name, basis, note)
        session.commit()
        rprint(f"[green]Case created[/green] {case.id}  \"{case.name}\" (basis={basis})")
    finally:
        session.close()


@case_app.command("list")
def case_list() -> None:
    """List all cases."""
    repo, session = _repo()
    try:
        cases = repo.list_cases()
        table = Table(title="Cases")
        for col in ("id", "name", "basis", "created", "closed"):
            table.add_column(col)
        for c in cases:
            table.add_row(c.id, c.name, c.authorization_basis,
                          c.created_at.strftime("%Y-%m-%d %H:%M"), str(c.closed))
        rprint(table)
    finally:
        session.close()


@case_app.command("seed")
def case_seed(
    case_id: str = typer.Argument(...),
    etype: str = typer.Option(..., "-t", "--type", help=f"one of: {', '.join(e.value for e in EntityType)}"),
    value: str = typer.Option(..., "-v", "--value"),
    confidence: float = typer.Option(0.95, "--confidence"),
) -> None:
    """Seed a case with a starting entity (domain/ip/email/username/org/person/...)."""
    try:
        et = EntityType(etype)
    except ValueError:
        raise typer.BadParameter(f"type must be one of: {', '.join(e.value for e in EntityType)}")
    repo, session = _repo()
    try:
        case = repo.get_case(case_id)
        if not case:
            rprint(f"[red]Unknown case[/red] {case_id}")
            raise typer.Exit(1)
        ent = repo.seed(case_id, EntityIn(type=et, value=value, confidence=confidence))
        session.commit()
        rprint(f"[green]Seeded[/green] {ent.id} {ent.type}={ent.value}")
    finally:
        session.close()


def run_case(
    case_id: str = typer.Argument(...),
    depth: Optional[int] = typer.Option(None, "-d", "--depth"),
    collectors: Optional[str] = typer.Option(None, "-c", "--collectors", help="comma-separated collector names"),
    max_entities: Optional[int] = typer.Option(None, "--max-entities"),
) -> None:
    """Run the collector orchestrator on a case (BFS pivots; auto-scores after)."""
    repo, session = _repo()
    try:
        cols = [c.strip() for c in collectors.split(",")] if collectors else None
        orch = Orchestrator(repo)
        stats = orch.run(case_id, depth=depth, max_entities=max_entities, collectors=cols)
        session.commit()
        render_run_summary(stats)
    except ValueError as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    finally:
        session.close()


def score_cmd(
    case_id: str = typer.Argument(...),
    dry_run: bool = typer.Option(False, "--dry-run", help="Compute scores without persisting them"),
    out: Optional[Path] = typer.Option(None, "-o", "--out", help="Write the report to a file instead of stdout"),
) -> None:
    """Re-score every entity's confidence on a case (also runs automatically after `umbra run`)."""
    repo, session = _repo()
    try:
        results = score_case(repo, case_id, persist=not dry_run)
        if not dry_run:
            session.commit()
        report = render_score_report(results, case_id)
        if out:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(report, encoding="utf-8")
            rprint(f"[green]Score report[/green] {out}")
        else:
            rprint(report)
    finally:
        session.close()


def profile_cmd(
    case_id: str = typer.Argument(...),
    seed_value: Optional[str] = typer.Option(None, "--seed", help="focus the profile on one seed value"),
) -> None:
    """Write the Markdown subject profile + GraphML export for a case."""
    settings = get_settings()
    repo, session = _repo()
    try:
        prof_path = settings.exports_dir / f"{case_id}_profile.md"
        write_profile(repo, case_id, prof_path, seed_value=seed_value)
        graph_path = settings.exports_dir / f"{case_id}.graphml"
        export_graphml(repo, case_id, graph_path)
        rprint(f"[green]Profile[/green] {prof_path}")
        rprint(f"[green]Graph[/green] {graph_path}")
    finally:
        session.close()


def entities_cmd(
    case_id: str = typer.Argument(...),
    include_merged: bool = typer.Option(False, "--include-merged"),
) -> None:
    """List entities on a case (id, type, value, confidence, band, verification)."""
    repo, session = _repo()
    try:
        ents = repo.list_entities(case_id, include_merged=include_merged)
        table = Table(title=f"Entities — {case_id}")
        for col in ("id", "type", "value", "confidence", "band", "seed", "verified"):
            table.add_column(col)
        for e in sorted(ents, key=lambda x: x.confidence, reverse=True):
            band = (e.props or {}).get("score_band", "-")
            table.add_row(e.id, e.type, e.value[:60], f"{e.confidence:.2f}",
                          band, "✓" if e.is_seed else "", e.verification)
        rprint(table)
        rprint(f"[dim]{len(ents)} entities[/dim]")
    finally:
        session.close()


def graph_cmd(
    case_id: str = typer.Argument(...),
) -> None:
    """Export a case's entity graph as GraphML."""
    settings = get_settings()
    repo, session = _repo()
    try:
        path = export_graphml(repo, case_id, settings.exports_dir / f"{case_id}.graphml")
        rprint(f"[green]Graph exported[/green] {path}")
    finally:
        session.close()


def audit_cmd(
    case_id: str = typer.Argument(...),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """Show the audit log for a case."""
    repo, session = _repo()
    try:
        events = repo.list_audit(case_id)  # newest first
        table = Table(title=f"Audit log — {case_id}")
        for col in ("ts", "action", "detail"):
            table.add_column(col)
        for ev in events[:limit]:
            table.add_row(ev.ts.strftime("%Y-%m-%d %H:%M:%S"), ev.action, str(ev.detail)[:100])
        rprint(table)
    finally:
        session.close()
