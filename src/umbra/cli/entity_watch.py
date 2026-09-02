"""CLI: entity verify/merge + watchlist monitor."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.monitor import check_all_watches, check_watch_item, render_monitor_report
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db

entity_app = typer.Typer(help="Entity verification and merge")
watch_app = typer.Typer(help="Watchlist monitoring (backend cron-friendly)")


def _repo() -> tuple[Repository, any]:
    settings = get_settings()
    init_db(settings)
    session = get_session()
    return Repository(session, settings.raw_dir), session


@entity_app.command("verify")
def entity_verify(
    entity_id: str = typer.Argument(...),
    status: str = typer.Option(..., "--status", "-s", help="true|false|unknown|disputed"),
    note: str = typer.Option("", "--note", "-n"),
) -> None:
    """Mark an entity true/false for operator validation loops."""
    repo, session = _repo()
    try:
        ent = repo.set_verification(entity_id, status, note)
        rprint(f"[green]Verified[/green] {ent.id} {ent.norm_key} → {ent.verification}")
    finally:
        session.close()


@entity_app.command("merge")
def entity_merge(
    case_id: str = typer.Argument(...),
    keep: str = typer.Option(..., "--keep", help="Entity id to keep"),
    drop: str = typer.Option(..., "--drop", help="Entity id to merge away"),
) -> None:
    """Merge two entities on a case (rewire edges, keep provenance)."""
    repo, session = _repo()
    try:
        ent = repo.merge_entities(case_id, keep, drop)
        rprint(f"[green]Merged[/green] {drop} → {ent.id} ({ent.norm_key})")
    finally:
        session.close()


@entity_app.command("find")
def entity_find(
    case_id: str = typer.Argument(...),
    type: str = typer.Option(..., "--type", "-t"),
    value: str = typer.Option(..., "--value", "-v"),
) -> None:
    repo, session = _repo()
    try:
        ent = repo.find_entity(case_id, type, value)
        if not ent:
            rprint("[yellow]Not found[/yellow]")
            raise typer.Exit(1)
        rprint(
            f"{ent.id}  {ent.norm_key}  conf={ent.confidence:.2f}  "
            f"verify={getattr(ent, 'verification', 'unknown')}  seed={ent.is_seed}"
        )
    finally:
        session.close()


@watch_app.command("add")
def watch_add(
    type: str = typer.Option(..., "--type", "-t", help="domain|email"),
    value: str = typer.Option(..., "--value", "-v"),
    case_id: Optional[str] = typer.Option(None, "--case", "-c"),
    label: str = typer.Option("", "--label"),
) -> None:
    if type not in {"domain", "email"}:
        raise typer.BadParameter("type must be domain or email for monitor checks")
    repo, session = _repo()
    try:
        item = repo.add_watch(type, value, case_id=case_id, label=label)
        rprint(f"[green]Watching[/green] {item.id} {type}:{value}")
    finally:
        session.close()


@watch_app.command("list")
def watch_list() -> None:
    repo, session = _repo()
    try:
        table = Table("ID", "Type", "Value", "Enabled", "Checks", "Last checked")
        for w in repo.list_watch():
            table.add_row(
                w.id,
                w.entity_type,
                w.value,
                "yes" if w.enabled else "no",
                str(w.check_count or 0),
                str(w.last_checked or ""),
            )
        rprint(table)
    finally:
        session.close()


@watch_app.command("check")
def watch_check(
    watch_id: Optional[str] = typer.Option(None, "--id"),
    out: Optional[Path] = typer.Option(None, "--out", "-o"),
) -> None:
    """Run monitor checks (all watches or one). Exit 2 if any changes detected."""
    settings = get_settings()
    repo, session = _repo()
    try:
        if watch_id:
            results = [check_watch_item(repo, settings, watch_id)]
        else:
            results = check_all_watches(repo, settings)
        report = render_monitor_report(results)
        path = out or (settings.data_dir / "exports" / "watch_report.md")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
        rprint(report)
        rprint(f"[green]Wrote[/green] {path}")
        if any((r.get("diff") or {}).get("changed") for r in results):
            raise typer.Exit(2)
    finally:
        session.close()
