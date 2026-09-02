"""CLI: `umbra feed` — ingest, list, sources (stage S14 / F1)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.feeds.ingest import ingest_sources, seed_default_sources

feed_app = typer.Typer(help="Cyber news feed: ingest RSS sources, list recent items.")


def _repo() -> Repository:
    settings = get_settings()
    init_db(settings)
    return Repository(get_session(), settings.raw_dir)


@feed_app.command("ingest")
def feed_ingest(
    seed: bool = typer.Option(True, "--seed/--no-seed", help="Ensure the default source pack exists"),
) -> None:
    """Poll every enabled source once and store new items."""
    repo = _repo()
    if seed:
        added = seed_default_sources(repo)
        if added:
            rprint(f"[green]seeded[/green] {added} default source(s)")
    sources = repo.list_feed_sources()
    if not sources:
        rprint("[yellow]No sources configured.[/yellow]")
        raise typer.Exit(1)
    stats = ingest_sources(repo, sources)
    rprint(
        f"[green]ingest[/green] sources={stats['sources']} fetched={stats['fetched']} "
        f"new={stats['new']} dupes={stats['duplicates']} errors={stats['errors']} "
        f"skipped={stats['skipped']}"
    )
    if stats["errors"]:
        # Not a failure: sources fail independently and the run still stored the
        # healthy ones. Surfaced so a timer log shows it.
        rprint("[yellow]some sources failed — see `umbra feed sources`[/yellow]")


@feed_app.command("list")
def feed_list(
    hours: int = typer.Option(24, "--hours", "-h", help="Window to show"),
    limit: int = typer.Option(30, "--limit", "-n"),
) -> None:
    """Recent feed items (default: last 24h)."""
    repo = _repo()
    since = datetime.now(tz=timezone.utc) - timedelta(hours=max(1, hours))
    items = repo.list_feed_items(since=since, limit=limit)
    if not items:
        total = repo.count_feed_items()
        if total:
            rprint(f"[dim]No items in the last {hours}h — {total} stored overall "
                   f"(advisories are often days old). Try `--hours 168`.[/dim]")
        else:
            rprint("[dim]No items stored. Run `umbra feed ingest`.[/dim]")
        return
    table = Table(title=f"Cyber news — last {hours}h")
    table.add_column("published", style="dim")
    table.add_column("source", style="dim")
    table.add_column("title")
    for i in items:
        table.add_row(i.published_at.strftime("%m-%d %H:%M"), i.source.name, i.title[:90])
    rprint(table)
    rprint("[dim]Signals, not findings — leads to check, not verified facts.[/dim]")


@feed_app.command("sources")
def feed_sources(
    seed: bool = typer.Option(True, "--seed/--no-seed", help="Ensure the default pack exists"),
) -> None:
    """List configured sources and their last poll result."""
    repo = _repo()
    if seed:
        seed_default_sources(repo)
    table = Table(title="Feed sources")
    for col in ("name", "url", "enabled", "last poll", "status", "trust"):
        table.add_column(col)
    for s in repo.list_feed_sources():
        table.add_row(
            s.name, s.url, "yes" if s.enabled else "no",
            s.last_polled_at.strftime("%Y-%m-%d %H:%M") if s.last_polled_at else "—",
            s.last_status or "never", f"{s.trust:.2f}",
        )
    rprint(table)


@feed_app.command("mute")
def feed_mute(source: str = typer.Argument(..., help="Source URL or exact name")) -> None:
    """Stop polling a source (it keeps its stored items)."""
    if not _repo().set_feed_source_enabled(source, False):
        rprint(f"[red]no such source:[/red] {source}")
        raise typer.Exit(1)
    rprint(f"[yellow]muted[/yellow] {source}")


@feed_app.command("unmute")
def feed_unmute(source: str = typer.Argument(..., help="Source URL or exact name")) -> None:
    """Resume polling a source."""
    if not _repo().set_feed_source_enabled(source, True):
        rprint(f"[red]no such source:[/red] {source}")
        raise typer.Exit(1)
    rprint(f"[green]unmuted[/green] {source}")
