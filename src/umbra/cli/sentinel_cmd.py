"""CLI: `umbra sentinel` — who has been scanning us, and what they are.

Run on a timer in production (`umbra-sentinel.timer`). `status` and `list` are
read-only and safe to run any time; `run` is the one that opens cases.
"""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra import sentinel
from umbra.core.config import get_settings
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db

sentinel_app = typer.Typer(help="Fingerprint the hosts that scan Umbra (passive).")


def _repo():
    settings = get_settings()
    init_db(settings)
    session = get_session()
    return Repository(session, settings.raw_dir), session


@sentinel_app.command("list")
def list_candidates(
    min_hits: int = typer.Option(sentinel.MIN_HITS, "--min-hits"),
    window: int = typer.Option(sentinel.WINDOW_HOURS, "--window",
                               help="Hours to look back"),
) -> None:
    """Show the addresses that would be fingerprinted, without doing it."""
    repo, session = _repo()
    try:
        found = sentinel.candidates(session, min_hits=min_hits,
                                    window_hours=window)
        if not found:
            rprint(f"[dim]No address has been seen scanning "
                   f"{min_hits}+ times in the last {window}h.[/dim]")
            return
        table = Table("Address", "Hits", "Why", "Paths", "Last seen",
                      title=f"Scanning us ({window}h)")
        for c in found:
            table.add_row(c["ip"], str(c["hits"]), ", ".join(c["reasons"]),
                          ", ".join(c["paths"][:3])[:60],
                          (c["last_seen"] or "")[:19])
        rprint(table)
    finally:
        session.close()


@sentinel_app.command("run")
def run_tick(
    min_hits: int = typer.Option(sentinel.MIN_HITS, "--min-hits"),
    window: int = typer.Option(sentinel.WINDOW_HOURS, "--window"),
    limit: int = typer.Option(sentinel.MAX_PER_TICK, "--limit"),
    purge: bool = typer.Option(True, "--purge/--no-purge",
                               help="Also drop observations past retention"),
) -> None:
    """Open a case per new scanning address and run the passive lookups."""
    repo, session = _repo()
    try:
        result = sentinel.tick(repo, min_hits=min_hits, window_hours=window,
                               max_per_tick=limit)
        rprint(f"[green]Fingerprinted[/green] {result['fingerprinted']} of "
               f"{result['candidates']} candidate address(es)")
        for case_id in result["cases"]:
            rprint(f"  • {case_id}")
        if result["deferred"]:
            rprint(f"[yellow]{result['deferred']} more were over the per-run "
                   f"cap and will be picked up next time.[/yellow]")
        if purge:
            removed = sentinel.purge_observations(session)
            if removed:
                rprint(f"[dim]Purged {removed} observation(s) past "
                       f"{sentinel.PURGE_DAYS} days.[/dim]")
    finally:
        session.close()


@sentinel_app.command("status")
def status() -> None:
    """What the sentinel is configured to do, and what it is holding."""
    from sqlalchemy import func, select

    from umbra.db.schema import SentinelObservation

    repo, session = _repo()
    try:
        held = session.scalar(
            select(func.count()).select_from(SentinelObservation)) or 0
        distinct = session.scalar(
            select(func.count(func.distinct(SentinelObservation.ip)))) or 0
        rprint(f"Observations held: [bold]{held}[/bold] across "
               f"[bold]{distinct}[/bold] address(es)")
        rprint(f"Threshold: {sentinel.MIN_HITS} hits in "
               f"{sentinel.WINDOW_HOURS}h · cooldown {sentinel.COOLDOWN_DAYS}d "
               f"· cap {sentinel.MAX_PER_TICK}/run · retention "
               f"{sentinel.PURGE_DAYS}d")
        rprint("Collectors (all passive): " + ", ".join(sentinel.COLLECTORS))
        rprint("[dim]Nothing is ever sent to the address being looked up.[/dim]")
    finally:
        session.close()
