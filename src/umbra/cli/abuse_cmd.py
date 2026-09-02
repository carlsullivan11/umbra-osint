"""`umbra abuse` — owned abuse.ch malware infrastructure lake.

Bulk feeds (URLhaus, ThreatFox, SSLBL, Feodo) are key-free. Sync once into the
local lake; collectors `malware_infra` and `sslbl_cert` read it offline.

Egress goes through `GuardedClient` so feed URLs are SSRF-checked like every
other collector hop.
"""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake import abusech
from umbra.lake.store import LakeStore

abuse_app = typer.Typer(help="Owned abuse.ch lake (URLhaus / ThreatFox / SSLBL / Feodo)")


def _http() -> GuardedClient:
    s = get_settings()
    return GuardedClient(
        timeout=s.request_timeout_s,
        headers={"User-Agent": s.user_agent},
    )


@abuse_app.command("sync")
def sync_cmd(
    feed: str = typer.Option(
        "all",
        "--feed",
        "-f",
        help="One of urlhaus, threatfox, sslbl, feodo, or 'all'",
    ),
) -> None:
    """Fetch abuse.ch bulk feeds into the owned lake (key-free)."""
    settings = get_settings()
    store = LakeStore.from_settings(settings)
    feeds = list(abusech.FEEDS) if feed == "all" else [feed]
    unknown = [f for f in feeds if f not in abusech.FEEDS]
    if unknown:
        rprint(f"[red]unknown feed(s)[/red]: {', '.join(unknown)}")
        rprint(f"known: {', '.join(abusech.FEEDS)}")
        raise typer.Exit(code=2)

    rprint(f"[cyan]syncing[/cyan] {', '.join(feeds)} …")
    with _http() as http:
        counts = abusech.sync(store, http, feeds=feeds)

    table = Table(title="abuse.ch lake sync")
    table.add_column("feed")
    table.add_column("rows", justify="right")
    table.add_column("synced_at")
    failed = 0
    for name in feeds:
        n = counts.get(name, 0)
        when = store.abuse_feed_synced_at(name) or "—"
        if n == 0 and when == "—":
            failed += 1
            table.add_row(name, "[red]0[/red]", "[red]failed / not marked synced[/red]")
        else:
            table.add_row(name, f"{n:,}", (when or "")[:19])
    rprint(table)
    if failed:
        rprint(
            f"[yellow]{failed} feed(s) produced no sync mark[/yellow] "
            f"— collectors will report those feeds as unchecked, not clean"
        )
    else:
        rprint("[green]done[/green] — `malware_infra` / `sslbl_cert` can read the lake offline")


@abuse_app.command("status")
def status_cmd() -> None:
    """Show which abuse.ch feeds have been synced into the owned lake."""
    store = LakeStore.from_settings(get_settings())
    table = Table(title="abuse.ch lake status")
    table.add_column("feed")
    table.add_column("synced_at")
    for name in abusech.FEEDS:
        when = store.abuse_feed_synced_at(name)
        if when:
            table.add_row(name, when[:19])
        else:
            table.add_row(name, "[dim]never[/dim]")
    rprint(table)
    rprint("[dim]fill with:[/dim] umbra abuse sync")
