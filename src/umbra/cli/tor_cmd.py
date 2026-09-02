"""``umbra tor`` — the owned Tor relay lake."""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.tor import TorLake, describe_flags
from umbra.lake.tor import sync as tor_sync

tor_app = typer.Typer(help="Owned Tor relay consensus (all relays, not just exits).",
                      no_args_is_help=True)


@tor_app.command("sync")
def sync_cmd(force: bool = typer.Option(False, "--force",
                                        help="ignore the 30-minute source limit")) -> None:
    """Refresh the relay consensus into the owned lake."""
    settings = get_settings()
    lake = TorLake.from_settings(settings)
    try:
        with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
            out = tor_sync(http, lake, force=force)
        if not out.get("fetched"):
            rprint(f"[yellow]not fetched[/yellow] — {out.get('reason')}")
        st = lake.status()
        rprint(f"relays [bold]{st['relays']:,}[/bold] · exits {st['exits']:,} · "
               f"guards {st['guards']:,} · bad exits {st['bad_exits']:,}")
        rprint(f"[dim]synced {st['synced_at']}[/dim]")
    finally:
        lake.close()


@tor_app.command("status")
def status_cmd() -> None:
    """What the lake holds."""
    lake = TorLake.from_settings(get_settings())
    try:
        st = lake.status()
        if not st["synced"]:
            rprint("[yellow]Never synced.[/yellow] Run [bold]umbra tor sync[/bold]. "
                   "Until then a lookup is unknown, not 'not a relay'.")
            return
        t = Table(title="Tor relay lake")
        t.add_column("key"); t.add_column("value")
        for k in ("relays", "exits", "guards", "bad_exits", "synced_at"):
            t.add_row(k.replace("_", " "), f"{st[k]:,}" if isinstance(st[k], int) else str(st[k]))
        rprint(t)
    finally:
        lake.close()


@tor_app.command("check")
def check_cmd(ip: str = typer.Argument(..., help="IPv4 address")) -> None:
    """Is this address a Tor relay, and in what role?"""
    lake = TorLake.from_settings(get_settings())
    try:
        if not lake.status()["synced"]:
            rprint("[yellow]unknown[/yellow] — the relay lake has never synced "
                   "(`umbra tor sync`). That is not the same as 'not a relay'.")
            raise typer.Exit(1)
        r = lake.lookup(ip)
        if not r:
            rprint(f"{ip}: not in the current Tor consensus.")
            return
        role = "exit" if r["is_exit"] else "guard" if r["is_guard"] else "middle"
        rprint(f"[bold]{ip}[/bold] — Tor [bold]{role}[/bold] relay"
               + (f" '{r['nickname']}'" if r["nickname"] else ""))
        rprint(f"  flags: {', '.join(describe_flags(r['flags'])) or r['flags']}")
        if r["is_bad_exit"]:
            rprint("  [red]BadExit[/red] — flagged as misbehaving by the directory authorities.")
        else:
            rprint("  [dim]Running a relay is not wrongdoing.[/dim]")
        if not r["is_exit"]:
            rprint("  [dim]A non-exit relay cannot originate traffic to your service; "
                   "seeing it in a log is usually not Tor traffic reaching you.[/dim]")
    finally:
        lake.close()
