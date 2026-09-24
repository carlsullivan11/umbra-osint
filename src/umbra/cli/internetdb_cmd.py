"""``umbra internetdb`` — read Shodan's free InternetDB index for an IPv4.

Lookup only, and deliberately not a scanner. `umbra scan ports` sends packets
and refuses on `public_cti`/`other` bases; this reads an index Shodan already
built and sends nothing to the address, which is why it needs no such gate.
Nothing here may become a way to get scan output without that gate.
"""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.collectors.base import CollectorContext
from umbra.collectors.internetdb import InternetDbCollector
from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

internetdb_app = typer.Typer(
    help="Shodan InternetDB index lookups (no key, no scan).",
    no_args_is_help=True,
)


@internetdb_app.command("lookup")
def internetdb_lookup(
    ip: str = typer.Argument(..., help="Public IPv4 address, e.g. 1.2.3.4"),
) -> None:
    """Show what Shodan's index already holds for an address. Scans nothing."""
    settings = get_settings()
    value = ip.strip()
    try:
        norm_key = entity_key(EntityType.IP, value)
    except ValueError as exc:
        rprint(f"[red]not an IP address:[/red] {value}")
        raise typer.Exit(2) from exc

    entity = Entity(id="cli", case_id="cli", type=EntityType.IP.value, value=value,
                    norm_key=norm_key, props={}, confidence=1.0, is_seed=True)

    with GuardedClient(
        timeout=30.0, headers={"User-Agent": settings.user_agent}
    ) as http:
        ctx = CollectorContext(settings=settings, case_id="cli", run_id="cli", http=http)
        result = InternetDbCollector().collect(entity, ctx)

    if result.entities:
        props = result.entities[0].props
        table = Table(title=f"Shodan InternetDB — {value}")
        table.add_column("field")
        table.add_column("value", overflow="fold")
        for key in ("internetdb_ports", "internetdb_hostnames", "internetdb_cpes",
                    "internetdb_tags", "internetdb_vulns", "internetdb_fetched_at"):
            if key in props:
                shown = props[key]
                table.add_row(key.replace("internetdb_", ""),
                              ", ".join(str(v) for v in shown)
                              if isinstance(shown, list) else str(shown))
        rprint(table)

    for note in result.notes:
        rprint(f"[dim]{note}[/dim]")

    if not result.evidence:
        raise typer.Exit(1)
