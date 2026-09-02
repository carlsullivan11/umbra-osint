"""CLI: `umbra mac lookup` (stage S13 / M3).

Offline vendor resolution against the owned OUI lake, with the flag bits shown
next to the vendor rather than buried — a locally administered address has no
registrant, and reading a manufacturer off one is the mistake this command is
shaped to prevent.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.mac import mac_facts
from umbra.lake.oui import OuiTable

mac_app = typer.Typer(help="MAC address lookup (offline OUI lake).")


@mac_app.command("lookup")
def mac_lookup(
    value: str = typer.Argument(..., help="MAC or OUI prefix, any common format"),
    csv_path: Optional[Path] = typer.Option(
        None, "--csv", help="OUI table (defaults to the umbra-wiki corpus)"
    ),
) -> None:
    """Resolve a MAC address to its IEEE registrant."""
    try:
        facts = mac_facts(value)
    except ValueError as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(2) from exc

    table = Table(title=f"MAC {facts['mac']}")
    table.add_column("field")
    table.add_column("value")
    table.add_row("oui", facts["oui"])

    lake = OuiTable(csv_path)
    if facts["is_probably_randomized"]:
        table.add_row("vendor", "[yellow]none — locally administered[/yellow]")
    elif not lake.available:
        table.add_row("vendor", "[yellow]OUI corpus not available[/yellow]")
    else:
        hit = lake.lookup(facts["mac"])
        if hit:
            for v in hit.get("vendors") or [hit["vendor"]]:
                table.add_row("vendor", v)
            table.add_row("registry", f"{hit['registry']} (/{hit['bits']})")
            table.add_row("prefix", hit["prefix"])
        else:
            table.add_row("vendor", "[yellow]no registration found[/yellow]")

    for flag in ("is_multicast", "is_local", "is_broadcast", "is_probably_randomized"):
        if facts[flag]:
            table.add_row(flag, "yes")
    rprint(table)

    for note in facts["notes"]:
        rprint(f"[yellow]•[/yellow] {note}")
    rprint(
        "[dim]A MAC is a layer 2 identifier — not routable on the public "
        "Internet, not geolocatable from the address.[/dim]"
    )
    if not lake.available:
        rprint(
            "[dim]Clone https://github.com/carlsullivan11/umbra-wiki or set "
            "UMBRA_OUI_CSV to enable vendor resolution.[/dim]"
        )
