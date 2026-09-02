"""``umbra rf`` — bounded RF lake (OSM cameras / WiGLE hits / surveys)."""

from __future__ import annotations

from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.rf import DEFAULT_REGIONS, RfLake, sync_regions

rf_app = typer.Typer(
    help="RF lake: OSM ALPR/cameras near packed cities (not a WiGLE dump).",
    no_args_is_help=True,
)


@rf_app.command("status")
def rf_status() -> None:
    lake = RfLake.from_settings(get_settings())
    st = lake.status().as_dict()
    lake.close()
    table = Table(title="RF lake")
    table.add_column("key")
    table.add_column("value")
    for k, v in st.items():
        table.add_row(k, str(v))
    rprint(table)
    if not st["synced"]:
        rprint("[yellow]Lake empty — run[/yellow] umbra rf sync")

    stale = lake2.stale_regions() if (lake2 := RfLake.from_settings(get_settings())) else []
    lake2.close()
    if stale:
        rprint(f"\n[yellow]{len(stale)} region(s) could not be checked last sync[/yellow] "
               "— these are unknown, not empty:")
        for row in stale:
            rprint(f"  • {row['region']}: {row['detail']} "
                   f"[dim]({str(row['checked_at'])[:19]})[/dim]")


@rf_app.command("cameras")
def rf_cameras(
    region: str = typer.Argument(..., help="City blob, e.g. Bentonville"),
) -> None:
    lake = RfLake.from_settings(get_settings())
    rows = lake.cameras_for_region(region)
    if not rows:
        lake.backfill_geocode_from_cameras()
        coords = lake.geocode_get(region)
        if coords:
            rows = lake.cameras_near(coords[0], coords[1], km=6.0)
    # Why there are no rows matters more than the fact. "We looked and found
    # none" and "Overpass rate limited us and we never looked" render the same
    # in an empty table, and only one of them is an answer.
    st = lake.region_status(region)
    lake.close()
    if not rows:
        if st is None:
            rprint(f"[yellow]never synced[/yellow] — {region!r} has not been "
                   f"checked. Run [bold]umbra rf sync[/bold].")
        elif st.get("status") != "ok":
            rprint(f"[yellow]not checked[/yellow] — the last attempt at {region!r} "
                   f"failed ({st.get('detail')}) at {str(st.get('checked_at'))[:19]}. "
                   f"This is unknown, not zero. Run [bold]umbra rf sync[/bold].")
        else:
            rprint(f"[green]no cameras[/green] mapped near {region!r} "
                   f"(checked {str(st.get('checked_at'))[:19]}) — that is the answer, "
                   f"not a gap.")
        raise typer.Exit(1)
    table = Table(title=f"Cameras near {region}")
    table.add_column("label")
    table.add_column("lat")
    table.add_column("lon")
    table.add_column("region")
    for r in rows[:40]:
        table.add_row(str(r.get("label") or ""), str(r.get("lat")), str(r.get("lon")), str(r.get("region") or ""))
    rprint(table)


@rf_app.command("sync")
def rf_sync(
    region: Optional[str] = typer.Option(None, "--region", help="One city instead of the default pack"),
) -> None:
    """Query Nominatim + OSM Overpass for packed cities; store cameras."""
    settings = get_settings()
    lake = RfLake.from_settings(settings)
    regions = [region] if region else list(DEFAULT_REGIONS)
    rprint(f"[dim]lake[/dim] {lake.path}")
    rprint(f"[dim]regions[/dim] {len(regions)}")
    with GuardedClient(timeout=25.0, headers={"User-Agent": settings.user_agent}) as http:
        stats = sync_regions(
            http,
            lake=lake,
            regions=regions,
            user_agent=settings.user_agent,
        )
    lake.close()
    # "rf sync ok ... fails=4" called a run with four unchecked cities "ok".
    # The headline now states coverage, because that is what a cron reader needs
    # to decide whether the lake can be trusted this morning.
    checked, total = stats["checked"], stats["regions"]
    ok = not stats["fails"]
    rprint(
        f"[{'green' if ok else 'yellow'}]rf sync[/] "
        f"{checked}/{total} regions checked · "
        f"cameras_upserted={stats['cameras_upserted']} · path={stats['path']}"
    )
    if stats["fails"]:
        rprint(f"[yellow]{len(stats['fails'])} region(s) not checked[/yellow] "
               "— unknown, not zero:")
        # Never a silent cap: if the list is trimmed, say by how much.
        for f in stats["fails"][:8]:
            rprint(f"  • {f}")
        if len(stats["fails"]) > 8:
            rprint(f"  [dim]and {len(stats['fails']) - 8} more[/dim]")
    if stats.get("capped"):
        shown = ", ".join(stats["capped"][:5])
        # This message is itself a list that can be trimmed. Saying "7 regions"
        # and then naming five, with no note, is the same omission it exists to
        # report.
        if len(stats["capped"]) > 5:
            shown += f", and {len(stats['capped']) - 5} more"
        rprint(f"[yellow]{len(stats['capped'])} region(s) hit the per-region cap[/yellow] "
               f"({shown}) — these cities have more mapped cameras than were stored. "
               f"Raise --max-per-region to widen.")
