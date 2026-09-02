"""``umbra epss`` — sync / status / score for the owned EPSS lake."""

from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.epss import BULK_URL, EpssLake, sync as sync_epss

epss_app = typer.Typer(
    help="EPSS lake (FIRST exploitation probability → offline CVE triage).",
    no_args_is_help=True,
)


@epss_app.command("status")
def epss_status() -> None:
    """Rows, model version, score date, attribution."""
    lake = EpssLake.from_settings(get_settings())
    st = lake.status()
    lake.close()

    table = Table(title="EPSS lake")
    table.add_column("key")
    table.add_column("value")
    for key, value in st.items():
        table.add_row(key, f"{value:,}" if isinstance(value, int) else str(value))
    rprint(table)
    if not st["rows"]:
        rprint("[yellow]Lake empty — run[/yellow] umbra epss sync")


@epss_app.command("sync")
def epss_sync(
    url: str = typer.Option(BULK_URL, "--url", help="Bulk feed URL."),
) -> None:
    """Replace the lake from FIRST's current bulk feed (~2.5 MB gzipped)."""
    settings = get_settings()
    lake = EpssLake.from_settings(settings)
    rprint(f"[dim]lake[/dim] {lake.path}")
    try:
        with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
            out = sync_epss(lake, http, url=url)
    finally:
        lake.close()
    rprint(
        f"[green]epss sync ok[/green] rows={out['rows']:,} "
        f"model={out['model_version']} scored={out['score_date']}"
    )
    rprint("[dim]EPSS by FIRST.org — https://www.first.org/epss[/dim]")


@epss_app.command("score")
def epss_score(
    cve: str = typer.Argument(..., help="e.g. CVE-2021-44228"),
) -> None:
    """Modelled exploitation probability for one CVE."""
    lake = EpssLake.from_settings(get_settings())
    hit = lake.score(cve)
    rows = lake.row_count()
    lake.close()

    if hit is None:
        # Three different reasons for "no number", and they are not the same.
        if not rows:
            rprint("[yellow]EPSS lake empty[/yellow] — run [bold]umbra epss sync[/bold]. "
                   "This is unknown, not low.")
        else:
            rprint(f"[yellow]{cve.upper()} is not scored[/yellow] in this lake "
                   f"({rows:,} CVEs, as of the last sync). Unscored is not low — a CVE "
                   f"published since the sync has no row yet.")
        raise typer.Exit(1)

    rprint(
        f"[bold]{hit['cve']}[/bold]  EPSS [bold]{hit['score']:.5f}[/bold] "
        f"({hit['band']}) · percentile {hit['percentile']:.3f}"
    )
    rprint(f"  {hit['meaning']}")
    # The number without the model that produced it is not evidence.
    rprint(f"  [dim]model {hit['model_version']} · scored {hit['score_date']} · "
           f"{hit['source']}[/dim]")
    rprint("  [dim]EPSS is a prediction, not an observation. CISA KEV is the "
           "record of what has actually been exploited.[/dim]")
