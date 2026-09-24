"""``umbra faa`` — sync / import-zip / status / lookup for the owned FAA lake."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient, check_url
from umbra.lake.faa import (
    RELEASABLE_ZIP_URL,
    SOURCE_PAGE,
    FaaLake,
    default_faa_path,
)

faa_app = typer.Typer(
    help="FAA aircraft registration lake (N-number → registrant, offline).",
    no_args_is_help=True,
)


@faa_app.command("status")
def faa_status() -> None:
    """Show lake path, row counts, edition and import date."""
    st = FaaLake().status()
    table = Table(title="FAA registry lake")
    table.add_column("key")
    table.add_column("value")
    for k, v in st.items():
        table.add_row(k, str(v))
    rprint(table)
    if not st["available"]:
        rprint("[yellow]Lake empty — run[/yellow] umbra faa sync")


@faa_app.command("lookup")
def faa_lookup(
    n_number: str = typer.Argument(..., help="US registration, e.g. N737KL"),
) -> None:
    """Look up one N-number against the local lake (no network)."""
    lake = FaaLake()
    if not lake.available:
        rprint("[red]FAA lake not loaded.[/red] Run: umbra faa sync")
        raise typer.Exit(2)

    hit = lake.lookup(n_number)
    if hit is None:
        # Deliberately not "not registered". Beyond a stale lake, the FAA
        # withholds some owners' details on request under 49 USC 44114(b).
        rprint(f"[yellow]no record[/yellow] for {n_number} in the current lake")
        rprint(
            "[dim]This is unchecked, not an absence of registration: an owner "
            "may have asked the FAA to withhold their details (49 U.S.C. "
            "§ 44114(b)), and the lake is only as current as its last sync.[/dim]"
        )
        raise typer.Exit(1)

    table = Table(title=hit.n_number)
    table.add_column("field")
    table.add_column("value")
    for k, v in hit.as_dict().items():
        if v is not None:
            table.add_row(k, str(v))
    rprint(table)
    rprint(
        "[dim]Registrant of record — not necessarily the operator, the lessee, "
        "or whoever was flying.[/dim]"
    )


@faa_app.command("import-zip")
def faa_import_zip(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    edition: Optional[str] = typer.Option(None, "--edition", help="Label stored in meta"),
) -> None:
    """Import a local ReleasableAircraft.zip (offline / air-gapped)."""
    lake = FaaLake()
    stats = lake.import_zip(path, edition=edition or path.name)
    rprint(
        f"[green]imported[/green] aircraft={stats['aircraft']:,} "
        f"models={stats['models']:,} → {stats['path']}"
    )


@faa_app.command("sync")
def faa_sync(
    url: Optional[str] = typer.Option(
        None, "--url", help=f"Override download URL (default: {RELEASABLE_ZIP_URL})"
    ),
) -> None:
    """Download the FAA Releasable Aircraft Database and rebuild the lake.

    Streams to disk through GuardedClient: the archive is ~60MB and MASTER.txt
    alone expands to ~194MB, so reading `resp.content` into memory would OOM a
    small API container.
    """
    target = url or RELEASABLE_ZIP_URL
    dest = default_faa_path()
    settings = get_settings()
    rprint(f"[dim]lake path[/dim] {dest}")
    rprint(f"[dim]source[/dim] {SOURCE_PAGE}")

    with tempfile.TemporaryDirectory(prefix="umbra-faa-") as td:
        raw_path = Path(td) / "ReleasableAircraft.zip"
        with GuardedClient(
            timeout=600.0,
            headers={"User-Agent": settings.user_agent},
        ) as http:
            rprint(f"[dim]downloading[/dim] {target}")
            try:
                check_url(target)
                with http.stream("GET", target) as resp:
                    resp.raise_for_status()
                    with raw_path.open("wb") as out:
                        for chunk in resp.iter_bytes(chunk_size=1024 * 256):
                            out.write(chunk)
            except Exception as exc:  # noqa: BLE001
                rprint(f"[red]download failed[/red] {exc}")
                # registry.faa.gov sits behind a WAF that answers a plain
                # client with an HTML error page carrying a 200-family or 503
                # status. Say so rather than leaving the operator to guess,
                # and point at the manual path that always works.
                rprint(
                    "[dim]If this looks like a block rather than an outage, "
                    "download the zip in a browser from the page above and run "
                    "`umbra faa import-zip <path>`.[/dim]"
                )
                raise typer.Exit(1) from exc

        size_mb = raw_path.stat().st_size / (1024 * 1024)
        rprint(f"[dim]downloaded[/dim] {size_mb:.1f} MiB — importing…")
        lake = FaaLake(dest)
        try:
            stats = lake.import_zip(raw_path, edition="ReleasableAircraft.zip")
        except ValueError as exc:
            # A WAF HTML page saved as .zip lands here rather than as a
            # half-built lake, because import_zip validates before it swaps.
            rprint(f"[red]import failed[/red] {exc}")
            raise typer.Exit(1) from exc

    rprint(
        f"[green]faa sync ok[/green] aircraft={stats['aircraft']:,} "
        f"models={stats['models']:,}"
    )
    rprint(
        "[dim]Registrant of record only. Not operator, not pilot. The FAA "
        "refreshes this file daily at 23:30 US Central.[/dim]"
    )
