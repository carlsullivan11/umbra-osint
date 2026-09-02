"""``umbra scan`` — active checks, gated on recorded authorization.

CLI only, and deliberately so. `POST /run` is anonymous; exposing this behind it
would let a stranger aim Umbra's egress IP at a third party. The hosted site
never supplies an authorization basis, so it can never reach this.
"""

from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.iana_ports import IANA_URL, IanaPortsLake, sync as sync_ports
from umbra.scan.ports import (
    ALLOWED_BASES,
    DEFAULT_CONCURRENCY,
    DEFAULT_PORTS,
    DEFAULT_TIMEOUT_S,
    NotAuthorized,
    scan as scan_host,
)

scan_app = typer.Typer(
    help="Active checks against hosts you are authorized to test.",
    no_args_is_help=True,
)


@scan_app.command("ports")
def scan_ports(
    host: str = typer.Argument(..., help="Hostname or IP you are authorized to scan."),
    basis: str = typer.Option(
        ..., "--basis", "-b",
        help=f"Authorization basis. One of: {', '.join(sorted(ALLOWED_BASES))}.",
    ),
    note: str = typer.Option(
        ..., "--note", "-n",
        help="Why you are authorized. Recorded with the scan.",
    ),
    ports: str = typer.Option("", "--ports", help="Comma-separated. Default: common services."),
    timeout: float = typer.Option(DEFAULT_TIMEOUT_S, "--timeout"),
    concurrency: int = typer.Option(DEFAULT_CONCURRENCY, "--concurrency"),
) -> None:
    """TCP connect scan. Refuses unless the basis permits sending packets."""
    settings = get_settings()
    lake = IanaPortsLake.from_settings(settings)

    chosen = DEFAULT_PORTS
    if ports.strip():
        chosen = tuple(int(p) for p in ports.replace(" ", "").split(",") if p.isdigit())

    try:
        result = scan_host(
            host,
            authorization_basis=basis,
            ports=chosen,
            timeout_s=timeout,
            concurrency=concurrency,
            resolve_service=lake.service if lake.available else None,
        )
    except NotAuthorized as exc:
        rprint(f"[red]refused[/red] {exc}")
        raise typer.Exit(2)
    finally:
        pass

    rprint(f"\n[bold]{result.host}[/bold] · {result.ports_scanned} ports · "
           f"{result.duration_s}s · basis [bold]{basis}[/bold]")
    rprint(f"[dim]note: {note}[/dim]")

    if not lake.available:
        rprint("[yellow]IANA registry not synced[/yellow] — open ports will have no "
               "service name. Run [bold]umbra scan sync-ports[/bold]. Unnamed is "
               "not unknown-safe; it just means we cannot say what it is for.")

    if result.open_ports:
        table = Table(title="Open")
        table.add_column("port")
        table.add_column("service (IANA assignment)")
        table.add_column("note")
        for r in result.open_ports:
            info = lake.describe(r.port) if lake.available else {}
            table.add_row(str(r.port), r.service or "—", info.get("sensitive") or "")
        rprint(table)
        rprint("[dim]Service names are IANA assignments, not observations of what "
               "is really listening.[/dim]")
    else:
        rprint("[green]no open ports[/green] among those scanned")

    # Filtered is not closed. A dropped packet answered nothing.
    filtered = result.filtered_ports
    if filtered:
        rprint(f"[yellow]{len(filtered)} port(s) did not answer[/yellow] — dropped or "
               f"slow, which is unknown rather than closed: "
               f"{', '.join(str(r.port) for r in filtered[:12])}"
               + (" …" if len(filtered) > 12 else ""))
    lake.close()


@scan_app.command("sync-ports")
def sync_iana(url: str = typer.Option(IANA_URL, "--url")) -> None:
    """Load the IANA service-name registry (~1.1 MB)."""
    settings = get_settings()
    lake = IanaPortsLake.from_settings(settings)
    try:
        with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
            out = sync_ports(lake, http, url=url)
    finally:
        lake.close()
    rprint(f"[green]iana ports sync ok[/green] rows={out['rows']:,}")
