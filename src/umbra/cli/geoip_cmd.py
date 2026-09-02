"""``umbra geoip`` — sync / status / lookup for the owned IP geolocation lake."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient, check_url
from umbra.lake.geoip import GeoIpStore, candidate_dbip_urls, default_geoip_path

geoip_app = typer.Typer(
    help="IP geolocation lake (free DB-IP City Lite → offline lookups).",
    no_args_is_help=True,
)


@geoip_app.command("status")
def geoip_status() -> None:
    """Show lake path, row counts, edition, attribution."""
    store = GeoIpStore()
    st = store.status()
    table = Table(title="GeoIP lake")
    table.add_column("key")
    table.add_column("value")
    for k, v in st.items():
        table.add_row(k, str(v))
    rprint(table)
    if not st["available"]:
        rprint("[yellow]Lake empty — run[/yellow] umbra geoip sync")


@geoip_app.command("lookup")
def geoip_lookup(
    ip: str = typer.Argument(..., help="IPv4 or IPv6 address"),
) -> None:
    """Look up one address against the local lake (no network)."""
    store = GeoIpStore()
    if not store.available:
        rprint("[red]GeoIP lake not loaded.[/red] Run: umbra geoip sync")
        raise typer.Exit(2)
    hit = store.lookup(ip)
    if hit is None:
        rprint(f"[yellow]no hit[/yellow] for {ip}")
        raise typer.Exit(1)
    rprint(hit.as_dict())


@geoip_app.command("import-csv")
def geoip_import_csv(
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    edition: Optional[str] = typer.Option(None, "--edition", help="Label stored in meta"),
) -> None:
    """Import a local DB-IP City Lite CSV or .csv.gz (offline / air-gap)."""
    store = GeoIpStore()
    stats = store.import_csv_file(path, edition=edition or path.name)
    rprint(f"[green]imported[/green] v4={stats['rows_v4']} v6={stats['rows_v6']} → {stats['path']}")


@geoip_app.command("sync")
def geoip_sync(
    url: Optional[str] = typer.Option(
        None,
        "--url",
        help="Override download URL (default: current/previous DB-IP City Lite CSV.gz)",
    ),
) -> None:
    """Download free DB-IP City Lite CSV and rebuild the local lake.

    Uses GuardedClient egress. Attribution: IP Geolocation by DB-IP (CC-BY 4.0).
    """
    urls = [url] if url else candidate_dbip_urls()
    dest = default_geoip_path()
    settings = get_settings()
    rprint(f"[dim]lake path[/dim] {dest}")

    last_err: Exception | None = None
    with tempfile.TemporaryDirectory(prefix="umbra-geoip-") as td:
        raw_path = Path(td) / "dbip-city-lite.csv.gz"
        downloaded_from: str | None = None
        with GuardedClient(
            timeout=300.0,
            headers={"User-Agent": settings.user_agent},
        ) as http:
            for u in urls:
                rprint(f"[dim]try[/dim] {u}")
                try:
                    # Validate SSRF target; stream to disk so a ~100MB CSV.gz
                    # cannot OOM a small API container (resp.content did).
                    check_url(u)
                    with http.stream("GET", u) as resp:
                        if resp.status_code == 404:
                            rprint(f"[yellow]404[/yellow] {u}")
                            continue
                        resp.raise_for_status()
                        with raw_path.open("wb") as out:
                            for chunk in resp.iter_bytes(chunk_size=1024 * 256):
                                out.write(chunk)
                    downloaded_from = u
                    break
                except Exception as exc:  # noqa: BLE001
                    last_err = exc
                    rprint(f"[yellow]fail[/yellow] {u}: {exc}")
                    if raw_path.exists():
                        raw_path.unlink(missing_ok=True)
                    continue

        if not downloaded_from:
            rprint(f"[red]sync failed[/red] last_error={last_err}")
            raise typer.Exit(1)

        size_mb = raw_path.stat().st_size / (1024 * 1024)
        rprint(f"[dim]downloaded[/dim] {size_mb:.1f} MiB — importing…")
        store = GeoIpStore(dest)
        edition = downloaded_from.rstrip("/").split("/")[-1]
        stats = store.import_csv_file(raw_path, edition=edition)
        store.set_meta("download_url", downloaded_from)
        rprint(
            f"[green]geoip sync ok[/green] "
            f"v4={stats['rows_v4']} v6={stats['rows_v6']} edition={edition}"
        )
        rprint("[dim]IP Geolocation by DB-IP — https://db-ip.com — CC-BY 4.0[/dim]")
