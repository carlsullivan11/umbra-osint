"""``umbra urlscan`` — read the public urlscan.io corpus.

`lookup` only. There is deliberately no `submit` in this slice: submitting asks
urlscan to fetch a URL with a real browser and publish the result, which is a
live connection to someone else's host made on your behalf and a public record
naming it. That is a different decision from reading an archive, and it is not
one this command makes.
"""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.collectors.base import CollectorContext
from umbra.collectors.urlscan_io import API_KEY_ENV, UrlscanIoCollector
from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.core.models import EntityType
from umbra.core.normalize import entity_key
from umbra.db.schema import Entity

urlscan_app = typer.Typer(
    help="Search the public urlscan.io corpus (read-only; never submits a scan).",
    no_args_is_help=True,
)


def _kind_for(value: str) -> EntityType:
    return EntityType.URL if "://" in value else EntityType.DOMAIN


@urlscan_app.command("lookup")
def urlscan_lookup(
    target: str = typer.Argument(..., help="URL or domain, e.g. example.com"),
) -> None:
    """Show existing public scans of a URL or domain. Submits nothing."""
    settings = get_settings()
    value = target.strip()
    kind = _kind_for(value)

    try:
        norm_key = entity_key(kind, value)
    except ValueError as exc:
        rprint(f"[red]not a URL or domain:[/red] {value} ({exc})")
        raise typer.Exit(2) from exc

    entity = Entity(id="cli", case_id="cli", type=kind.value, value=value,
                    norm_key=norm_key, props={}, confidence=1.0, is_seed=True)

    with GuardedClient(
        timeout=30.0, headers={"User-Agent": settings.user_agent}
    ) as http:
        ctx = CollectorContext(settings=settings, case_id="cli", run_id="cli", http=http)
        result = UrlscanIoCollector().collect(entity, ctx)

    if result.evidence:
        table = Table(title=f"urlscan.io — public scans of {value}")
        table.add_column("scanned")
        table.add_column("url", overflow="fold")
        table.add_column("verdict")
        table.add_column("permalink", overflow="fold")
        for ev in result.evidence:
            raw = ev.raw or {}
            verdict = raw.get("verdict_malicious")
            # "—" for a missing verdict, never "benign": most public scans
            # carry no verdict, and an absent field is not an all-clear.
            label = ("[red]malicious[/red]" if verdict is True
                     else "[green]not flagged[/green]" if verdict is False else "—")
            table.add_row((raw.get("scanned_at") or "")[:10],
                          raw.get("scanned_url") or "",
                          label, raw.get("permalink") or "")
        rprint(table)

    for note in result.notes:
        rprint(f"[dim]{note}[/dim]")

    if not result.evidence:
        rprint(
            f"[dim]An unauthenticated search is rate limited; set {API_KEY_ENV} "
            "to raise it.[/dim]"
        )
        raise typer.Exit(1)
