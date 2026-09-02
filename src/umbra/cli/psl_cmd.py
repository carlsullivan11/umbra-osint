"""``umbra psl`` — sync / status / check for the Public Suffix List."""

from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.lake.psl import PSL_URL, PublicSuffixList, sync as sync_psl

psl_app = typer.Typer(
    help="Public Suffix List (organisation boundary for DMARC alignment).",
    no_args_is_help=True,
)


@psl_app.command("status")
def psl_status() -> None:
    """Rules loaded, file age, attribution."""
    psl = PublicSuffixList.from_settings(get_settings())
    st = psl.status()
    table = Table(title="Public Suffix List")
    table.add_column("key")
    table.add_column("value")
    for key, value in st.items():
        table.add_row(key, f"{value:,}" if isinstance(value, int) else str(value))
    rprint(table)
    if not st["rules"]:
        rprint("[yellow]Not synced[/yellow] — org_domain falls back to a built-in set. "
               "Run [bold]umbra psl sync[/bold] for the full list.")


@psl_app.command("sync")
def psl_sync(url: str = typer.Option(PSL_URL, "--url")) -> None:
    """Fetch the current list from publicsuffix.org (~333 KB)."""
    settings = get_settings()
    psl = PublicSuffixList.from_settings(settings)
    with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
        out = sync_psl(psl, http, url=url)
    rprint(f"[green]psl sync ok[/green] rules={out['rules']:,} "
           f"wildcards={out['wildcards']} exceptions={out['exceptions']}")
    rprint(f"[dim]{psl.status()['attribution']}[/dim]")


@psl_app.command("check")
def psl_check(host: str = typer.Argument(..., help="e.g. attacker.github.io")) -> None:
    """Show the public suffix and registrable domain for a host."""
    from umbra.email.parse import org_domain

    psl = PublicSuffixList.from_settings(get_settings())
    suffix = psl.public_suffix(host)
    rprint(f"[bold]{host}[/bold]")
    rprint(f"  public suffix     {suffix or '— (list not synced)'}")
    rprint(f"  registrable       {psl.registrable(host) or '—'}")
    # What the email verdict will actually use, which is the number that matters.
    rprint(f"  org_domain (used) {org_domain(host)}")
    if not psl.available:
        rprint("  [dim]built-in fallback in use — run `umbra psl sync` for the full list[/dim]")
