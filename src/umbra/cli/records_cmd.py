"""``umbra records`` — search court, county and property records by name."""

from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.records import search as search_records

records_app = typer.Typer(help="Search court, county and property records.",
                          no_args_is_help=True)


@records_app.command("search")
def records_search(
    name: str = typer.Argument(..., help='e.g. "Jane Q Doe" or a company name'),
    region: str = typer.Option("", "--region", "-r",
                               help="Portal pack key, e.g. us-ar-benton or us-ca"),
    limit: int = typer.Option(10, "--limit"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    settings = get_settings()
    with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
        out = search_records(name, http=http, settings=settings,
                             region=region or None, limit=limit)

    if json_out:
        import json

        # Plain print: rich soft-wraps and corrupts JSON.
        print(json.dumps(out.as_dict(), indent=2))
        return

    rprint(f"\n[bold]{out.query}[/bold] — {out.record_count} record(s)")

    if out.court:
        t = Table(title="Court records (CourtListener)")
        t.add_column("type"); t.add_column("case"); t.add_column("court · filed")
        for h in out.court:
            t.add_row(h.kind.replace("court_", ""), h.title[:52], h.detail[:34])
        rprint(t)

    if out.parcels:
        t = Table(title="Property records (statewide assessor layers)")
        t.add_column("owner"); t.add_column("address"); t.add_column("county")
        for h in out.parcels:
            t.add_row(h.title[:36], h.detail[:44], h.region[:18])
        rprint(t)

    if out.lake:
        t = Table(title="Held in Umbra's lake")
        t.add_column("kind"); t.add_column("what"); t.add_column("where")
        for h in out.lake:
            t.add_row(h.kind, h.title[:44], (h.region or h.detail)[:30])
        rprint(t)

    if out.portals:
        # Labelled as pointers, never merged into the record count above.
        t = Table(title="Where to look (links, not records)")
        t.add_column("portal"); t.add_column("kind"); t.add_column("automated?")
        for h in out.portals:
            reach = {"fetchable": "yes", "link_only": "no — open it yourself",
                     "broken": "link is dead", "blocked_by_guard": "our guard blocks it",
                     "": "unchecked"}[h.reachable]
            t.add_row(h.title[:40], h.detail[:14], reach)
        rprint(t)

    for n in out.notes:
        rprint(f"  [dim]· {n}[/dim]")


sources_app = typer.Typer(help="The parcel-layer registry Umbra verifies and owns.",
                          no_args_is_help=True)
records_app.add_typer(sources_app, name="sources")


@sources_app.command("sync")
def sources_sync(
    max_items: int = typer.Option(120, "--max", help="catalog items to probe this run"),
) -> None:
    """Discover county parcel layers, probe them, keep only what answered."""
    from umbra.lake.parcel_sources import ParcelSourceLake
    from umbra.records.discover import sync as discover_sync

    settings = get_settings()
    lake = ParcelSourceLake.from_settings(settings)

    def progress(n: int, title: str, reason: str) -> None:
        mark = "[green]ok  [/green]" if reason == "verified" else "[dim]skip[/dim]"
        rprint(f"  {mark} {n:>3}. {title[:44]:44} [dim]{reason[:44]}[/dim]")

    try:
        with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
            stats = discover_sync(http, lake, max_items=max_items, progress=progress)
        st = lake.status()
    finally:
        lake.close()

    rprint(f"\n[bold]probed {stats['probed']}[/bold] — "
           f"{stats['verified']} verified, {stats['rejected']} rejected")
    # A rejection is usually the county's choice, not a fault.
    rprint("[dim]Most rejections are counties that publish parcel geometry "
           "without owner names. That is deliberate on their part.[/dim]")
    rprint(f"registry now: [bold]{st['verified']}[/bold] verified layer(s) across "
           f"{st['states']} state(s), {st['counties']} county/counties")


@sources_app.command("list")
def sources_list(
    state: str = typer.Option("", "--state", "-s"),
    limit: int = typer.Option(40, "--limit"),
) -> None:
    """What the registry can actually search."""
    from umbra.lake.parcel_sources import ParcelSourceLake

    lake = ParcelSourceLake.from_settings(get_settings())
    try:
        st = lake.status()
        if not st["synced"]:
            # Never checked is not the same as nothing to find.
            rprint("[yellow]The registry has never been synced.[/yellow] "
                   "Run [bold]umbra records sources sync[/bold]. Until then "
                   "property search uses the 5 curated statewide layers only.")
            return
        rows = lake.verified(state=state or None, limit=limit)
        t = Table(title=f"Verified parcel layers ({st['verified']} total, "
                        f"{st['states']} states, {st['counties']} counties)")
        t.add_column("where"); t.add_column("layer"); t.add_column("owner field")
        t.add_column("sample")
        for r in rows:
            where = " ".join(x for x in (r.get("county") or "",
                                         r.get("state") or "") if x) or "[dim]unresolved[/dim]"
            sample = ""
            if r.get("sample"):
                import json as _json

                try:
                    sample = (_json.loads(r["sample"]) or [""])[0][:24]
                except Exception:  # noqa: BLE001
                    sample = ""
            t.add_row(where[:22], (r.get("title") or "")[:30],
                      r.get("owner_field") or "", sample)
        rprint(t)
        rprint(f"[dim]last verified: {st['verified_at']} · "
               f"{st['rejected']} candidate(s) rejected on probe[/dim]")
    finally:
        lake.close()
