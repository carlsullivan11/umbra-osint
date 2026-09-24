"""``umbra records`` — search court, county and property records by name."""

from __future__ import annotations

import json

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.core.http_guard import GuardedClient
from umbra.records import search as search_records

records_app = typer.Typer(help="Search court, county and property records.",
                          no_args_is_help=True)


@records_app.command("parcel-coverage")
def parcel_coverage(
    show: int = typer.Option(0, "--missing", help="List N uncovered counties"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """How much of the country's parcel data the lake actually holds."""
    from umbra.lake.parcels import ParcelLake
    from umbra.records.coverage import coverage_report, uncovered_counties

    lake = ParcelLake()
    try:
        rep = coverage_report(lake)
        missing = uncovered_counties(lake, limit=show) if show else []
    finally:
        lake.close()

    if json_out:
        print(json.dumps({"report": rep, "missing": missing}, indent=2))
        return
    rprint(f"[green]parcel coverage[/green] {rep['counties_covered']:,} / "
           f"{rep['counties_total']:,} counties ({rep['percent']}%) · "
           f"{rep['parcels']:,} owner records")
    rprint(f"[dim]{rep['note']}[/dim]")
    for m in missing:
        rprint(f"[dim]  missing: {m['state']} {m['county']}[/dim]")


@records_app.command("parcels-discover")
def parcels_discover(
    states: bool = typer.Option(True, "--states/--no-states",
                                help="Sweep the 51 statewide queries first"),
    counties: int = typer.Option(0, "--counties", help="Also probe N uncovered counties"),
    max_items: int = typer.Option(80, "--max-items"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Find parcel layers with targeted queries instead of five generic ones.

    A statewide layer covers every county in it, so states are swept first.
    County queries are bounded — 3,143 counties is 3,143 catalog requests, and
    a sweep takes a slice rather than the whole list.
    """
    from umbra.lake.parcel_sources import ParcelSourceLake
    from umbra.lake.parcels import ParcelLake
    from umbra.records import discover
    from umbra.records.coverage import county_queries, state_queries, uncovered_counties

    queries: list[str] = []
    if states:
        queries.extend(state_queries())
    if counties:
        plake = ParcelLake()
        try:
            queries.extend(county_queries(uncovered_counties(plake, limit=counties)))
        finally:
            plake.close()

    if not queries:
        rprint("[yellow]nothing to search[/yellow]")
        raise typer.Exit(1)

    settings = get_settings()
    lake = ParcelSourceLake.from_settings(settings)
    try:
        with GuardedClient(timeout=60.0,
                           headers={"User-Agent": settings.user_agent}) as http:
            stats = discover.sync(http, lake, max_items=max_items, queries=queries)
    finally:
        try:
            lake.close()
        except Exception:
            pass

    if json_out:
        print(json.dumps({"queries": len(queries), **stats}, indent=2))
        return
    rprint(f"[green]discover[/green] queries={len(queries)} probed={stats['probed']} "
           f"verified={stats['verified']} rejected={stats['rejected']}")


@records_app.command("parcels-sync")
def parcels_sync(
    state: str = typer.Option(None, "--state", help="Only this state"),
    limit_sources: int = typer.Option(3, "--sources", help="How many layers"),
    max_rows: int = typer.Option(50000, "--max-rows", help="Cap per layer, 0 = all"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Bulk-ingest county parcel owner rolls into the owned parcel lake.

    `umbra records "Name"` asks one layer about one name. This pages the whole
    layer — Hillsborough County FL alone is 367,316 owner records — so the lake
    can answer offline instead of hitting a county server per lookup.
    """
    from umbra.lake.parcel_sources import ParcelSourceLake
    from umbra.lake.parcels import ParcelLake, ParcelSource, order_for_sweep

    # `verified()`, not `_conn.execute`. The connection is lazy, so reaching
    # past the public API got a None and an AttributeError on the first prod run.
    # from_settings, not the bare constructor: default_path() falls back to a
    # home-relative directory that does not exist in the container, so a bare
    # ParcelSourceLake() silently reported "no verified layers" while 36 sat in
    # /data/lake. An empty registry and an unreadable one looked identical.
    src_lake = ParcelSourceLake.from_settings(get_settings())
    try:
        # Every verified layer, not the first `limit_sources`. `verified()`
        # orders `state, county`, so slicing it there returned the same handful
        # on every run — 195 sources verified and 10 ever ingested. The slice
        # has to happen *after* the sweep order is known.
        candidates = src_lake.verified(state=state, limit=10_000)
    finally:
        try:
            src_lake.close()
        except Exception:
            pass

    if not candidates:
        rprint("[yellow]no verified parcel layers[/yellow] — run `umbra records discover` first")
        raise typer.Exit(1)

    lake = ParcelLake()
    ordered = order_for_sweep(candidates, lake.ingest_state())
    rows = ordered[: max(1, limit_sources)]
    fresh = sum(1 for r in rows if r["layer_url"] not in lake.ingest_state())
    rprint(f"[dim]{len(candidates)} verified layer(s); paging {len(rows)} "
           f"({fresh} never ingested)[/dim]")

    out = []
    try:
        for r in rows:
            source = ParcelSource(
                layer_url=r["layer_url"], state=r.get("state"),
                county=r.get("county"), owner_field=r.get("owner_field") or "OWNER",
                address_field=r.get("address_field"),
                parcel_field=r.get("parcel_field"),
                city_field=r.get("city_field"),
                page=int(r.get("page") or 2000),
            )
            rprint(f"[dim]paging[/dim] {source.county or source.layer_url}")
            stats = lake.ingest_source(source, max_rows=max_rows or None)
            out.append({"county": source.county, "state": source.state, **stats})
            rprint(f"  [green]{stats['note']}[/green]")
        status = lake.status()
    finally:
        lake.close()

    if json_out:
        print(json.dumps({"sources": out, "lake": status}, indent=2, default=str))
        return
    rprint(f"[green]parcel lake[/green] {status['parcels']:,} owner records "
           f"across {status['counties']} county layer(s)")


@records_app.command("parcels-region-repair")
def parcels_region_repair(
    apply: bool = typer.Option(False, "--apply", help="Write; default is a dry run"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Attach a state and county to parcel rows that were stored without one.

    352,679 rows sat in the lake with NULL state and county — searchable by
    owner, invisible to any filter by place, and worth nothing to the coverage
    ledger, which is why it read 0 of 3,143 while 408,935 records were in the
    table. The registry cannot supply the answer: it has NULL for those layers
    too. The layer URL and its ArcGIS service metadata can, and this derives it
    from them.

    **Nothing is invented.** A name that does not resolve against the real county
    list stays NULL, because a NULL is visibly unknown and a wrong county is not.
    """
    from umbra.lake.parcels import ParcelLake
    from umbra.records.region import region_from_layer

    settings = get_settings()
    lake = ParcelLake()
    out: list[dict] = []
    try:
        pending = lake.unresolved_layers()
        if not pending:
            rprint("[green]every parcel row already has a region[/green]")
            return

        with GuardedClient(timeout=30.0,
                           headers={"User-Agent": settings.user_agent}) as http:
            for row in pending:
                url = row["layer_url"]
                meta = ""
                # Service metadata is what disambiguates a county name shared by
                # several states — "Russell County" exists in AL, KS, KY and VA.
                try:
                    base = url.rsplit("/FeatureServer", 1)[0] + "/FeatureServer"
                    r = http.get(base, params={"f": "json"})
                    d = r.json() or {}
                    meta = " ".join(str(d.get(k) or "") for k in
                                    ("serviceDescription", "description", "copyrightText"))
                except Exception:  # noqa: BLE001 - metadata is a bonus, not a need
                    meta = ""

                region = region_from_layer(url, meta)
                entry = {"layer_url": url, "rows": row["rows"],
                         "state": region.state, "county": region.county,
                         "statewide": region.statewide, "basis": region.basis,
                         "applied": False}
                if apply and (region.state or region.county):
                    entry["applied"] = True
                    entry["updated"] = lake.set_region(
                        url, region.state, region.county, region.statewide)
                out.append(entry)
    finally:
        lake.close()

    if json_out:
        print(json.dumps(out, indent=2, default=str))
        return

    fixed = sum(e["rows"] for e in out if e["state"] or e["county"])
    left = sum(e["rows"] for e in out if not (e["state"] or e["county"]))
    for e in out:
        where = ("%s STATEWIDE" % e["state"]) if e["statewide"] else (
            "%s/%s" % (e["state"], e["county"]) if e["county"] else "[yellow]unresolved[/yellow]")
        rprint(f"  {e['rows']:>7,}  {where} [dim]{e['basis']}[/dim]")
    verb = "repaired" if apply else "would repair"
    rprint(f"[green]{verb}[/green] {fixed:,} row(s); {left:,} stay unknown "
           f"[dim](no state or county is derivable — that is the honest answer)[/dim]")
    if not apply:
        rprint("[dim]dry run — re-run with --apply to write[/dim]")


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
