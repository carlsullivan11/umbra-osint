"""CLI: umbra people — people-lake status / lookup (obituary person map corpus)."""

from __future__ import annotations

import json
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.lake.people import PeopleLake
from umbra.people.graph import enrichment_from_lakes, graph_from_lake, serialize_graph
from umbra.people.seed import DEFAULT_SEEDS, seed_people

people_app = typer.Typer(help="People lake: obituaries, kinship, person lookup")


@people_app.command("status")
def status() -> None:
    """Show people.sqlite path and row counts."""
    lake = PeopleLake.from_settings(get_settings())
    st = lake.status()
    lake.close()
    rprint(st.as_dict())


@people_app.command("seed")
def seed(
    limit: Optional[int] = typer.Option(
        None, "--limit", "-n", help="Only first N curated public seeds"
    ),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Seed the people lake from curated public wiki/memorial URLs (no DDG).

    Safe public decedents only. Stores every successful source **link** + parse.
    Run this before enabling person search on the website.
    """
    seeds = list(DEFAULT_SEEDS)
    if limit is not None:
        seeds = seeds[: max(0, limit)]
    rprint(f"[cyan]Seeding {len(seeds)} public person(s) into people lake…[/cyan]")
    stats = seed_people(seeds)
    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    lake = stats.get("lake") or {}
    rprint(
        f"[green]ok[/green] people_upserted={stats['people_upserted']}/{stats['attempted_people']} "
        f"urls_ok={stats['urls_ok']} urls_fail={stats['urls_fail']} "
        f"lake_people={lake.get('people')} lake_obits={lake.get('obituaries')} "
        f"kinship={lake.get('kinship_edges')}"
    )
    for p in stats.get("people") or []:
        rprint(f"  • {p['name']}: {len(p.get('links') or [])} link(s), kin_parsed≈{p.get('kin_parsed')}")
    if stats.get("errors"):
        rprint(f"[yellow]{len(stats['errors'])} fetch note(s)[/yellow]")
        for e in stats["errors"][:12]:
            rprint(f"    - {e}")


@people_app.command("lookup")
def lookup(
    name: str = typer.Argument(..., help="Person name (full or partial)"),
    limit: int = typer.Option(20, "--limit", "-n"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Search the people lake by name; show obituaries + kinship."""
    lake = PeopleLake.from_settings(get_settings())
    try:
        rows = lake.lookup_name(name, limit=limit)
        if json_out:
            out = []
            for r in rows:
                item = dict(r)
                item["obituaries"] = lake.obituaries_for_person(r["id"])
                item["kinship"] = lake.kinship_for_person(r["id"])
                out.append(item)
            print(json.dumps(out, indent=2, default=str))
            return
        if not rows:
            rprint(f"[yellow]No people lake hits for {name!r}[/yellow]")
            return
        table = Table(title=f"People lake · {name!r}")
        table.add_column("name")
        table.add_column("death")
        table.add_column("age")
        table.add_column("residence")
        table.add_column("obits")
        table.add_column("kin")
        table.add_column("id")
        for r in rows:
            table.add_row(
                r.get("full_name") or "",
                str(r.get("death_date") or ""),
                str(r.get("age") or ""),
                str(r.get("residence") or ""),
                str(r.get("obit_count") or 0),
                str(r.get("kin_count") or 0),
                r.get("id") or "",
            )
        rprint(table)
        # Detail first hit
        top = rows[0]
        obits = lake.obituaries_for_person(top["id"])
        kin = lake.kinship_for_person(top["id"])
        if obits:
            rprint("\n[bold]Obituary links[/bold]")
            for o in obits:
                rprint(f"  • {o.get('url')}")
                if o.get("title"):
                    rprint(f"    {o.get('title')}")
        if kin:
            rprint("\n[bold]Kinship[/bold]")
            for k in kin:
                live = "living" if k.get("living") else "preceded"
                rprint(
                    f"  • {k.get('relative_name')} ({k.get('role')}, {live}) "
                    f"← {k.get('source_url') or ''}"
                )
        facts = []
        for label, key in (
            ("born", "birth_date"),
            ("birth place", "birth_place"),
            ("died", "death_date"),
            ("death place", "death_place"),
            ("occupation", "occupation"),
            ("funeral", "funeral_home"),
            ("cemetery", "cemetery"),
            ("military", "military"),
        ):
            if top.get(key):
                facts.append(f"{label}: {top.get(key)}")
        if facts:
            rprint("\n[bold]Facts[/bold]")
            for f in facts:
                rprint(f"  • {f}")
        county = lake.county_for_name(top.get("full_name") or name, limit=8)
        land = lake.land_for_name(top.get("full_name") or name, limit=8)
        corps = lake.corps_for_name(top.get("full_name") or name, limit=8)
        if county:
            rprint("\n[bold]County sources[/bold]")
            for c in county:
                hit = " hit" if c.get("name_hit") else ""
                rprint(f"  • {c.get('kind') or ''}{hit} {c.get('url')}")
        if land:
            rprint("\n[bold]Land candidates[/bold]")
            for L in land:
                rprint(f"  • APN {L.get('apn') or '—'} {L.get('situs') or ''} ← {L.get('source_url')}")
        if corps:
            rprint("\n[bold]Corp candidates[/bold]")
            for c in corps:
                rprint(f"  • {c.get('org_name')} {c.get('file_number') or ''} ← {c.get('source_url')}")
        sor = lake.sor_for_name(top.get("full_name") or name, limit=8)
        if sor:
            rprint("\n[bold]Sex-offender registry candidates[/bold]")
            for s in sor:
                rprint(
                    f"  • {s.get('registry_id') or ''} {s.get('dob') or ''} "
                    f"{s.get('address') or ''} ← {s.get('source_url')}"
                )
    finally:
        lake.close()


@people_app.command("obits")
def obits(
    limit: int = typer.Option(30, "--limit", "-n"),
) -> None:
    """List recent obituary source URLs in the lake."""
    lake = PeopleLake.from_settings(get_settings())
    try:
        import sqlite3

        con = sqlite3.connect(str(lake.path))
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT url, title, source_host, fetched_at, person_id "
            "FROM obituary_sources ORDER BY fetched_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        con.close()
        table = Table(title="Recent obituary sources")
        table.add_column("fetched")
        table.add_column("host")
        table.add_column("title")
        table.add_column("url")
        for r in rows:
            table.add_row(
                str(r["fetched_at"] or "")[:19],
                str(r["source_host"] or ""),
                str(r["title"] or "")[:40],
                str(r["url"] or "")[:70],
            )
        rprint(table)
    finally:
        lake.close()


@people_app.command("confirm")
def confirm(
    person: str = typer.Argument(..., help="Decedent / person name in the lake"),
    relative: str = typer.Option(..., "--relative", "-r", help="Kinship candidate name"),
    verdict: str = typer.Option(
        ...,
        "--verdict",
        "-v",
        help="true | false | unknown",
    ),
) -> None:
    """Operator T/F on a kinship candidate (lake only — not a public web write)."""
    lake = PeopleLake.from_settings(get_settings())
    try:
        n = lake.confirm_kinship(person, relative, verdict)
        if n == 0:
            rprint(f"[yellow]No kinship rows matched {person!r} / {relative!r}[/yellow]")
            raise typer.Exit(code=1)
        rprint(f"[green]updated {n} kinship row(s)[/green] → {verdict}")
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    finally:
        lake.close()


@people_app.command("graph")
def graph_cmd(
    name: str = typer.Argument(..., help="Person name in the people lake"),
    json_out: bool = typer.Option(True, "--json/--table", help="JSON graph dump (default)"),
) -> None:
    """Emit the person neighborhood (kin, places, orgs, source URLs) from the lake.

    Same payload as GET /v1/people/graph?q=
    """
    lake = PeopleLake.from_settings(get_settings())
    try:
        rows = lake.lookup_name(name, limit=1)
        if not rows:
            rprint(f"[yellow]No people lake hits for {name!r}[/yellow]")
            raise typer.Exit(code=1)
        row = rows[0]
        extra = enrichment_from_lakes(lake, row.get("full_name") or name, dict(row), get_settings())
        ents, edges = graph_from_lake(
            row.get("full_name") or name,
            dict(row),
            lake.obituaries_for_person(row["id"]),
            lake.kinship_for_person(row["id"]),
            **extra,
        )
        payload = serialize_graph(ents, edges)
        payload["query"] = name
        payload["person"] = row.get("full_name")
        print(json.dumps(payload, indent=2, default=str))
    finally:
        lake.close()


@people_app.command("coverage")
def coverage(
    state: Optional[str] = typer.Option(None, "--state", "-s", help="State abbr filter (e.g. AR)"),
    open_only: bool = typer.Option(False, "--open", help="List open (no deep pack) counties only"),
    limit: int = typer.Option(40, "--limit", "-n"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """US county collector coverage rollup (Census tracker checklist).

    Full sheet: docs/US-COUNTY-COLLECTOR-TRACKER.md
    """
    from umbra.geo.us_counties import coverage_rollup, load_tracker

    roll = coverage_rollup()
    tracker = load_tracker()
    states = tracker.get("states") or {}
    if json_out and not state:
        print(json.dumps({"rollup": roll, "states": {
            k: {
                "county_total": v.get("county_total"),
                "county_deep": v.get("county_deep"),
                "sos": v.get("sos"),
                "courts": v.get("courts"),
                "sor": v.get("sor"),
            }
            for k, v in states.items()
        }}, indent=2))
        return
    rprint(
        f"[bold]US coverage[/bold] states={roll.get('states')} counties={roll.get('counties')} "
        f"L1={roll.get('l1_state_packs')}/{roll.get('states')} "
        f"L2_deep={roll.get('l2_county_deep')} open={roll.get('l2_open')}"
    )
    rprint("Sheet: docs/US-COUNTY-COLLECTOR-TRACKER.md")
    if not state:
        return
    st = state.strip().upper()
    block = states.get(st)
    if not block:
        rprint(f"[yellow]Unknown state {st!r}[/yellow]")
        raise typer.Exit(code=1)
    rows = list(block.get("counties") or [])
    if open_only:
        rows = [c for c in rows if c.get("status") != "deep"]
    rprint(
        f"{st} L1 sos={block.get('sos')} courts={block.get('courts')} sor={block.get('sor')} "
        f"deep={block.get('county_deep')}/{block.get('county_total')}"
    )
    from rich.markup import escape

    for c in rows[: max(0, limit)]:
        mark = "x" if c.get("status") == "deep" else " "
        pack = c.get("pack") or ""
        rprint(escape(f"  [{mark}] {c.get('name')} FIPS {c.get('fips')} {pack}"))
    if len(rows) > limit:
        rprint(f"  … {len(rows) - limit} more")


@people_app.command("grow")
def grow(
    add: int = typer.Option(400, "--add", help="Max new Wikidata bios this tick"),
    harvest_only: bool = typer.Option(False, "--harvest-only"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Harvest public US-decedent Wikipedia bios and seed the people lake.

    Nightly automation. Wikimedia-compliant UA. Does not scrape /people.
    """
    from umbra.people.grow import grow as grow_lake

    stats = grow_lake(add=max(0, add), seed=not harvest_only)
    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    harv = stats.get("harvest") or {}
    seed_st = stats.get("seed") or {}
    lake = stats.get("lake") or {}
    rprint(
        f"[green]grow[/green] harvest_added={harv.get('added')} corpus={harv.get('corpus_total')} "
        f"seed_ok={seed_st.get('ok')} seed_fail={seed_st.get('fail')} "
        f"lake_people={lake.get('people')}"
    )



@people_app.command("portals")
def portals(
    check: bool = typer.Option(False, "--check", help="Probe every portal URL and record the result."),
    broken: bool = typer.Option(False, "--broken", help="List entries whose URL needs updating."),
) -> None:
    """Reachability of the record portals behind county/state coverage.

    `/people/coverage` counts packs that have been *written*. This counts the
    ones a collector can actually *read*, which is a smaller number and the one
    that predicts what an investigation returns.
    """
    from umbra.core.http_guard import GuardedClient
    from umbra.collectors.public_records_portals import _PORTALS
    from umbra.people.portal_health import PortalHealth, check_all

    settings = get_settings()
    health = PortalHealth.from_settings(settings)
    try:
        if check:
            rows = [(region, p.get("kind", "?"), p.get("name", ""), p["url"])
                    for region, portals_ in _PORTALS.items() for p in portals_]
            rprint(f"[dim]probing {len({r[3] for r in rows})} distinct portal URLs…[/dim]")
            with GuardedClient(headers={"User-Agent": settings.user_agent}) as http:
                out = check_all(health, http, rows,
                                progress=lambda i, u: None)
            rprint(f"[green]checked {out['checked']}[/green] · "
                   f"fetchable {out['fetchable']} · link-only {out['link_only']} · "
                   f"guard-blocked {out['blocked_by_guard']} · broken {out['broken']}")

        if broken:
            rows = health.broken()
            if not rows:
                rprint("[green]no broken portal URLs[/green]")
            else:
                table = Table(title=f"{len(rows)} portal URL(s) needing an update")
                table.add_column("region"); table.add_column("name"); table.add_column("why")
                for r in rows:
                    table.add_row(r["region"], (r["name"] or "")[:34], r["detail"][:60])
                rprint(table)
            return

        st = health.summary()
        if not st["checked"]:
            rprint("[yellow]never checked[/yellow] — run [bold]umbra people portals --check[/bold]. "
                   "Coverage counts packs written, not portals reachable.")
            return
        table = Table(title="Portal reachability")
        table.add_column("status"); table.add_column("count"); table.add_column("means")
        table.add_row("fetchable", str(st["fetchable"]), "a collector can read it")
        table.add_row("link-only", str(st["link_only"]),
                      "site refuses automation — still a good link for a person")
        table.add_row("guard-blocked", str(st["blocked_by_guard"]),
                      "our egress guard refused it — about us, not the portal")
        table.add_row("broken", str(st["broken"]), "404 or no response — needs a new URL")
        rprint(table)
        rprint(f"[dim]last checked {str(st['checked_at'])[:19]}[/dim]")
    finally:
        health.close()
