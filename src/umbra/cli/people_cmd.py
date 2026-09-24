"""CLI: umbra people — people-lake status / lookup (obituary person map corpus)."""

from __future__ import annotations

import json
from pathlib import Path
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
    cc = st.claims_cursor
    if cc:
        rprint(
            f"[cyan]claims cursor[/cyan] windows_exhausted={cc['windows_exhausted']}/"
            f"{cc['windows_total']} last_new={cc['last_new']} "
            f"last_updated={cc['last_updated']} last_run_at={cc['last_run_at']}"
        )
        for w in cc["windows"]:
            flag = "exhausted" if w["exhausted"] else "open"
            rprint(f"[dim]  {w['window']}: offset={w['offset']} ({flag})[/dim]")


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
    """US county collector coverage rollup (Census tracker checklist), plus
    owned-lake row counts (people/FEC/parcels/NPPES/990/ULS) — same rollup as
    `/people/coverage`.

    Full sheet: docs/US-COUNTY-COLLECTOR-TRACKER.md
    """
    from umbra.geo.us_counties import coverage_rollup, load_tracker
    from umbra.people.lake_coverage import lakes_coverage_payload

    roll = coverage_rollup()
    tracker = load_tracker()
    states = tracker.get("states") or {}
    lakes = lakes_coverage_payload()["lakes"]
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
        }, "lakes": lakes}, indent=2))
        return
    rprint(
        f"[bold]US coverage[/bold] states={roll.get('states')} counties={roll.get('counties')} "
        f"L1={roll.get('l1_state_packs')}/{roll.get('states')} "
        f"L2_deep={roll.get('l2_county_deep')} open={roll.get('l2_open')}"
    )
    rprint("Sheet: docs/US-COUNTY-COLLECTOR-TRACKER.md")
    rprint("[bold]Lakes[/bold] (own corpus, not identity claims):")
    for lk in lakes:
        if lk["available"]:
            rprint(f"  [green]{lk['name']}[/green] {lk['count']:,} rows, last import {lk['imported_at']}")
        else:
            rprint(f"  [yellow]{lk['name']}[/yellow] not imported")
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



FIND_DEFAULT_LIMIT = 20
FIND_MAX_LIMIT = 100


@people_app.command("find")
def find(
    name: str = typer.Argument(..., help="Full or partial name"),
    state: Optional[str] = typer.Option(None, "--state", help="Two-letter state"),
    city: Optional[str] = typer.Option(
        None, "--city", help="City (case-insensitive; narrows parcels, clinicians, licensees)"
    ),
    limit: int = typer.Option(
        FIND_DEFAULT_LIMIT, "--limit",
        help=f"Rows per group, {FIND_DEFAULT_LIMIT} default, {FIND_MAX_LIMIT} max",
    ),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Search both lakes: obituaries/claims and FEC contributors.

    `lookup` reads the people lake only. This one also reaches the FEC
    contributor lake, which is where almost everybody actually is.
    """
    from umbra.lake.people import PeopleLake
    from umbra.people.search import unified_search

    limit = max(1, min(limit, FIND_MAX_LIMIT))

    lake = PeopleLake.from_settings(get_settings())
    try:
        res = unified_search(lake, name, state=state, city=city, limit=limit)
    finally:
        lake.close()

    if json_out:
        print(json.dumps(res.as_dict(), indent=2, default=str))
        return

    if res.people:
        t = Table(title="people lake")
        t.add_column("name"); t.add_column("match"); t.add_column("obits")
        for p_ in res.people:
            t.add_row(p_.get("full_name") or "", p_.get("match") or "",
                      str(p_.get("obit_count") or 0))
        rprint(t)

    if res.contributors:
        t = Table(title="FEC contributors")
        t.add_column("name"); t.add_column("city"); t.add_column("st")
        t.add_column("occupation", overflow="fold"); t.add_column("filings", justify="right")
        for c in res.contributors:
            t.add_row(c.get("name_raw") or "", c.get("city") or "—",
                      c.get("state") or "—", (c.get("occupations") or "—")[:40],
                      f"{c.get('contributions') or 0:,}")
        rprint(t)

    if res.parcels:
        t = Table(title="Parcels (county owner rolls)")
        t.add_column("owner"); t.add_column("address"); t.add_column("city")
        t.add_column("st"); t.add_column("county"); t.add_column("parcel id")
        for p_ in res.parcels:
            t.add_row(p_.get("owner") or "", p_.get("address") or "—",
                      p_.get("city") or "—", p_.get("state") or "—",
                      p_.get("county") or "—", p_.get("parcel_id") or "—")
        rprint(t)

    if res.officers:
        t = Table(title="IRS Form 990 officers/directors")
        t.add_column("name"); t.add_column("title"); t.add_column("org")
        t.add_column("ein"); t.add_column("st"); t.add_column("tax year")
        for o in res.officers:
            t.add_row(o.get("name_raw") or "", o.get("title") or "—",
                      o.get("org_name") or "—", o.get("ein") or "—",
                      o.get("state") or "—", o.get("tax_year") or "—")
        rprint(t)

    if res.clinicians:
        t = Table(title="Clinicians (NPPES registry)")
        t.add_column("npi"); t.add_column("name"); t.add_column("city")
        t.add_column("st"); t.add_column("taxonomy")
        for c in res.clinicians:
            t.add_row(c.get("npi") or "", c.get("name_raw") or "",
                      c.get("city") or "—", c.get("state") or "—",
                      c.get("taxonomy") or "—")
        rprint(t)

    if res.licensees:
        t = Table(title="FCC ULS radio licenses")
        t.add_column("callsign"); t.add_column("name"); t.add_column("city")
        t.add_column("st"); t.add_column("service"); t.add_column("status")
        for u in res.licensees:
            t.add_row(u.get("callsign") or "—", u.get("name_raw") or "",
                      u.get("city") or "—", u.get("state") or "—",
                      u.get("radio_service") or "—", u.get("status") or "—")
        rprint(t)

    if res.inmates:
        t = Table(title="BOP inmate locator")
        t.add_column("name"); t.add_column("register #"); t.add_column("facility")
        t.add_column("age"); t.add_column("identity confirmed")
        for i_ in res.inmates:
            t.add_row(i_.get("person_name") or "", i_.get("register_number") or "—",
                      i_.get("facility") or "—", i_.get("age") or "—",
                      str(i_.get("identity_confirmed")))
        rprint(t)

    rprint(f"[dim]{res.note}[/dim]")
    if res.ambiguous:
        rprint("[yellow]Ambiguous — narrow with --state[/yellow]")
    rprint(f"[dim]{res.parcels_note}[/dim]")
    if res.parcels_ambiguous:
        rprint("[yellow]Parcels ambiguous across states — narrow with --state[/yellow]")
    rprint(f"[dim]{res.officers_note}[/dim]")
    rprint(f"[dim]{res.clinicians_note}[/dim]")
    if res.clinicians_ambiguous:
        rprint("[yellow]Clinicians ambiguous across states — narrow with --state[/yellow]")
    rprint(f"[dim]{res.licensees_note}[/dim]")
    if res.licensees_ambiguous:
        rprint("[yellow]Licensees ambiguous across states — narrow with --state[/yellow]")
    rprint(f"[dim]{res.inmates_note}[/dim]")
    if (not res.total and not res.parcels and not res.officers
            and not res.clinicians and not res.licensees and not res.inmates):
        raise typer.Exit(1)


@people_app.command("claims")
def claims(
    add: int = typer.Option(500, "--add", help="Max people to write this run"),
    reset: bool = typer.Option(False, "--reset", help="Rewind the paging cursor"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Fill the lake from structured Wikidata claims (no prose parsing).

    Replaces the `grow` path for the fields Wikidata carries. `grow` asked
    Wikidata for a name, then regex-parsed the Wikipedia article; occupation and
    residence came out as sentence fragments. This reads the claims.
    """
    from umbra.people.wikidata import harvest_claims

    stats = harvest_claims(add=max(0, add), reset=reset)
    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    rprint(
        f"[green]claims[/green] new={stats['new']:,} updated={stats['updated']:,} "
        f"people={stats['people']:,} kinship={stats['kinship_edges']:,}"
    )
    if stats.get("exhausted"):
        rprint(f"[dim]windows exhausted: {', '.join(stats['exhausted'])}[/dim]")
    if stats.get("error_count"):
        # Never a silent partial: a window that failed is a hole in the corpus.
        rprint(f"[yellow]{stats['error_count']} window/row error(s)[/yellow]")
        for e in stats.get("errors", []):
            rprint(f"[dim]  {e}[/dim]")


@people_app.command("repair")
def repair(
    apply: bool = typer.Option(False, "--apply", help="Write; otherwise dry run"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Clear prose-derived residence/occupation that the old parser invented.

    The old path wrote things like 'The Manhattan Transfer' and 'Cuba from' into
    `residence`, and truncated sentences into `occupation`. Those are not
    degraded facts, they are non-facts, and a later claims pass cannot tell them
    from real values. This nulls them so the claims pass can fill them in.

    Dry run by default: it reports what it would clear before touching anything.
    """
    from umbra.people.repair import repair_prose_fields

    stats = repair_prose_fields(apply=apply)
    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    verb = "cleared" if apply else "would clear"
    rprint(
        f"[green]repair[/green] {verb} residence={stats['residence']} "
        f"occupation={stats['occupation']} of {stats['people']} people"
    )
    if not apply:
        rprint("[dim]dry run — re-run with --apply to write[/dim]")


@people_app.command("fec")
def fec(
    path: Optional[Path] = typer.Option(None, "--zip", help="Local indiv*.zip"),
    cycle: int = typer.Option(2024, "--cycle", help="Election cycle for --download"),
    download: bool = typer.Option(False, "--download", help="Fetch the bulk file first"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Index FEC individual contributions (living people, with occupation).

    The bulk file is ~4 GB compressed and expands past 30 GB, so it is streamed
    and aggregated in SQLite rather than held in memory. Re-running the same
    cycle is a no-op: imports are keyed on the member CRC.
    """
    import tempfile

    from umbra.core.http_guard import GuardedClient
    from umbra.lake.fec import BULK_URL, FecLake
    from umbra.people.fill import guarded_download

    lake = FecLake()
    try:
        if not path and not download:
            st = lake.status()
            rprint(f"[green]fec lake[/green] contributors={st['contributors']:,}")
            for f in st.get("files", []):
                rprint(f"[dim]  {f['filename']}: {f['rows']:,} rows, {f['imported_at']}[/dim]")
            if not st["available"]:
                rprint("[yellow]empty — run[/yellow] umbra people fec --download")
            return

        with tempfile.TemporaryDirectory(prefix="umbra-fec-") as td:
            if download:
                url = BULK_URL.format(cycle=cycle, yy=str(cycle)[2:])
                dest = Path(td) / f"indiv{str(cycle)[2:]}.zip"
                rprint(f"[dim]downloading[/dim] {url}")
                settings = get_settings()
                with GuardedClient(
                    timeout=1800.0, headers={"User-Agent": settings.user_agent}
                ) as http:
                    # Not http.stream(follow_redirects=True): that path skips
                    # GuardedClient's per-hop check on redirects.
                    guarded_download(http, url, dest)
                rprint(f"[dim]downloaded[/dim] {dest.stat().st_size / 1e9:.2f} GB")
                path = dest

            stats = lake.import_zip(path)
    finally:
        lake.close()

    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    if stats.get("already_imported"):
        rprint("[yellow]already imported[/yellow] (same file CRC) — nothing changed")
        return
    rprint(
        f"[green]fec import[/green] rows={stats['rows']:,} "
        f"contributors={stats['contributors']:,} "
        f"non_individual_skipped={stats['skipped_non_individual']:,}"
    )
    rprint("[dim]A name in campaign finance filings is a name match, not an "
           "identification.[/dim]")


@people_app.command("nppes")
def nppes(
    path: Optional[Path] = typer.Option(None, "--zip", help="Local NPPES npidata_pfile zip"),
    download: bool = typer.Option(False, "--download", help="Fetch the current monthly file first"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Index CMS NPPES individual providers (NPI, legal name, practice, taxonomy).

    A registry row, not a person-finder result: the NPI is unique to one
    provider for life, but the name on it is exactly as ambiguous as anywhere
    else. Default is status + import-from-path; --download fetches the current
    monthly file first (large — hundreds of MB to low GB).
    """
    from umbra.lake.nppes import NPI_FILES_URL, NppesLake

    lake = NppesLake()
    try:
        if not path and not download:
            st = lake.status()
            rprint(f"[green]nppes lake[/green] providers={st['providers']:,}")
            for f in st.get("files", []):
                rprint(f"[dim]  {f['filename']}: {f['rows']:,} rows, {f['imported_at']}[/dim]")
            if not st["available"]:
                rprint(f"[yellow]empty — download the current monthly file from[/yellow] "
                        f"{NPI_FILES_URL} [yellow]and run with --zip PATH[/yellow]")
            return

        if download:
            rprint(
                "[red]--download is not implemented in this CLI[/red]: the "
                f"NPPES direct URL changes every month. Fetch it manually from "
                f"{NPI_FILES_URL} and re-run with --zip PATH."
            )
            raise typer.Exit(code=1)

        stats = lake.import_zip(path)
    finally:
        lake.close()

    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    if stats.get("already_imported"):
        rprint("[yellow]already imported[/yellow] (same file CRC) — nothing changed")
        return
    rprint(
        f"[green]nppes import[/green] rows={stats['rows']:,} "
        f"providers={stats['providers']:,} "
        f"organizations_skipped={stats['skipped_organization']:,}"
    )
    rprint("[dim]A name+NPI hit is a registry row, not confirmation this is the "
           "person you meant.[/dim]")


@people_app.command("990")
def irs990(
    year: Optional[int] = typer.Option(None, "--year", help="Filing year to import"),
    max_files: int = typer.Option(25, "--max-files", help="Filings to fetch this run"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """IRS Form 990 officer/director/trustee lake (org-officer candidates).

    Default is status. `--year` streams up to --max-files new filings from
    the official IRS bulk index for that year, resuming from a persisted
    cursor — it never downloads a whole year in one call and never merges
    rows into `people`, FEC, or NPPES.
    """
    from umbra.lake.irs990 import Irs990Lake

    lake = Irs990Lake()
    try:
        if year is None:
            st = lake.status()
            rprint(f"[green]irs990 lake[/green] officers={st['officers']:,}")
            if st.get("years"):
                rprint(f"[dim]  years: {', '.join(st['years'])}[/dim]")
            if not st["available"]:
                rprint("[yellow]empty — run[/yellow] umbra people 990 --year YYYY")
            if json_out:
                print(json.dumps(st, indent=2, default=str))
            return

        stats = lake.import_year(year, max_files=max_files)
    finally:
        lake.close()

    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    rprint(
        f"[green]irs990 import[/green] year={stats['year']} "
        f"files_processed={stats['files_processed']} "
        f"officers_kept={stats['officers_kept']} "
        f"already_imported={stats['already_imported']} "
        f"cursor={stats['cursor']}"
    )
    rprint("[dim]A name on a 990 is an officer/director role at one "
           "organization in one tax year — not an identity claim.[/dim]")


@people_app.command("uls")
def uls(
    path: Optional[Path] = typer.Option(None, "--zip", help="Local ULS per-radio-service zip (HD.dat + EN.dat)"),
    download: bool = typer.Option(False, "--download", help="Fetch a bulk file first"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Index FCC ULS licenses (callsign, licensee name, address, radio service).

    A registry row, not a person-finder result, and not the FAA N-number lake
    (`umbra faa`) — a callsign is a radio license, not an aircraft. Default is
    status + import-from-path; --download is not implemented, since ULS bulk
    is one zip per radio service rather than a single "complete" archive.
    """
    from umbra.lake.uls import ULS_INDEX_URL, UlsLake

    lake = UlsLake()
    try:
        if not path and not download:
            st = lake.status()
            rprint(f"[green]uls lake[/green] licenses={st['licenses']:,}")
            for f in st.get("files", []):
                rprint(f"[dim]  {f['filename']}: {f['rows']:,} rows, {f['imported_at']}[/dim]")
            if not st["available"]:
                rprint(f"[yellow]empty — download a per-radio-service bulk zip from[/yellow] "
                        f"{ULS_INDEX_URL} [yellow]and run with --zip PATH[/yellow]")
            return

        if download:
            rprint(
                "[red]--download is not implemented in this CLI[/red]: ULS "
                f"publishes one zip per radio service, not a single archive. "
                f"Fetch the one you want from {ULS_INDEX_URL} and re-run with "
                "--zip PATH."
            )
            raise typer.Exit(code=1)

        stats = lake.import_zip(path)
    finally:
        lake.close()

    if json_out:
        print(json.dumps(stats, indent=2, default=str))
        return
    if stats.get("already_imported"):
        rprint("[yellow]already imported[/yellow] (same file CRC) — nothing changed")
        return
    rprint(
        f"[green]uls import[/green] rows={stats['rows']:,} "
        f"licenses={stats['licenses']:,} "
        f"skipped_company={stats['skipped_company']:,}"
    )
    rprint("[dim]A licensee name on file with the FCC is a registry row, not "
           "an identification.[/dim]")


@people_app.command("fill")
def fill(
    only: Optional[str] = typer.Option(
        None, "--only", help="Comma list of sources: fec,nppes,uls,990 (default: all)"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """One bounded pass that tops up the bulk people lakes (for a timer).

    FEC: the next closed election cycle not yet imported (never the open one).
    NPPES: the current monthly file, if not already imported. ULS: the amateur
    service's complete file, at most every 28 days. IRS 990: advances the
    latest two filing years by a bounded number of filings. See docs/PEOPLE.md.
    """
    from umbra.people.fill import SOURCES, run_fill

    chosen = [s.strip() for s in (only or "").split(",") if s.strip()] or None
    bad = [s for s in chosen or [] if s not in SOURCES]
    if bad:
        raise typer.BadParameter(f"unknown source(s) {bad}; choose from {list(SOURCES)}")
    outcomes = run_fill(only=chosen)
    if json_out:
        print(json.dumps([o.as_dict() for o in outcomes], indent=2, default=str))
    else:
        colour = {"imported": "green", "skipped": "dim", "failed": "red"}
        for o in outcomes:
            rprint(f"[{colour[o.status]}]{o.source:6} {o.status}[/{colour[o.status]}] {o.detail}")
    if any(o.status == "failed" for o in outcomes):
        raise typer.Exit(code=1)


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
