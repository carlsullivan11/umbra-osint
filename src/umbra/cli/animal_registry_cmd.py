"""``umbra animal-registry`` — cited animal-abuse findings, reports and disputes.

See docs/ANIMAL-REGISTRY.md. Every entry is an official finding with its source;
reports are reviewer leads and are never shown as entries.
"""
from __future__ import annotations

import getpass
import json
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.lake.animal_registry import (
    FINDING_DISPOSITIONS,
    SOURCE_KINDS,
    AnimalRegistryLake,
    RegistryError,
    read_csv_rows,
)

animal_registry_app = typer.Typer(
    help="Animal-abuse registry: cited official findings only (offline lake).",
    no_args_is_help=True,
)
source_app = typer.Typer(help="Official sources findings are filed under.", no_args_is_help=True)
report_app = typer.Typer(help="Reports from rescues/shelters — reviewer leads, never published.",
                         no_args_is_help=True)
dispute_app = typer.Typer(help="Disputes: an open one hides the entry until resolved.",
                          no_args_is_help=True)
animal_registry_app.add_typer(source_app, name="source")
animal_registry_app.add_typer(report_app, name="report")
animal_registry_app.add_typer(dispute_app, name="dispute")

_FINDINGS = ", ".join(sorted(FINDING_DISPOSITIONS))


def _lake() -> AnimalRegistryLake:
    return AnimalRegistryLake.from_settings(get_settings())


def _actor(value: str | None) -> str:
    if value and value.strip():
        return value.strip()
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return "cli"


def _fail(exc: RegistryError) -> None:
    rprint(f"[red]refused:[/red] {exc}")
    raise typer.Exit(2)


def _entries_table(title: str, rows: list[dict], *, with_match: bool = False) -> Table:
    t = Table(title=title)
    if with_match:
        t.add_column("match")
    for col in ("name", "disposition", "offense", "date", "where", "source", "entry"):
        t.add_column(col)
    for r in rows:
        where = ", ".join(p for p in (r.get("city"), r.get("county"), r.get("state")) if p)
        cells = [r["name_raw"], r["disposition"].replace("_", " "), r["offense"],
                 r.get("finding_date") or "", where, r.get("source_name") or r["source_id"],
                 r["entry_id"]]
        if with_match:
            cells.insert(0, r["match"])
        t.add_row(*cells)
    return t


@animal_registry_app.command("status")
def status_cmd() -> None:
    """Counts: entries, publishable, removed, suppressed, pending reports, open disputes."""
    lake = _lake()
    try:
        st = lake.status()
        t = Table(title="Animal-abuse registry")
        t.add_column("key")
        t.add_column("value")
        for k, v in st.items():
            t.add_row(k.replace("_", " "), str(v))
        rprint(t)
        if not st["available"]:
            rprint("[yellow]No publishable findings.[/yellow] Add a source and import it; "
                   "until then a search is unchecked, not clean.")
    finally:
        lake.close()


@animal_registry_app.command("search")
def search_cmd(
    name: str = typer.Argument(..., help="Person name"),
    state: Optional[str] = typer.Option(None, "--state", help="Two-letter state"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Publishable findings matching a name. A match is a candidate, not an identity."""
    lake = _lake()
    try:
        hits = lake.search(name, state=state)
        if as_json:
            print(json.dumps(hits, indent=2, default=str))
            return
        if not hits:
            rprint(f"No publishable finding matches {name!r}. "
                   "[dim]Not a clean record: only imported sources are covered, and "
                   "charges, sealed and expunged cases are never held.[/dim]")
            return
        rprint(_entries_table(f"Registry matches for {name!r}", hits, with_match=True))
        rprint("[dim]A name on a finding is not an identification — confirm against the "
               "source record. Consumer-reporting uses are subject to the FCRA.[/dim]")
    finally:
        lake.close()


@animal_registry_app.command("list")
def list_cmd(
    state: Optional[str] = typer.Option(None, "--state"),
    limit: int = typer.Option(50, "--limit"),
    offset: int = typer.Option(0, "--offset"),
) -> None:
    """The publishable registry — exactly what a public page is allowed to show."""
    lake = _lake()
    try:
        rprint(_entries_table("Animal-abuse registry", lake.browse(
            state=state, limit=limit, offset=offset)))
    finally:
        lake.close()


@animal_registry_app.command("show")
def show_cmd(entry_id: str = typer.Argument(...)) -> None:
    """One entry, including whether it is publishable and why not, and its audit trail."""
    lake = _lake()
    try:
        e = lake.entry(entry_id)
        if e is None:
            rprint(f"[red]no entry[/red] {entry_id}")
            raise typer.Exit(1)
        print(json.dumps({**e, "events": lake.events(target=entry_id)}, indent=2, default=str))
    finally:
        lake.close()


@animal_registry_app.command("import-csv")
def import_csv_cmd(
    source_id: str = typer.Argument(..., help="A source added with `source add`"),
    csv_path: Path = typer.Argument(..., exists=True, dir_okay=False),
    append: bool = typer.Option(
        False, "--append",
        help="File is additions only; do not delist entries missing from it"),
    actor: Optional[str] = typer.Option(None, "--by"),
) -> None:
    """Import a source's CSV export (columns: name, offense, disposition, …).

    By default the file is the source's full current list, so entries missing
    from it are marked removed — that is how delistings arrive.
    """
    lake = _lake()
    try:
        res = lake.import_rows(source_id, read_csv_rows(csv_path),
                               snapshot=not append, actor=_actor(actor))
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"rows {res.rows} · stored [bold]{res.stored}[/bold] · "
           f"not a finding {res.skipped_not_a_finding} · invalid {res.skipped_invalid} · "
           f"delisted {res.delisted} · relisted {res.relisted}")
    if res.skipped_not_a_finding:
        rprint("[dim]Rows whose disposition is not one of "
               f"({_FINDINGS}) are charges, reversals or unknown, and are never stored.[/dim]")


@animal_registry_app.command("add-finding")
def add_finding_cmd(
    name: str = typer.Option(..., "--name"),
    offense: str = typer.Option(..., "--offense"),
    disposition: str = typer.Option(..., "--disposition", help=_FINDINGS),
    source_url: str = typer.Option(..., "--source-url", help="URL of the court/agency record"),
    citation: str = typer.Option(..., "--citation", help="Docket / case number / order"),
    state: Optional[str] = typer.Option(None, "--state"),
    county: Optional[str] = typer.Option(None, "--county"),
    city: Optional[str] = typer.Option(None, "--city"),
    statute: Optional[str] = typer.Option(None, "--statute"),
    finding_date: Optional[str] = typer.Option(None, "--date", help="YYYY-MM-DD"),
    actor: Optional[str] = typer.Option(None, "--by"),
) -> None:
    """Add one finding a reviewer located in an official record."""
    lake = _lake()
    try:
        e = lake.add_finding(name=name, offense=offense, disposition=disposition,
                             source_url=source_url, citation=citation, state=state,
                             county=county, city=city, statute=statute,
                             finding_date=finding_date, actor=_actor(actor))
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"[green]added[/green] {e['entry_id']}")


# --- sources ---------------------------------------------------------------

@source_app.command("add")
def source_add_cmd(
    source_id: str = typer.Argument(..., help="short id, e.g. ny-suffolk"),
    name: str = typer.Option(..., "--name"),
    url: str = typer.Option(..., "--url", help="Where the public can check the source"),
    kind: str = typer.Option("government_registry", "--kind", help=", ".join(sorted(SOURCE_KINDS))),
    jurisdiction: Optional[str] = typer.Option(None, "--jurisdiction"),
    terms_note: Optional[str] = typer.Option(
        None, "--terms", help="What the source's terms say about republication"),
    retention_years: Optional[int] = typer.Option(
        None, "--retention-years", help="Stop publishing findings older than this"),
    actor: Optional[str] = typer.Option(None, "--by"),
) -> None:
    """Register or update an official source."""
    lake = _lake()
    try:
        s = lake.add_source(source_id, name=name, kind=kind, url=url,
                            jurisdiction=jurisdiction, terms_note=terms_note,
                            retention_years=retention_years, actor=_actor(actor))
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"[green]source[/green] {s['source_id']} ({s['kind']})")
    if not s.get("terms_note"):
        rprint("[yellow]No --terms recorded.[/yellow] Check the source's access terms before "
               "publishing: some registries are licensed to shelters and sellers only.")


@source_app.command("list")
def source_list_cmd() -> None:
    lake = _lake()
    try:
        t = Table(title="Registry sources")
        for col in ("id", "kind", "name", "jurisdiction", "retention", "last import", "rows"):
            t.add_column(col)
        for s in lake.sources():
            t.add_row(s["source_id"], s["kind"], s["name"], s["jurisdiction"] or "",
                      str(s["retention_years"] or ""), s["last_imported_at"] or "never",
                      str(s["last_rows"] or 0))
        rprint(t)
    finally:
        lake.close()


# --- reports ---------------------------------------------------------------

@report_app.command("submit")
def report_submit_cmd(
    org: str = typer.Option(..., "--org", help="Submitting rescue, shelter or agency"),
    subject: str = typer.Option(..., "--subject", help="Subject's full name"),
    narrative: str = typer.Option(..., "--narrative"),
    state: Optional[str] = typer.Option(None, "--state"),
    county: Optional[str] = typer.Option(None, "--county"),
    city: Optional[str] = typer.Option(None, "--city"),
    reference_url: Optional[str] = typer.Option(None, "--reference-url",
                                                help="Case, news or agency link to start from"),
    contact: Optional[str] = typer.Option(None, "--contact"),
    actor: Optional[str] = typer.Option(None, "--by"),
) -> None:
    """File a report. It is queued for review and never published as-is."""
    lake = _lake()
    try:
        r = lake.submit_report(submitter_org=org, subject_name=subject, narrative=narrative,
                               state=state, county=county, city=city,
                               reference_url=reference_url, submitter_contact=contact,
                               actor=_actor(actor))
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"[green]queued[/green] {r['report_id']} — becomes an entry only if a reviewer "
           "links it to an official finding.")


@report_app.command("list")
def report_list_cmd(status: str = typer.Option("pending", "--status")) -> None:
    lake = _lake()
    try:
        t = Table(title=f"Reports ({status})")
        for col in ("id", "submitted", "org", "subject", "state", "reference", "linked"):
            t.add_column(col)
        for r in lake.reports(status=status):
            t.add_row(r["report_id"], r["submitted_at"], r["submitter_org"], r["subject_name"],
                      r["state"] or "", r["reference_url"] or "", r["linked_entry_id"] or "")
        rprint(t)
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()


@report_app.command("link")
def report_link_cmd(
    report_id: str = typer.Argument(...),
    entry_id: str = typer.Argument(..., help="Finding that backs the report"),
    note: Optional[str] = typer.Option(None, "--note"),
    reviewer: Optional[str] = typer.Option(None, "--by"),
) -> None:
    """Close a report against the official finding a reviewer found for it."""
    lake = _lake()
    try:
        lake.link_report(report_id, entry_id, reviewer=_actor(reviewer), note=note)
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"[green]linked[/green] {report_id} → {entry_id}")


@report_app.command("reject")
def report_reject_cmd(
    report_id: str = typer.Argument(...),
    note: str = typer.Option(..., "--note", help="Why (no record found, wrong person, …)"),
    reviewer: Optional[str] = typer.Option(None, "--by"),
) -> None:
    lake = _lake()
    try:
        lake.reject_report(report_id, reviewer=_actor(reviewer), note=note)
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"rejected {report_id}")


# --- disputes --------------------------------------------------------------

@dispute_app.command("open")
def dispute_open_cmd(
    entry_id: str = typer.Argument(...),
    basis: str = typer.Option(..., "--basis", help="wrong person, expunged, overturned, …"),
    contact: Optional[str] = typer.Option(None, "--contact"),
    actor: Optional[str] = typer.Option(None, "--by"),
) -> None:
    """Open a dispute. The entry is hidden until it is resolved."""
    lake = _lake()
    try:
        d = lake.open_dispute(entry_id, basis=basis, contact=contact, actor=_actor(actor))
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"[green]opened[/green] {d['dispute_id']} — {entry_id} hidden pending review")


@dispute_app.command("list")
def dispute_list_cmd(status: str = typer.Option("open", "--status")) -> None:
    lake = _lake()
    try:
        t = Table(title=f"Disputes ({status})")
        for col in ("id", "entry", "opened", "basis", "resolved by", "note"):
            t.add_column(col)
        for d in lake.disputes(status=status):
            t.add_row(d["dispute_id"], d["entry_id"], d["opened_at"], d["basis"],
                      d["resolved_by"] or "", d["note"] or "")
        rprint(t)
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()


@dispute_app.command("resolve")
def dispute_resolve_cmd(
    dispute_id: str = typer.Argument(...),
    upheld: bool = typer.Option(..., "--upheld/--rejected",
                                help="--upheld suppresses the entry permanently"),
    note: str = typer.Option(..., "--note"),
    reviewer: Optional[str] = typer.Option(None, "--by"),
) -> None:
    lake = _lake()
    try:
        d = lake.resolve_dispute(dispute_id, upheld=upheld, reviewer=_actor(reviewer), note=note)
    except RegistryError as exc:
        _fail(exc)
    finally:
        lake.close()
    rprint(f"{dispute_id} {d['status']}")
