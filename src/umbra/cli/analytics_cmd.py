"""CLI: umbra analytics — where a run's time goes, and whether the lakes are sound.

Open core on purpose. These numbers are about how Umbra behaves, so someone who
installed it from PyPI can audit the same things the hosted operator can; the
private web dashboard renders the same two functions rather than reimplementing
them.
"""
from __future__ import annotations

import json as jsonlib
from dataclasses import asdict

import typer
from rich.console import Console
from rich.table import Table

from umbra.analytics.collectors import collector_scorecard
from umbra.analytics.lakes import lake_health, record_snapshot

app = typer.Typer(help="How Umbra is behaving: collector cost, lake health.")
console = Console()


def _fmt_seconds(value: float) -> str:
    return f"{value:,.1f}" if value >= 0.05 else f"{value:.2f}"


@app.command("collectors")
def collectors_command(
    days: int = typer.Option(30, "--days", "-d", help="Window in days"),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output"),
) -> None:
    """Per-collector cost and yield, from the timing every run already records."""
    from umbra.db.schema import get_session

    session = get_session()
    try:
        card = collector_scorecard(session, days=days)
    finally:
        session.close()

    if json_out:
        payload = {
            "days": card.days,
            "runs_total": card.runs_total,
            "runs_with_timing": card.runs_with_timing,
            "coverage_note": card.coverage_note,
            "measured_seconds": round(card.measured_seconds, 2),
            "rows": [
                {
                    **asdict(row),
                    "mean_seconds_per_run": round(row.mean_seconds_per_run, 3),
                    "evidence_per_run": round(row.evidence_per_run, 2),
                    "share_of_seconds": round(row.share_of_seconds, 4),
                }
                for row in card.rows
            ],
        }
        console.print_json(jsonlib.dumps(payload))
        return

    if not card.rows:
        # An empty table would read as "no collector costs anything".
        console.print(f"[yellow]{card.coverage_note}[/yellow]")
        return

    # Eight columns, not eleven. At an 80-column terminal Rich pays for extra
    # columns out of the first one, which truncated the collector name — the
    # one value the whole table exists to give you. `share` and `ev/run` are
    # both derivable from columns that are here, so they went.
    table = Table(title=f"collector scorecard · last {card.days}d")
    table.add_column("collector", no_wrap=True, min_width=16)
    table.add_column("runs", justify="right")
    table.add_column("total s", justify="right")
    # Named per run, not per call: collector_seconds sums every entity the
    # collector saw in that run, so a per-call figure would be invented.
    table.add_column("s/run", justify="right")
    table.add_column("share", justify="right")
    table.add_column("evid", justify="right")
    table.add_column("conf", justify="right")
    table.add_column("fail", justify="right")

    for row in card.rows:
        # A collector that costs real time and returns nothing is the row worth
        # finding, so it is the one that gets coloured.
        dud = row.total_seconds >= 1.0 and row.evidence == 0
        name = f"[yellow]{row.collector}[/yellow]" if dud else row.collector
        # Timeouts and errors share a column: both mean "this collector did
        # not answer", and the distinction is in the run notes for anyone who
        # needs it. A "t"/"e" suffix keeps it recoverable at a glance.
        fails = []
        if row.timeouts:
            fails.append(f"{row.timeouts}t")
        if row.errors:
            fails.append(f"{row.errors}e")
        table.add_row(
            name,
            str(row.runs),
            _fmt_seconds(row.total_seconds),
            _fmt_seconds(row.mean_seconds_per_run),
            f"{row.share_of_seconds * 100:.0f}%",
            str(row.evidence),
            "—" if row.mean_confidence is None else f"{row.mean_confidence:.2f}",
            " ".join(fails),
        )

    console.print(table)
    console.print(f"[dim]{card.coverage_note}[/dim]")
    console.print("[dim]s/run is per run, not per call: a run that fanned out to "
                  "many entities records one figure covering all of them.[/dim]")


@app.command("lakes")
def lakes_command(
    record: bool = typer.Option(
        False, "--record",
        help="Take a snapshot now (what the timer runs), then report"),
    days: int = typer.Option(90, "--days", "-d", help="History window in days"),
    json_out: bool = typer.Option(False, "--json", help="Machine-readable output"),
) -> None:
    """Row counts and freshness over time — catches a sync that succeeded and
    brought back less than it should have."""
    from umbra.core.config import get_settings
    from umbra.db.schema import get_session
    from umbra.lake.inventory import lake_inventory

    session = get_session()
    try:
        if record:
            readings = lake_inventory(get_settings())
            written = record_snapshot(session, readings)
            skipped = [r for r in readings if not r.readable]
            if not json_out:
                console.print(f"[green]recorded {written} lake snapshot(s)[/green]")
                for r in skipped:
                    # Never a silent cap: a lake we could not read is a gap in
                    # the series, and the series is the whole signal.
                    console.print(f"[yellow]  {r.lake}: {r.error} — not recorded[/yellow]")
        health = lake_health(session, days=days)
    finally:
        session.close()

    if json_out:
        payload = {
            "note": health.note,
            "rows": [
                {
                    "lake": r.lake,
                    "rows": r.rows,
                    "delta": r.delta,
                    "shrank": r.shrank,
                    "stale": r.stale,
                    "healthy": r.healthy,
                    "age_days": None if r.age_days is None else round(r.age_days, 2),
                    "cadence_days": r.cadence_days,
                    "note": r.note,
                }
                for r in health.rows
            ],
        }
        console.print_json(jsonlib.dumps(payload))
        return

    if not health.rows:
        console.print(f"[yellow]{health.note}[/yellow]")
        return

    table = Table(title=f"lake health · last {days}d")
    table.add_column("")
    table.add_column("lake")
    table.add_column("rows", justify="right")
    table.add_column("change", justify="right")
    table.add_column("synced", justify="right")
    table.add_column("note")

    for row in health.rows:
        mark = "[green]✓[/green]" if row.healthy else "[red]✗[/red]"
        if row.delta is None:
            change = "—"
        elif row.delta < 0:
            change = f"[red]{row.delta:,}[/red]"
        else:
            change = f"+{row.delta:,}"
        if row.age_days is None:
            synced = "unknown"
        elif row.age_days < 1:
            synced = "today"
        else:
            synced = f"{row.age_days:.0f}d"
        table.add_row(mark, row.lake, f"{row.rows:,}", change, synced, row.note)

    console.print(table)
    console.print(f"[dim]{health.note}[/dim]")
