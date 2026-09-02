"""`umbra phone` — look up, seed and maintain community phone reputation.

`seed` exists so the operator can put their own known-spam numbers in. Those
reports are filed with `source="operator"`, not laundered into the community
count: one person's call log rendered as consensus would be inventing a crowd,
and the result page says where the report came from.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.db.schema import get_session, init_db
from umbra.phone import store as phone_store
from umbra.phone.normalize import phone_facts
from umbra.phone.verdict import CATEGORIES

phone_app = typer.Typer(help="Phone number validation and community reputation")

OPERATOR_KEY = "operator:seed:v1"


def _session():
    settings = get_settings()
    init_db(settings)
    return get_session()


@phone_app.command("check")
def phone_check(number: str = typer.Argument(..., help="Phone number")) -> None:
    """Numbering-plan facts and any community reports for one number."""
    session = _session()
    try:
        facts = phone_facts(number)
        if not facts.get("possible"):
            rprint(f"[red]not a phone number[/red]: {number}")
            raise typer.Exit(code=1)
        rprint(f"[cyan]{facts['e164']}[/cyan] · {facts.get('region')} · "
               f"{facts.get('number_type')} · valid={facts.get('valid')}")
        row = phone_store.get_or_create(session, number)
        if row is None:
            rprint("[yellow]no reputation page[/yellow] (emergency number or short code)")
            return
        view = phone_store.public_view(session, row.id)
        rprint(f"[bold]{view['verdict']['label']}[/bold] — {view['reports']} report(s)"
               + ("" if view["active"] else " [dim](delisted)[/dim]"))
        rprint(f"[dim]{view['verdict']['note']}[/dim]")
    finally:
        session.close()


@phone_app.command("seed")
def phone_seed(
    numbers: Optional[list[str]] = typer.Argument(None, help="Numbers to report"),
    file: Optional[Path] = typer.Option(None, "--file", "-f",
                                        help="One number per line"),
    category: str = typer.Option("spam", "--category", "-c",
                                 help=f"one of: {', '.join(CATEGORIES)}"),
    note: str = typer.Option("", "--note", help="Optional note (no personal data)"),
) -> None:
    """File operator reports for known-spam numbers.

    Marked `source=operator` so the page shows them as the operator's own
    reports rather than as community consensus. They count as the single voice
    they are: one seeded number reads "Unconfirmed", not "Likely unwanted".
    """
    if category not in CATEGORIES:
        raise typer.BadParameter(f"category must be one of: {', '.join(CATEGORIES)}")

    values: list[str] = list(numbers or [])
    if file:
        values += [ln.strip() for ln in Path(file).read_text().splitlines() if ln.strip()]
    if not values:
        raise typer.BadParameter("give numbers as arguments or --file")

    session = _session()
    added = skipped = refused = 0
    seen: set[str] = set()
    try:
        for raw in values:
            facts = phone_facts(raw)
            e164 = facts.get("e164")
            if not e164:
                rprint(f"  [red]unparseable[/red] {raw}")
                refused += 1
                continue
            if e164 in seen:
                skipped += 1
                continue
            seen.add(e164)
            row = phone_store.get_or_create(session, raw)
            if row is None:
                rprint(f"  [yellow]refused[/yellow] {e164} (emergency or short code)")
                refused += 1
                continue
            report = phone_store.add_report(session, row.id, OPERATOR_KEY, category,
                                            note=note or None, source="operator")
            if report is None:
                rprint(f"  [red]not recorded[/red] {e164}")
                refused += 1
                continue
            added += 1
            rprint(f"  [green]reported[/green] {e164} as {category}")
    finally:
        session.close()
    rprint(f"\n[green]{added}[/green] reported · {skipped} duplicate(s) · {refused} refused")


@phone_app.command("expire")
def phone_expire(
    days: int = typer.Option(phone_store.LISTING_ACTIVE_DAYS, "--days",
                             help="Delist after this long with no new report; 0 disables"),
) -> None:
    """Delist numbers nobody has reported lately. Keeps the reports and the log."""
    session = _session()
    try:
        n = phone_store.expire_stale_listings(session, days=days)
        rprint(f"[green]delisted[/green] {n} number(s) with no report in {days}d"
               if n else f"[dim]nothing to delist (window {days}d)[/dim]")
    finally:
        session.close()


@phone_app.command("list")
def phone_list(limit: int = typer.Option(50, "--limit", "-n")) -> None:
    """Numbers currently on the active list."""
    session = _session()
    try:
        rows = phone_store.active_listings(session, limit=limit)
        table = Table(title=f"Active phone listings ({len(rows)})")
        for col in ("number", "reports", "last report"):
            table.add_column(col)
        for row in rows:
            table.add_row(row["e164"], str(row["reports"]),
                          row["last_report_at"].strftime("%Y-%m-%d")
                          if row["last_report_at"] else "—")
        rprint(table)
    finally:
        session.close()


@phone_app.command("ftc-sync")
def phone_ftc_sync(
    days: int = typer.Option(7, "--days", "-d", help="Newest N published days"),
) -> None:
    """Ingest the FTC's daily Do Not Call complaint files.

    No API key: the daily CSVs are public files. The FTC *API* needs a key and
    is useless for this — it cannot be filtered by number and walks ~19M records
    from the oldest end — so this reads the published files instead.
    """
    from umbra.core.http_guard import GuardedClient
    from umbra.phone import ftc

    settings = get_settings()
    session = _session()
    try:
        with GuardedClient(timeout=max(60.0, settings.request_timeout_s),
                           headers={"User-Agent": settings.user_agent}) as http:
            stats = ftc.sync(session, http, days=days)
        rprint(f"[green]ftc[/green] days={stats['days']} skipped={stats['skipped']} "
               f"fetched={stats['fetched']} stored={stats['stored']} "
               f"errors={stats['errors']}")
    finally:
        session.close()
