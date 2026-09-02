"""CLI: `umbra ops` — triage surface for ops events (E1).

This is deliberately the *first* surface, before any web UI: it is what the
Hermes review job reads over SSH, and it means the pull needs no HTTP, no
Cloudflare Access service token, and no new inbound port.

    ssh vps 'docker exec umbra-api umbra ops events --needs-plan --json'
    ssh vps 'docker exec umbra-api umbra ops plan oe_123 --priority P2 --file -'

Bots draft, humans decide: `plan` attaches a proposed fix and a suggested
priority but never changes status, and nothing here closes an event except an
explicit `resolve`.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db

ops_app = typer.Typer(help="Operational events: triage, plan fixes, mute, prune.")

STATUSES = ("open", "ack", "planned", "in_progress", "done", "wontfix")


def _repo() -> Repository:
    settings = get_settings()
    init_db(settings)
    return Repository(get_session(), settings.raw_dir)


def _as_dict(e) -> dict:
    return {
        "id": e.id,
        "severity": e.severity,
        "kind": e.kind,
        "source": e.source,
        "title": e.title,
        "count": e.count,
        "status": e.status,
        "priority": e.priority,
        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
        "detail": e.detail,
        "proposed_fix": e.proposed_fix,
        "resolution": e.resolution,
        "fingerprint": e.fingerprint,
    }


@ops_app.command("events")
def ops_events(
    status: Optional[str] = typer.Option("open", "--status", help="Filter by status ('' for all)"),
    severity: Optional[str] = typer.Option(None, "--severity", help="S0..S4"),
    needs_plan: bool = typer.Option(False, "--needs-plan", help="Only events with no proposed fix"),
    hours: Optional[int] = typer.Option(None, "--hours", help="Only seen in the last N hours"),
    limit: int = typer.Option(50, "--limit", "-n"),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable (for the review job)"),
) -> None:
    """List ops events."""
    since = (datetime.now(tz=timezone.utc) - timedelta(hours=hours)) if hours else None
    rows = _repo().list_ops_events(
        status=status or None, severity=severity, needs_plan=needs_plan,
        since=since, limit=limit,
    )
    if as_json:
        print(json.dumps([_as_dict(e) for e in rows], indent=2, default=str))
        return
    if not rows:
        rprint("[green]No matching ops events.[/green]")
        return
    table = Table(title=f"ops events ({len(rows)})")
    for col in ("id", "sev", "kind", "count", "status", "P", "last seen", "title"):
        table.add_column(col)
    for e in rows:
        table.add_row(
            e.id, e.severity, e.kind, str(e.count), e.status, e.priority or "—",
            e.last_seen.strftime("%m-%d %H:%M") if e.last_seen else "—",
            (e.title or "")[:60],
        )
    rprint(table)


@ops_app.command("show")
def ops_show(
    event_id: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Full detail for one event."""
    event = _repo().get_ops_event(event_id)
    if event is None:
        rprint(f"[red]no such event:[/red] {event_id}")
        raise typer.Exit(1)
    if as_json:
        print(json.dumps(_as_dict(event), indent=2, default=str))
        return
    rprint(f"[bold]{event.id}[/bold] {event.severity} {event.kind} "
           f"×{event.count} · {event.status}" + (f" · {event.priority}" if event.priority else ""))
    rprint(f"[dim]{event.first_seen} → {event.last_seen} · {event.source}[/dim]")
    rprint(event.title)
    if event.detail:
        rprint("\n[bold]detail[/bold]")
        print(json.dumps(event.detail, indent=2, default=str))
    if event.proposed_fix:
        rprint("\n[bold]proposed fix[/bold]")
        rprint(event.proposed_fix)
    if event.resolution:
        rprint("\n[bold]resolution[/bold]")
        rprint(event.resolution)


@ops_app.command("ack")
def ops_ack(event_id: str = typer.Argument(...)) -> None:
    """Acknowledge: seen, not yet fixed."""
    if not _repo().set_ops_event_status(event_id, "ack"):
        rprint(f"[red]no such event:[/red] {event_id}")
        raise typer.Exit(1)
    rprint(f"[yellow]ack[/yellow] {event_id}")


@ops_app.command("plan")
def ops_plan(
    event_id: str = typer.Argument(...),
    text: Optional[str] = typer.Option(None, "--text", help="Proposed fix (markdown)"),
    file: Optional[str] = typer.Option(None, "--file", help="Read the proposal from a file, or - for stdin"),
    priority: Optional[str] = typer.Option(None, "--priority", help="P0..P3 (suggested)"),
) -> None:
    """Attach a proposed fix. Does NOT change status — drafting is not deciding."""
    body = text
    if file:
        body = sys.stdin.read() if file == "-" else open(file, encoding="utf-8").read()
    if not body:
        rprint("[red]nothing to record — pass --text or --file[/red]")
        raise typer.Exit(2)
    if priority and priority.upper() not in {"P0", "P1", "P2", "P3"}:
        rprint("[red]priority must be P0, P1, P2 or P3[/red]")
        raise typer.Exit(2)
    if not _repo().plan_ops_event(event_id, proposed_fix=body.strip(),
                                  priority=priority.upper() if priority else None):
        rprint(f"[red]no such event:[/red] {event_id}")
        raise typer.Exit(1)
    rprint(f"[green]planned[/green] {event_id}" + (f" ({priority.upper()})" if priority else ""))


@ops_app.command("resolve")
def ops_resolve(
    event_id: str = typer.Argument(...),
    resolution: str = typer.Option(..., "--resolution", "-r", help="What shipped (commit sha, note)"),
    wontfix: bool = typer.Option(False, "--wontfix", help="Close without a fix"),
) -> None:
    """Close an event. If it happens again it reopens automatically."""
    status = "wontfix" if wontfix else "done"
    if not _repo().set_ops_event_status(event_id, status, resolution=resolution):
        rprint(f"[red]no such event:[/red] {event_id}")
        raise typer.Exit(1)
    rprint(f"[green]{status}[/green] {event_id}")


@ops_app.command("mute")
def ops_mute(
    event_id: str = typer.Argument(...),
    hours: int = typer.Option(24, "--hours", "-h", help="Snooze alerts for N hours"),
) -> None:
    """Stop alerting on a fingerprint for a while. It keeps counting."""
    until = datetime.now(tz=timezone.utc) + timedelta(hours=max(1, hours))
    if not _repo().mute_ops_event(event_id, until=until):
        rprint(f"[red]no such event:[/red] {event_id}")
        raise typer.Exit(1)
    rprint(f"[yellow]muted[/yellow] {event_id} until {until:%Y-%m-%d %H:%M} UTC")


@ops_app.command("emit")
def ops_emit(
    kind: str = typer.Option(..., "--kind", help="e.g. deploy_fail, backup_stale"),
    title: str = typer.Option(..., "--title"),
    severity: str = typer.Option("S2", "--severity"),
    source: str = typer.Option("cron", "--source"),
    key: Optional[str] = typer.Option(None, "--key", help="Stable fingerprint key"),
    detail: Optional[str] = typer.Option(None, "--detail", help="JSON object"),
) -> None:
    """Emit an event from outside the app (host scripts, cron, deploy poller)."""
    from umbra.ops.events import emit

    payload = {}
    if detail:
        try:
            payload = json.loads(detail)
        except ValueError as exc:
            rprint(f"[red]--detail must be JSON:[/red] {exc}")
            raise typer.Exit(2) from exc
    event = emit(severity=severity, kind=kind, title=title, detail=payload,
                 fingerprint_key=key, source=source)
    if event is None:
        rprint("[red]emit failed — see logs[/red]")
        raise typer.Exit(1)
    rprint(f"[green]{event.id}[/green] {event.kind} ×{event.count}")


@ops_app.command("prune")
def ops_prune(
    days: int = typer.Option(30, "--days", help="Retention window for closed events"),
) -> None:
    """Delete closed events past the retention window (open ones are kept)."""
    rprint(f"[green]pruned[/green] {_repo().prune_ops_events(days=days)} closed event(s)")


@ops_app.command("digest")
def ops_digest(
    hours: int = typer.Option(1, "--hours", help="Window to summarise"),
    force: bool = typer.Option(False, "--force", help="Print even if nothing would be sent"),
) -> None:
    """Summarise S3/S4 signals for the window and send one Telegram message.

    Silent when there is nothing — an hourly "nothing happened" trains you to
    ignore the one that matters.
    """
    from umbra.ops.digest import build_digest, send_digest

    if force:
        rprint(build_digest(hours=hours) or "[dim]nothing to report[/dim]")
        return
    rprint("[green]digest sent[/green]" if send_digest(hours=hours)
           else "[dim]nothing to report[/dim]")


@ops_app.command("link")
def ops_link(
    minutes: int = typer.Option(5, "--minutes", "-m", help="How long the link is valid"),
    path: str = typer.Option("/ops/analytics", "--path", "-p", help="Where it lands"),
    site: Optional[str] = typer.Option(None, "--site", help="Base URL (default UMBRA_SITE_URL)"),
    qr: bool = typer.Option(True, "--qr/--no-qr", help="Draw a QR code for a phone camera"),
) -> None:
    """Print a short-lived login link for opening the console on another device.

    The ordinary login URL carries `UMBRA_OPERATOR_TOKEN`, which is fine on the
    machine that already has it and wrong as a way to reach a phone: getting it
    there means the permanent credential passes through a messaging app, a
    clipboard manager, or a screenshot that lands in a cloud backup, and all of
    those keep it long after the tab is closed.

    This link is signed the same way and expires in minutes. Once redeemed it
    grants a normal 30-day session — what expires is the link, not the access.
    """
    import os
    import time

    try:
        from umbra.web.operator import is_configured, sign_handoff
    except ImportError as exc:  # pragma: no cover - depends on install shape
        # The hosted console is not part of the published package
        # (docs/OPEN-CORE.md), and a login link for a console this install does
        # not serve would be meaningless anyway. Plain print: rich would read
        # a bracketed extra name as markup and silently eat it.
        print("This command mints a login link for the hosted operator console, "
              "which is not part of the umbra-osint package. Run it from a "
              "checkout of the source.")
        raise typer.Exit(code=2) from exc

    if not is_configured():
        rprint("[red]No operator credential configured[/red] — set "
               "UMBRA_OPERATOR_TOKEN (the console is closed without one).")
        raise typer.Exit(code=2)

    token = sign_handoff(expires_at=int(time.time() + max(1, minutes) * 60))
    base = (site or os.environ.get("UMBRA_SITE_URL")
            or "https://umbra-osint.com").rstrip("/")
    safe_path = path if path.startswith("/") and not path.startswith("//") else "/ops/analytics"
    url = f"{base}/ops/login?token={token}&next={safe_path}"

    if qr:
        art = _qr_ascii(url)
        if art:
            rprint(art)
        else:
            rprint("[yellow]([/yellow]no QR renderer available — "
                   "`pip install segno` for a scannable code[yellow])[/yellow]")
    # Plain print, deliberately. rich wraps to the terminal width, and a login
    # URL split across two lines is a URL that does not work — copied by hand it
    # loses characters, and piped into a script it silently truncates the
    # signature. This line is the machine-readable output of the command.
    print()
    print(url)
    rprint(f"[dim]valid for {minutes} minute(s); grants a normal session once opened[/dim]")


def _qr_ascii(data: str) -> str | None:
    """A terminal QR, if a renderer happens to be installed. Optional by design:
    the URL alone is enough, and the CLI should not grow a dependency for it."""
    try:
        import segno
    except ImportError:
        return None
    try:
        import io

        buf = io.StringIO()
        segno.make(data, error="m").terminal(out=buf, compact=True)
        return buf.getvalue()
    except Exception:  # noqa: BLE001 - a failed QR must not cost the link
        return None
