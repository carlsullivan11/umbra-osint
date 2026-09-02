"""Password exposure check via HIBP Pwned Passwords (k-anonymity range API).

Only the first 5 chars of the SHA-1 hash leave the machine. Full password is never sent.
"""

from __future__ import annotations

import hashlib
import getpass
from typing import Optional

import httpx
import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from umbra.collectors.hibp_breach import remediation_for_data_classes
from umbra.core.config import get_settings


def check_password_pwned(password: str, user_agent: str, timeout: float = 20.0) -> dict:
    """Return {pwned: bool, count: int, prefix: str} using k-anonymity API."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": user_agent, "Add-Padding": "true"}
    with httpx.Client(timeout=timeout, headers=headers) as client:
        resp = client.get(url)
        resp.raise_for_status()
    count = 0
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) != 2:
            continue
        if parts[0].upper() == suffix:
            count = int(parts[1].replace(",", ""))
            break
    return {"pwned": count > 0, "count": count, "prefix": prefix, "sha1_prefix_only": True}


def format_password_advice(pwned: bool, count: int) -> list[str]:
    if not pwned:
        return [
            "This password was not found in the HIBP Pwned Passwords corpus.",
            "Still use unique passwords + MFA; absence from the corpus is not a guarantee of safety.",
        ]
    steps = [
        f"This password appears about {count:,} time(s) in known breach corpora — treat it as public.",
        "Change it everywhere it was used — assume attackers try credential stuffing.",
        "Never reuse it on email, banking, work SSO, or your password manager.",
    ]
    steps.extend(remediation_for_data_classes(["passwords"]))
    return steps


# Typer sub-app for breach commands (imported by main)
breach_app = typer.Typer(help="Breach exposure checks (HIBP) + remediation guidance")


@breach_app.command("password")
def breach_password(
    password: Optional[str] = typer.Option(
        None,
        "--password",
        "-p",
        help="Password to check (omit to get a hidden prompt). Not logged.",
    ),
) -> None:
    """Check whether a password appears in known breaches (k-anonymity; full password never sent)."""
    settings = get_settings()
    if password is None:
        password = getpass.getpass("Password (hidden): ")
    if not password:
        raise typer.BadParameter("Empty password")
    try:
        result = check_password_pwned(password, settings.hibp_user_agent, settings.request_timeout_s)
    except Exception as exc:  # noqa: BLE001
        rprint(f"[red]Check failed:[/red] {exc}")
        raise typer.Exit(1) from exc

    # drop password from memory ASAP
    del password

    if result["pwned"]:
        rprint(
            Panel.fit(
                f"[bold red]EXPOSED[/bold red] — seen ~{result['count']:,} times in breach data\n"
                f"Only hash prefix {result['prefix']} was sent to HIBP (k-anonymity).",
                title="Pwned Passwords",
            )
        )
    else:
        rprint(
            Panel.fit(
                "[bold green]Not found[/bold green] in HIBP Pwned Passwords corpus.\n"
                f"Only hash prefix {result['prefix']} was sent (k-anonymity).",
                title="Pwned Passwords",
            )
        )
    for step in format_password_advice(result["pwned"], result["count"]):
        rprint(f"  • {step}")


@breach_app.command("email")
def breach_email(
    email: str = typer.Argument(..., help="Email to check (authorized use only)"),
    case_id: Optional[str] = typer.Option(
        None,
        "--case",
        "-c",
        help="Optional case ID to attach results into the graph",
    ),
) -> None:
    """Check email against Have I Been Pwned (requires UMBRA_HIBP_API_KEY)."""
    from umbra.collectors.base import CollectorContext
    from umbra.collectors.hibp_breach import HibpBreachCollector
    from umbra.core.models import EntityIn, EntityType
    from umbra.core.normalize import entity_key
    from umbra.db.repository import Repository
    from umbra.db.schema import Entity, get_session, init_db
    from umbra.export.remediation import render_breach_report

    settings = get_settings()
    if not settings.hibp_api_key:
        rprint(
            "[yellow]UMBRA_HIBP_API_KEY not set.[/yellow]\n"
            "Get a key: https://haveibeenpwned.com/API/Key\n"
            "Then: export UMBRA_HIBP_API_KEY=your_key\n"
            "Password checks work without a key: [bold]umbra breach password[/bold]"
        )
        raise typer.Exit(2)

    init_db(settings)
    # Build a transient entity for the collector
    ent = Entity(
        id="tmp",
        case_id=case_id or "adhoc",
        type=EntityType.EMAIL.value,
        value=email.strip().lower(),
        norm_key=entity_key(EntityType.EMAIL, email),
        props={},
        confidence=1.0,
        is_seed=True,
    )
    col = HibpBreachCollector()
    with httpx.Client(
        timeout=settings.request_timeout_s,
        headers={"User-Agent": settings.hibp_user_agent},
    ) as http:
        ctx = CollectorContext(
            settings=settings,
            case_id=case_id or "adhoc",
            run_id="adhoc",
            http=http,
        )
        result = col.collect(ent, ctx)

    for n in result.notes:
        rprint(f"[yellow]note:[/yellow] {n}")

    breaches = [e for e in result.entities if e.type == EntityType.BREACH]
    table = Table("Breach", "Date", "Severity", "Data classes")
    for b in sorted(breaches, key=lambda x: (x.props or {}).get("breach_date") or "", reverse=True):
        props = b.props or {}
        classes = ", ".join(props.get("data_classes") or [])[:60]
        table.add_row(
            str(props.get("title") or b.value),
            str(props.get("breach_date") or "?"),
            str(props.get("severity") or "?"),
            classes,
        )
    if breaches:
        rprint(table)
    else:
        rprint("[green]No breaches returned for this email (or lookup skipped).[/green]")

    report = render_breach_report(email, result)
    rprint(Panel(report, title="Remediation plan", expand=False))

    if case_id:
        session = get_session()
        try:
            repo = Repository(session, settings.raw_dir)
            if not repo.get_case(case_id):
                rprint(f"[red]Unknown case {case_id}[/red]")
                raise typer.Exit(1)
            repo.seed(case_id, EntityIn(type=EntityType.EMAIL, value=email, confidence=1.0))
            repo.apply_result(case_id, None, result)
            repo.audit(case_id, "breach.email_check", {"email": email, "breaches": len(breaches)})
            session.commit()
            rprint(f"[green]Attached to case[/green] {case_id}")
        finally:
            session.close()

    # Write standalone report
    out = settings.data_dir / "exports" / f"breach_{email.replace('@', '_at_')}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"# Breach report: {email}\n\n{report}\n", encoding="utf-8")
    rprint(f"[green]Wrote[/green] {out}")
