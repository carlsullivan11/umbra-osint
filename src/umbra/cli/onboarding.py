"""`umbra init` and `umbra doctor` — first-run setup and diagnosis (stage S8).

The goal is that a new user can get from `pip install` to a working, correctly
configured install without reading half the repo, and can diagnose a broken one
without guessing.

Two deliberate choices:

- **`init` is idempotent.** Re-running is a normal thing to do (after an
  upgrade, or when unsure); it must never clobber an existing install, so it
  only creates what is missing and reports exactly that.
- **The ethics acknowledgement is recorded, not displayed.** Umbra requires an
  authorization basis on every case; a banner nobody reads is not an
  acknowledgement. `init` writes a timestamped record, and `doctor` fails if it
  is absent, so "did the operator accept the terms?" has an auditable answer.
"""
from __future__ import annotations

import json
import platform
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from umbra.core.config import Settings, get_settings

ETHICS_ACK_FILE = "ethics-ack.json"

ETHICS_STATEMENT = (
    "I will use Umbra only for authorized defensive security, CTI, asset "
    "inventory, or training work. Every case records an authorization basis. "
    "I will not use it to stalk, harass, dox, or surveil people without lawful "
    "authority, and I accept responsibility for lawful use in my jurisdiction. "
    "See docs/ETHICS.md."
)

# Well-known public resolvers. DNSBLs refuse queries arriving via these and
# answer 127.255.255.x for everything, so reputation silently marks every
# address listed. Mirrors umbra.core.dns.PUBLIC_RESOLVERS.
_PUBLIC_RESOLVERS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6",
    "77.88.8.8", "77.88.8.1", "4.2.2.1", "4.2.2.2",
}


@dataclass
class DoctorCheck:
    name: str
    ok: bool
    detail: str
    optional: bool = False

    @property
    def symbol(self) -> str:
        if self.ok:
            return "[green]✓[/green]"
        return "[yellow]•[/yellow]" if self.optional else "[red]✗[/red]"


# --- ethics acknowledgement ----------------------------------------------

def ethics_ack_path(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    return s.data_dir / ETHICS_ACK_FILE


def write_ack(settings: Settings | None = None) -> Path:
    s = settings or get_settings()
    path = ethics_ack_path(s)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "accepted": True,
                "acknowledged_at": datetime.now(tz=timezone.utc).isoformat(),
                "statement": ETHICS_STATEMENT,
                "umbra_version": "0.1.0",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def read_ack(settings: Settings | None = None) -> dict | None:
    path = ethics_ack_path(settings)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# --- init -----------------------------------------------------------------

def initialize(settings: Settings | None = None, accept_ethics: bool = False) -> dict:
    """Create the data layout; record the ethics acknowledgement if accepted.

    Returns what was *actually* created, so a second run visibly does nothing.
    """
    s = settings or get_settings()
    created: list[str] = []
    for path in (s.data_dir, s.raw_dir, s.exports_dir, s.cache_dir):
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            created.append(str(path))

    ack_written = False
    if accept_ethics and read_ack(s) is None:
        write_ack(s)
        ack_written = True

    return {
        "data_dir": str(s.data_dir),
        "created": created,
        "ethics_recorded": ack_written or (read_ack(s) is not None),
        "db_url": s.sqlalchemy_url,
    }


# --- doctor ---------------------------------------------------------------

def _resolver_nameservers() -> list[str]:
    """Nameservers the DNSBL path would actually use (no public failover)."""
    try:
        from umbra.core.dns import get_resolver

        return [str(n) for n in get_resolver(allow_public_failover=False).nameservers]
    except Exception:  # noqa: BLE001 - doctor must never crash
        return []


def _wiki_corpus_dir() -> Path | None:
    try:
        from umbra.wiki.service import WikiService

        return WikiService().corpus_dir
    except Exception:  # noqa: BLE001
        return None



# --- owned data lakes -----------------------------------------------------

#: Lakes an operator is expected to keep warm, with the command that does it.
#: A cold lake is not an error — Umbra works without any of them and says so
#: per-check — but it silently narrows what a run can answer.
_LAKE_REMEDY = {
    "abuse.ch": "umbra abuse sync",
    "certificate transparency": "umbra ct ingest",
    "geoip": "umbra geoip sync",
    "epss": "umbra epss sync",
    "public suffix": "umbra psl sync",
    "people": "umbra people seed",
    "faa registry": "umbra faa sync",
}

_STALE_AFTER_DAYS = {
    # Blocklists move in hours; a week-old copy is materially wrong.
    "abuse.ch": 7,
    # CT is tail-forward and always incomplete; a month is fine.
    "certificate transparency": 30,
    # DB-IP publish City Lite monthly.
    "geoip": 45,
    # FIRST rescores daily and the numbers move when an exploit drops.
    "epss": 7,
    # The PSL changes weekly-ish; a month behind still gets alignment right for
    # everything but brand-new namespaces.
    "public suffix": 60,
    "people": 90,
    # Refreshed daily by the FAA; ownership changes are the reason to care.
    "faa registry": 30,
}


def _age_days(stamp: Any) -> float | None:
    """Days since an ISO timestamp, or None when it cannot be read."""
    if not stamp:
        return None
    try:
        text = str(stamp).replace("Z", "+00:00")
        when = datetime.fromisoformat(text)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return (datetime.now(tz=timezone.utc) - when).total_seconds() / 86400.0
    except (ValueError, TypeError):
        return None


def _corpus_age_days(corpus) -> float | None:
    """Days since the corpus last changed.

    Prefers the git commit date — the corpus is a git repo refreshed by an
    importer, so a commit is the honest "as of". Falls back to the newest file
    mtime for a plain directory.
    """
    import subprocess

    try:
        out = subprocess.run(
            ["git", "-C", str(corpus), "log", "-1", "--format=%cI"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return _age_days(out.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        newest = max(p.stat().st_mtime for p in corpus.rglob("*.md"))
    except ValueError:
        return None
    return (datetime.now(tz=timezone.utc).timestamp() - newest) / 86400.0


def _lake_check(name: str, rows: int, newest: Any) -> DoctorCheck:
    """One lake, reported as rows plus how stale.

    These are `optional`: Umbra runs without any lake. But a cold lake is why
    a case fills with "not checked" notes, and before this the only place that
    surfaced was inside the run output itself, repeated once per affected
    entity. An operator should be able to ask.
    """
    remedy = _LAKE_REMEDY.get(name, "")
    if not rows:
        return DoctorCheck(name + " lake", False,
                           f"empty — run `{remedy}`", optional=True)

    age = _age_days(newest)
    if age is None:
        return DoctorCheck(name + " lake", True,
                           f"{rows:,} rows, last sync unknown", optional=True)

    limit = _STALE_AFTER_DAYS.get(name, 30)
    fresh = age <= limit
    when = f"{age:.0f}d ago" if age >= 1 else "today"
    detail = f"{rows:,} rows, synced {when}"
    if not fresh:
        detail += f" — stale past {limit}d, run `{remedy}`"
    return DoctorCheck(name + " lake", fresh, detail, optional=True)


def lake_checks(settings: Settings | None = None) -> list[DoctorCheck]:
    """Freshness of every owned corpus. Never raises.

    Renders `lake_inventory()` rather than reading the lakes itself. The
    analytics in `umbra.analytics.lakes` snapshot the same readings, and two
    independent readers is how a diagnostic and its monitor start disagreeing —
    at which point the operator has to work out which one is lying before they
    can act on either.
    """
    from umbra.lake.inventory import lake_inventory

    s = settings or get_settings()
    out: list[DoctorCheck] = []
    for reading in lake_inventory(s):
        if not reading.readable:
            out.append(DoctorCheck(reading.lake + " lake", False,
                                   reading.error or "unreadable", optional=True))
            continue
        out.append(_lake_check(reading.lake, int(reading.rows or 0),
                               reading.synced_at))
    return out


def doctor_checks(settings: Settings | None = None) -> list[DoctorCheck]:
    """Diagnose the install. Never raises — this is what you run when broken."""
    s = settings or get_settings()
    checks: list[DoctorCheck] = []

    py_ok = sys.version_info >= (3, 11)
    checks.append(DoctorCheck(
        "python", py_ok,
        f"{platform.python_version()}" + ("" if py_ok else " — Umbra needs >= 3.11"),
    ))

    data_ok = s.data_dir.is_dir()
    checks.append(DoctorCheck(
        "data directory", data_ok,
        str(s.data_dir) if data_ok else f"{s.data_dir} missing — run `umbra init`",
    ))

    try:
        url = s.sqlalchemy_url
        backend = "postgres" if s.using_postgres else "sqlite"
        if s.using_postgres:
            detail, db_ok = f"{backend} (UMBRA_DATABASE_URL set)", True
        else:
            detail, db_ok = f"{backend} at {s.db_path}", s.data_dir.is_dir()
        checks.append(DoctorCheck("database", db_ok, detail))
    except Exception as exc:  # noqa: BLE001
        checks.append(DoctorCheck("database", False, f"unreadable config: {exc}"))

    corpus = _wiki_corpus_dir()
    if corpus and corpus.is_dir():
        pages = sum(1 for _ in corpus.rglob("*.md"))
        cves = sum(1 for _ in corpus.rglob("CVE-*.md"))
        # Age, not just size. A corpus eleven days behind upstream reported
        # "3681 pages" and looked perfectly healthy — the KEV entries added
        # since simply were not there, and nothing said so. Same failure as a
        # cold lake reporting rows without a sync time.
        age = _corpus_age_days(corpus)
        detail = f"{pages} pages ({cves} CVE) at {corpus}"
        fresh = True
        if age is None:
            detail += " · age unknown"
        else:
            detail += f" · updated {'today' if age < 1 else f'{age:.0f}d ago'}"
            # KEV moves several times a week; a fortnight behind is materially
            # incomplete for the thing people look up most.
            fresh = age <= 14
            if not fresh:
                detail += " — stale past 14d, run `umbra wiki update`"
        checks.append(DoctorCheck("wiki corpus", fresh, detail, optional=True))
    else:
        checks.append(DoctorCheck(
            "wiki corpus", False,
            "not present — optional; `umbra wiki update` or clone umbra-wiki "
            "and set UMBRA_WIKI_PATH",
            optional=True,
        ))

    nameservers = _resolver_nameservers()
    public = [n for n in nameservers if n in _PUBLIC_RESOLVERS]
    if not nameservers:
        checks.append(DoctorCheck(
            "dns resolver", False,
            "no local recursive resolver for DNSBL — set UMBRA_DNS_RESOLVER "
            "(see docs/DNS-SERVICE.md); reputation checks will report errors",
        ))
    elif public:
        checks.append(DoctorCheck(
            "dns resolver", False,
            f"{', '.join(public)} is a public resolver — DNSBLs refuse these and "
            "answer 127.255.255.x for everything. Set UMBRA_DNS_RESOLVER to a "
            "local recursive resolver (docs/DNS-SERVICE.md)",
        ))
    else:
        checks.append(DoctorCheck("dns resolver", True, ", ".join(nameservers)))

    ack = read_ack(s)
    checks.append(DoctorCheck(
        "ethics acknowledgement",
        bool(ack and ack.get("accepted")),
        f"recorded {ack['acknowledged_at'][:19]}" if ack and ack.get("accepted")
        else "not recorded — run `umbra init` and accept (docs/ETHICS.md)",
    ))

    checks.extend(lake_checks(s))

    checks.append(DoctorCheck(
        "git", shutil.which("git") is not None,
        shutil.which("git") or "not found — needed for `umbra wiki update`",
        optional=True,
    ))

    return checks


# --- CLI commands ---------------------------------------------------------

def init_command(
    yes: bool = False,
    wiki: bool = False,
) -> None:
    """Create the data directory, record the ethics acknowledgement, optionally fetch the wiki."""
    import typer
    from rich import print as rprint

    # Settings() rather than get_settings(): the latter calls ensure_dirs() as a
    # side effect, so by the time initialize() ran the directories already
    # existed and a genuinely fresh install misreported "already present".
    s = Settings()
    rprint(f"[bold]Umbra init[/bold] · data dir: {s.data_dir}")

    accepted = yes
    if not accepted:
        rprint("")
        rprint(f"[yellow]{ETHICS_STATEMENT}[/yellow]")
        rprint("")
        accepted = typer.confirm("Do you accept these terms?", default=False)

    result = initialize(s, accept_ethics=accepted)

    if result["created"]:
        for path in result["created"]:
            rprint(f"  [green]created[/green] {path}")
    else:
        rprint("  [dim]data directories already present — nothing to create[/dim]")

    if accepted:
        rprint(f"  [green]recorded[/green] ethics acknowledgement → {ethics_ack_path(s)}")
    else:
        rprint("  [red]not accepted[/red] — Umbra is for authorized use only; "
               "cases will still require an authorization basis. Re-run `umbra init` to accept.")

    if wiki:
        rprint("\n[bold]Fetching wiki corpus…[/bold]")
        try:
            from umbra.wiki.service import WikiService

            svc = WikiService()
            n = svc.rebuild_index()
            rprint(f"  [green]indexed[/green] {n} pages from {svc.corpus_dir}")
        except Exception as exc:  # noqa: BLE001
            rprint(f"  [yellow]wiki setup skipped:[/yellow] {exc}")
            rprint("  Clone https://github.com/example-org/umbra-wiki and set UMBRA_WIKI_PATH")

    rprint("\nNext: [bold]umbra doctor[/bold] to verify, then "
           "[bold]umbra case create -n \"My case\" -b own_asset[/bold]")
    if not accepted:
        raise typer.Exit(1)


def doctor_command() -> None:
    """Check the install: python, data dir, database, wiki corpus, DNS resolver, ethics ack."""
    import typer
    from rich import print as rprint
    from rich.table import Table

    checks = doctor_checks()
    table = Table(title="umbra doctor")
    for col in ("", "check", "detail"):
        table.add_column(col)
    for c in checks:
        table.add_row(c.symbol, c.name, c.detail)
    rprint(table)

    hard_failures = [c for c in checks if not c.ok and not c.optional]
    if hard_failures:
        rprint(f"[red]{len(hard_failures)} problem(s) found.[/red] "
               "Fix the ✗ rows above; • rows are optional.")
        raise typer.Exit(1)
    rprint("[green]All required checks passed.[/green]")
