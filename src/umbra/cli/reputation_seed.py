"""High-fidelity reputation seeding utility.

Usage:
    umbra reputation-seed --file assets.txt --type ip --note "known tor exits"
    umbra reputation-seed --file domains.txt --type domain --note "client-owned"
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import typer
from rich import print as rprint

from umbra.core.config import get_settings
from umbra.core.models import EntityIn, EntityType
from umbra.core.orchestrator import Orchestrator
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db


# Every case carries an authorization basis (AGENTS.md #1). It was being taken
# verbatim, so a typo became the recorded justification for the whole case.
_BASES = {"own_asset", "client_engagement", "public_cti", "training_lab", "other"}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _is_valid(etype: EntityType, value: str) -> bool:
    """Reject a line before it becomes an entity.

    `normalize_value` does not validate IPs — it passes any string through — so
    without this check `--type ip` will happily store `not-an-ip-at-all` in the
    graph and then send collectors off to look it up. A bulk import from an
    operator-supplied file is exactly where malformed lines turn up, so it is
    exactly where they should be caught.
    """
    if etype is EntityType.IP:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    return bool(_DOMAIN_RE.match(value.strip().lower().rstrip(".")))


def seed_reputation(
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True),
    type: str = typer.Option(..., "--type", "-t", help="ip or domain"),
    note: str = typer.Option("", "--note", "-n"),
    # `--basis` was missing its long form, so the spelling every other command
    # in this CLI uses was a usage error here.
    basis: str = typer.Option("own_asset", "--basis", "-b",
                              help="|".join(sorted(_BASES))),
) -> None:
    """Seed high-fidelity reputation signatures for a list of assets."""
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {sorted(_BASES)}")
    if type.lower() not in {"ip", "domain"}:
        raise typer.BadParameter("--type must be 'ip' or 'domain'")

    etype = EntityType.IP if type.lower() == "ip" else EntityType.DOMAIN
    assets = [line.strip() for line in file.read_text().splitlines() if line.strip() and not line.startswith("#")]

    if not assets:
        rprint("[red]No assets found in file[/red]")
        raise typer.Exit(1)

    settings = get_settings()
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)

    try:
        case = repo.create_case(
            f"Reputation Seed: {file.name}",
            basis,
            note or f"high-fidelity seeding of {len(assets)} {type}s",
        )
        session.commit()


        # Seed entities. A line that will not normalise is reported rather
        # than swallowed — "seeded 400 assets" when 200 were dropped is the
        # same lie as an unreachable source rendering as a clean result.
        rejected: list[str] = []
        seeded = 0
        for value in assets:
            if not _is_valid(etype, value):
                rejected.append(f"{value} (not a valid {type})")
                continue
            try:
                repo.seed(case.id, EntityIn(type=etype, value=value, confidence=0.95))
                seeded += 1
            except Exception as exc:  # noqa: BLE001 - one bad line must not stop the file
                rejected.append(f"{value} ({exc})")
        session.commit()

        rprint(f"[green]Created case[/green] {case.id} with {seeded} "
               f"of {len(assets)} assets")

        if rejected:
            rprint(f"[yellow]{len(rejected)} line(s) were not valid {type}s "
                   f"and were skipped:[/yellow]")
            for line in rejected[:10]:
                rprint(f"  • {line}")
            if len(rejected) > 10:
                rprint(f"  … and {len(rejected) - 10} more")

        # Run reputation collectors
        orch = Orchestrator(repo)
        collectors = ["ip_reputation"] if etype == EntityType.IP else ["domain_reputation"]

        stats = orch.run(case.id, depth=0, collectors=collectors)
        rprint(f"[green]Reputation seeding complete[/green] — {stats}")

    finally:
        session.close()


if __name__ == "__main__":
    typer.run(seed_reputation)
