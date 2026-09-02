"""Authorized exposure monitoring playbook (passive & defensive only)."""

from __future__ import annotations

import typer
from rich import print as rprint

from umbra.core.config import get_settings
from umbra.core.models import EntityIn, EntityType
from umbra.core.orchestrator import Orchestrator
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.export.profile import write_profile


def exposure_monitor(
    target: str = typer.Argument(..., help="domain or email to monitor for exposure"),
    basis: str = typer.Option("own_asset", "-b", "--basis"),
    note: str = typer.Option("", "--note"),
    depth: int = typer.Option(1, "-d", "--depth"),
) -> None:
    """
    Run a defensive exposure monitoring case on an authorized asset.

    This uses only passive collectors (HIBP, lookalikes, breach corpora, etc.).
    No active scanning or marketplace access.
    """
    allowed = {"own_asset", "client_engagement", "public_cti", "training_lab", "other"}
    if basis not in allowed:
        raise typer.BadParameter(f"basis must be one of {allowed}")

    settings = get_settings()
    init_db(settings)
    session = get_session()
    repo = Repository(session, settings.raw_dir)

    try:
        case = repo.create_case(
            f"Exposure-Monitor: {target}",
            basis,
            note or f"passive defensive monitoring of {target}",
        )

        # Seed the target and pick the passive collectors that fit its type.
        if "@" in target:
            repo.seed(case.id, EntityIn(type=EntityType.EMAIL, value=target, confidence=0.95))
            collectors = ["hibp_breach"]
        else:
            repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value=target, confidence=0.95))
            collectors = [
                "hibp_breach",
                "lookalike_domains",
                "domain_reputation",
                "ransomware_exposure",
            ]

        session.commit()

        rprint(f"[green]Created case[/green] {case.id}")
        rprint(f"[dim]Passive collectors:[/dim] {', '.join(collectors)}")

        orch = Orchestrator(repo)
        stats = orch.run(case.id, depth=depth, collectors=collectors)

        prof = settings.data_dir / "exports" / f"{case.id}_profile.md"
        write_profile(repo, case.id, prof, seed_value=target)

        rprint(f"[green]Exposure monitoring complete[/green] — {stats}")
        rprint(f"[green]Profile:[/green] {prof}")

    finally:
        session.close()


if __name__ == "__main__":
    typer.run(exposure_monitor)
