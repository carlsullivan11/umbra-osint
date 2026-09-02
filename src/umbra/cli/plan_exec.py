"""Turn a confirmed `IntentPlan` into a case and run it.

Lifted out of `umbra.cli.intent_cmd` unchanged when the file readers arrived:
`umbra intent --confirm`, `umbra email --confirm` and `umbra file --confirm` all
need exactly this, and three copies of it would be three places for the audit
trail to drift apart.
"""
from __future__ import annotations

import typer
from rich import print as rprint

from umbra.core.config import get_settings
from umbra.core.models import EntityIn
from umbra.core.orchestrator import Orchestrator
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.export.profile import export_graphml, write_profile
from umbra.intent.schema import IntentPlan
from umbra.cli.run_summary import render_run_summary


def confirm_and_run(plan: IntentPlan, *, source: str = "cli",
                    action: str = "intent.confirm") -> str:
    """Create the case, seed the included entities, run the collectors.

    `plan.included_seeds()` is the whole contract with the confirm step: seeds
    the analyst unchecked are not seeded, so they are never collected against.
    """
    if plan.refuse:
        rprint("[red]Refusing to confirm a refused plan. "
               "Change basis/note or rephrase.[/red]")
        raise typer.Exit(2)

    included = plan.included_seeds()
    if not included:
        rprint("[red]No included seeds — nothing to run.[/red]")
        raise typer.Exit(2)

    settings = get_settings()
    init_db(settings)
    session = get_session()
    try:
        repo = Repository(session, settings.raw_dir)
        case = repo.create_case(
            plan.case_name,
            plan.authorization_basis,
            plan.authorization_note or f"intent:{plan.plan_id}",
        )
        repo.audit(
            case.id,
            action,
            {
                "plan_id": plan.plan_id,
                "raw_intent": plan.raw_intent,
                "collectors": plan.collectors,
                "seed_count": len(included),
                "extractor": plan.extractor,
            },
        )
        for seed in included:
            repo.seed(
                case.id,
                EntityIn(
                    type=seed.type,
                    value=seed.value,
                    confidence=seed.confidence,
                    props={
                        **(seed.props or {}),
                        "intent_span": seed.source_span,
                        "intent_notes": seed.notes,
                    },
                ),
            )
        session.commit()
        rprint(f"[green]Case[/green] {case.id}")

        orch = Orchestrator(repo)
        stats = orch.run(
            case.id,
            depth=plan.depth,
            collectors=plan.collectors or None,
            max_entities=plan.max_entities,
        )
        render_run_summary(stats)

        from umbra.ops.quality import check_run_quality

        check_run_quality(stats, case_id=case.id, collectors=plan.collectors,
                          source=source)

        profile = settings.data_dir / "exports" / f"{case.id}_profile.md"
        write_profile(repo, case.id, profile)
        export_graphml(repo, case.id,
                       settings.data_dir / "exports" / f"{case.id}.graphml")
        rprint(f"[green]Profile[/green] {profile}")
        rprint(f"[bold]Case ID:[/bold] {case.id}")
        return case.id
    finally:
        session.close()
