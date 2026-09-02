"""`umbra playbook` — deterministic seed shortcuts for the two common cases.

This is the flag-driven counterpart to `intent` (which parses free text with an
optional LLM): no text extraction, just explicit typed flags → seeds → the same
create_case → seed → run → score → profile pipeline as `case`/`intent`.

Two playbooks, matching how `umbra.intent.plan.infer_playbook` already labels
plans built from the same seed shapes:
- `person_footprint` — a named person, optionally with org/username/domain/
  location as context props (no relationship is asserted between them without
  collector evidence — they're seeded as independent leads plus context).
- `domain_dossier` — one or more domains.
"""
from __future__ import annotations

from typing import Optional

import typer
from rich import print as rprint

from umbra.core.config import get_settings
from umbra.core.models import EntityIn, EntityType
from umbra.core.orchestrator import Orchestrator
from umbra.db.repository import Repository
from umbra.db.schema import get_session, init_db
from umbra.export.profile import export_graphml, write_profile
from umbra.cli.run_summary import render_run_summary

playbook_app = typer.Typer(help="Deterministic seed shortcuts: person_footprint, domain_dossier")

_BASES = ["own_asset", "client_engagement", "public_cti", "training_lab", "other"]

# The curated, ordered collector set for `umbra playbook` (docs/COLLECTORS.md
# "Playbook default set"). Depth-1 pivoting against ALL registered collectors
# fans out fast (dozens of resolved hosts each probed by http_probe/html_links/
# tech_fingerprint/etc.), so this stays the standing curated set rather than
# "everything" — use `umbra run <case>` (no -c filter) for the full surface.
# Extends the original list with reputation/exposure and the offline abuse.ch
# lake readers (malware_infra after domain_reputation; sslbl_cert after tls_cert).
_PLAYBOOK_COLLECTORS = [
    "email_split", "dns_resolve", "dns_email_auth", "rdap_domain", "rdap_ip",
    "asn_cymru", "ip_geo", "http_probe", "tech_fingerprint", "html_links", "tls_cert",
    "sslbl_cert",
    "ct_lake", "crtsh", "security_txt", "lookalike_domains", "wayback_cdx", "github_user",
    "mac_oui", "phone_validate", "crypto_screen", "wikidata", "cve_lookup",
    "github_commits", "username_presence", "gravatar", "ddg_search",
    "public_records_portals", "county_records", "wifi_maps", "sex_offender_registry", "obituary_search", "court_records", "edgar_search", "opencorporates",
    "hibp_breach", "ip_reputation", "domain_reputation", "malware_infra",
    "ransomware_exposure",
]


def _repo():
    settings = get_settings()
    init_db(settings)
    session = get_session()
    return Repository(session, settings.raw_dir), session, settings


def _run_and_report(repo, session, settings, case, depth: int) -> None:
    session.commit()
    rprint(f"[green]Case[/green] {case.id}  \"{case.name}\"")
    orch = Orchestrator(repo)
    stats = orch.run(case.id, depth=depth, collectors=_PLAYBOOK_COLLECTORS)
    from umbra.ops.quality import check_run_quality

    check_run_quality(stats, case_id=case.id, collectors=_PLAYBOOK_COLLECTORS,
                      source="cli")
    render_run_summary(stats)
    prof = settings.exports_dir / f"{case.id}_profile.md"
    write_profile(repo, case.id, prof)
    export_graphml(repo, case.id, settings.exports_dir / f"{case.id}.graphml")
    rprint(f"[green]Profile[/green] {prof}")
    rprint(f"[bold]Case ID:[/bold] {case.id}")


def _split(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


@playbook_app.command("person_footprint")
def person_footprint(
    person: str = typer.Option(..., "--person", help="Full name (required)"),
    name: Optional[str] = typer.Option(None, "-n", "--name", help="Case name (default: derived from --person)"),
    location: Optional[str] = typer.Option(None, "--location", help="City/region context (stored as a prop, not a pivot)"),
    org: Optional[str] = typer.Option(None, "--org", help="Known org affiliation — seeded as a separate ORG lead"),
    domain: Optional[str] = typer.Option(None, "--domain", help="Known associated domain(s), comma-separated — seeded as DOMAIN leads"),
    username: Optional[str] = typer.Option(
        None, "--username",
        help="Known handle(s), comma-separated. Each may be bare (\"janedoe\") or "
             "platform-tagged (\"github:janedoe\") — username_presence understands both.",
    ),
    basis: str = typer.Option("own_asset", "-b", "--basis", help=f"one of: {', '.join(_BASES)}"),
    depth: int = typer.Option(1, "-d", "--depth"),
) -> None:
    """Seed a person + optional context leads, run, score, and profile."""
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {_BASES}")
    repo, session, settings = _repo()
    try:
        case = repo.create_case(name or f"Playbook:person_footprint:{person}", basis,
                                f"person_footprint playbook for {person}")
        props = {}
        if location:
            props["location"] = location
        if org:
            props["org_hint"] = org
        repo.seed(case.id, EntityIn(type=EntityType.PERSON, value=person, confidence=0.9, props=props))
        if org:
            repo.seed(case.id, EntityIn(type=EntityType.ORG, value=org, confidence=0.6,
                                        props={"role": "person_footprint_context"}))
        for d in _split(domain):
            repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value=d, confidence=0.6,
                                        props={"role": "person_footprint_context"}))
        for u in _split(username):
            repo.seed(case.id, EntityIn(type=EntityType.USERNAME, value=u, confidence=0.7,
                                        props={"role": "person_footprint_context"}))
        _run_and_report(repo, session, settings, case, depth)
    except ValueError as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    finally:
        session.close()


@playbook_app.command("domain_dossier")
def domain_dossier(
    domain: str = typer.Option(..., "--domain", help="Domain(s), comma-separated"),
    name: Optional[str] = typer.Option(None, "-n", "--name", help="Case name (default: derived from --domain)"),
    basis: str = typer.Option("own_asset", "-b", "--basis", help=f"one of: {', '.join(_BASES)}"),
    depth: int = typer.Option(1, "-d", "--depth"),
) -> None:
    """Seed one or more domains, run, score, and profile."""
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {_BASES}")
    domains = _split(domain)
    if not domains:
        raise typer.BadParameter("at least one domain is required")
    repo, session, settings = _repo()
    try:
        case = repo.create_case(name or f"Playbook:domain_dossier:{domains[0]}", basis,
                                f"domain_dossier playbook for {', '.join(domains)}")
        for d in domains:
            repo.seed(case.id, EntityIn(type=EntityType.DOMAIN, value=d, confidence=0.95))
        _run_and_report(repo, session, settings, case, depth)
    except ValueError as exc:
        rprint(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    finally:
        session.close()
