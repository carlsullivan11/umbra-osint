"""CLI: `umbra triage` — a tier-1 triage call on an alert or indicator (docs/TRIAGE.md).

    umbra triage 185.220.101.1
    umbra triage alert.json            # ECS / Suricata EVE / Wazuh / flat JSON, list or NDJSON
    umbra triage iocs.txt
    siem-export | umbra triage - --json --exit-code

Bring your own Jev key. Umbra's hosted key is never used here: with no
`UMBRA_OPENROUTER_API_KEY` (or `UMBRA_JEV_PROVIDER=typesafe` +
`UMBRA_TYPESAFE_API_KEY`) triage still runs, on the deterministic checks
alone, and says so. Setting the key is the opt-in for this command;
`UMBRA_JEV_ENABLED` only governs automatic adjudication elsewhere.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.markup import escape

from umbra.core.config import Settings, get_settings
from umbra.jev.client import JevClient, provider_headers
from umbra.triage.alert import parse_input
from umbra.triage.disposition import ESCALATE, FITTED_MODEL, NEEDS_ANALYST, SUGGEST_CLOSE, RANK, worst
from umbra.triage.engine import assess, enrich

MAX_INPUT_BYTES = 5 * 1024 * 1024
EXIT_CODES = {SUGGEST_CLOSE: 0, NEEDS_ANALYST: 10, ESCALATE: 20}
_ASSETS = {"workstation": "user workstation", "server": "server", "critical": "critical server"}
_BASES = {"own_asset", "client_engagement", "public_cti", "training_lab", "other"}
_STYLE = {ESCALATE: "bold red", NEEDS_ANALYST: "bold yellow", SUGGEST_CLOSE: "bold green"}
_WORD = {ESCALATE: "ESCALATE", NEEDS_ANALYST: "NEEDS ANALYST", SUGGEST_CLOSE: "SUGGEST CLOSE"}

BYOK_HINT = (
    "Jev is off: bring your own key. export UMBRA_OPENROUTER_API_KEY=sk-or-... "
    "(openrouter.ai/keys), or UMBRA_JEV_PROVIDER=typesafe with UMBRA_TYPESAFE_API_KEY. "
    "Without it, an unlisted indicator is never suggested for closing."
)


def _client(s: Settings) -> JevClient:
    """The user's own key, from their environment. Separate so tests can swap it."""
    return JevClient(
        s.jev_api_key, model=s.jev_model, base_url=s.jev_endpoint_base,
        extra_headers=provider_headers(s.jev_provider),
        # The global default (3s) suits a page render; a terminal can wait.
        timeout_s=max(s.jev_timeout_s, 10.0),
        cache_dir=s.cache_dir / "jev", daily_token_budget=s.jev_daily_token_budget,
    )


def _lake_gaps(s: Settings) -> list[str]:
    """abuse.ch feeds never synced into the local lake. Without them a known C2
    reads "clean" on this machine; the card says so rather than letting it."""
    try:
        from umbra.lake import abusech
        from umbra.lake.store import LakeStore

        store = LakeStore.from_settings(s)
        return [f for f in abusech.FEEDS if not store.abuse_feed_synced_at(f)]
    except Exception:  # noqa: BLE001 - a hint must never break triage
        return []


def _read(target: str) -> str:
    if target == "-":
        return sys.stdin.read(MAX_INPUT_BYTES)
    p = Path(target)
    if p.is_file():
        if p.stat().st_size > MAX_INPUT_BYTES:
            raise typer.BadParameter(f"{target} is larger than {MAX_INPUT_BYTES // 1024 // 1024} MB")
        return p.read_text(encoding="utf-8", errors="replace")
    return target


def triage(
    target: str = typer.Argument(..., help="Indicator, alert/IOC file, or - for stdin"),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print what Jev would be sent; ask nothing"),
    no_jev: bool = typer.Option(False, "--no-jev", help="Deterministic checks only"),
    no_collect: bool = typer.Option(False, "--no-collect",
                                    help="Skip enrichment: no case, no lookups (never suggests close)"),
    active: bool = typer.Option(False, "--active",
                                help="Also run collectors that connect to the indicator (off: it tips off the operator)"),
    asset: Optional[str] = typer.Option(None, "--asset", help="workstation | server | critical"),
    basis: str = typer.Option("own_asset", "--basis", "-b", help="|".join(sorted(_BASES))),
    exit_code: bool = typer.Option(False, "--exit-code",
                                   help="Exit 0 suggest-close, 10 needs analyst, 20 escalate"),
) -> None:
    """Triage an alert: Umbra investigates, Jev makes the call, a person decides."""
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {sorted(_BASES)}")
    if asset is not None and asset not in _ASSETS:
        raise typer.BadParameter(f"asset must be one of {sorted(_ASSETS)}")

    alerts, notes = parse_input(_read(target))
    if not any(a.indicators for a in alerts):
        rprint("[yellow]Nothing external to triage.[/yellow] "
               "Give a public IP, domain or URL, or an alert that contains one.")
        for n in notes:
            rprint(f"[dim]· {escape(n)}[/dim]")
        raise typer.Exit(2)

    s = get_settings()
    client = None
    if not no_jev and not dry_run and s.jev_api_key:
        client = _client(s)

    case_id, props_by, enriched = None, {}, False
    if not no_collect:
        from umbra.cli.case_cmd import _repo

        repo, session = _repo()
        try:
            case_id, props_by = enrich([a for a in alerts if a.indicators], repo, basis=basis,
                                       active=active)
            session.commit()
        finally:
            session.close()
        enriched = True
        if gaps := _lake_gaps(s):
            notes.append(f"local abuse.ch lake has never synced {', '.join(gaps)}: known C2 and malware "
                         "hosts can read as unlisted here. Run `umbra abuse sync` first.")

    results = []
    for a in alerts:
        if not a.indicators:
            continue
        r = assess(a, props_by, client, enriched=enriched, asset=_ASSETS.get(asset or ""),
                   critical_asset=asset == "critical", dry_run=dry_run)
        r.case_id = case_id
        results.append(r)

    if dry_run:
        for r in results:
            for ir in r.indicators:
                rprint(f"[bold]── {escape(r.alert.label)} · {ir.indicator.type.value} "
                       f"{escape(ir.indicator.value)}[/bold]")
                print(ir.state)
                print()
        rprint("[dim]Dry run: nothing was sent to Jev.[/dim]")
        return

    models = sorted({ir.model for r in results for ir in r.indicators if ir.model})
    overall = worst([r.disposition for r in results])
    if as_json:
        print(json.dumps({
            "disposition": overall,
            "jev": {"used": client is not None, "provider": s.jev_provider if client else None,
                    "models": models, "thresholds_fitted_on": FITTED_MODEL},
            "enriched": enriched, "case_id": case_id, "notes": notes,
            "alerts": [r.to_dict() for r in sorted(results, key=lambda r: -RANK[r.disposition])],
        }, indent=2, default=str))
    else:
        _print_cards(results, notes)
        _print_footer(client is not None, s, models, enriched, case_id)

    if exit_code:
        raise typer.Exit(EXIT_CODES[overall])


def _pct(x: float | None) -> str:
    return "—" if x is None else f"{x:.2f}"


def _print_cards(results, notes) -> None:
    for r in sorted(results, key=lambda r: -RANK[r.disposition]):
        style = _STYLE[r.disposition]
        rprint(f"\n[{style}]{_WORD[r.disposition]}[/{style}]  {escape(r.alert.label)}")
        for ir in r.indicators:
            d = ir.decision
            ind_style = _STYLE[d.disposition]
            rprint(f"  {escape(ir.indicator.value)} [dim]({ir.indicator.type.value})[/dim] "
                   f"[{ind_style}]{d.disposition.replace('_', ' ')}[/{ind_style}]")
            listed = ir.listing + (f" ({', '.join(ir.listed_by)})" if ir.listed_by else "")
            bits = [f"listing: {listed}"]
            if d.role:
                bits.append(f"role: {d.role.replace('_', ' ')} ({_pct(d.role_confidence)})")
            if d.p_malicious is not None:
                bits.append(f"p(malicious): {_pct(d.p_malicious)}")
            if d.urgency:
                bits.append(f"urgency: {d.urgency}")
            rprint("    [dim]" + escape(" · ".join(bits)) + "[/dim]")
            for reason in d.reasons:
                rprint(f"    → {escape(reason)}")
        if r.alert.kept_local:
            rprint(f"  [dim]kept local (never sent): {escape(', '.join(sorted(set(r.alert.kept_local))))}[/dim]")
    for n in notes:
        rprint(f"[dim]· {escape(n)}[/dim]")


def _print_footer(jev_used: bool, s: Settings, models: list[str], enriched: bool,
                  case_id: str | None) -> None:
    print()
    if jev_used:
        rprint(f"[dim]Jev: {escape(', '.join(models) or s.jev_model)} via {s.jev_provider} (your key).[/dim]")
        if models and any(m != FITTED_MODEL for m in models):
            rprint(f"[yellow]Thresholds were fitted on {FITTED_MODEL}; this answer came from "
                   f"{escape(', '.join(models))}. Treat suggest-close with extra care.[/yellow]")
    else:
        rprint(f"[yellow]{escape(BYOK_HINT)}[/yellow]")
    if not enriched:
        rprint("[dim]Not enriched (--no-collect): nothing will be suggested for closing.[/dim]")
    if case_id:
        rprint(f"[dim]Evidence: case {case_id} (`umbra case export {case_id}`).[/dim]")
    rprint("[dim]Umbra never closes an alert or takes an action. Suggest-close is for a person to confirm.[/dim]")
