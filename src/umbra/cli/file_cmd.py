"""CLI: `umbra email` and `umbra file` — read a file, choose, then run.

Carl asked for `umbra example.email` to work directly, so `umbra.cli.main`
installs a Click group that routes a bare path into `umbra file`. All three
spellings land here:

```bash
umbra example.email          # a path that is not a command name
umbra email example.email    # explicit, and accepts stdin
umbra file iocs.csv          # explicit, any supported type
```

Nothing runs from a read. The file is parsed, the identifiers are printed with
their provenance, and `--confirm` is what turns the armed ones into a case —
the terminal equivalent of the confirm page's checkboxes, and subject to the
same rule that the analyst decides what gets touched.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table

from umbra.ingest import ingest
from umbra.ingest.detect import Kind

_BASES = {"own_asset", "client_engagement", "public_cti", "training_lab", "other"}

_SEVERITY_COLOUR = {"high": "red", "medium": "yellow", "low": "cyan",
                    "info": "dim"}


def _read(path: str) -> tuple[str, bytes]:
    """Bytes from a path, or from stdin when the path is `-` or missing."""
    if not path or path == "-":
        data = sys.stdin.buffer.read()
        return "stdin", data
    target = Path(path).expanduser()
    if not target.exists():
        raise typer.BadParameter(f"no such file: {target}")
    if target.is_dir():
        raise typer.BadParameter(f"{target} is a directory")
    try:
        return target.name, target.read_bytes()
    except OSError as exc:
        raise typer.BadParameter(f"could not read {target}: {exc}") from exc


def _print_findings(findings) -> None:
    if not findings:
        return
    table = Table("", "Finding", "Why", title="Verdict", show_lines=False)
    for finding in findings:
        colour = _SEVERITY_COLOUR.get(finding.severity, "white")
        table.add_row(f"[{colour}]{finding.severity}[/{colour}]",
                      finding.title, finding.detail)
    rprint(table)


def _print_chain(parsed) -> None:
    """Render an already-parsed chain. Takes the parse rather than the bytes so
    a single `umbra email` run parses the message once instead of three times."""
    from umbra.email.parse import Trust

    if parsed is None or not parsed.hops:
        return
    table = Table("#", "Trust", "Received from", "Address", "Recorded by",
                  title="Received chain (newest first)")
    colours = {Trust.TRUSTED: "green", Trust.UNTRUSTED: "red",
               Trust.UNKNOWN: "yellow"}
    for hop in parsed.hops:
        colour = colours[hop.trust]
        table.add_row(
            str(hop.index),
            f"[{colour}]{hop.trust.value}[/{colour}]",
            (hop.from_host or hop.helo or "—")[:44],
            hop.from_ip or "—",
            (hop.by or "—")[:44],
        )
    rprint(table)
    rprint(f"[dim]{parsed.boundary_basis}[/dim]")
    rprint(f"[bold]Origin:[/bold] {parsed.origin_ip or 'not established'} — "
           f"{parsed.origin_note}")


def _print_metadata(metadata: dict) -> None:
    if not metadata:
        return
    table = Table("Field", "Value", title="Metadata")
    for key, value in metadata.items():
        if value in (None, "", []):
            continue
        text = ", ".join(str(v) for v in value) if isinstance(value, list) else str(value)
        table.add_row(key, text[:110])
    rprint(table)


def _print_seeds(plan) -> None:
    table = Table("Run", "Type", "Value", "Conf", "From", "Why",
                  title=f"Identifiers ({len(plan.seeds)})")
    for seed in plan.seeds:
        table.add_row(
            "[green]yes[/green]" if seed.include else "[dim]no[/dim]",
            seed.type.value,
            seed.value[:46],
            f"{seed.confidence:.2f}",
            (seed.source_span or "")[:22],
            (seed.notes or "")[:52],
        )
    rprint(table)


def _render(result) -> None:
    plan = result.plan
    armed = len(plan.included_seeds())
    rprint(Panel(
        f"[bold]{plan.case_name}[/bold]\n"
        f"{plan.summary}\n"
        f"kind={result.kind.value} · size={result.size} bytes · "
        f"extractor={plan.extractor}",
        title="Umbra",
    ))

    if result.kind is Kind.EMAIL:
        _print_findings(result.findings)
        _print_chain(result.parsed)
    else:
        _print_metadata(result.metadata)

    if plan.seeds:
        _print_seeds(plan)
    else:
        rprint("[yellow]No identifiers were extracted.[/yellow]")

    if plan.collectors:
        rprint(f"Collectors ({len(plan.collectors)}): "
               + ", ".join(plan.collectors))

    for note in result.notes:
        rprint(f"[yellow]•[/yellow] {note}")
    for question in plan.clarifying_questions:
        rprint(f"[cyan]?[/cyan] {question}")

    rprint(f"[dim]{armed} of {len(plan.seeds)} identifier(s) selected. "
           f"Nothing has been collected — add --confirm to run them, or "
           f"--only/--drop to change the selection.[/dim]")


def _apply_selection(plan, only: list[str], drop: list[str]) -> None:
    """Narrow the selection from the command line.

    Only ever narrows, matching `_apply_plan_edits` on the web side: `--only`
    restricts to the named values, `--drop` removes them, and neither can arm a
    seed the reader deliberately left off — for that, name it in `--only`.
    """
    wanted = {v.strip().lower() for v in only if v.strip()}
    unwanted = {v.strip().lower() for v in drop if v.strip()}
    for seed in plan.seeds:
        value = seed.value.lower()
        if wanted:
            seed.include = value in wanted
        if value in unwanted:
            seed.include = False


def file_command(
    path: str = typer.Argument(..., help="File to read (- for stdin)"),
    basis: str = typer.Option("own_asset", "--basis", "-b",
                              help="|".join(sorted(_BASES))),
    note: str = typer.Option("", "--note", "-n"),
    depth: int = typer.Option(1, "--depth", "-d"),
    only: list[str] = typer.Option([], "--only",
                                   help="Run only these values (repeatable)"),
    drop: list[str] = typer.Option([], "--drop",
                                   help="Never run these values (repeatable)"),
    trusted_domain: list[str] = typer.Option(
        [], "--trusted-domain",
        help="Your own mail domains, for the Received trust boundary"),
    json_out: bool = typer.Option(False, "--json", help="Print JSON"),
    confirm: bool = typer.Option(False, "--confirm",
                                 help="Create a case and run the collectors"),
) -> None:
    """Read a file — email, indicator list, CSV, JSON, image, PDF, Office — and
    plan an investigation from what is in it."""
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {sorted(_BASES)}")

    name, data = _read(path)
    trusted = {d.strip().lower() for d in trusted_domain if d.strip()} or None
    result = ingest(name, data, authorization_basis=basis,
                    authorization_note=note, trusted_domains=trusted,
                    depth=depth)
    _apply_selection(result.plan, only, drop)

    if json_out:
        # Plain print, not rprint: rich soft-wraps to the terminal width and
        # inserts newlines inside string values, which turns valid JSON into
        # invalid JSON and silently corrupts long values. Same bug that once
        # truncated an operator handoff URL mid-signature.
        print(json.dumps({
            "kind": result.kind.value,
            "filename": result.filename,
            "size": result.size,
            "metadata": result.metadata,
            "notes": result.notes,
            "findings": [
                {"key": f.key, "severity": f.severity, "title": f.title,
                 "detail": f.detail, "evidence": f.evidence}
                for f in result.findings
            ],
            "plan": json.loads(result.plan.model_dump_json()),
        }, indent=2, default=str))
    else:
        _render(result)

    if not confirm:
        return

    from umbra.cli.plan_exec import confirm_and_run

    confirm_and_run(result.plan, source="cli_ingest",
                    action=f"ingest.{result.kind.value}.confirm")


def email_command(
    path: Optional[str] = typer.Argument(None,
                                         help="Message or header file "
                                              "(omit or - to read stdin)"),
    basis: str = typer.Option("own_asset", "--basis", "-b",
                              help="|".join(sorted(_BASES))),
    note: str = typer.Option("", "--note", "-n"),
    depth: int = typer.Option(1, "--depth", "-d"),
    only: list[str] = typer.Option([], "--only"),
    drop: list[str] = typer.Option([], "--drop"),
    trusted_domain: list[str] = typer.Option(
        [], "--trusted-domain",
        help="Your own mail domains. Without this the boundary is inferred "
             "from the topmost hop, which you should check."),
    json_out: bool = typer.Option(False, "--json"),
    confirm: bool = typer.Option(False, "--confirm"),
) -> None:
    """Analyze email headers: alignment, the Received chain, and what to run.

    Forces the header reader, so a message whose headers are unusual enough to
    fail detection still gets parsed as mail rather than as a text file.
    """
    if basis not in _BASES:
        raise typer.BadParameter(f"basis must be one of {sorted(_BASES)}")

    name, data = _read(path or "-")
    trusted = {d.strip().lower() for d in trusted_domain if d.strip()} or None

    from umbra.email.plan import analyze
    from umbra.ingest import IngestResult
    from umbra.ingest.detect import decode

    # One pass for the parse, the findings and the plan.
    parsed, findings, plan = analyze(
        decode(data), trusted_domains=trusted, authorization_basis=basis,
        authorization_note=note, depth=depth)
    plan.case_name = f"Email: {name}"[:120]
    result = IngestResult(
        kind=Kind.EMAIL, filename=name, size=len(data), plan=plan,
        findings=findings, parsed=parsed,
        metadata={"from": parsed.from_addr, "subject": parsed.subject,
                  "hops": len(parsed.hops), "origin_ip": parsed.origin_ip},
    )
    if not parsed.hops and not parsed.from_addr:
        result.notes.append(
            "no mail headers were recognised in this input. That is a parse "
            "failure, not a clean message — check you pasted the full header "
            "block (Gmail: Show original; Outlook: File → Properties → "
            "Internet headers)."
        )

    _apply_selection(plan, only, drop)

    if json_out:
        # See the note in `file_command` — rich must not touch JSON.
        print(json.dumps({
            "kind": result.kind.value,
            "filename": name,
            "metadata": result.metadata,
            "notes": result.notes,
            "findings": [
                {"key": f.key, "severity": f.severity, "title": f.title,
                 "detail": f.detail, "evidence": f.evidence}
                for f in result.findings
            ],
            "plan": json.loads(plan.model_dump_json()),
        }, indent=2, default=str))
    else:
        _render(result)

    if not confirm:
        return

    from umbra.cli.plan_exec import confirm_and_run

    confirm_and_run(plan, source="cli_email", action="email.confirm")
