"""CLI: umbra lookup / umbra wiki."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

from umbra.wiki.service import WikiService

wiki_app = typer.Typer(help="Cyber wiki corpus: update index, show pages.")


def _svc(path: Optional[Path], index: Optional[Path]) -> WikiService:
    return WikiService(
        corpus_dir=path if path else None,
        index_path=index if index else None,
    )


@wiki_app.command("update")
def wiki_update(
    path: Optional[Path] = typer.Option(None, "--path", help="Corpus directory (umbra-wiki checkout)"),
    index: Optional[Path] = typer.Option(None, "--index", help="SQLite FTS index path"),
    git: bool = typer.Option(True, "--git/--no-git", help="git pull/clone remote wiki repo"),
) -> None:
    """Refresh corpus (optional git) and rebuild local FTS index."""
    svc = _svc(path, index)
    if git:
        try:
            msg = svc.update_from_git()
            rprint(f"[green]{msg}[/green]")
            return
        except Exception as exc:  # noqa: BLE001
            rprint(f"[yellow]git update skipped ({exc}); rebuilding local corpus only[/yellow]")
    n = svc.rebuild_index()
    rprint(f"[green]Indexed {n} pages from {svc.corpus_dir} → {svc.index_path}[/green]")


@wiki_app.command("path")
def wiki_path(
    path: Optional[Path] = typer.Option(None, "--path"),
) -> None:
    """Print resolved corpus and index paths."""
    svc = _svc(path, None)
    rprint(f"corpus: {svc.corpus_dir}")
    rprint(f"index:  {svc.index_path}")
    rprint(f"exists: corpus={svc.corpus_dir.is_dir()} index={svc.index_path.is_file()}")


@wiki_app.command("show")
def wiki_show(
    slug: str = typer.Argument(..., help="Page slug, e.g. protocol/arp"),
    path: Optional[Path] = typer.Option(None, "--path"),
    index: Optional[Path] = typer.Option(None, "--index"),
) -> None:
    """Show a single wiki page by slug."""
    svc = _svc(path, index)
    page = svc.get(slug)
    if not page:
        rprint(f"[red]Not found:[/red] {slug}")
        raise typer.Exit(1)
    header = f"{page['title']}  [{page.get('page_type')}]  `{page['slug']}`"
    rprint(Panel(Markdown(page.get("body") or ""), title=header))


def lookup_command(
    query: str = typer.Argument(..., help="Free text, CVE-ID, or MITRE technique id"),
    limit: int = typer.Option(8, "--limit", "-n"),
    path: Optional[Path] = typer.Option(None, "--path", help="Corpus directory"),
    index: Optional[Path] = typer.Option(None, "--index"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Search the cyber wiki (concepts, protocols, CVE, MITRE, …)."""
    svc = _svc(path, index)
    hits = svc.lookup(query, limit=limit)
    if json_out:
        import json

        print(json.dumps(hits, indent=2))
        return
    if not hits:
        # A recognised identifier deserves better than "no hits": say whether
        # this is scope or nonsense, and hand over what we do know.
        why = svc.explain(query)
        if why:
            rprint(f"[yellow]{why['headline']}[/yellow]")
            rprint(f"  {why['detail']}")
            for line in why["known"]:
                rprint(f"  [bold]Umbra does know:[/bold] {line}")
            rprint(f"  [dim]authoritative record:[/dim] {why['upstream_url']}")
            raise typer.Exit(1)
        rprint(f"[yellow]No wiki hits for[/yellow] {query!r}")
        rprint("Tip: umbra wiki update --path ~/umbra-wiki")
        raise typer.Exit(1)
    table = Table(title=f"Umbra Wiki · {query!r}")
    table.add_column("#", style="dim")
    table.add_column("title")
    table.add_column("type")
    table.add_column("slug")
    table.add_column("summary")
    for i, h in enumerate(hits, 1):
        table.add_row(
            str(i),
            h.get("title") or "",
            h.get("page_type") or "",
            h.get("slug") or "",
            (h.get("summary") or "")[:80],
        )
    rprint(table)
    rprint("[dim]umbra wiki show <slug>  ·  related pages listed in each article[/dim]")
