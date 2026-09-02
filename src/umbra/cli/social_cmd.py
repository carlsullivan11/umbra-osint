"""``umbra social`` — preview and (deliberately) publish KEV posts.

`preview` is the default mode everywhere. Publishing is public, costs money per
call and happens under Carl's account, so it takes an explicit `--confirm` on
top of the environment switch.
"""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.social import x as xclient
from umbra.social.compose import compose, select
from umbra.social.store import SocialStore

social_app = typer.Typer(help="Post Umbra's KEV findings to X.", no_args_is_help=True)

KIND = "kev_addition"


def _pct(score: float) -> str:
    """EPSS at one significant figure. 0.0004 shown as "0%" reads as a
    measured zero; it is four hundredths of a percent, which is a different
    statement."""
    pct = score * 100
    if pct >= 10:
        return f"{pct:.0f}%"
    return f"{pct:.2g}%"


def _no_candidates_reason(pages: list[dict]) -> str:
    """Why there is nothing to post — and the two reasons are different.

    An empty corpus means *nothing was checked*. Reporting that as "everything
    has already been posted" is the same unchecked-reads-as-clean error this
    codebase refuses everywhere else, and a pip user hits it on day one because
    the corpus is an optional download.
    """
    if not pages:
        return ("No CVE pages in the corpus, so nothing was checked. KEV posts "
                "come from the wiki — run `umbra wiki update` first.")
    return ("Every recent KEV entry has already gone out — that is the dedupe "
            "working, not a fault.")


def _pages() -> list[dict]:
    """Every CVE page in the corpus.

    Reads `umbra.wiki.service` directly rather than through
    `umbra.web.routes_wiki`. The web package is excluded from the published
    distribution (docs/OPEN-CORE.md), so routing a CLI command through it
    makes that command crash for everyone who installed with pip — which is
    exactly what it did until a fresh-venv check caught it.
    """
    from umbra.wiki.service import WikiService

    svc = WikiService()
    return [p for p in (svc.get(s) for s in svc.index.slugs(limit=50_000))
            if p and str(p.get("slug", "")).startswith("cve/")]


def _epss():
    try:
        from umbra.lake.epss import EpssLake

        lake = EpssLake.from_settings(get_settings())
        return lake if lake.available else None
    except Exception:  # noqa: BLE001
        return None


@social_app.command("preview")
def preview(limit: int = typer.Option(3, "--limit", "-n")) -> None:
    """Show exactly what would go out. Sends nothing."""
    settings = get_settings()
    store = SocialStore.from_settings(settings)
    epss = _epss()
    try:
        pages = _pages()
        picks = select(pages, store=store, epss=epss, limit=limit, kind=KIND)
        if not picks:
            rprint(f"[yellow]Nothing to post.[/yellow] {_no_candidates_reason(pages)}")
            return
        for c in picks:
            text, url = compose(c)
            rprint(f"\n[bold]{c.cve}[/bold]  [dim]added {c.date_added}"
                   f"{' · ransomware' if c.ransomware else ''}"
                   f"{f' · EPSS {_pct(c.epss)}' if c.epss is not None else ' · EPSS unscored'}[/dim]")
            rprint(f"  {text}")
            rprint(f"  [blue]{url}[/blue]  [dim]{len(text)} chars + link[/dim]")
            store.record(kind=KIND, ref=c.ref, text=text, url=url, dry_run=True)
        rprint(f"\n[dim]{len(picks)} preview(s). Nothing sent. "
               f"Live cost would be ${len(picks) * 0.20:.2f}.[/dim]")
    finally:
        store.close()
        if epss is not None:
            epss.close()


@social_app.command("post")
def post(
    limit: int = typer.Option(1, "--limit", "-n"),
    confirm: bool = typer.Option(False, "--confirm",
                                 help="actually publish; without this it previews"),
) -> None:
    """Publish. Requires --confirm *and* UMBRA_X_ENABLED=1."""
    settings = get_settings()
    store = SocialStore.from_settings(settings)
    epss = _epss()
    dry = not confirm
    try:
        blocked = xclient.preflight(store, dry_run=dry)
        if blocked:
            rprint(f"[red]Refusing to post:[/red] {blocked}")
            raise typer.Exit(1)

        pages = _pages()
        picks = select(pages, store=store, epss=epss, limit=limit, kind=KIND)
        if not picks:
            rprint(f"[yellow]Nothing to post.[/yellow] {_no_candidates_reason(pages)}")
            return

        for c in picks:
            text, url = compose(c)
            body = f"{text} {url}"
            try:
                result = xclient.post(body, store=store, dry_run=dry)
            except xclient.NotEnabled as exc:
                rprint(f"[red]Stopped:[/red] {exc}")
                raise typer.Exit(1) from None
            store.record(kind=KIND, ref=c.ref, text=text, url=url,
                         dry_run=dry, remote_id=result.remote_id)
            mark = "[dim]dry[/dim]" if dry else "[green]sent[/green]"
            rprint(f"  {mark} {c.cve} — {result.detail}")

        st = store.status()
        rprint(f"\n[dim]today {st['today']}/{xclient.MAX_PER_DAY} · "
               f"30-day spend ${st['spend_30d_usd']:.2f}[/dim]")
    finally:
        store.close()
        if epss is not None:
            epss.close()


@social_app.command("status")
def status() -> None:
    """Posted, previewed, spent — and whether the switch is even on."""
    store = SocialStore.from_settings(get_settings())
    try:
        st = store.status()
        t = Table(title="Umbra social (X)")
        t.add_column("key"); t.add_column("value")
        t.add_row("enabled", "yes" if xclient.enabled() else "no (UMBRA_X_ENABLED != 1)")
        missing = xclient.missing_credentials()
        t.add_row("credentials", "complete" if not missing else f"missing {len(missing)}")
        t.add_row("posted (live)", str(st["live"]))
        t.add_row("previewed", str(st["dry"]))
        t.add_row("today", f"{st['today']}/{xclient.MAX_PER_DAY}")
        t.add_row("30-day spend", f"${st['spend_30d_usd']:.2f}")
        t.add_row("last live post", str(st["last"] or "never"))
        rprint(t)
        rows = store.recent(limit=5)
        if rows:
            rprint("\n[dim]most recent:[/dim]")
            for r in rows:
                tag = "dry" if r["dry_run"] else "LIVE"
                rprint(f"  [dim]{tag}[/dim] {r['ref']}  {r['text'][:72]}")
    finally:
        store.close()
