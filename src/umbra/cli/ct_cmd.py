"""`umbra ct` — the owned Certificate Transparency corpus.

Ingest CT logs directly into Umbra's own store and query them with no external
API. This is the crt.sh replacement: `ct ingest` builds the corpus, `ct search`
queries what you own.
"""
from __future__ import annotations

import httpx
import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.lake import ct as ctmod
from umbra.lake.store import LakeStore

ct_app = typer.Typer(help="Owned Certificate Transparency corpus (crt.sh replacement)")


def _http() -> httpx.Client:
    s = get_settings()
    return httpx.Client(timeout=s.request_timeout_s,
                        headers={"User-Agent": s.user_agent}, follow_redirects=True)


@ct_app.command("logs")
def logs() -> None:
    """List known CT logs and their current live tree size."""
    http = _http()
    table = Table(title="Certificate Transparency logs")
    table.add_column("name"); table.add_column("tree_size", justify="right"); table.add_column("url")
    for name, url in ctmod.KNOWN_LOGS.items():
        try:
            size = ctmod.get_sth(http, url).get("tree_size", "?")
            table.add_row(name, f"{size:,}" if isinstance(size, int) else str(size), url)
        except Exception as exc:  # noqa: BLE001
            table.add_row(name, f"[red]err[/red]", f"{url} ({str(exc)[:40]})")
    rprint(table)


@ct_app.command("ingest")
def ingest(
    log: str = typer.Option(None, "--log", "-l",
                            help="log name from `ct logs`, or 'all' "
                                 "(default: the first active shard)"),
    count: int = typer.Option(500, "--count", "-n", help="entries to ingest this run"),
    resume: bool = typer.Option(True, "--resume/--newest",
                                help="resume from checkpoint, or tail the newest N"),
    batch: int = typer.Option(256, "--batch", help="entries per get-entries request"),
) -> None:
    """Ingest CT log entries into the owned corpus (parses certs → domains)."""
    settings = get_settings()
    store = LakeStore.from_settings(settings)
    http = _http()
    targets = list(ctmod.KNOWN_LOGS) if log == "all" else [log or ctmod.default_log()]
    for name in targets:
        url = ctmod.KNOWN_LOGS.get(name)
        if not url:
            # Name the reason. A retired shard is a different mistake from a
            # typo, and the ingest timer spent nine months on the former.
            if ctmod.log_status(name) == "retired":
                rprint(f"[yellow]{name} is a retired shard[/yellow] — it accepts "
                       "no new certificates. See `umbra ct logs`.")
            else:
                rprint(f"[red]unknown log[/red] {name} (see `umbra ct logs`)")
            continue
        try:
            _ingest_one(store, http, name, url, count, resume, batch)
        except Exception as exc:  # noqa: BLE001
            rprint(f"[red]{name}: ingest error[/red] {exc}")


def _ingest_one(store, http, name, url, count, resume, batch) -> None:
    tree_size = int(ctmod.get_sth(http, url)["tree_size"])
    cp = store.get_checkpoint(name) if resume else None
    if cp is not None:
        start = cp + 1
    else:
        start = max(0, tree_size - count)
    end = min(start + count - 1, tree_size - 1)
    if start > end:
        rprint(f"[dim]{name}: up to date at index {tree_size - 1:,}[/dim]")
        return
    rprint(f"[cyan]{name}[/cyan]: ingesting {start:,}..{end:,} (tree {tree_size:,})")
    total_c = total_d = 0
    cur = start
    while cur <= end:
        stop = min(cur + batch - 1, end)
        entries = ctmod.get_entries(http, url, cur, stop)
        if not entries:
            break
        records = [ctmod.parse_ct_entry(e.get("leaf_input", ""), e.get("extra_data", ""))
                   for e in entries]
        c, d = store.add_records(name, cur, records)
        total_c += c; total_d += d
        got = len(entries)
        store.set_checkpoint(name, cur + got - 1, tree_size)
        cur += got  # logs may return a prefix shorter than requested
    rprint(f"[green]{name}: +{total_c} certs, +{total_d} domains[/green] "
           f"(checkpoint {store.get_checkpoint(name):,})")


@ct_app.command("search")
def search(
    domain: str = typer.Argument(..., help="domain to look up in the owned corpus"),
    exact: bool = typer.Option(False, "--exact", help="exact name only (no subdomains)"),
    limit: int = typer.Option(100, "--limit"),
) -> None:
    """Search the owned CT corpus — no external API."""
    store = LakeStore.from_settings(get_settings())
    subs = store.distinct_subdomains(domain) if not exact else None
    rows = store.search(domain, exact=exact, limit=limit)
    if not rows:
        rprint(f"[yellow]No certs for {domain} in the owned corpus yet.[/yellow] "
               f"Run `umbra ct ingest` to grow it (CT is tail-forward — "
               f"backfill accumulates over time).")
        return
    if subs is not None:
        rprint(f"[bold]{len(subs)} distinct name(s)[/bold] under {domain} in corpus:")
        for s in subs[:50]:
            rprint(f"  {s}")
        if len(subs) > 50:
            rprint(f"  … +{len(subs) - 50} more")
    table = Table(title=f"Certs matching {domain} (owned corpus)")
    for col in ("domain", "issuer", "not_before", "log"):
        table.add_column(col)
    for r in rows[:limit]:
        table.add_row(r["domain"], (r["issuer"] or "?")[:24],
                      (r["not_before"] or "?")[:10], r["log"])
    rprint(table)


@ct_app.command("stats")
def stats() -> None:
    """Show the owned corpus size and per-log ingest checkpoints."""
    store = LakeStore.from_settings(get_settings())
    st = store.stats()
    rprint(f"[bold]Owned CT corpus[/bold]: {st['certs']:,} certs, "
           f"{st['distinct_domains']:,} distinct domains")
    for log, cp in st["checkpoints"].items():
        rprint(f"  {log}: "
               f"{ctmod.describe_checkpoint(log, cp['last_index'], cp['tree_size'])}"
               f" — updated {cp['updated_at'][:19]}")

    # A corpus with no active log is frozen, and the per-log lines above do not
    # add up to that conclusion on their own.
    if not any(ctmod.log_status(name) == "active" for name in st["checkpoints"]):
        rprint("[yellow]No active log has been ingested — the corpus cannot "
               "grow. Run `umbra ct ingest` against a current shard.[/yellow]")
