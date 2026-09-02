"""`umbra crypto` — address screening against the owned label lake (C1).

Screening is offline: `labels sync` pulls the sources, `screen` answers from the
lake with no network call. Same "own the data" pattern as the CT corpus, the OUI
table and the abuse.ch feeds.

The copy rule from `docs/CRYPTO-EXPLORATION.md` applies to every line this
prints: a label is a **risk signal with provenance**, not a determination of
guilt, and a sanctions listing is a claim about the list as it stands today.
"""
from __future__ import annotations

import typer
from rich import print as rprint
from rich.table import Table

from umbra.core.config import get_settings
from umbra.crypto import lake as crypto_lake
from umbra.crypto import ofac
from umbra.crypto.normalize import detect_and_normalize
from umbra.lake.store import LakeStore

crypto_app = typer.Typer(help="Crypto address screening (OFAC + curated labels)")


def _store() -> LakeStore:
    return LakeStore.from_settings(get_settings())


@crypto_app.command("screen")
def crypto_screen(
    address: str = typer.Argument(..., help="Address to screen"),
    chain: str = typer.Option("", "--chain", "-c",
                              help="Force a chain when formats collide (sol, bsc…)"),
) -> None:
    """Screen one address against the label lake. No network call."""
    normalized = detect_and_normalize(address, chain_hint=chain or None)
    if normalized is None:
        rprint(f"[red]unrecognised address format[/red]: {address}")
        rprint("[dim]pass --chain to force interpretation (sol, bsc, …)[/dim]")
        raise typer.Exit(code=1)

    result = crypto_lake.screen(_store(), normalized.chain, normalized.address)
    rprint(f"[cyan]{normalized.address}[/cyan]  chain={normalized.chain}")

    for svc in result.get("services") or []:
        # The address *is* the service. Infrastructure, not a suspect.
        rprint(f"  [magenta]{svc['kind']}[/magenta]: {svc['name']}")
        if svc.get("notes"):
            rprint(f"    [dim]{svc['notes']}[/dim]")

    if not result["checked"]:
        rprint("[yellow]not checked[/yellow] — the label lake is empty on this "
               "instance. Run `umbra crypto labels sync`.")
        rprint("[dim]An empty lake is not evidence the address is clean.[/dim]")
        return

    if not result["labels"]:
        rprint("[green]no active labels[/green] — not on any list Umbra has "
               f"indexed ({result['indexed']['active']:,} addresses).")
        rprint("[dim]Absence from these lists is not proof the address is "
               "clean; they cover sanctions and curated reports, not all "
               "criminal activity.[/dim]")
    for label in result["labels"]:
        rprint(f"  [red]{label['tag']}[/red] "
               f"[dim](source={label['source']}, confidence={label['confidence']})[/dim]")
        if label["summary"]:
            rprint(f"    {label['summary']}")
        if label["url"]:
            rprint(f"    [dim]{label['url']}[/dim]")

    for label in result["former_labels"]:
        # The Tornado Cash case: listed once, not listed now. Saying so is more
        # useful than silence and more honest than a live accusation.
        rprint(f"  [yellow]formerly {label['tag']}[/yellow] "
               f"[dim](delisted {(label['delisted_at'] or '')[:10]}, "
               f"source={label['source']})[/dim]")
        rprint("    [dim]No longer on the current list. Historic listing only.[/dim]")


@crypto_app.command("stats")
def crypto_stats() -> None:
    """What the label lake currently holds."""
    stats = _store().crypto_label_stats()
    rprint(f"[cyan]{stats['active']:,}[/cyan] active label(s) · "
           f"{stats['delisted']:,} delisted")
    if stats["by_chain"]:
        table = Table(title="by chain")
        table.add_column("chain")
        table.add_column("active", justify="right")
        for chain, n in sorted(stats["by_chain"].items(), key=lambda kv: -kv[1]):
            table.add_row(chain, f"{n:,}")
        rprint(table)
    for source, meta in stats["sources"].items():
        rprint(f"  {source}: {meta['active']:,} active · synced {meta['synced_at'][:19]}")
    if not stats["sources"]:
        rprint("[yellow]no sources synced yet[/yellow] — run "
               "`umbra crypto labels sync`")


labels_app = typer.Typer(help="Label sources")
crypto_app.add_typer(labels_app, name="labels")


@labels_app.command("sync")
def labels_sync(
    source: str = typer.Option("ofac", "--source", "-s", help="ofac"),
) -> None:
    """Reconcile a label source against its current published file.

    A reconciliation, not an append: addresses missing from the new file are
    delisted with a date rather than left asserting a sanctions listing that no
    longer exists. OFAC removes entries — Tornado Cash was delisted in 2025.
    """
    from umbra.core.http_guard import GuardedClient

    if source not in {"ofac", "ofac_sdn"}:
        rprint(f"[red]unknown source[/red]: {source}")
        raise typer.Exit(code=2)

    settings = get_settings()
    rprint("[cyan]fetching[/cyan] OFAC SDN…")
    with GuardedClient(timeout=max(120.0, settings.request_timeout_s),
                       headers={"User-Agent": settings.user_agent},
                       follow_redirects=True) as http:
        resp = http.get(ofac.SDN_URL)
        resp.raise_for_status()
        labels = ofac.parse(resp.text)

    if not labels:
        # Never reconcile against nothing: a bad fetch and a genuine mass
        # delisting look identical, and only one should clear every label.
        rprint("[red]no addresses parsed[/red] — refusing to reconcile, the "
               "existing labels are left alone.")
        raise typer.Exit(code=1)

    stats = crypto_lake.replace_source(_store(), ofac.SOURCE, labels)
    rprint(f"[green]ofac_sdn[/green] active={stats['active']:,} "
           f"added={stats['added']:,} refreshed={stats['refreshed']:,} "
           f"delisted={stats['delisted']:,}")


@crypto_app.command("neighbors")
def crypto_neighbors(
    address: str = typer.Argument(..., help="Bitcoin or TRON address"),
    limit: int = typer.Option(25, "--limit", "-n", help="Cap transfers shown"),
    chain: str = typer.Option("", "--chain", "-c", help="Force btc or tron"),
) -> None:
    """Depth-1 counterparties for a Bitcoin or TRON address. No key either way.

    Two independent public instances run the same open backend, and the same
    software self-hosts against a full node later — so this path does not become
    a dependency on any one explorer.
    """
    from umbra.core.http_guard import GuardedClient
    from umbra.crypto.providers.base import ProviderCaps
    from umbra.crypto.providers.esplora import EsploraProvider
    from umbra.crypto.types import AddressRef

    from umbra.crypto.providers.trongrid import TronGridProvider

    normalized = detect_and_normalize(address, chain_hint=chain or None)
    if normalized is None or normalized.chain not in {"btc", "tron"}:
        rprint(f"[red]no neighbour provider for that address[/red]: {address}")
        rprint("[dim]Bitcoin (Esplora) and TRON (TronGrid) are wired; both "
               "key-free.[/dim]")
        raise typer.Exit(code=1)

    settings = get_settings()
    caps = ProviderCaps(max_transfers=limit)
    with GuardedClient(timeout=max(30.0, settings.request_timeout_s),
                       headers={"User-Agent": settings.user_agent}) as http:
        if normalized.chain == "tron":
            provider = TronGridProvider(
                http, api_key=getattr(settings, "trongrid_api_key", None))
        else:
            provider = EsploraProvider(http)
        result = provider.fetch(AddressRef(normalized.chain, normalized.address), caps)

    if result.unavailable:
        # Not "no transactions" — not checked.
        rprint(f"[yellow]not checked[/yellow] — {result.note}")
        raise typer.Exit(code=2)

    rprint(f"[cyan]{normalized.address}[/cyan] via {result.instance}")
    if not result.transfers:
        rprint("[dim]no transactions found for this address[/dim]")
        return

    store = _store()
    counterparties = [tr.to_addr if tr.from_addr == normalized.address
                      else tr.from_addr for tr in result.transfers]
    touches = crypto_lake.service_touches(normalized.chain, counterparties)
    table = Table(title=f"{len(result.transfers)} transfer(s), newest first")
    for col in ("direction", "counterparty", "amount", "asset", "labels"):
        table.add_column(col)
    for tr in result.transfers:
        outgoing = tr.from_addr == normalized.address
        other = tr.to_addr if outgoing else tr.from_addr
        labels = store.crypto_labels(normalized.chain, other)
        marks = [lab["tag"] for lab in labels]
        marks += [f"{svc['kind']}:{svc['name']}"
                  for svc in touches.get(other.lower(), [])]
        # An unverified token's symbol is whatever its deployer typed, so it is
        # never shown as if Umbra had checked it.
        verified = tr.props.get("token_verified", True)
        asset = tr.asset if verified else f"[yellow]unverified[/yellow] {tr.asset[:12]}…"
        table.add_row(
            "out" if outgoing else "in",
            other[:40],
            f"{tr.amount_raw / 10 ** tr.decimals:.8f}".rstrip("0").rstrip("."),
            asset,
            ", ".join(marks) or "—",
        )
    rprint(table)
    if getattr(result, "spoofed", 0):
        rprint(f"[yellow]{result.spoofed} transfer(s) came from unverified token "
               f"contracts.[/yellow] TRC-20 tokens report their own name and "
               f"symbol, so an impostor can call itself USDT — those rows show "
               f"the contract instead of the claimed symbol.")
    if touches:
        rprint("[yellow]Service interaction noted.[/yellow] Using a mixer or "
               "bridge is not a crime and is not evidence of one — people use "
               "privacy tools for private reasons.")
    rprint("[dim]Counterparty labels are risk signals with provenance, not "
           "determinations of guilt.[/dim]")


@crypto_app.command("tail")
def crypto_tail(
    blocks: int = typer.Option(24, "--blocks", "-b", help="Blocks per tick"),
) -> None:
    """Follow the chain head and index transfers touching watched addresses.

    Deliberately targeted rather than exhaustive. Free RPC offers roughly
    fifteen minutes of history, so Umbra cannot out-archive an explorer — but it
    can follow the head continuously, keep only what touches an address it
    already cares about, and do it without telling anyone which addresses those
    are.
    """
    from umbra.core.http_guard import GuardedClient
    from umbra.crypto import tail as crypto_tail_mod
    from umbra.crypto.providers.evm_rpc import EvmRpc

    settings = get_settings()
    store = _store()
    watching = crypto_tail_mod.watch_set(store)
    if not watching:
        rprint("[yellow]nothing to watch[/yellow] — sync labels first "
               "(`umbra crypto labels sync`)")
        raise typer.Exit(code=2)

    from umbra.db.repository import Repository
    from umbra.db.schema import get_session, init_db

    init_db(settings)
    repo = Repository(get_session(), settings.raw_dir)
    try:
        with GuardedClient(timeout=max(60.0, settings.request_timeout_s),
                           headers={"User-Agent": settings.user_agent}) as http:
            stats = crypto_tail_mod.tick(store, EvmRpc(http), blocks=blocks,
                                         watch=watching, repo=repo)
    finally:
        repo.session.close()

    rprint(f"[green]tail[/green] head={stats['head']} blocks={stats['blocks']} "
           f"logs={stats['logs']} kept={stats['kept']} stored={stats['stored']} "
           f"alerted={stats['alerted']} watching={len(watching):,}")
    if stats["note"]:
        rprint(f"[dim]{stats['note']}[/dim]")


@crypto_app.command("activity")
def crypto_activity(
    address: str = typer.Argument("", help="Filter to one address"),
    limit: int = typer.Option(20, "--limit", "-n"),
) -> None:
    """Transfers the head-follower has recorded for watched addresses."""
    store = _store()
    stats = store.crypto_transfer_stats()
    if not stats["transfers"]:
        rprint("[yellow]nothing recorded yet[/yellow] — the index is "
               "tail-forward and starts empty. It answers "
               "\"has this moved since we started watching\", never "
               "\"what did it do in 2022\".")
        for chain, cp in stats["checkpoints"].items():
            rprint(f"[dim]  {chain}: following from block {cp['last_block']:,}"
                   f" (updated {cp['updated_at'][:19]})[/dim]")
        return

    rows = (store.crypto_transfers_for("eth", address, limit=limit) if address
            else store.crypto_recent_transfers(limit=limit))
    table = Table(title=f"{len(rows)} recorded transfer(s) of "
                        f"{stats['transfers']:,} indexed")
    for col in ("block", "from", "to", "amount", "asset"):
        table.add_column(col)
    for row in rows:
        decimals = row.get("decimals") or 0
        amount = int(row["amount_raw"]) / (10 ** decimals) if decimals else row["amount_raw"]
        table.add_row(str(row["block_number"]), row["from_addr"][:16] + "…",
                      row["to_addr"][:16] + "…",
                      f"{amount:,.6f}".rstrip("0").rstrip("."), row["asset"])
    rprint(table)
