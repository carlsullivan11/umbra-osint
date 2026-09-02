from __future__ import annotations

from pathlib import Path

import typer
from rich import print as rprint
from rich.table import Table
from typer.core import TyperGroup

from umbra import __version__
from umbra.collectors.base import default_registry
from umbra.cli.breach import breach_app
from umbra.cli.case_cmd import (
    audit_cmd,
    case_app,
    entities_cmd,
    graph_cmd,
    profile_cmd,
    run_case,
    score_cmd,
)
from umbra.cli.abuse_cmd import abuse_app
from umbra.cli.crypto_cmd import crypto_app
from umbra.cli.phone_cmd import phone_app
from umbra.cli.ct_cmd import ct_app
from umbra.cli.entity_watch import entity_app, watch_app
from umbra.cli.exposure_cmd import exposure_monitor
from umbra.cli.intent_cmd import intent_command
from umbra.cli.onboarding import doctor_command, init_command
from umbra.cli.playbook_cmd import playbook_app
from umbra.cli.reputation_seed import seed_reputation
from umbra.cli.ui_cmd import ui_command
from umbra.cli.wiki_cmd import lookup_command, wiki_app
from umbra.cli.mac_cmd import mac_app
from umbra.cli.epss_cmd import epss_app
from umbra.cli.psl_cmd import psl_app
from umbra.cli.records_cmd import records_app
from umbra.cli.social_cmd import social_app
from umbra.cli.tor_cmd import tor_app
from umbra.cli.scan_cmd import scan_app
from umbra.cli.geoip_cmd import geoip_app
from umbra.cli.people_cmd import people_app
from umbra.cli.rf_cmd import rf_app
from umbra.cli.feed_cmd import feed_app
from umbra.cli.file_cmd import email_command, file_command
from umbra.cli.ops_cmd import ops_app
from umbra.cli.sentinel_cmd import sentinel_app


class _PathAwareGroup(TyperGroup):
    """Let `umbra example.email` work, the way Carl asked for it.

    A first argument that is not a command name but *is* an existing file gets
    routed to `umbra file`, which sniffs the type and reads it. Real commands
    always win — a file called `doctor` in the working directory does not
    shadow `umbra doctor` — and an unknown word that is not a file still gets
    Click's ordinary "no such command" error rather than a confusing one about
    a missing path.
    """

    def resolve_command(self, ctx, args):
        name = args[0] if args else None
        if (name and not name.startswith("-")
                and self.get_command(ctx, name) is None):
            try:
                is_file = Path(name).expanduser().is_file()
            except (OSError, ValueError):
                is_file = False
            if is_file:
                # `args` rather than `args[1:]`, so the path stays in place as
                # the PATH argument of the command being handed the work.
                return "file", self.get_command(ctx, "file"), args
        return super().resolve_command(ctx, args)


app = typer.Typer(
    name="umbra",
    help="Umbra — graph-first local OSINT for authorized investigations.",
    no_args_is_help=True,
    cls=_PathAwareGroup,
)


def _version_callback(value: bool) -> None:
    """`umbra --version`.

    Every other surface could answer this and the CLI could not: `pip show
    umbra-osint` gave one number, `GET /health` another, and `umbra --version`
    was an error. All three now read umbra.__version__, which reads the
    installed package metadata.
    """
    if value:
        rprint(f"umbra {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", "-V", callback=_version_callback, is_eager=True,
        help="Show the installed Umbra version and exit.",
    ),
) -> None:
    """Umbra — graph-first local OSINT for authorized investigations."""


app.add_typer(case_app, name="case")
app.add_typer(breach_app, name="breach")
app.add_typer(entity_app, name="entity")
app.add_typer(watch_app, name="watch")
app.add_typer(ct_app, name="ct")
app.add_typer(abuse_app, name="abuse")
app.add_typer(phone_app, name="phone")
app.add_typer(crypto_app, name="crypto")
app.add_typer(playbook_app, name="playbook")
app.add_typer(wiki_app, name="wiki")
app.add_typer(mac_app, name="mac")
app.add_typer(geoip_app, name="geoip")
app.add_typer(epss_app, name="epss")
app.add_typer(psl_app, name="psl")
app.add_typer(scan_app, name="scan")
app.add_typer(records_app, name="records")
app.add_typer(social_app, name="social")
app.add_typer(tor_app, name="tor")
app.add_typer(people_app, name="people")
app.add_typer(rf_app, name="rf")
app.add_typer(feed_app, name="feed")
app.add_typer(ops_app, name="ops")
app.add_typer(sentinel_app, name="sentinel")
app.command("init")(init_command)
app.command("doctor")(doctor_command)
app.command("intent")(intent_command)
app.command("email")(email_command)
app.command("file")(file_command)
app.command("lookup")(lookup_command)
app.command("ui")(ui_command)
app.command("exposure-monitor")(exposure_monitor)
app.command("reputation-seed")(seed_reputation)
app.command("run")(run_case)
app.command("score")(score_cmd)
app.command("profile")(profile_cmd)
app.command("entities")(entities_cmd)
app.command("graph")(graph_cmd)
app.command("audit")(audit_cmd)


@app.command("collectors")
def collectors_cmd() -> None:
    """List every registered collector (name, accepted entity types, description)."""
    reg = default_registry()
    table = Table(title=f"Collectors ({len(reg.list())})")
    for col in ("name", "inputs", "description"):
        table.add_column(col)
    for c in reg.list():
        inputs = ", ".join(sorted(e.value for e in c.inputs)) if c.inputs else "-"
        table.add_row(c.name, inputs, c.description)
    rprint(table)
