"""CLI: umbra ui — launch basic web interface."""

from __future__ import annotations

import typer
from rich import print as rprint


def ui_command(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="Bind host"),
    port: int = typer.Option(8787, "--port", "-p", help="Bind port"),
    reload: bool = typer.Option(False, "--reload", help="Dev auto-reload"),
) -> None:
    """Start the Umbra web UI (search, reputation, people, crypto, wiki)."""
    try:
        import uvicorn  # noqa: F401  (checked here so the error is about the UI)

        import umbra.web  # noqa: F401
    except ImportError as exc:
        # Two ways to get here, one message. Note what it does *not* say: the
        # web package is excluded from the published distribution entirely
        # (docs/OPEN-CORE.md), so telling a pip user to install the [web] extra
        # would be advice that cannot work — the extra brings the server stack,
        # not the application.
        #
        # It used to end "from a checkout of the source, install the web extra
        # and this works as before", which was true of the private tree and a
        # dead end from the public one: the open-core repo does not contain the
        # web application either, so that reader follows the instruction, gets
        # the same error, and concludes their install is broken.
        raise typer.BadParameter(
            "The web UI is not part of the umbra-osint package — the CLI is the "
            "open core, and the hosted web application is a separate private "
            "codebase. Umbra on the web is at https://umbra-osint.com ."
        ) from exc

    rprint(f"[green]Umbra UI[/green] http://{host}:{port}/")
    rprint("[dim]Search · /people · /crypto · /reputation · /guide · /wiki · Ctrl+C[/dim]")
    uvicorn.run(
        "umbra.web:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )
