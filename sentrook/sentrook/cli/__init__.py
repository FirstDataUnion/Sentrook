"""Sentrook CLI — root app assembly.

Commands live in per-sub-app modules (`scan`, `replay`, `shadow`, `library`);
shared option handling is in `common`. The console script entry point is
`sentrook.cli:app`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from sentrook import __version__
from sentrook.cli.library import library_app
from sentrook.cli.replay import replay_app
from sentrook.cli.scan import scan_cmd
from sentrook.cli.shadow import shadow_app

app = typer.Typer(
    name="sentrook",
    help="Sentrook — local agent trajectory security scanner (prototype).",
    no_args_is_help=True,
)
app.command("scan")(scan_cmd)
app.add_typer(replay_app, name="replay")
app.add_typer(shadow_app, name="shadow")
app.add_typer(library_app, name="library")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def sentrook_root(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show Sentrook version and exit",
        ),
    ] = None,
) -> None:
    """Sentrook CLI."""


if __name__ == "__main__":
    app()
