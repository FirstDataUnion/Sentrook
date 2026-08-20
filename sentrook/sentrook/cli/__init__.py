"""Sentrook CLI — root app assembly.

Commands live in per-sub-app modules (`scan`, `replay`, `serve`, `library`,
`review_copy`); shared option handling is in `common`. The console script
entry point is `sentrook.cli:app`.
"""

from __future__ import annotations

from typing import Annotated

import typer

from sentrook import __version__
from sentrook.cli.library import library_app
from sentrook.cli.replay import replay_app
from sentrook.cli.review_copy import review_copy_app
from sentrook.cli.scan import scan_cmd
from sentrook.cli.serve import analyze_cmd, harvest_submit_cmd, serve_app, verify_cmd

app = typer.Typer(
    name="sentrook",
    help="Sentrook — local agent trajectory security scanner.",
    no_args_is_help=True,
)
app.command("scan")(scan_cmd)
app.add_typer(serve_app, name="serve")
app.command("analyze")(analyze_cmd)
app.command("verify")(verify_cmd)
app.command("harvest-submit")(harvest_submit_cmd)
app.add_typer(replay_app, name="replay")
app.add_typer(library_app, name="library")
app.add_typer(review_copy_app, name="review-copy")


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
