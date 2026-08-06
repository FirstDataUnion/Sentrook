from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sentrook import __version__ as sentrook_version
from sentrook.corpus.loader import default_corpus_dir
from sentrook.rules.loader import resolve_rules_dir
from testnest import __version__ as testnest_version
from testnest.loader import filter_scenarios, load_scenarios, load_suites
from testnest.report import format_json_report, format_text_report, write_junit
from testnest.runner import run_suite

PKG_DIR = Path(__file__).resolve().parent


def _default_scenarios_dir() -> Path:
    for base in (PKG_DIR.parent, PKG_DIR.parent.parent):
        candidate = base / "fixtures" / "scenarios"
        if candidate.is_dir():
            return candidate
    return PKG_DIR.parent / "fixtures" / "scenarios"


app = typer.Typer(
    name="testnest",
    help="TestNest — scenario test harness for Sentrook.",
    invoke_without_command=True,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"testnest {testnest_version} (sentrook {sentrook_version})")
        raise typer.Exit()


@app.callback()
def testnest_root(
    ctx: typer.Context,
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show TestNest and Sentrook versions and exit",
        ),
    ] = None,
) -> None:
    if ctx.invoked_subcommand is None:
        ctx.invoke(testnest_run)


@app.command("run")
def testnest_run(
    suite: Annotated[
        str,
        typer.Option("--suite", "-s", help="Scenario suite name from suites.yaml"),
    ] = "smoke",
    profile: Annotated[
        str,
        typer.Option(
            "--profile",
            "-p",
            help="Expectation profile (v0, l3_primary, l3_heavy)",
        ),
    ] = "v0",
    scenarios: Annotated[
        Path | None,
        typer.Option("--scenarios", help="Scenario definitions directory"),
    ] = None,
    rules: Annotated[
        Path | None,
        typer.Option("--rules", help="YAIRA rules directory"),
    ] = None,
    corpus: Annotated[
        Path | None,
        typer.Option("--corpus", help="Layer 3 corpus directory (default repo corpus/)"),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t", help="Filter scenarios by tag (repeatable)"),
    ] = None,
    format: Annotated[
        str,
        typer.Option("--format", help="Report format: text, json"),
    ] = "text",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    junit: Annotated[
        Path | None,
        typer.Option("--junit", help="Write JUnit XML report to path"),
    ] = None,
) -> None:
    """Run a TestNest scenario suite against Sentrook."""
    scenarios = scenarios or _default_scenarios_dir()
    rules = rules or resolve_rules_dir()
    corpus = corpus or default_corpus_dir()
    if not scenarios.is_dir():
        typer.echo(f"scenarios directory not found: {scenarios}", err=True)
        raise typer.Exit(code=1)
    if not rules.exists():
        typer.echo(f"rules path not found: {rules}", err=True)
        raise typer.Exit(code=1)

    try:
        report = run_suite(
            scenarios_dir=scenarios,
            rules_dir=rules,
            profile=profile,
            suite=suite if not tag else None,
            tags=tag,
            corpus_dir=corpus,
        )
    except (ValueError, RuntimeError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    if format == "json":
        typer.echo(format_json_report(report))
    else:
        typer.echo(format_text_report(report, verbose=verbose))

    if junit is not None:
        write_junit(report, junit)

    raise typer.Exit(code=0 if report.ok else 1)


@app.command("list")
def testnest_list(
    scenarios: Annotated[Path | None, typer.Option("--scenarios")] = None,
    suite: Annotated[str | None, typer.Option("--suite", "-s")] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t"),
    ] = None,
) -> None:
    """List TestNest scenarios and defined profiles."""
    scenarios = scenarios or _default_scenarios_dir()
    if not scenarios.is_dir():
        typer.echo(f"scenarios directory not found: {scenarios}", err=True)
        raise typer.Exit(code=1)

    loaded = load_scenarios(scenarios)
    suites = load_suites(scenarios)
    try:
        selected = filter_scenarios(loaded, suite=suite, tags=tag, suites=suites)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    for scenario in selected:
        profiles = ", ".join(sorted(scenario.profiles))
        tags = ",".join(scenario.tags) if scenario.tags else "-"
        typer.echo(f"{scenario.name}\t[{tags}]\tprofiles={profiles}")
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
