"""Flaw CLI — entry point."""

from __future__ import annotations

import logging
from typing import Annotated

import typer

from flaw import __version__
from flaw.commands.cache import cache_app
from flaw.commands.lint import lint_command
from flaw.commands.scan import scan_command
from flaw.core.config import RuntimeFlags
from flaw.core.logging import setup_logging
from flaw.core.state import set_flags

logger = logging.getLogger("flaw")

app = typer.Typer(
    name="flaw",
    help="Flaw: Intelligent vulnerability scanner for container environments.",
    no_args_is_help=True,
    add_completion=False,
)

app.add_typer(cache_app, name="cache")
app.command(name="scan")(scan_command)
app.command(name="lint")(lint_command)


def _version_callback(value: bool) -> None:
    if value:
        print(f"flaw {__version__}")  # noqa: T201
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Display the flaw version.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed output with timings")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress all output except errors")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Disable network access, use cached data only")
    ] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Force refresh cached data")] = False,
) -> None:
    """Flaw: Intelligent vulnerability scanner for container environments."""
    flags = RuntimeFlags(
        offline=offline,
        no_cache=no_cache,
        verbose=verbose,
        quiet=quiet,
    )
    set_flags(flags)
    setup_logging(verbose=verbose, quiet=quiet)
