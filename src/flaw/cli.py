"""Flaw CLI — entry point."""

from __future__ import annotations

from typing import Annotated

import typer

from flaw import __version__
from flaw.commands.cache import cache_app
from flaw.commands.lint import lint_app
from flaw.commands.scan import scan_app
from flaw.core.config import RuntimeFlags
from flaw.core.logging import setup_logging
from flaw.core.state import set_flags

app = typer.Typer(
    name="flaw",
    help="Flaw: Intelligent vulnerability scanner for container environments.",
    no_args_is_help=True,
    add_completion=False,
)

app.add_typer(scan_app)
app.add_typer(lint_app)
app.add_typer(cache_app)


@app.callback()
def main(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed output with timings")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", "-q", help="Suppress all output except errors")
    ] = False,
    offline: Annotated[
        bool, typer.Option("--offline", help="Disable network access, use cached data only")
    ] = False,
    no_cache: Annotated[
        bool, typer.Option("--no-cache", help="Skip reading/writing cache")
    ] = False,
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


@app.command()
def version() -> None:
    """Display the flaw version."""
    print(f"flaw {__version__}")  # noqa: T201
