"""Flaw CLI — entry point."""

from __future__ import annotations

import typer

from flaw import __version__
from flaw.commands.cache import cache_app
from flaw.commands.scan import scan_app

app = typer.Typer(
    name="flaw",
    help="Flaw: Intelligent vulnerability scanner for container environments.",
    no_args_is_help=True,
    add_completion=False,
)

app.add_typer(scan_app)
app.add_typer(cache_app)


@app.command()
def version() -> None:
    """Display the flaw version."""
    print(f"flaw {__version__}")  # noqa: T201
