"""Implementation of the `flaw cache` command group."""

from __future__ import annotations

import time

import typer
from rich.table import Table

from flaw.core.paths import CACHE_DIR, DATA_DIR, ensure_dirs
from flaw.core.state import get_flags
from flaw.intelligence import epss, kev
from flaw.intelligence.db import (
    DB_PATH,
    clear_all,
    get_connection,
    get_entry_count,
    get_last_update,
)
from flaw.report.terminal import stderr

cache_app = typer.Typer(help="Manage local vulnerability databases.")


@cache_app.command()
def update() -> None:
    """Download or refresh EPSS and KEV databases."""
    flags = get_flags()

    if flags.offline:
        stderr.print("[yellow]Cannot update in offline mode.[/yellow]")
        raise typer.Exit(code=2)

    ensure_dirs()
    conn = get_connection()

    try:
        stderr.print("Updating EPSS database...", end=" ")
        try:
            count = epss.update(conn, CACHE_DIR)
            stderr.print(f"[green]done[/green] ({count:,} entries)")
        except epss.EPSSError as e:
            stderr.print(f"[red]failed[/red] ({e})")

        stderr.print("Updating KEV catalog...", end="  ")
        try:
            count = kev.update(conn, CACHE_DIR)
            stderr.print(f"[green]done[/green] ({count:,} entries)")
        except kev.KEVError as e:
            stderr.print(f"[red]failed[/red] ({e})")
    finally:
        conn.close()


@cache_app.command()
def status() -> None:
    """Show cache age, size, and entry counts."""
    ensure_dirs()

    if not DB_PATH.exists():
        stderr.print("[yellow]No cache database found. Run `flaw cache update`.[/yellow]")
        raise typer.Exit(code=1)

    conn = get_connection()

    try:
        table = Table(show_header=True, header_style="bold", box=None)
        table.add_column("Database", min_width=10)
        table.add_column("Entries", justify="right", min_width=8)
        table.add_column("Age", min_width=10)
        table.add_column("Status", min_width=8)

        for source, tbl_name in [("epss", "epss_scores"), ("kev", "kev_entries")]:
            count = get_entry_count(conn, tbl_name)
            last = get_last_update(conn, source)

            if last == 0.0:
                age_str = "never"
                status_str = "[red]✗ Empty[/red]"
            else:
                age_hours = (time.time() - last) / 3600
                if age_hours < 1:
                    age_str = f"{int(age_hours * 60)}m"
                else:
                    age_str = f"{age_hours:.0f}h"
                status_str = (
                    "[green]✓ Fresh[/green]" if age_hours < 24 else "[yellow]⚠ Stale[/yellow]"
                )

            table.add_row(source.upper(), f"{count:,}", age_str, status_str)

        stderr.print(f"\nCache directory: [bold]{DATA_DIR}[/bold]\n")
        stderr.print(table)

        if DB_PATH.exists():
            size_mb = DB_PATH.stat().st_size / (1024 * 1024)
            stderr.print(f"\nTotal: {size_mb:.1f} MB\n")
    finally:
        conn.close()


@cache_app.command()
def clean() -> None:
    """Remove all cached data."""
    if DB_PATH.exists():
        conn = get_connection()
        try:
            clear_all(conn)
        finally:
            conn.close()
        DB_PATH.unlink()
        stderr.print("[green]Cache cleared.[/green]")
    else:
        stderr.print("[yellow]No cache to clear.[/yellow]")


@cache_app.command(name="dir")
def cache_dir() -> None:
    """Print the cache directory path."""
    print(DATA_DIR)  # noqa: T201
