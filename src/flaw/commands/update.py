"""Implementation of the `flaw update` command group."""

from __future__ import annotations

import typer

from flaw.core.paths import CACHE_DIR, ensure_dirs
from flaw.core.state import get_flags
from flaw.intelligence import epss, kev
from flaw.intelligence.db import get_connection
from flaw.intelligence.model_manager import ensure_model
from flaw.report.terminal import stderr
from flaw.scanner.installer import InstallerError, ensure_trivy

update_app = typer.Typer(help="Update local databases, ML model, and scanner.")


def _do_update_cache() -> None:
    flags = get_flags()
    if flags.offline:
        stderr.print("[yellow]Cannot update cache in offline mode.[/yellow]")
        return

    ensure_dirs()
    conn = get_connection()
    try:
        stderr.print("Updating EPSS database...", end=" ")
        try:
            count = epss.update(conn, CACHE_DIR)
            stderr.print(f"[green]done[/green] ({count:,} entries)")
        except epss.EPSSError as e:
            stderr.print(f"[red]failed[/red] ({e})")

        stderr.print("Updating KEV catalog...", end="   ")
        try:
            count = kev.update(conn, CACHE_DIR)
            stderr.print(f"[green]done[/green] ({count:,} entries)")
        except kev.KEVError as e:
            stderr.print(f"[red]failed[/red] ({e})")
    finally:
        conn.close()


def _do_update_model() -> None:
    flags = get_flags()
    if flags.offline:
        stderr.print("[yellow]Cannot update ML model in offline mode.[/yellow]")
        return

    stderr.print("Updating ML Model...", end="      ")
    model_path = ensure_model(force=True, offline=False)
    if model_path:
        stderr.print(f"[green]done[/green] ({model_path.name})")
    else:
        stderr.print("[red]failed[/red]")


def _do_update_trivy() -> None:
    flags = get_flags()
    if flags.offline:
        stderr.print("[yellow]Cannot update Trivy in offline mode.[/yellow]")
        return

    stderr.print("Checking Trivy Engine...", end="  ")
    try:
        bin_path = ensure_trivy(offline=False, force=True)
        stderr.print(f"[green]done[/green] ({bin_path})")
    except InstallerError as e:
        stderr.print(f"[red]failed[/red]\n[dim]{e}[/dim]")


@update_app.command("cache")
def update_cache() -> None:
    """Download or refresh EPSS and KEV databases."""
    _do_update_cache()

@update_app.command("model")
def update_model() -> None:
    """Download the latest Context-Aware ML Model."""
    _do_update_model()

@update_app.command("trivy")
def update_trivy() -> None:
    """Download or update the Trivy scanning engine."""
    _do_update_trivy()

@update_app.command("all")
def update_all() -> None:
    """Update cache, ML model, and Trivy all at once."""
    _do_update_cache()
    _do_update_model()
    _do_update_trivy()
    stderr.print("\n[bold green]All components are up to date![/bold green]")
