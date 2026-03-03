"""Implementation of the `flaw status` command."""

from __future__ import annotations

import time

from rich.table import Table

from flaw.core.paths import DATA_DIR, ensure_dirs
from flaw.intelligence.db import DB_PATH, get_connection, get_entry_count, get_last_update
from flaw.intelligence.model_manager import MODEL_PATH
from flaw.report.terminal import stderr
from flaw.scanner.installer import get_trivy_info


def _format_age(last_update: float) -> str:
    if last_update == 0.0:
        return "never"
    age_hours = (time.time() - last_update) / 3600
    if age_hours < 1:
        return f"{int(age_hours * 60)}m ago"
    return f"{age_hours:.0f}h ago"


def status_command() -> None:
    """Display the health and status of all system components."""
    ensure_dirs()
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Component", min_width=12)
    table.add_column("Status", min_width=10)
    table.add_column("Details", min_width=30)

    if DB_PATH.exists():
        conn = get_connection()
        try:
            for source, tbl_name in [("EPSS Cache", "epss_scores"), ("KEV Cache", "kev_entries")]:
                count = get_entry_count(conn, tbl_name)
                last = get_last_update(conn, source.split()[0].lower())
                age_hours = (time.time() - last) / 3600 if last > 0 else 999

                if count > 0:
                    status = "[green]Fresh[/green]" if age_hours < 24 else "[yellow]Stale[/yellow]"
                    details = f"{count:,} records ({_format_age(last)})"
                else:
                    status = "[red]Empty[/red]"
                    details = "Run `flaw update cache`"
                table.add_row(source, status, details)
        finally:
            conn.close()
    else:
        table.add_row("EPSS Cache", "[red]Missing[/red]", "Run `flaw update cache`")
        table.add_row("KEV Cache", "[red]Missing[/red]", "Run `flaw update cache`")

    if MODEL_PATH.exists():
        size_kb = MODEL_PATH.stat().st_size / 1024
        mtime = MODEL_PATH.stat().st_mtime
        table.add_row(
            "ML Model",
            "[green]Ready[/green]",
            f"XGBoost Portable | {size_kb:.0f} KB ({_format_age(mtime)})",
        )
    else:
        table.add_row(
            "ML Model", "[yellow]Missing[/yellow]", "Formula fallback. Run `flaw update model`"
        )

    trivy_path, trivy_version = get_trivy_info()
    if trivy_path:
        table.add_row("Trivy Scanner", "[green]Ready[/green]", f"{trivy_version} ({trivy_path})")
    else:
        table.add_row("Trivy Scanner", "[red]Missing[/red]", "Run `flaw update trivy`")

    stderr.print("\n[bold]System Status[/bold]")
    stderr.print(table)
    stderr.print(f"\n[dim]Data directory: {DATA_DIR}[/dim]\n")
