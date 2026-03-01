"""Implementation of the `flaw clean` command."""

from __future__ import annotations

import shutil
from typing import Annotated

import typer

from flaw.core.paths import BIN_DIR, CACHE_DIR, MODELS_DIR
from flaw.intelligence.db import DB_PATH, clear_all, get_connection
from flaw.report.terminal import stderr


def clean_command(
    all: Annotated[bool, typer.Option("--all", help="Clean everything (cache, model, trivy)")] = False,
    cache: Annotated[bool, typer.Option("--cache", help="Clean vulnerability databases")] = False,
    model: Annotated[bool, typer.Option("--model", help="Clean ML models")] = False,
    trivy: Annotated[bool, typer.Option("--trivy", help="Clean local Trivy binary")] = False,
) -> None:
    """Remove downloaded data (cache, models, binaries)."""

    if not any([all, cache, model, trivy]):
        cache = True

    if all or cache:
        if DB_PATH.exists():
            conn = get_connection()
            try:
                clear_all(conn)
            finally:
                conn.close()
            DB_PATH.unlink()
            stderr.print("[green]✓ Cache databases cleared.[/green]")

        if CACHE_DIR.exists():
            shutil.rmtree(CACHE_DIR)
            CACHE_DIR.mkdir()

    if all or model:
        if MODELS_DIR.exists():
            shutil.rmtree(MODELS_DIR)
            MODELS_DIR.mkdir()
            stderr.print("[green]✓ ML models cleared.[/green]")

    if all or trivy:
        if BIN_DIR.exists():
            shutil.rmtree(BIN_DIR)
            BIN_DIR.mkdir()
            stderr.print("[green]✓ Local Trivy binaries cleared.[/green]")

    if not any([all, cache, model, trivy]) and not DB_PATH.exists():
        stderr.print("[yellow]Nothing to clean.[/yellow]")
