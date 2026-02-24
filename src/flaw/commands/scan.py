"""Implementation of the `flaw scan` command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from flaw.core.config import load_settings
from flaw.core.state import get_flags
from flaw.models import ScanReport
from flaw.pipeline import run_scan
from flaw.report.json_fmt import write_scan_report
from flaw.report.terminal import print_scan_report, stderr
from flaw.scanner.trivy import ScannerError


def _apply_top(report: ScanReport, top: int | None) -> ScanReport:
    """Return a copy of the report with only top N vulnerabilities."""
    if top is None or top >= len(report.vulnerabilities):
        return report
    return report.model_copy(update={"vulnerabilities": report.vulnerabilities[:top]})


def scan_command(
    image: Annotated[str, typer.Argument(help="Container image to scan (e.g., nginx:1.24)")],
    format_: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write JSON report to file")
    ] = None,
    threshold: Annotated[
        float | None,
        typer.Option("--threshold", "-t", help="Exit code 1 if any CVE risk exceeds this score"),
    ] = None,
    top: Annotated[
        int | None, typer.Option("--top", help="Show only top N vulnerabilities")
    ] = None,
    dockerfile: Annotated[
        Path | None,
        typer.Option("--dockerfile", "-d", help="Also analyze a Dockerfile alongside the image"),
    ] = None,
) -> None:
    """Scan a container image for vulnerabilities and prioritize risks."""
    flags = get_flags()
    settings = load_settings(flags=flags)

    try:
        full_report = run_scan(
            image,
            dockerfile=dockerfile,
            settings=settings,
        )
    except ScannerError as e:
        if not flags.quiet:
            stderr.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    threshold_exceeded = threshold is not None and full_report.summary.max_risk_score > threshold

    report = _apply_top(full_report, top)

    if format_ == "json":
        write_scan_report(report, output=output)
    else:
        if not flags.quiet:
            print_scan_report(report)
        if output is not None:
            write_scan_report(report, output=output)

    if threshold_exceeded:
        if not flags.quiet:
            stderr.print(
                f"\n[bold red]FAIL:[/bold red] Max risk score"
                f" {full_report.summary.max_risk_score} exceeds threshold {threshold}"
            )
        raise typer.Exit(code=1)
