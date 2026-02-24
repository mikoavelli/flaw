"""Implementation of the `flaw scan` command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from flaw.pipeline import run_scan
from flaw.report.json_fmt import write_scan_report
from flaw.report.terminal import print_scan_report, stderr
from flaw.scanner.trivy import ScannerError

scan_app = typer.Typer(name="scan", help="Scan a container image for vulnerabilities.")


@scan_app.callback(invoke_without_command=True)
def scan(
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
    no_enrich: Annotated[
        bool, typer.Option("--no-enrich", help="Skip EPSS/KEV enrichment")
    ] = False,
    dockerfile: Annotated[
        Path | None,
        typer.Option("--dockerfile", "-d", help="Also analyze a Dockerfile alongside the image"),
    ] = None,
) -> None:
    """Scan a container image for vulnerabilities and prioritize risks."""
    try:
        report = run_scan(image, skip_enrich=no_enrich, dockerfile=dockerfile)
    except ScannerError as e:
        stderr.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    # Output
    if format_ == "json":
        write_scan_report(report, output=output)
    else:
        print_scan_report(report, top=top)
        if output is not None:
            write_scan_report(report, output=output)

    # Threshold check
    if threshold is not None and report.summary.max_risk_score > threshold:
        stderr.print(
            f"\n[bold red]FAIL:[/bold red] Max risk score {report.summary.max_risk_score}"
            f" exceeds threshold {threshold}"
        )
        raise typer.Exit(code=1)
