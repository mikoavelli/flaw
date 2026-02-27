"""Implementation of the `flaw lint` command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from flaw.core.state import get_flags
from flaw.report.json_fmt import write_lint_report
from flaw.report.sarif_fmt import write_lint_sarif_report
from flaw.report.terminal import print_lint_report, stderr
from flaw.scanner.dockerfile import DockerfileLintError, lint


def lint_command(
    path: Annotated[Path, typer.Argument(help="Path to Dockerfile")] = Path("Dockerfile"),
    format_: Annotated[
        str, typer.Option("--format", "-f", help="Output format: table, json, sarif")
    ] = "table",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write JSON/SARIF report to file")
    ] = None,
    ci: Annotated[
        bool, typer.Option("--ci", help="Exit code 1 if any HIGH severity issue found")
    ] = False,
) -> None:
    """Analyze a Dockerfile for security misconfigurations."""
    flags = get_flags()

    try:
        issues = lint(path)
    except DockerfileLintError as e:
        if not flags.quiet:
            stderr.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    path_str = str(path)

    if format_ == "json":
        write_lint_report(issues, path_str, output=output)
    elif format_ == "sarif":
        write_lint_sarif_report(issues, path_str, output=output)
    else:
        if not flags.quiet:
            print_lint_report(issues, path_str)
        if output is not None:
            write_lint_report(issues, path_str, output=output)

    if ci:
        high_issues = [i for i in issues if i.severity == "HIGH"]
        if high_issues:
            if not flags.quiet:
                stderr.print(
                    f"\n[bold red]FAIL:[/bold red] {len(high_issues)} HIGH severity issue(s) found"
                )
            raise typer.Exit(code=1)
