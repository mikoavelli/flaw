"""Implementation of the `flaw lint` command."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from flaw.report.json_fmt import write_lint_report
from flaw.report.terminal import print_lint_report, stderr
from flaw.scanner.dockerfile import DockerfileLintError, lint

lint_app = typer.Typer(name="lint", help="Analyze a Dockerfile for security misconfigurations.")


@lint_app.callback(invoke_without_command=True)
def lint_command(
    path: Annotated[Path, typer.Argument(help="Path to Dockerfile")] = Path("Dockerfile"),
    format_: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "table",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write JSON report to file")
    ] = None,
    ci: Annotated[
        bool, typer.Option("--ci", help="Exit code 1 if any HIGH severity issue found")
    ] = False,
) -> None:
    """Lint a Dockerfile for security misconfigurations."""
    try:
        issues = lint(path)
    except DockerfileLintError as e:
        stderr.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=2) from e

    path_str = str(path)

    if format_ == "json":
        write_lint_report(issues, path_str, output=output)
    else:
        print_lint_report(issues, path_str)
        if output is not None:
            write_lint_report(issues, path_str, output=output)

    if ci:
        high_issues = [i for i in issues if i.severity == "HIGH"]
        if high_issues:
            stderr.print(
                f"\n[bold red]FAIL:[/bold red] {len(high_issues)} HIGH severity issue(s) found"
            )
            raise typer.Exit(code=1)
