"""JSON report output to stdout or file."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rich.console import Console

from flaw.models import DockerfileIssue, ScanReport

stderr = Console(stderr=True)


def write_scan_report(
    report: ScanReport,
    *,
    output: Path | None = None,
) -> None:
    """
    Write scan report as JSON.

    If output is given, writes to file and prints confirmation to stderr.
    Otherwise writes to stdout.
    """
    data = report.model_dump(mode="json")
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output is not None:
        output.write_text(json_str, encoding="utf-8")
        stderr.print(f"Report saved to [bold]{output}[/bold]")
    else:
        sys.stdout.write(json_str + "\n")


def write_lint_report(
    issues: list[DockerfileIssue],
    path: str,
    *,
    output: Path | None = None,
) -> None:
    """
    Write lint report as JSON.

    If output is given, writes to file.
    Otherwise writes to stdout.
    """
    data = {
        "dockerfile": path,
        "total_issues": len(issues),
        "issues": [issue.model_dump(mode="json") for issue in issues],
    }
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output is not None:
        output.write_text(json_str, encoding="utf-8")
        stderr.print(f"Report saved to [bold]{output}[/bold]")
    else:
        sys.stdout.write(json_str + "\n")
