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
    """Write scan report as JSON."""
    data = report.model_dump(mode="json", exclude_none=True)
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output is not None:
        output.write_text(json_str, encoding="utf-8")
    else:
        sys.stdout.write(json_str + "\n")


def write_lint_report(
    issues: list[DockerfileIssue],
    path: str,
    *,
    output: Path | None = None,
) -> None:
    """Write lint report as JSON."""
    data = {
        "dockerfile": path,
        "total_issues": len(issues),
        "issues": [issue.model_dump(mode="json") for issue in issues],
    }
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output is not None:
        output.write_text(json_str, encoding="utf-8")
    else:
        sys.stdout.write(json_str + "\n")
