"""Tests for report output modules."""

from __future__ import annotations

import json
from pathlib import Path

from flaw.models import (
    DockerfileIssue,
    EnrichedVulnerability,
    ReportSummary,
    ScanReport,
)
from flaw.report.json_fmt import write_lint_report, write_scan_report
from flaw.report.sarif_fmt import write_lint_sarif_report, write_scan_sarif_report
from flaw.report.terminal import print_lint_report, print_scan_report


def _make_report(
    *,
    num_vulns: int = 2,
    critical: int = 1,
    with_issues: bool = False,
) -> ScanReport:
    """Create a test scan report."""
    vulns = []
    for i in range(num_vulns):
        vulns.append(
            EnrichedVulnerability(
                cve_id=f"CVE-2024-{i:04d}",
                pkg_name=f"pkg-{i}",
                installed_version="1.0.0",
                severity="CRITICAL" if i < critical else "HIGH",
                cvss=7.5 + i * 0.5,
                epss=0.5 - i * 0.1,
                in_kev=i == 0,
                has_exploit=i == 0,
                risk_score=90.0 - i * 10,
            )
        )

    issues = []
    if with_issues:
        issues = [
            DockerfileIssue(
                id="DF-001",
                severity="HIGH",
                description="No USER directive — container runs as root",
                line=1,
            ),
        ]

    return ScanReport(
        image="nginx:1.24",
        scan_time="2024-02-23T15:30:00Z",
        duration_seconds=5.3,
        runtime="docker",
        summary=ReportSummary(
            total=num_vulns,
            critical=critical,
            high=num_vulns - critical,
            max_risk_score=90.0,
            kev_count=1,
            exploit_count=1,
        ),
        vulnerabilities=vulns,
        dockerfile_issues=issues,
    )


class TestTerminalReport:
    """Tests for Rich terminal output (smoke tests — no crash)."""

    def test_print_scan_report(self) -> None:
        report = _make_report()
        print_scan_report(report)

    def test_print_scan_report_with_top(self) -> None:
        report = _make_report(num_vulns=5, critical=2)
        print_scan_report(report, top=3)

    def test_print_scan_report_no_vulns(self) -> None:
        report = _make_report(num_vulns=0, critical=0)
        print_scan_report(report)

    def test_print_scan_report_with_dockerfile_issues(self) -> None:
        report = _make_report(with_issues=True)
        print_scan_report(report)

    def test_print_lint_report(self) -> None:
        issues = [
            DockerfileIssue(
                id="DF-001",
                severity="HIGH",
                description="No USER directive",
            ),
        ]
        print_lint_report(issues, "./Dockerfile")

    def test_print_lint_report_empty(self) -> None:
        print_lint_report([], "./Dockerfile")


class TestJSONReport:
    """Tests for JSON report output."""

    def test_write_scan_report_to_file(self, tmp_path: Path) -> None:
        report = _make_report()
        out = tmp_path / "report.json"

        write_scan_report(report, output=out)

        data = json.loads(out.read_text())
        assert data["image"] == "nginx:1.24"
        assert data["summary"]["total"] == 2
        assert len(data["vulnerabilities"]) == 2

    def test_write_scan_report_to_stdout(self, capsys: object) -> None:
        report = _make_report()
        write_scan_report(report)

        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert data["image"] == "nginx:1.24"

    def test_write_lint_report_to_file(self, tmp_path: Path) -> None:
        issues = [
            DockerfileIssue(
                id="DF-001",
                severity="HIGH",
                description="No USER directive",
            ),
        ]
        out = tmp_path / "lint.json"

        write_lint_report(issues, "./Dockerfile", output=out)

        data = json.loads(out.read_text())
        assert data["dockerfile"] == "./Dockerfile"
        assert data["total_issues"] == 1
        assert len(data["issues"]) == 1

    def test_write_lint_report_to_stdout(self, capsys: object) -> None:
        issues = [
            DockerfileIssue(
                id="DF-001",
                severity="HIGH",
                description="No USER directive",
            ),
        ]
        write_lint_report(issues, "./Dockerfile")

        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert data["total_issues"] == 1

    def test_json_report_includes_dockerfile_issues(self, tmp_path: Path) -> None:
        report = _make_report(with_issues=True)
        out = tmp_path / "report.json"

        write_scan_report(report, output=out)

        data = json.loads(out.read_text())
        assert len(data["dockerfile_issues"]) == 1
        assert data["dockerfile_issues"][0]["id"] == "DF-001"


class TestSARIFReport:
    """Tests for SARIF report output."""

    def test_write_scan_sarif_report_to_file(self, tmp_path: Path) -> None:
        report = _make_report(with_issues=True)
        out = tmp_path / "report.sarif"

        write_scan_sarif_report(report, output=out)

        data = json.loads(out.read_text())
        assert data["$schema"].endswith("sarif-2.1.0.json")
        assert data["version"] == "2.1.0"

        runs = data["runs"]
        assert len(runs) == 1
        assert runs[0]["tool"]["driver"]["name"] == "flaw"

        # We have 2 vulns + 1 dockerfile issue = 3 results
        assert len(runs[0]["results"]) == 3
        # And 3 distinct rules
        assert len(runs[0]["tool"]["driver"]["rules"]) == 3

    def test_write_scan_sarif_report_to_stdout(self, capsys: object) -> None:
        report = _make_report()
        write_scan_sarif_report(report)

        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert data["version"] == "2.1.0"

    def test_write_lint_sarif_report_to_file(self, tmp_path: Path) -> None:
        issues = [
            DockerfileIssue(
                id="DF-001",
                severity="HIGH",
                description="No USER directive",
                line=5,
            ),
        ]
        out = tmp_path / "lint.sarif"

        write_lint_sarif_report(issues, "Dockerfile", output=out)

        data = json.loads(out.read_text())
        runs = data["runs"]
        assert len(runs[0]["results"]) == 1
        assert runs[0]["results"][0]["ruleId"] == "DF-001"
        assert runs[0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 5

    def test_write_lint_sarif_report_to_stdout(self, capsys: object) -> None:
        issues = [
            DockerfileIssue(
                id="DF-001",
                severity="HIGH",
                description="No USER directive",
            ),
        ]
        write_lint_sarif_report(issues, "Dockerfile")

        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert len(data["runs"][0]["results"]) == 1
