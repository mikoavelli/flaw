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

    def test_print_vuln_table_badges(self) -> None:
        from flaw.report.terminal import _print_vuln_table

        vulns = [
            EnrichedVulnerability(
                cve_id="CVE-1",
                pkg_name="a",
                installed_version="1.0",
                severity="HIGH",
                purl="pkg:npm/a",
                references=["exploit-db.com"],
            ),
            EnrichedVulnerability(
                cve_id="CVE-2",
                pkg_name="b",
                installed_version="1.0",
                severity="MEDIUM",
                purl="pkg:pypi/b",
                references=["packetstormsecurity.com"],
            ),
            EnrichedVulnerability(
                cve_id="CVE-3",
                pkg_name="c",
                installed_version="1.0",
                severity="LOW",
                purl="pkg:golang/c",
                references=["github.com/user/poc"],
            ),
            EnrichedVulnerability(
                cve_id="CVE-4",
                pkg_name="d",
                installed_version="1.0",
                severity="CRITICAL",
                purl="pkg:maven/d",
            ),
            EnrichedVulnerability(
                cve_id="CVE-5",
                pkg_name="e",
                installed_version="1.0",
                severity="HIGH",
                purl="pkg:cargo/e",
            ),
            EnrichedVulnerability(
                cve_id="CVE-6",
                pkg_name="f",
                installed_version="1.0",
                severity="HIGH",
                vex_status="fixed",
            ),
            EnrichedVulnerability(
                cve_id="CVE-7",
                pkg_name="g",
                installed_version="1.0",
                severity="HIGH",
                vex_status="not_affected",
            ),
            EnrichedVulnerability(
                cve_id="CVE-8",
                pkg_name="h",
                installed_version="1.0",
                severity="HIGH",
                vex_status="not_affected",
                vex_justification="vulnerable_code_not_in_execute_path",
            ),
        ]

        _print_vuln_table(vulns)


class TestJSONReport:
    def test_write_scan_report_to_file(self, tmp_path: Path) -> None:
        report = _make_report()
        out = tmp_path / "report.json"
        write_scan_report(report, output=out)
        data = json.loads(out.read_text())
        assert data["image"] == "nginx:1.24"

    def test_write_scan_report_to_stdout(self, capsys: object) -> None:
        report = _make_report()
        write_scan_report(report)
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert data["image"] == "nginx:1.24"

    def test_write_lint_report_to_file(self, tmp_path: Path) -> None:
        issues = [DockerfileIssue(id="DF", severity="HIGH", description="test")]
        out = tmp_path / "lint.json"
        write_lint_report(issues, "./Dockerfile", output=out)
        data = json.loads(out.read_text())
        assert data["total_issues"] == 1

    def test_write_lint_report_to_stdout(self, capsys: object) -> None:
        issues = [DockerfileIssue(id="DF", severity="HIGH", description="test")]
        write_lint_report(issues, "./Dockerfile")
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        assert json.loads(captured.out)["total_issues"] == 1


class TestSARIFReport:
    def test_write_scan_sarif_report_to_file(self, tmp_path: Path) -> None:
        report = _make_report(with_issues=True)
        out = tmp_path / "report.sarif"

        write_scan_sarif_report(report, output=out)

        data = json.loads(out.read_text())
        runs = data["runs"]
        assert len(runs[0]["results"]) == 3

    def test_write_scan_sarif_report_to_stdout(self, capsys: object) -> None:
        report = _make_report()
        write_scan_sarif_report(report)
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert data["version"] == "2.1.0"

    def test_write_scan_sarif_report_none_issues(self, capsys: object) -> None:
        report = _make_report(with_issues=False)
        report.dockerfile_issues = None
        write_scan_sarif_report(report)
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)
        assert len(data["runs"][0]["results"]) == 2

    def test_write_lint_sarif_report_to_file(self, tmp_path: Path) -> None:
        issues = [DockerfileIssue(id="DF", severity="HIGH", description="x", line=5)]
        out = tmp_path / "lint.sarif"
        write_lint_sarif_report(issues, "Dockerfile", output=out)
        data = json.loads(out.read_text())
        assert (
            data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
            == 5
        )

    def test_write_lint_sarif_report_to_stdout(self, capsys: object) -> None:
        issues = [DockerfileIssue(id="DF", severity="HIGH", description="x")]
        write_lint_sarif_report(issues, "Dockerfile")
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        assert len(json.loads(captured.out)["runs"][0]["results"]) == 1

    def test_write_scan_sarif_report_to_file_output(self, tmp_path: Path) -> None:
        report = _make_report()
        out_file = tmp_path / "output.sarif"
        write_scan_sarif_report(report, output=out_file)
        assert out_file.exists()
        assert "2.1.0" in out_file.read_text()

    def test_write_lint_sarif_report_to_file_output(self, tmp_path: Path) -> None:
        issues = [DockerfileIssue(id="DF-001", severity="HIGH", description="x")]
        out_file = tmp_path / "lint.sarif"
        write_lint_sarif_report(issues, "Dockerfile", output=out_file)
        assert out_file.exists()
        assert "DF-001" in out_file.read_text()

    def test_sarif_suppressions_for_vex(self, capsys: object) -> None:
        """Test that VEX 'not_affected' creates SARIF suppressions."""
        report = _make_report(num_vulns=1)
        report.vulnerabilities[0].vex_status = "not_affected"
        report.vulnerabilities[0].vex_justification = "vulnerable_code_not_in_execute_path"

        write_scan_sarif_report(report)
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        data = json.loads(captured.out)

        results = data["runs"][0]["results"]
        assert len(results) > 0

        suppressions = results[0].get("suppressions", [])
        assert len(suppressions) == 1
        assert suppressions[0]["kind"] == "external"
        assert suppressions[0]["justification"] == "vulnerable_code_not_in_execute_path"
        assert results[0]["level"] == "note"
