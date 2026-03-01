"""SARIF (Static Analysis Results Interchange Format) generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from flaw import __version__
from flaw.models import DockerfileIssue, ScanReport


def _severity_to_level(severity: str) -> str:
    """Map Flaw/Trivy severities to SARIF levels."""
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _write_sarif(
    rules: list[dict[str, Any]], results: list[dict[str, Any]], output: Path | None
) -> None:
    """Construct and write the final SARIF structure."""
    sarif_data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "flaw",
                        "informationUri": "https://github.com/mikoavelli/flaw",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    json_str = json.dumps(sarif_data, indent=2, ensure_ascii=False)

    if output is not None:
        output.write_text(json_str, encoding="utf-8")
    else:
        sys.stdout.write(json_str + "\n")


def write_scan_sarif_report(report: ScanReport, *, output: Path | None = None) -> None:
    """Generate and write a SARIF 2.1.0 compliant report for an image scan."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids = set()

    for vuln in report.vulnerabilities:
        if vuln.cve_id not in rule_ids:
            rule_ids.add(vuln.cve_id)
            rules.append(
                {
                    "id": vuln.cve_id,
                    "shortDescription": {"text": f"{vuln.cve_id} in {vuln.pkg_name}"},
                    "fullDescription": {"text": vuln.description or "No description available."},
                    "helpUri": f"https://nvd.nist.gov/vuln/detail/{vuln.cve_id}",
                    "properties": {
                        "security-severity": str(vuln.cvss),
                        "tags": ["vulnerability", vuln.severity] + vuln.cwe_ids,
                    },
                }
            )

        msg = f"Vulnerable package '{vuln.pkg_name}' ({vuln.installed_version}). \
            Risk Score: {vuln.risk_score}"
        results.append(
            {
                "ruleId": vuln.cve_id,
                "level": _severity_to_level(vuln.severity),
                "message": {"text": msg},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"docker://{report.image}"}
                        },
                        "logicalLocations": [{"name": vuln.pkg_name, "kind": "package"}],
                    }
                ],
            }
        )

    for issue in report.dockerfile_issues or []:
        if issue.id not in rule_ids:
            rule_ids.add(issue.id)
            rules.append(
                {
                    "id": issue.id,
                    "shortDescription": {"text": issue.description},
                    "properties": {"tags": ["misconfiguration", "dockerfile", issue.severity]},
                }
            )

        location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": "Dockerfile"}}}
        if issue.line:
            location["physicalLocation"]["region"] = {
                "startLine": issue.line,
                "endLine": issue.line,
            }

        results.append(
            {
                "ruleId": issue.id,
                "level": _severity_to_level(issue.severity),
                "message": {"text": issue.description},
                "locations": [location],
            }
        )

    _write_sarif(rules, results, output)


def write_lint_sarif_report(
    issues: list[DockerfileIssue], path: str, *, output: Path | None = None
) -> None:
    """Generate and write a SARIF 2.1.0 compliant report for a Dockerfile lint."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids = set()

    for issue in issues:
        if issue.id not in rule_ids:
            rule_ids.add(issue.id)
            rules.append(
                {
                    "id": issue.id,
                    "shortDescription": {"text": issue.description},
                    "properties": {"tags": ["misconfiguration", "dockerfile", issue.severity]},
                }
            )

        location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": path}}}
        if issue.line:
            location["physicalLocation"]["region"] = {
                "startLine": issue.line,
                "endLine": issue.line,
            }

        results.append(
            {
                "ruleId": issue.id,
                "level": _severity_to_level(issue.severity),
                "message": {"text": issue.description},
                "locations": [location],
            }
        )

    _write_sarif(rules, results, output)
