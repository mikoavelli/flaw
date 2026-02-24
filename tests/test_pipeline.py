"""Tests for the scan pipeline."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from flaw.models import ScanReport
from flaw.pipeline import run_scan


def _mock_trivy(payload: dict[str, Any]) -> Any:
    """Create a mock for subprocess.run that returns Trivy JSON."""
    from unittest.mock import MagicMock

    mock = MagicMock()
    mock.stdout = json.dumps(payload)
    mock.returncode = 0
    return mock


class TestRunScan:
    """Tests for the run_scan pipeline."""

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_full_pipeline_no_enrich(
        self, mock_run: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_run.return_value = _mock_trivy(trivy_payload_single)

        report = run_scan("nginx:1.24", skip_enrich=True)

        assert isinstance(report, ScanReport)
        assert report.image == "nginx:1.24"
        assert report.summary.total == 1
        assert report.summary.critical == 1
        assert len(report.vulnerabilities) == 1
        assert report.vulnerabilities[0].risk_score > 0.0

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_pipeline_empty_scan(self, mock_run: Any, trivy_payload_empty: dict[str, Any]) -> None:
        mock_run.return_value = _mock_trivy(trivy_payload_empty)

        report = run_scan("alpine:3.19", skip_enrich=True)

        assert report.summary.total == 0
        assert report.vulnerabilities == []
        assert report.summary.max_risk_score == 0.0

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_pipeline_sorts_by_risk(self, mock_run: Any) -> None:
        payload = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-0001",
                            "PkgName": "low-risk",
                            "InstalledVersion": "1.0",
                            "Severity": "LOW",
                        },
                        {
                            "VulnerabilityID": "CVE-2024-0002",
                            "PkgName": "high-risk",
                            "InstalledVersion": "1.0",
                            "Severity": "CRITICAL",
                            "CVSS": {"nvd": {"V3Score": 9.8}},
                        },
                    ],
                }
            ]
        }
        mock_run.return_value = _mock_trivy(payload)

        report = run_scan("test:latest", skip_enrich=True)

        assert report.vulnerabilities[0].cve_id == "CVE-2024-0002"
        assert report.vulnerabilities[0].risk_score >= report.vulnerabilities[1].risk_score

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_pipeline_duration_tracked(
        self, mock_run: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_run.return_value = _mock_trivy(trivy_payload_single)

        report = run_scan("nginx:1.24", skip_enrich=True)

        assert report.duration_seconds >= 0.0

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_pipeline_scan_time_is_utc(
        self, mock_run: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_run.return_value = _mock_trivy(trivy_payload_single)

        report = run_scan("nginx:1.24", skip_enrich=True)

        assert "T" in report.scan_time
        assert report.scan_time.endswith("+00:00") or report.scan_time.endswith("Z")
