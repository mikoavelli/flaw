"""Tests for the scan pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

from flaw.core.config import RuntimeFlags, Settings, load_settings
from flaw.models import ScanReport, TrivyReport
from flaw.pipeline import run_scan


def _offline_settings() -> Settings:
    """Settings with offline mode to skip EPSS/KEV downloads in tests."""
    return load_settings(flags=RuntimeFlags(offline=True))


class TestRunScan:
    """Tests for the run_scan pipeline."""

    @patch("flaw.pipeline.scan_image")
    def test_full_pipeline(self, mock_scan: Any, trivy_payload_single: dict[str, Any]) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        report = run_scan("nginx:1.24", settings=_offline_settings())

        assert isinstance(report, ScanReport)
        assert report.image == "nginx:1.24"
        assert report.summary.total == 1
        assert report.summary.critical == 1
        assert len(report.vulnerabilities) == 1
        assert report.vulnerabilities[0].risk_score > 0.0

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_empty_scan(self, mock_scan: Any, trivy_payload_empty: dict[str, Any]) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_empty)

        report = run_scan("alpine:3.19", settings=_offline_settings())

        assert report.summary.total == 0
        assert report.vulnerabilities == []
        assert report.summary.max_risk_score == 0.0

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_sorts_by_risk(self, mock_scan: Any) -> None:
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
        mock_scan.return_value = TrivyReport.model_validate(payload)

        report = run_scan("test:latest", settings=_offline_settings())

        assert report.vulnerabilities[0].cve_id == "CVE-2024-0002"
        assert report.vulnerabilities[0].risk_score >= report.vulnerabilities[1].risk_score

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_duration_tracked(
        self, mock_scan: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        report = run_scan("nginx:1.24", settings=_offline_settings())

        assert report.duration_seconds >= 0.0

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_scan_time_is_utc(
        self, mock_scan: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        report = run_scan("nginx:1.24", settings=_offline_settings())

        assert "T" in report.scan_time
        assert report.scan_time.endswith("+00:00") or report.scan_time.endswith("Z")

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_with_dockerfile(
        self, mock_scan: Any, trivy_payload_single: dict[str, Any], tmp_path: Path
    ) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        df = tmp_path / "Dockerfile"
        df.write_text('FROM python\nCMD ["python"]\n')

        report = run_scan("nginx:1.24", dockerfile=df, settings=_offline_settings())

        assert report.dockerfile_issues is not None
        assert len(report.dockerfile_issues) > 0

        assert len(report.dockerfile_issues) > 0
        ids = [i.id for i in report.dockerfile_issues]
        assert "DF-001" in ids
        assert "DF-003" in ids
        assert "DF-006" in ids

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_without_dockerfile(
        self, mock_scan: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        report = run_scan("nginx:1.24", settings=_offline_settings())

        assert report.dockerfile_issues is None

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_bad_dockerfile_does_not_crash(
        self, mock_scan: Any, trivy_payload_single: dict[str, Any], tmp_path: Path
    ) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        report = run_scan(
            "nginx:1.24",
            dockerfile=tmp_path / "nonexistent",
            settings=_offline_settings(),
        )

        assert report.dockerfile_issues is None
        assert report.summary.total == 1

    @patch("flaw.pipeline.scan_image")
    def test_pipeline_runtime_detected(
        self, mock_scan: Any, trivy_payload_single: dict[str, Any]
    ) -> None:
        mock_scan.return_value = TrivyReport.model_validate(trivy_payload_single)

        report = run_scan("nginx:1.24", settings=_offline_settings())

        assert report.runtime in ("docker", "podman", "unknown")
