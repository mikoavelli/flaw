"""Tests for Pydantic model validation and edge cases."""

from __future__ import annotations

from typing import Any

from flaw.models import TrivyReport


class TestVulnerabilityModel:
    """Tests for CVSS extraction logic."""

    def test_nvd_cvss_extracted(self, trivy_payload_single: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_single)
        vuln = report.results[0].vulnerabilities[0]
        assert vuln.cvss == 7.5

    def test_fallback_to_non_nvd_source(self, trivy_payload_multi_source: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_multi_source)
        vuln = report.results[0].vulnerabilities[0]
        assert vuln.cvss == 8.1

    def test_missing_cvss_defaults_to_zero(self, trivy_payload_no_cvss: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_no_cvss)
        vuln = report.results[0].vulnerabilities[0]
        assert vuln.cvss == 0.0

    def test_basic_fields_parsed(self, trivy_payload_single: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_single)
        vuln = report.results[0].vulnerabilities[0]
        assert vuln.cve_id == "CVE-2023-44487"
        assert vuln.pkg_name == "nghttp2"
        assert vuln.installed_version == "1.55.1-r0"
        assert vuln.fixed_version == "1.57.0-r0"
        assert vuln.severity == "CRITICAL"


class TestScanResult:
    """Tests for null handling in ScanResult."""

    def test_null_vulnerabilities_becomes_empty_list(
        self, trivy_payload_null_vulns: dict[str, Any]
    ) -> None:
        report = TrivyReport.model_validate(trivy_payload_null_vulns)
        assert report.results[0].vulnerabilities == []
        assert report.total_vulnerabilities == 0


class TestTrivyReport:
    """Tests for TrivyReport aggregation."""

    def test_null_results_becomes_empty_list(
        self, trivy_payload_null_results: dict[str, Any]
    ) -> None:
        report = TrivyReport.model_validate(trivy_payload_null_results)
        assert report.results == []
        assert report.total_vulnerabilities == 0

    def test_empty_results(self, trivy_payload_empty: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_empty)
        assert report.total_vulnerabilities == 0
        assert report.all_vulnerabilities == []

    def test_total_vulnerabilities_count(self, trivy_payload_single: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_single)
        assert report.total_vulnerabilities == 1

    def test_all_vulnerabilities_flat_list(self, trivy_payload_single: dict[str, Any]) -> None:
        report = TrivyReport.model_validate(trivy_payload_single)
        flat = report.all_vulnerabilities
        assert len(flat) == 1
        assert flat[0].cve_id == "CVE-2023-44487"
