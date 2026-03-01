"""Tests for Pydantic model validation and edge cases."""

from __future__ import annotations

from typing import Any

from flaw.models import TrivyReport, Vulnerability


class TestVulnerabilityModel:
    """Tests for Vulnerability parsing logic."""

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

    def test_extract_nested_data_purl_variants(self) -> None:
        v1 = Vulnerability.model_validate(
            {
                "VulnerabilityID": "CVE-1",
                "PkgName": "a",
                "InstalledVersion": "1",
                "Severity": "LOW",
                "PkgIdentifier": {"PURL": "pkg:deb/debian/a"},
            }
        )
        assert v1.purl == "pkg:deb/debian/a"

        v2 = Vulnerability.model_validate(
            {
                "VulnerabilityID": "CVE-2",
                "PkgName": "b",
                "InstalledVersion": "1",
                "Severity": "LOW",
                "PkgIdentifier": "pkg:npm/b",
            }
        )
        assert v2.purl == "pkg:npm/b"

        v3 = Vulnerability.model_validate(
            {
                "VulnerabilityID": "CVE-3",
                "PkgName": "c",
                "InstalledVersion": "1",
                "Severity": "LOW",
                "PURL": "pkg:golang/c",
            }
        )
        assert v3.purl == "pkg:golang/c"


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
