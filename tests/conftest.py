"""Shared test fixtures for the flaw test suite."""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture()
def trivy_payload_single() -> dict[str, Any]:
    """Minimal Trivy JSON with one vulnerability."""
    return {
        "Results": [
            {
                "Target": "nginx:1.24 (debian 12.4)",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-44487",
                        "PkgName": "nghttp2",
                        "InstalledVersion": "1.55.1-r0",
                        "FixedVersion": "1.57.0-r0",
                        "Severity": "CRITICAL",
                        "CVSS": {
                            "nvd": {"V3Score": 7.5},
                        },
                    },
                ],
            },
        ],
    }


@pytest.fixture()
def trivy_payload_multi_source() -> dict[str, Any]:
    """Trivy JSON where CVSS comes from non-NVD source."""
    return {
        "Results": [
            {
                "Target": "app:latest",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "3.0.1",
                        "Severity": "HIGH",
                        "CVSS": {
                            "redhat": {"V3Score": 8.1},
                        },
                    },
                ],
            },
        ],
    }


@pytest.fixture()
def trivy_payload_no_cvss() -> dict[str, Any]:
    """Trivy JSON without any CVSS data."""
    return {
        "Results": [
            {
                "Target": "app:latest",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-0000",
                        "PkgName": "curl",
                        "InstalledVersion": "7.88.0",
                        "Severity": "MEDIUM",
                    },
                ],
            },
        ],
    }


@pytest.fixture()
def trivy_payload_null_vulns() -> dict[str, Any]:
    """Trivy JSON where Vulnerabilities is null."""
    return {
        "Results": [
            {
                "Target": "alpine:3.19 (alpine 3.19.0)",
                "Vulnerabilities": None,
            },
        ],
    }


@pytest.fixture()
def trivy_payload_empty() -> dict[str, Any]:
    """Trivy JSON with no results."""
    return {"Results": []}


@pytest.fixture()
def trivy_payload_null_results() -> dict[str, Any]:
    """Trivy JSON with null Results."""
    return {"Results": None}
