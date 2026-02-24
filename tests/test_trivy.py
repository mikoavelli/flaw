"""Tests for Trivy scanner wrapper."""

from __future__ import annotations

import json
import subprocess
from typing import Any
from unittest.mock import patch

import pytest

from flaw.scanner.trivy import ScannerError, scan_image


class TestScanImage:
    """Tests for scan_image function."""

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_successful_scan(self, mock_run: Any, trivy_payload_single: dict[str, Any]) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_single)
        mock_run.return_value.returncode = 0

        report = scan_image("nginx:1.24")

        mock_run.assert_called_once_with(
            ["trivy", "image", "--format", "json", "--quiet", "nginx:1.24"],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
        assert report.total_vulnerabilities == 1
        assert report.results[0].vulnerabilities[0].cve_id == "CVE-2023-44487"

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_trivy_not_installed(self, mock_run: Any) -> None:
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(ScannerError, match="Trivy is not installed"):
            scan_image("nginx:1.24")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_trivy_scan_failure(self, mock_run: Any) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(
            returncode=1,
            cmd=["trivy"],
            stderr="FATAL: image not found",
        )

        with pytest.raises(ScannerError, match="Trivy scan failed"):
            scan_image("nonexistent:tag")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_trivy_timeout(self, mock_run: Any) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["trivy"], timeout=300)

        with pytest.raises(ScannerError, match="timed out"):
            scan_image("huge-image:latest")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_invalid_json_output(self, mock_run: Any) -> None:
        mock_run.return_value.stdout = "not valid json"
        mock_run.return_value.returncode = 0

        with pytest.raises(ScannerError, match="invalid JSON"):
            scan_image("nginx:1.24")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_custom_timeout(self, mock_run: Any, trivy_payload_empty: dict[str, Any]) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_empty)
        mock_run.return_value.returncode = 0

        scan_image("nginx:1.24", timeout=60)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 60

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_null_vulnerabilities_handled(
        self, mock_run: Any, trivy_payload_null_vulns: dict[str, Any]
    ) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_null_vulns)
        mock_run.return_value.returncode = 0

        report = scan_image("alpine:3.19")
        assert report.total_vulnerabilities == 0
        assert report.results[0].vulnerabilities == []
