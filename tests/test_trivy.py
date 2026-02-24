"""Tests for Trivy scanner wrapper."""

from __future__ import annotations

import json
import subprocess
from typing import Any
from unittest.mock import patch

import pytest

from flaw.scanner.trivy import ScannerError, _parse_error, scan_image


class TestScanImage:
    """Tests for scan_image function."""

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_successful_scan(self, mock_run: Any, trivy_payload_single: dict[str, Any]) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_single)
        mock_run.return_value.returncode = 0

        report = scan_image("nginx:1.24")

        assert report.total_vulnerabilities == 1
        assert report.results[0].vulnerabilities[0].cve_id == "CVE-2023-44487"

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_trivy_not_installed(self, mock_run: Any) -> None:
        mock_run.side_effect = FileNotFoundError()

        with pytest.raises(ScannerError, match="Trivy is not installed"):
            scan_image("nginx:1.24")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_trivy_scan_failure(self, mock_run: Any) -> None:
        mock_run.return_value.returncode = 1
        mock_run.return_value.stderr = "unable to find the specified image"
        mock_run.return_value.stdout = ""

        with pytest.raises(ScannerError, match="not found"):
            scan_image("nonexistent:tag")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_trivy_timeout(self, mock_run: Any) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["trivy"], timeout=300)

        with pytest.raises(ScannerError, match="timed out"):
            scan_image("huge:latest")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_invalid_json(self, mock_run: Any) -> None:
        mock_run.return_value.stdout = "not json"
        mock_run.return_value.returncode = 0

        with pytest.raises(ScannerError, match="invalid JSON"):
            scan_image("nginx:1.24")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_empty_output(self, mock_run: Any) -> None:
        mock_run.return_value.stdout = ""
        mock_run.return_value.returncode = 0

        with pytest.raises(ScannerError, match="empty output"):
            scan_image("nginx:1.24")

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_image_src_flag(self, mock_run: Any, trivy_payload_empty: dict[str, Any]) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_empty)
        mock_run.return_value.returncode = 0

        scan_image("myapp:latest", image_src="podman")

        cmd = mock_run.call_args[0][0]
        assert "--image-src" in cmd
        assert "podman" in cmd

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_image_src_unknown_ignored(
        self, mock_run: Any, trivy_payload_empty: dict[str, Any]
    ) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_empty)
        mock_run.return_value.returncode = 0

        scan_image("myapp:latest", image_src="unknown")

        cmd = mock_run.call_args[0][0]
        assert "--image-src" not in cmd

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_quiet_flag_always_present(
        self, mock_run: Any, trivy_payload_empty: dict[str, Any]
    ) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_empty)
        mock_run.return_value.returncode = 0

        scan_image("nginx:1.24")

        cmd = mock_run.call_args[0][0]
        assert "--quiet" in cmd

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_null_vulnerabilities_handled(
        self, mock_run: Any, trivy_payload_null_vulns: dict[str, Any]
    ) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_null_vulns)
        mock_run.return_value.returncode = 0

        report = scan_image("alpine:3.19")
        assert report.total_vulnerabilities == 0

    @patch("flaw.scanner.trivy.subprocess.run")
    def test_custom_timeout(self, mock_run: Any, trivy_payload_empty: dict[str, Any]) -> None:
        mock_run.return_value.stdout = json.dumps(trivy_payload_empty)
        mock_run.return_value.returncode = 0

        scan_image("nginx:1.24", timeout=60)

        call_kwargs = mock_run.call_args[1]
        assert call_kwargs["timeout"] == 60


class TestParseError:
    """Tests for Trivy error message parsing."""

    def test_podman_socket(self) -> None:
        msg = _parse_error("podman socket not found", "img:tag")
        assert "podman" in msg.lower()

    def test_unauthorized_only(self) -> None:
        msg = _parse_error("UNAUTHORIZED: authentication required", "private/img:tag")
        assert "authentication" in msg.lower()

    def test_unable_to_find_with_unauthorized(self) -> None:
        """When both 'unable to find' and 'unauthorized' present, prefer not-found."""
        stderr = (
            'unable to find the specified image "fake:latest"\n'
            "UNAUTHORIZED: authentication required"
        )
        msg = _parse_error(stderr, "fake:latest")
        assert "not found" in msg.lower()
        assert "authentication" not in msg.lower()

    def test_image_not_found(self) -> None:
        msg = _parse_error("unable to find the specified image", "img:tag")
        assert "not found" in msg.lower()

    def test_generic_error(self) -> None:
        msg = _parse_error("something unexpected", "img:tag")
        assert "img:tag" in msg
