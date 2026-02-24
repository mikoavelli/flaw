"""Trivy subprocess wrapper for container image scanning."""

from __future__ import annotations

import json
import subprocess

from flaw.models import TrivyReport

TRIVY_TIMEOUT = 300


class ScannerError(Exception):
    """Raised when Trivy scan fails."""


def scan_image(image_ref: str, *, timeout: int = TRIVY_TIMEOUT) -> TrivyReport:
    """
    Run Trivy against a container image and return parsed results.

    Args:
        image_ref: Image reference (e.g., 'nginx:1.24').
        timeout: Maximum seconds to wait for Trivy.

    Returns:
        Parsed Trivy report.

    Raises:
        ScannerError: On any failure (missing binary, scan error, bad output).
    """
    cmd = [
        "trivy",
        "image",
        "--format",
        "json",
        "--quiet",
        image_ref,
    ]

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise ScannerError(
            "Trivy is not installed. Install it from https://github.com/aquasecurity/trivy"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise ScannerError(f"Trivy scan timed out after {timeout}s for image '{image_ref}'.") from e
    except subprocess.CalledProcessError as e:
        raise ScannerError(f"Trivy scan failed for '{image_ref}': {e.stderr.strip()}") from e

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError("Trivy returned invalid JSON output.") from e

    return TrivyReport.model_validate(payload)
