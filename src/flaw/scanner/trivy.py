"""Trivy subprocess wrapper for container image scanning."""

from __future__ import annotations

import json
import logging
import subprocess

from flaw.models import TrivyReport

logger = logging.getLogger("flaw")

TRIVY_TIMEOUT = 300


class ScannerError(Exception):
    """Raised when Trivy scan fails."""


def _parse_error(stderr_text: str, image_ref: str) -> str:
    """Parse Trivy stderr into a user-friendly error message."""
    lower = stderr_text.lower()

    if "podman" in lower and "socket" in lower:
        return (
            f"Image '{image_ref}' exists in podman but Trivy cannot access it.\n"
            "  Start the podman socket: systemctl --user start podman.socket"
        )

    if "unable to find" in lower:
        return f"Image '{image_ref}' not found locally or in any remote registry."

    if "no such image" in lower and "unauthorized" not in lower:
        return f"Image '{image_ref}' not found locally or in any remote registry."

    if "unauthorized" in lower or "authentication required" in lower:
        return (
            f"Authentication required to pull '{image_ref}'.\n"
            "  Log in first: docker login / podman login"
        )

    if "timeout" in lower:
        return f"Trivy timed out scanning '{image_ref}'."

    return f"Trivy scan failed for '{image_ref}'."


def scan_image(
    image_ref: str,
    *,
    timeout: int = TRIVY_TIMEOUT,
    image_src: str | None = None,
) -> TrivyReport:
    """
    Run Trivy against a container image and return parsed results.

    Args:
        image_ref: Image reference (e.g., 'nginx:1.24').
        timeout: Maximum seconds to wait for Trivy.
        image_src: Force Trivy to use specific image source.

    Raises:
        ScannerError: On any failure.
    """
    cmd = ["trivy", "image", "--format", "json", "--quiet"]

    if image_src and image_src != "unknown":
        cmd.extend(["--image-src", image_src])
        logger.debug("Trivy image source: %s", image_src)

    cmd.append(image_ref)
    logger.debug("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as e:
        raise ScannerError(
            "Trivy is not installed. Install it from https://github.com/aquasecurity/trivy"
        ) from e
    except subprocess.TimeoutExpired as e:
        raise ScannerError(f"Trivy scan timed out after {timeout}s for '{image_ref}'.") from e

    if result.returncode != 0:
        raise ScannerError(_parse_error(result.stderr or "", image_ref))

    if not result.stdout or not result.stdout.strip():
        raise ScannerError("Trivy returned empty output.")

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise ScannerError("Trivy returned invalid JSON output.") from e

    return TrivyReport.model_validate(payload)
