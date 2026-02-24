"""Container runtime detection (Docker / Podman)."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess

logger = logging.getLogger("flaw")


def detect_runtime() -> str:
    """
    Detect available container runtime.

    Returns:
        'docker', 'podman', or 'unknown'.
    """
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            logger.debug("Detected container runtime: %s", candidate)
            return candidate

    logger.debug("No container runtime found")
    return "unknown"


def inspect_image(image_ref: str, runtime: str | None = None) -> dict:
    """
    Run docker/podman inspect on an image.

    Args:
        image_ref: Image reference.
        runtime: Override runtime binary. Auto-detects if None.

    Returns:
        Parsed inspect JSON (first element).
        Empty dict on any failure.
    """
    rt = runtime or detect_runtime()
    if rt == "unknown":
        return {}

    try:
        result = subprocess.run(  # noqa: S603
            [rt, "inspect", image_ref],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        data = json.loads(result.stdout)
        return data[0] if isinstance(data, list) and data else {}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
        logger.debug("Failed to inspect image %s with %s", image_ref, rt)
        return {}
