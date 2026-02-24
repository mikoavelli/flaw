"""Container runtime detection and image source resolution."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("flaw")


@dataclass(frozen=True, slots=True)
class ImageSource:
    """Result of image source resolution."""

    runtime: str
    is_local: bool
    image_ref: str


def _image_exists(runtime: str, image_ref: str) -> bool:
    """Check if an image exists in local storage for a given runtime."""
    try:
        result = subprocess.run(  # noqa: S603
            [runtime, "image", "inspect", image_ref],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def resolve_image_source(image_ref: str) -> ImageSource:
    """
    Determine where an image will come from.

    Checks local storage in order: docker → podman.
    Logs each step for --verbose output.
    """
    runtimes: list[str] = []
    for candidate in ("docker", "podman"):
        if shutil.which(candidate):
            runtimes.append(candidate)
            logger.debug("Runtime '%s' is available", candidate)
        else:
            logger.debug("Runtime '%s' not found in PATH", candidate)

    if not runtimes:
        logger.warning("No container runtime found (docker, podman)")
        return ImageSource(runtime="unknown", is_local=False, image_ref=image_ref)

    for rt in runtimes:
        logger.debug("Checking %s local storage for '%s'...", rt, image_ref)
        if _image_exists(rt, image_ref):
            logger.debug("Found '%s' in %s local storage", image_ref, rt)
            return ImageSource(runtime=rt, is_local=True, image_ref=image_ref)
        logger.debug("Image '%s' not in %s local storage", image_ref, rt)

    logger.debug("Image '%s' will be pulled from remote registry", image_ref)
    return ImageSource(runtime=runtimes[0], is_local=False, image_ref=image_ref)


def inspect_image(image_ref: str, runtime: str | None = None) -> dict:
    """Run docker/podman inspect on an image. Returns empty dict on failure."""
    rt = runtime or "unknown"
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
