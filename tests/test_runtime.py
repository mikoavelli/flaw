"""Tests for container runtime detection."""

from __future__ import annotations

import subprocess
from typing import Any
from unittest.mock import patch

from flaw.scanner.runtime import (
    inspect_image,
    resolve_image_source,
)


class TestResolveImageSource:
    """Tests for image source resolution."""

    @patch("flaw.scanner.runtime._image_exists")
    @patch("flaw.scanner.runtime.shutil.which")
    def test_image_found_in_docker(self, mock_which: Any, mock_exists: Any) -> None:
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        mock_exists.side_effect = lambda rt, img: rt == "docker"

        result = resolve_image_source("nginx:1.24")

        assert result.runtime == "docker"
        assert result.is_local is True
        assert result.image_ref == "nginx:1.24"

    @patch("flaw.scanner.runtime._image_exists")
    @patch("flaw.scanner.runtime.shutil.which")
    def test_image_found_in_podman_only(self, mock_which: Any, mock_exists: Any) -> None:
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        mock_exists.side_effect = lambda rt, img: rt == "podman"

        result = resolve_image_source("myapp:latest")

        assert result.runtime == "podman"
        assert result.is_local is True

    @patch("flaw.scanner.runtime._image_exists")
    @patch("flaw.scanner.runtime.shutil.which")
    def test_image_not_local(self, mock_which: Any, mock_exists: Any) -> None:
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        mock_exists.return_value = False

        result = resolve_image_source("nginx:1.24")

        assert result.runtime == "docker"
        assert result.is_local is False

    @patch("flaw.scanner.runtime.shutil.which")
    def test_no_runtime_available(self, mock_which: Any) -> None:
        mock_which.return_value = None

        result = resolve_image_source("nginx:1.24")

        assert result.runtime == "unknown"
        assert result.is_local is False

    @patch("flaw.scanner.runtime._image_exists")
    @patch("flaw.scanner.runtime.shutil.which")
    def test_docker_checked_before_podman(self, mock_which: Any, mock_exists: Any) -> None:
        """When both runtimes have the image, docker wins (checked first)."""
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        mock_exists.return_value = True

        result = resolve_image_source("nginx:1.24")
        assert result.runtime == "docker"

    @patch("flaw.scanner.runtime._image_exists")
    @patch("flaw.scanner.runtime.shutil.which")
    def test_only_podman_installed(self, mock_which: Any, mock_exists: Any) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/podman" if x == "podman" else None
        mock_exists.return_value = True

        result = resolve_image_source("myapp:latest")
        assert result.runtime == "podman"
        assert result.is_local is True


class TestInspectImage:
    """Tests for image inspection."""

    @patch("flaw.scanner.runtime.subprocess.run")
    def test_successful_inspect(self, mock_run: Any) -> None:
        mock_run.return_value.stdout = '[{"Config": {"User": "app"}}]'
        mock_run.return_value.returncode = 0

        result = inspect_image("nginx:1.24", runtime="docker")
        assert result["Config"]["User"] == "app"

    @patch("flaw.scanner.runtime.subprocess.run")
    def test_inspect_failure_returns_empty(self, mock_run: Any) -> None:
        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        result = inspect_image("nonexistent:tag", runtime="docker")
        assert result == {}

    def test_inspect_unknown_runtime(self) -> None:
        result = inspect_image("nginx:1.24", runtime="unknown")
        assert result == {}
