"""Tests for container runtime detection."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from flaw.scanner.runtime import detect_runtime, inspect_image


class TestDetectRuntime:
    """Tests for runtime detection."""

    @patch("flaw.scanner.runtime.shutil.which")
    def test_docker_found(self, mock_which: Any) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/docker" if x == "docker" else None
        assert detect_runtime() == "docker"

    @patch("flaw.scanner.runtime.shutil.which")
    def test_podman_fallback(self, mock_which: Any) -> None:
        mock_which.side_effect = lambda x: "/usr/bin/podman" if x == "podman" else None
        assert detect_runtime() == "podman"

    @patch("flaw.scanner.runtime.shutil.which")
    def test_nothing_found(self, mock_which: Any) -> None:
        mock_which.return_value = None
        assert detect_runtime() == "unknown"

    @patch("flaw.scanner.runtime.shutil.which")
    def test_docker_preferred_over_podman(self, mock_which: Any) -> None:
        mock_which.side_effect = lambda x: f"/usr/bin/{x}"
        assert detect_runtime() == "docker"


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
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, "docker")

        result = inspect_image("nonexistent:tag", runtime="docker")
        assert result == {}

    def test_inspect_unknown_runtime(self) -> None:
        result = inspect_image("nginx:1.24", runtime="unknown")
        assert result == {}
