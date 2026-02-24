"""Dockerfile static analysis for security misconfigurations."""

from __future__ import annotations

import re
from pathlib import Path

from flaw.models import DockerfileIssue


class DockerfileLintError(Exception):
    """Raised when Dockerfile cannot be read or parsed."""


_RULES: list[dict] = [
    {
        "id": "DF-001",
        "severity": "HIGH",
        "description": "No USER directive — container runs as root",
        "check": "_check_no_user",
    },
    {
        "id": "DF-002",
        "severity": "HIGH",
        "description": "Using ADD instead of COPY for local files",
        "check": "_check_add_instead_of_copy",
    },
    {
        "id": "DF-003",
        "severity": "MEDIUM",
        "description": "Base image uses :latest tag",
        "check": "_check_latest_tag",
    },
    {
        "id": "DF-004",
        "severity": "MEDIUM",
        "description": "apt-get install without --no-install-recommends",
        "check": "_check_apt_no_recommends",
    },
    {
        "id": "DF-005",
        "severity": "MEDIUM",
        "description": "pip install without pinned versions",
        "check": "_check_pip_no_pin",
    },
    {
        "id": "DF-006",
        "severity": "INFO",
        "description": "No HEALTHCHECK defined",
        "check": "_check_no_healthcheck",
    },
    {
        "id": "DF-007",
        "severity": "HIGH",
        "description": "Secrets or sensitive data in ENV directive",
        "check": "_check_env_secrets",
    },
]

# Patterns for secret detection in ENV
_SECRET_PATTERNS = re.compile(
    r"(password|secret|api_key|token|private_key|access_key)",
    re.IGNORECASE,
)

# Pattern for URLs in ADD (remote fetch — legitimate use of ADD)
_URL_PATTERN = re.compile(r"https?://")


def lint(path: Path) -> list[DockerfileIssue]:
    """
    Analyze a Dockerfile and return a list of security issues.

    Args:
        path: Path to the Dockerfile.

    Returns:
        List of issues found, sorted by severity.

    Raises:
        DockerfileLintError: If the file cannot be read.
    """
    if not path.is_file():
        raise DockerfileLintError(f"Dockerfile not found: {path}")

    try:
        content = path.read_text(encoding="utf-8")
    except OSError as e:
        raise DockerfileLintError(f"Cannot read Dockerfile: {e}") from e

    lines = content.splitlines()
    issues: list[DockerfileIssue] = []

    issues.extend(_check_no_user(lines))
    issues.extend(_check_add_instead_of_copy(lines))
    issues.extend(_check_latest_tag(lines))
    issues.extend(_check_apt_no_recommends(lines))
    issues.extend(_check_pip_no_pin(lines))
    issues.extend(_check_no_healthcheck(lines))
    issues.extend(_check_env_secrets(lines))

    severity_order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    issues.sort(key=lambda i: severity_order.get(i.severity, 99))

    return issues


def _check_no_user(lines: list[str]) -> list[DockerfileIssue]:
    """Check if any USER directive exists."""
    for line in lines:
        stripped = line.strip().upper()
        if stripped.startswith("USER "):
            return []
    return [
        DockerfileIssue(
            id="DF-001",
            severity="HIGH",
            description="No USER directive — container runs as root",
        )
    ]


def _check_add_instead_of_copy(lines: list[str]) -> list[DockerfileIssue]:
    """Flag ADD commands that could be COPY (non-URL sources)."""
    issues = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.upper().startswith("ADD "):
            args = stripped[4:].strip()
            if not _URL_PATTERN.search(args) and not args.endswith(".tar.gz"):
                issues.append(
                    DockerfileIssue(
                        id="DF-002",
                        severity="HIGH",
                        description="Using ADD instead of COPY for local files",
                        line=i,
                    )
                )
    return issues


def _check_latest_tag(lines: list[str]) -> list[DockerfileIssue]:
    """Check if FROM uses :latest or no tag."""
    issues = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.upper().startswith("FROM "):
            image = stripped.split()[1] if len(stripped.split()) > 1 else ""
            # Skip build stage aliases
            image_part = image.split(" AS ")[0] if " AS " in image.upper() else image
            image_part = image_part.split(" as ")[0]

            if image_part == "scratch":
                continue
            if ":" not in image_part or image_part.endswith(":latest"):
                issues.append(
                    DockerfileIssue(
                        id="DF-003",
                        severity="MEDIUM",
                        description="Base image uses :latest tag",
                        line=i,
                    )
                )
    return issues


def _check_apt_no_recommends(lines: list[str]) -> list[DockerfileIssue]:
    """Flag apt-get install without --no-install-recommends."""
    issues = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if "apt-get" in stripped and "install" in stripped:
            if "--no-install-recommends" not in stripped:
                issues.append(
                    DockerfileIssue(
                        id="DF-004",
                        severity="MEDIUM",
                        description="apt-get install without --no-install-recommends",
                        line=i,
                    )
                )
    return issues


def _check_pip_no_pin(lines: list[str]) -> list[DockerfileIssue]:
    """Flag pip install without pinned versions (no == in package spec)."""
    issues = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if "pip install" in stripped and "-r " not in stripped:
            # Extract packages after 'pip install'
            parts = stripped.split("pip install")[-1].strip().split()
            for part in parts:
                if part.startswith("-"):
                    continue
                if "==" not in part and ">=" not in part and "<=" not in part:
                    issues.append(
                        DockerfileIssue(
                            id="DF-005",
                            severity="MEDIUM",
                            description=f"pip install without pinned version: {part}",
                            line=i,
                        )
                    )
                    break  # One issue per line is enough
    return issues


def _check_no_healthcheck(lines: list[str]) -> list[DockerfileIssue]:
    """Check if HEALTHCHECK directive exists."""
    for line in lines:
        if line.strip().upper().startswith("HEALTHCHECK "):
            return []
    return [
        DockerfileIssue(
            id="DF-006",
            severity="INFO",
            description="No HEALTHCHECK defined",
        )
    ]


def _check_env_secrets(lines: list[str]) -> list[DockerfileIssue]:
    """Flag ENV directives that may contain secrets."""
    issues = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.upper().startswith("ENV "):
            if _SECRET_PATTERNS.search(stripped):
                issues.append(
                    DockerfileIssue(
                        id="DF-007",
                        severity="HIGH",
                        description="Secrets or sensitive data in ENV directive",
                        line=i,
                    )
                )
    return issues
