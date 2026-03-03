"""Auto-installer for Trivy binary."""

from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import httpx

from flaw.core.config import load_settings
from flaw.core.paths import BIN_DIR

logger = logging.getLogger("flaw")

TRIVY_BIN = BIN_DIR / ("trivy.exe" if platform.system() == "Windows" else "trivy")


class InstallerError(Exception):
    """Raised when Trivy installation fails."""


def get_trivy_info() -> tuple[str | None, str]:
    """Return (path, version) of Trivy if installed, else (None, 'Unknown')."""
    sys_trivy = shutil.which("trivy")
    candidate = sys_trivy if sys_trivy else (str(TRIVY_BIN) if TRIVY_BIN.exists() else None)

    if not candidate:
        return None, "Unknown"

    try:
        res = subprocess.run([candidate, "--version"], capture_output=True, text=True, timeout=5)  # noqa: S603
        first_line = res.stdout.split("\n")[0]
        return candidate, first_line.replace("Version: ", "v")
    except Exception:
        return candidate, "Unknown version"


def ensure_trivy(*, force: bool = False, offline: bool = False) -> str:
    """Find Trivy in PATH or local bin. Download if missing or force=True."""
    if not force:
        sys_trivy = shutil.which("trivy")
        if sys_trivy:
            return sys_trivy

        if TRIVY_BIN.exists() and os.access(TRIVY_BIN, os.X_OK):
            return str(TRIVY_BIN)

    if offline:
        raise InstallerError("Trivy not found and cannot download in offline mode.")

    if not force:
        logger.warning("Trivy not found. Downloading the latest version automatically...")

    return _download_trivy()


def _download_trivy() -> str:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    settings = load_settings()

    system = platform.system()
    machine = platform.machine().lower()

    os_map = {"Linux": "Linux", "Darwin": "macOS", "Windows": "Windows"}
    arch_map = {"x86_64": "64bit", "amd64": "64bit", "arm64": "ARM64", "aarch64": "ARM64"}

    t_os = os_map.get(system)
    t_arch = arch_map.get(machine, "64bit")

    if not t_os:
        raise InstallerError(f"Unsupported OS for automatic install: {system}")

    headers = {}
    if settings.network.github_token:
        headers["Authorization"] = f"Bearer {settings.network.github_token}"

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=settings.network.timeout,
            verify=settings.network.verify_ssl,
            headers=headers,
        ) as client:
            resp = client.get(settings.urls.trivy_api)
            resp.raise_for_status()
            data = resp.json()

            asset_url = None
            for asset in data.get("assets", []):
                name = asset["name"]
                if (
                    t_os in name
                    and t_arch in name
                    and (name.endswith(".tar.gz") or name.endswith(".zip"))
                ):
                    asset_url = asset["browser_download_url"]
                    break

            if not asset_url:
                raise InstallerError(f"No Trivy release found for {t_os} {t_arch}")

            logger.debug("Downloading %s", asset_url)
            archive_path = BIN_DIR / asset_url.split("/")[-1]

            with open(archive_path, "wb") as f:
                with client.stream("GET", asset_url) as r:
                    r.raise_for_status()
                    for chunk in r.iter_bytes():
                        f.write(chunk)

        _extract_binary(archive_path)
        archive_path.unlink()

        if not TRIVY_BIN.exists():
            raise InstallerError("Extraction failed: trivy binary not found.")

        TRIVY_BIN.chmod(0o755)
        return str(TRIVY_BIN)

    except Exception as e:
        raise InstallerError(f"Failed to install Trivy: {e}") from e


def _extract_binary(archive_path: Path) -> None:
    target_name = "trivy.exe" if platform.system() == "Windows" else "trivy"

    if archive_path.name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            for zip_member in zip_ref.namelist():
                if zip_member.endswith(target_name):
                    with zip_ref.open(zip_member) as source, open(TRIVY_BIN, "wb") as target:
                        shutil.copyfileobj(source, target)
                    break
    else:
        with tarfile.open(archive_path, "r:gz") as tar_ref:
            for tar_member in tar_ref.getmembers():
                if tar_member.name.endswith(target_name):
                    f = tar_ref.extractfile(tar_member)
                    if f:
                        with open(TRIVY_BIN, "wb") as target:
                            shutil.copyfileobj(f, target)
                    break
