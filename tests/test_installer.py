"""Tests for the Trivy auto-installer."""

from __future__ import annotations

from unittest.mock import MagicMock, mock_open, patch

import httpx
import pytest

from flaw.scanner.installer import (
    InstallerError,
    _download_trivy,
    _extract_binary,
    ensure_trivy,
    get_trivy_info,
)


class TestInstaller:
    @patch("flaw.scanner.installer.subprocess.run")
    @patch("flaw.scanner.installer.shutil.which")
    def test_get_trivy_info_found(self, mock_which: MagicMock, mock_run: MagicMock) -> None:
        mock_which.return_value = "/usr/bin/trivy"
        mock_run.return_value.stdout = "Version: 0.49.0\n..."
        path, version = get_trivy_info()
        assert path == "/usr/bin/trivy"
        assert version == "v0.49.0"

    @patch("flaw.scanner.installer.shutil.which")
    @patch("flaw.scanner.installer.TRIVY_BIN")
    def test_get_trivy_info_missing(self, mock_bin: MagicMock, mock_which: MagicMock) -> None:
        mock_which.return_value = None
        mock_bin.exists.return_value = False
        path, version = get_trivy_info()
        assert path is None
        assert version == "Unknown"

    @patch("flaw.scanner.installer.TRIVY_BIN")
    @patch("flaw.scanner.installer.shutil.which")
    def test_ensure_trivy_offline_fail(self, mock_which: MagicMock, mock_bin: MagicMock) -> None:
        mock_which.return_value = None
        mock_bin.exists.return_value = False
        with pytest.raises(InstallerError, match="offline mode"):
            ensure_trivy(offline=True)

    @patch("flaw.scanner.installer.shutil.which")
    def test_ensure_trivy_found_no_force(self, mock_which: MagicMock) -> None:
        mock_which.return_value = "/bin/trivy"
        assert ensure_trivy() == "/bin/trivy"

    @patch("flaw.scanner.installer.platform.system")
    def test_download_trivy_unsupported_os(self, mock_sys: MagicMock) -> None:
        mock_sys.return_value = "FreeBSD"
        with pytest.raises(InstallerError, match="Unsupported OS"):
            _download_trivy()

    @patch(
        "flaw.scanner.installer.Path.unlink"
    )  # FIX: мокаем unlink, чтобы не было FileNotFoundError
    @patch("flaw.scanner.installer.load_settings")
    @patch("flaw.scanner.installer.TRIVY_BIN")
    @patch("flaw.scanner.installer._extract_binary")
    @patch("flaw.scanner.installer.httpx.Client")
    @patch("flaw.scanner.installer.platform.machine", return_value="x86_64")
    @patch("flaw.scanner.installer.platform.system", return_value="Linux")
    def test_download_trivy_success(
        self,
        mock_sys: MagicMock,
        mock_mach: MagicMock,
        mock_client_cls: MagicMock,
        mock_extract: MagicMock,
        mock_bin: MagicMock,
        mock_settings: MagicMock,
        mock_unlink: MagicMock,
    ) -> None:
        mock_settings.return_value.network.github_token = ""
        mock_settings.return_value.network.timeout = 30
        mock_settings.return_value.network.verify_ssl = True
        mock_settings.return_value.urls.trivy_api = "https://api"

        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value.json.return_value = {
            "assets": [{"name": "trivy_Linux-64bit.tar.gz", "browser_download_url": "http://dl"}]
        }

        mock_stream_ctx = MagicMock()
        mock_stream_ctx.__enter__.return_value.iter_bytes.return_value = [b"data"]
        mock_client.stream.return_value = mock_stream_ctx
        mock_bin.exists.return_value = True

        m_open = mock_open()
        with patch("builtins.open", m_open):
            res = _download_trivy()
            assert res == str(mock_bin)
            mock_extract.assert_called_once()
            mock_unlink.assert_called_once()

    @patch("flaw.scanner.installer.load_settings")
    @patch("flaw.scanner.installer.httpx.Client")
    @patch("flaw.scanner.installer.platform.machine", return_value="x86_64")
    @patch("flaw.scanner.installer.platform.system", return_value="Linux")
    def test_download_trivy_api_error(
        self,
        mock_sys: MagicMock,
        mock_mach: MagicMock,
        mock_client_cls: MagicMock,
        mock_settings: MagicMock,
    ) -> None:
        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = httpx.HTTPError("API Down")

        with pytest.raises(InstallerError, match="Failed to install Trivy"):
            _download_trivy()

    def test_extract_binary_tar(self) -> None:
        archive_path = MagicMock()
        archive_path.name = "trivy.tar.gz"

        with (
            patch("flaw.scanner.installer.tarfile.open") as mock_tar,
            patch("builtins.open", mock_open()),
            patch("flaw.scanner.installer.shutil.copyfileobj"),
        ):
            mock_tar_obj = MagicMock()
            mock_tar.return_value.__enter__.return_value = mock_tar_obj
            member = MagicMock()
            member.name = "trivy"
            mock_tar_obj.getmembers.return_value = [member]
            mock_tar_obj.extractfile.return_value = MagicMock()

            _extract_binary(archive_path)
            mock_tar_obj.extractfile.assert_called_once_with(member)

    def test_extract_binary_zip(self) -> None:
        archive_path = MagicMock()
        archive_path.name = "trivy.zip"

        with (
            patch("flaw.scanner.installer.zipfile.ZipFile") as mock_zip,
            patch("builtins.open", mock_open()),
            patch("flaw.scanner.installer.shutil.copyfileobj"),
        ):
            mock_zip_obj = MagicMock()
            mock_zip.return_value.__enter__.return_value = mock_zip_obj
            mock_zip_obj.namelist.return_value = ["README.txt", "trivy.exe"]
            mock_zip_obj.open.return_value.__enter__.return_value = MagicMock()

            with patch("flaw.scanner.installer.platform.system", return_value="Windows"):
                _extract_binary(archive_path)
                mock_zip_obj.open.assert_called_once_with("trivy.exe")
