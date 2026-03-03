"""Tests for the ML model manager."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import httpx

from flaw.intelligence.model_manager import _is_model_stale, ensure_model


class TestModelManager:
    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_is_model_stale_missing(self, mock_path: MagicMock) -> None:
        mock_path.exists.return_value = False
        assert _is_model_stale(30) is True

    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_is_model_stale_fresh(self, mock_path: MagicMock) -> None:
        mock_path.exists.return_value = True
        mock_path.stat.return_value.st_mtime = time.time() - 86400
        assert _is_model_stale(30) is False

    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_is_model_stale_old(self, mock_path: MagicMock) -> None:
        mock_path.exists.return_value = True
        mock_path.stat.return_value.st_mtime = time.time() - (86400 * 40)
        assert _is_model_stale(30) is True

    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_ensure_model_offline_exists(self, mock_path: MagicMock) -> None:
        mock_path.exists.return_value = True
        mock_path.stat.return_value.st_mtime = time.time()
        assert ensure_model(offline=True) == mock_path

    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_ensure_model_offline_missing(self, mock_path: MagicMock) -> None:
        mock_path.exists.return_value = False
        assert ensure_model(offline=True) is None

    @patch("flaw.intelligence.model_manager._is_model_stale")
    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_ensure_model_cached_and_fresh(
        self, mock_path: MagicMock, mock_stale: MagicMock
    ) -> None:
        mock_path.exists.return_value = True
        mock_stale.return_value = False
        assert ensure_model() == mock_path

    @patch("flaw.intelligence.model_manager.httpx.Client")
    @patch("flaw.intelligence.model_manager.MODELS_DIR")
    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_ensure_model_download_success(
        self, mock_path: MagicMock, mock_dir: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_path.exists.return_value = False

        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.return_value.text = '{"format": "flaw_xgboost_v1"}'

        result = ensure_model(force=True)
        assert result == mock_path
        mock_path.write_text.assert_called_once()

    @patch("flaw.intelligence.model_manager.httpx.Client")
    @patch("flaw.intelligence.model_manager.MODEL_PATH")
    def test_ensure_model_download_http_error(
        self, mock_path: MagicMock, mock_client_cls: MagicMock
    ) -> None:
        mock_path.exists.return_value = False

        mock_client = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_client
        mock_client.get.side_effect = httpx.HTTPError("Network Error")

        assert ensure_model(force=True) is None
