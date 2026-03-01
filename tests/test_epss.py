"""Tests for EPSS data module."""

from __future__ import annotations

import gzip
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from flaw.intelligence.db import get_connection
from flaw.intelligence.epss import EPSSError, ensure_fresh, get_score, get_scores, update


class TestEPSSUpdate:
    """Tests for EPSS network updates and cache management."""

    @patch("flaw.intelligence.epss.httpx.Client")
    def test_update_success(self, mock_client_class: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        csv_data = b"cve,epss,percentile\nCVE-2023-1234,0.5,0.8\n#comment\n"
        gz_data = gzip.compress(csv_data)

        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.iter_bytes.return_value = [gz_data]
        mock_stream_ctx = MagicMock()
        mock_stream_ctx.__enter__.return_value = mock_response
        mock_client.stream.return_value = mock_stream_ctx

        count = update(conn, tmp_path)
        assert count == 1
        assert get_score(conn, "CVE-2023-1234") == 0.5
        conn.close()

    @patch("flaw.intelligence.epss.httpx.Client")
    def test_update_http_error(self, mock_client_class: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPError("Network Error")
        mock_stream_ctx = MagicMock()
        mock_stream_ctx.__enter__.return_value = mock_response
        mock_client.stream.return_value = mock_stream_ctx

        with pytest.raises(EPSSError, match="Failed to download"):
            update(conn, tmp_path)
        conn.close()

    @patch("flaw.intelligence.epss.update")
    def test_ensure_fresh_stale(self, mock_update: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        with patch("flaw.intelligence.epss.is_stale", return_value=True):
            ensure_fresh(conn, tmp_path)
            mock_update.assert_called_once()
        conn.close()

    @patch("flaw.intelligence.epss.update", side_effect=EPSSError("fail"))
    def test_ensure_fresh_stale_error_handled(self, mock_update: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        with patch("flaw.intelligence.epss.is_stale", return_value=True):
            ensure_fresh(conn, tmp_path)
        conn.close()

    @patch("flaw.intelligence.epss.update")
    def test_ensure_fresh_offline(self, mock_update: MagicMock, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        ensure_fresh(conn, tmp_path, offline=True)
        mock_update.assert_not_called()
        conn.close()


class TestEPSSLookup:
    """Tests for EPSS score lookups (no network)."""

    def test_get_score_found(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.execute(
            "INSERT INTO epss_scores (cve, score) VALUES (?, ?)",
            ("CVE-2023-44487", 0.9214),
        )
        conn.commit()

        assert get_score(conn, "CVE-2023-44487") == 0.9214
        conn.close()

    def test_get_score_not_found(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert get_score(conn, "CVE-9999-0000") == 0.0
        conn.close()

    def test_get_scores_batch(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        conn.executemany(
            "INSERT INTO epss_scores (cve, score) VALUES (?, ?)",
            [
                ("CVE-2023-0001", 0.5),
                ("CVE-2023-0002", 0.8),
                ("CVE-2023-0003", 0.1),
            ],
        )
        conn.commit()

        result = get_scores(conn, ["CVE-2023-0001", "CVE-2023-0003", "CVE-9999-0000"])
        assert result == {"CVE-2023-0001": 0.5, "CVE-2023-0003": 0.1}
        conn.close()

    def test_get_scores_empty_input(self, tmp_path: Path) -> None:
        conn = get_connection(tmp_path / "test.db")
        assert get_scores(conn, []) == {}
        conn.close()
